# Tests: file/schema validation, capture reconstruction, duplicates, labels,
# pairing, missing responses, split and test-partition protection.
from __future__ import annotations

import io

import pandas as pd
import pytest

from src.data.audit import duplicate_investigation
from src.data.loader import DataValidationError, validate_file, validate_schema, validate_upload
from src.data.pairing import pair_events
from src.data.preprocess import add_protocol_basics, map_labels, reconstruct_captures, standardize
from src.data.split import choose_test_captures
from src.inference.predict import preprocess_raw
from src.utils.config import TEST_PARQUET, assert_not_test_path, read_parquet_safe
from tests.conftest import mk_row


def test_file_validation_rejects_bad_files(tmp_path):
    with pytest.raises(DataValidationError):
        validate_file(tmp_path / "missing.csv")
    (tmp_path / "a.txt").write_text("x")
    with pytest.raises(DataValidationError):
        validate_file(tmp_path / "a.txt")
    (tmp_path / "empty.csv").write_text("")
    with pytest.raises(DataValidationError):
        validate_file(tmp_path / "empty.csv")


def test_upload_rejects_wrong_type_and_empty():
    with pytest.raises(DataValidationError):
        validate_upload("x.xlsx", b"a,b")
    with pytest.raises(DataValidationError):
        validate_upload("x.csv", b"")


def test_schema_validation_reports_missing_columns(raw_pairs):
    assert validate_schema(raw_pairs)["ok"]
    info = validate_schema(raw_pairs.drop(columns=["modbus_func_code"]))
    assert not info["ok"] and "modbus_func_code" in info["missing"]
    with pytest.raises(DataValidationError):
        validate_schema(raw_pairs.iloc[0:0])


def test_invalid_numeric_and_timestamp_are_reported_not_classified(raw_pairs):
    df = raw_pairs.copy()
    df["modbus_ref_num"] = df["modbus_ref_num"].astype(object)
    df.loc[0, "modbus_ref_num"] = "abc"
    df.loc[1, "timestamp"] = -5
    clean, invalid = standardize(df, "unit")
    assert set(invalid["source_row"]) == {0, 1}
    assert len(clean) == 2


def test_capture_reconstruction_by_resets():
    df = pd.DataFrame({"frame_number": [1, 2, 3, 1, 2], "timestamp": [10.0, 11, 12, 20, 21]})
    out = reconstruct_captures(df, "atk")
    assert list(out["capture_id"]) == ["atk-0", "atk-0", "atk-0", "atk-1", "atk-1"]
    assert out["boundary_reason"].iloc[3] == "frame_number reset"


def test_capture_uses_genuine_file_source_field():
    df = pd.DataFrame({"frame_number": [1, 2], "timestamp": [1.0, 2.0], "file_source": ["x-normal-1.pcap"] * 2})
    assert set(reconstruct_captures(df, "base")["capture_id"]) == {"base-x-normal-1"}


def test_duplicate_detection_counts_overlap(raw_pairs):
    other = raw_pairs.iloc[:2].copy()
    res = duplicate_investigation(raw_pairs, other)
    assert res["cross_file_duplicate_pairs"] == 2
    assert (
        duplicate_investigation(raw_pairs, other.assign(timestamp=other["timestamp"] + 500))[
            "cross_file_duplicate_pairs"
        ]
        == 0
    )


def _labelled(rows):
    """Label-mapping helper: rows are (is_attack, sub_type, fc, ref)."""
    df = pd.DataFrame(
        {
            "is_attack": [r[0] for r in rows],
            "attack_sub_type": [r[1] for r in rows],
            "attack_category": ["x"] * len(rows),
            "is_request": [1] * len(rows),
            "modbus_func_code": [r[2] for r in rows],
            "modbus_ref_num": [r[3] for r in rows],
        }
    )
    return map_labels(df, ["5:13"])


def test_label_mapping_and_legitimate_write_handling():
    out = _labelled(
        [
            (0, "Normal", 5, 13),
            (1, "Coil_Brute_Force", 5, 13),
            (1, "Coil_Brute_Force", 5, 77),
            (1, "Length_Manipulation", 3, 1),
            (1, "Coil_Brute_Force", 3, 1),
        ]
    )
    assert out["class_id"].iloc[0] == 0  # normal stays normal
    assert pd.isna(out["class_id"].iloc[1])  # write identical to a routine write: ambiguous
    assert out["label_status"].iloc[1] == "ambiguous_write_matches_normal_profile"
    assert out["class_id"].iloc[2] == 1  # unseen write: reconstructed command injection
    assert out["label_status"].iloc[3] == "unsupported_length_manipulation"
    assert pd.isna(out["class_id"].iloc[4])  # a read is not called injection
    assert 2 not in set(out["class_id"].dropna())  # no response-injection class exists


def test_unlabelled_input_has_no_labels(raw_pairs):
    packets, invalid, _ = preprocess_raw(raw_pairs)
    assert (packets["label_status"] == "no_label_available").all()


def test_pair_reconstruction_and_missing_response(raw_pairs):
    packets, _, _ = preprocess_raw(raw_pairs)
    events, orphans, stats = pair_events(packets)
    assert stats["requests"] == 2 and stats["matched_pairs"] == 1
    assert stats["missing_responses"] == 1 and stats["orphan_responses"] == 1
    assert set(events["pair_status"]) >= {"matched"}
    assert len(orphans) == 1


def test_exception_response_is_flagged():
    df = pd.DataFrame([mk_row(1.0, 1, 1, 5, 3), mk_row(1.1, 2, 0, 5, 3, exc=1)])
    packets, _, _ = preprocess_raw(df)
    _, _, stats = pair_events(packets)
    assert stats["exception_responses"] == 1


def test_transaction_id_reuse_is_counted():
    df = pd.DataFrame([mk_row(1.0, 1, 1, 7, 3), mk_row(1.1, 2, 1, 7, 3), mk_row(1.2, 3, 0, 7, 3)])
    packets, _, _ = preprocess_raw(df)
    _, _, stats = pair_events(packets)
    assert stats["requests_with_reused_transaction_key"] >= 1


def test_group_split_keeps_captures_whole():
    # (capture, normal count, attack count): unit-test counts only
    spec = [("a", 1500, 1500), ("b", 1500, 1500), ("c", 3000, 0), ("d", 1500, 1500), ("e", 1500, 1500), ("f", 4500, 0)]
    parts = [pd.DataFrame({"capture_id": c, "class_id": [0] * n + [1] * k}) for c, n, k in spec]
    ev = pd.concat(parts, ignore_index=True)
    sel = choose_test_captures(ev, target=0.25, min_class=500)
    assert not set(sel["test_captures"]) & set(sel["train_captures"])
    assert set(sel["test_captures"]) | set(sel["train_captures"]) == set("abcdef")


def test_final_test_partition_is_blocked():
    with pytest.raises(PermissionError):
        assert_not_test_path(TEST_PARQUET)
    with pytest.raises(PermissionError):
        read_parquet_safe(TEST_PARQUET)
    with pytest.raises(PermissionError):
        assert_not_test_path(TEST_PARQUET.parent / "test.csv")


def test_protocol_basics_interpret_function_codes(raw_pairs):
    out = add_protocol_basics(raw_pairs)
    assert out.loc[2, "function_name"] == "Write Single Register" and out.loc[2, "is_write"] == 1
    assert out.loc[0, "is_write"] == 0


def test_upload_roundtrip_validates(raw_pairs):
    buf = io.BytesIO(raw_pairs.to_csv(index=False).encode())
    assert len(validate_upload("ok.csv", buf.getvalue())) == 4
