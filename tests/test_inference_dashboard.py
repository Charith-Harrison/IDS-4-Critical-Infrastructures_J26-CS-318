# Tests: single/batch validation inference, probabilities, authorized CSV
# detection, unlabelled and unclassifiable input, exports, dashboard loading.
from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from src.data.loader import DataValidationError, validate_upload
from src.inference import dashboard_data as dd
from src.inference.predict import (
    _unclassifiable,
    attach_oof,
    detect_dataframe,
    detect_validation_records,
    load_artifacts,
    single_event_inference,
    to_csv_bytes,
    to_standard_json,
)
from src.utils.config import RAW_DIR, TEST_PARQUET
from tests.conftest import ROOT


@pytest.fixture(scope="module")
def art():
    return load_artifacts("contextual")


@pytest.fixture(scope="module")
def val_run(art):
    return detect_validation_records(art, dd.dev_captures()[-1], max_events=800)


def test_batch_validation_prediction_and_probabilities(val_run):
    r = val_run["results"]
    done = r[r["processing_status"] == "complete"]
    assert len(done) > 0
    assert np.allclose(done["normal_probability"] + done["command_injection_probability"], 1.0)
    assert (done["confidence"] == done[["normal_probability", "command_injection_probability"]].max(axis=1)).all()
    assert set(done["predicted_class"]) <= {"Normal", "Command Injection"}
    assert "Response Injection" not in set(r["predicted_class"])


def test_single_event_prediction(art, val_run):
    eid = val_run["features"]["event_id"].iloc[10]
    one = single_event_inference(val_run["features"], eid, art)
    assert one["predicted_class"] in ("Normal", "Command Injection")
    assert abs(one["normal_probability"] + one["command_injection_probability"] - 1) < 1e-9
    with pytest.raises(KeyError):
        single_event_inference(val_run["features"], "nope", art)


def test_normal_and_command_injection_predictions_exist_in_dev_data(art):
    seen = set()
    for cid in dd.dev_captures():
        r = detect_validation_records(art, cid, 600)["results"]
        seen |= set(r["predicted_class"])
    assert {"Normal", "Command Injection"} <= seen


def test_actual_and_predicted_are_separate_columns(val_run):
    r = val_run["results"]
    assert "actual_class" in r and "predicted_class" in r


def test_oof_join_adds_out_of_fold_columns(val_run):
    r = attach_oof(val_run["results"])
    assert {"oof_predicted_class", "oof_command_injection_probability"} <= set(r.columns)
    assert r["oof_predicted_class"].notna().any()


def test_authorized_csv_detection_unlabelled(art):
    raw = pd.read_csv(RAW_DIR / "normal_traffic_baseline.csv", nrows=1500)
    raw = raw.drop(columns=["attack_sub_type", "is_attack", "attack_category", "file_source"])
    out = detect_dataframe(raw, art, "authorized_test.csv")
    s = out["summary"]
    assert s["labels_available"] is False
    assert (out["results"]["actual_class"] == "Unavailable").all()
    assert s["successfully_classified"] == s["normal_predictions"] + s["command_injection_predictions"]
    assert s["invalid_records"] == 0


def test_csv_detection_does_not_use_labels_as_inputs(art):
    raw = pd.read_csv(RAW_DIR / "normal_traffic_baseline.csv", nrows=800)
    a = detect_dataframe(raw, art)["results"]["command_injection_probability"].to_numpy()
    b = detect_dataframe(raw.drop(columns=["attack_sub_type", "is_attack", "attack_category", "file_source"]), art)[
        "results"
    ]["command_injection_probability"].to_numpy()
    assert np.allclose(a, b)


def test_malformed_rows_are_invalid_not_classified(art):
    raw = pd.read_csv(RAW_DIR / "normal_traffic_baseline.csv", nrows=300)
    raw["modbus_ref_num"] = raw["modbus_ref_num"].astype(object)
    raw.loc[5, "modbus_ref_num"] = "garbage"
    out = detect_dataframe(raw, art)
    assert out["summary"]["invalid_records"] == 1
    assert out["invalid"].iloc[0]["field"] == "modbus_ref_num"


def test_unclassifiable_rows_detected():
    X = pd.DataFrame({"a": [1.0, np.nan], "b": [2.0, 3.0]})
    bad = _unclassifiable(X)
    assert list(bad["row"]) == [1] and list(bad["field"]) == ["a"]


def test_missing_schema_and_empty_upload_errors():
    with pytest.raises(DataValidationError):
        validate_upload("x.csv", b"a,b\n1,2\n")
    with pytest.raises(DataValidationError):
        validate_upload("x.csv", b"")


def test_csv_and_json_exports(val_run):
    r = val_run["results"]
    csv = to_csv_bytes(r)
    assert csv.decode().splitlines()[0].startswith("event_id")
    j = json.loads(to_standard_json(r))
    ev = j["events"][0]
    for k in (
        "event_id",
        "timestamp",
        "component",
        "predicted_class",
        "class_probabilities",
        "confidence",
        "supporting_observations",
        "model_version",
        "feature_schema_version",
        "processing_time_ms",
        "processing_status",
    ):
        assert k in ev
    assert "Response Injection" not in json.dumps(j)
    assert "final integration schema pending" in j["note"]


def test_dashboard_data_loads_without_test_partition():
    assert len(dd.capture_report()) > 0
    assert set(dd.oof_predictions()["model_name"]) == {"baseline", "contextual"}
    assert dd.json_result("cv_metrics.json")["selected"]
    split = dd.read_json(dd.MANIFEST_DIR / "split_manifest.json")
    assert set(dd.capture_report()["capture_id"]) <= set(split["train_captures"])


def test_oof_metrics_include_accuracy_error_rates_and_curves():
    predictions = pd.DataFrame(
        {
            "model_name": ["baseline"] * 4,
            "fold": [0, 0, 1, 1],
            "actual_class": ["Normal", "Normal", "Command Injection", "Command Injection"],
            "predicted_class": ["Normal", "Command Injection", "Command Injection", "Normal"],
            "command_injection_probability": [0.1, 0.8, 0.9, 0.2],
        }
    )
    summary = dd.summarize_oof_predictions(predictions)["baseline"]
    metrics = summary["metrics"]

    assert metrics["records"] == 4
    assert metrics["accuracy"] == 0.5
    assert metrics["balanced_accuracy"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["normal_support"] == metrics["command_injection_support"] == 2
    assert summary["confusion_matrix"].tolist() == [[1, 1], [1, 1]]
    assert len(summary["roc_curve"]["false_positive_rate"]) > 0
    assert len(summary["precision_recall_curve"]["precision"]) > 0
    assert len(summary["fold_macro_f1"]) == 2


def test_oof_metrics_reject_invalid_probabilities():
    predictions = pd.DataFrame(
        {
            "model_name": ["baseline", "baseline"],
            "fold": [0, 1],
            "actual_class": ["Normal", "Command Injection"],
            "predicted_class": ["Normal", "Command Injection"],
            "command_injection_probability": [0.1, 1.1],
        }
    )
    with pytest.raises(ValueError, match="must be finite values from 0 to 1"):
        dd.summarize_oof_predictions(predictions)


def test_dashboard_code_never_references_test_partition():
    for path in list((ROOT / "app").glob("*.py")) + list((ROOT / "src" / "inference").glob("*.py")):
        text = path.read_text()
        assert "TEST_PARQUET" not in text.replace("from src.utils.config", "") or path.name == "config.py"
        assert "test.parquet" not in text and "test_record_ids" not in text
    assert TEST_PARQUET.name == "test.parquet"


def test_missing_result_file_raises_clear_error(tmp_path):
    with pytest.raises(dd.MissingResultError):
        dd._need(tmp_path / "absent.json")


def test_all_dashboard_pages_render():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "app" / "dashboard.py"), default_timeout=180).run()
    for page in at.sidebar.radio[0].options:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, (page, [e.value for e in at.exception])
    text = " ".join(m.value for m in at.markdown)
    for banned in ("Project Details", "System Runtime Status", "Research Component Console"):
        assert banned not in text
