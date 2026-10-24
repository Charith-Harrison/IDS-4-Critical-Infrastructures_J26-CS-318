"""Comprehensive automated test suite for the C2 Reconnaissance Detection pipeline (Section 25).

Covers all 16 required verification categories:
1. Original dataset immutability (SHA-256 & byte-count verification)
2. Dataset profile exactness (879,225 packets; 175,800 sequences; 158 attack events)
3. Rebuilt sequence chronological monotonicity (0 backward time jumps in windows)
4. Stream boundary integrity (0 windows crossing session_id or capture_group)
5. Window label rule exactness (any_positive)
6. Zero capture-group leakage across fit/val/test splits
7. Zero packet overlap across fit/val/test splits in LOCGO-10 and SGKF-5
8. Training-only scaler fitting verification
9. Prohibited identifier exclusion from all feature schemas
10. Sequence tensor and window feature matrix shapes & batch-vs-single parity
11. Valid probability bounds [0, 1] for all baseline and LSTM models
12. Exact timing-feature ablation definition (Model D removes only SEQ_TIMING)
13. Single-class fold metric discipline (None/null for undefined ROC-AUC/PR-AUC/F1)
14. Deterministic reload of saved PyTorch and scikit-learn artifacts
15. C2 integration contract schema and FastAPI endpoint tests (/health, /metrics, /examples, /predict)
16. Positive numeric latency measurements in artifacts/latency.json
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import app  # noqa: E402
from common import ARTIFACTS, DATA_RAW, DATA_REBUILT, REPO_ROOT, read_json, sha256_file  # noqa: E402
from contract import C2InferenceEngine  # noqa: E402
from evaluate import evaluate_predictions  # noqa: E402
from features import (  # noqa: E402
    PACKET_FEATURES,
    SEQ_FEATURES,
    SEQ_FEATURES_NO_TIMING,
    SEQ_TIMING,
    WINDOW_FEATURES,
    SequenceScaler,
    extract_single_window_from_packets,
    packet_level_columns,
    sequence_tensor,
    window_aggregates,
)


def test_01_original_dataset_files_unmodified() -> None:
    manifest = read_json(DATA_RAW / "raw_manifest.json")
    for info in manifest["files"]:
        orig_path = Path(info["source"])
        assert orig_path.exists(), f"Missing original dataset file: {orig_path}"
        assert orig_path.stat().st_size == info["original_size"]
        assert sha256_file(orig_path) == info["original_sha256_before"]
        assert info["original_sha256_before"] == info["original_sha256_after"]


def test_02_dataset_profile_matches_actual_counts() -> None:
    profile = read_json(ARTIFACTS / "dataset_profile.json")
    assert profile["packets"]["rows"] == 879225
    assert profile["packets"]["label_counts"]["1"] == 8699
    assert profile["packets"]["label_counts"]["0"] == 870526
    assert profile["packets"]["n_session_id"] == 17
    assert profile["packets"]["n_file_source"] == 15

    assert profile["sequences"]["rows"] == 175800
    assert profile["sequences"]["label_counts"]["1"] == 18338
    assert profile["sequences"]["label_counts"]["0"] == 157462
    assert profile["sequences"]["n_session_id"] == 13
    assert profile["sequences"]["features_tensor_shape"] == [175800, 20, 7]

    assert profile["events"]["rows"] == 158


def test_03_rebuilt_sequences_preserve_chronological_order() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    ts = r["ts_ns"].to_numpy(dtype=np.int64)[idx_mat]
    dts = np.diff(ts, axis=1)
    assert (dts >= 0).all(), "Rebuilt windows must have strictly non-decreasing timestamps"


def test_04_rebuilt_windows_do_not_cross_session_or_capture_boundaries() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    cg = r["capture_group"].to_numpy()[idx_mat]
    sid = r["session_id"].to_numpy()[idx_mat]
    assert (cg[:, 0:1] == cg).all(), "Window crossed capture_group boundary"
    assert (sid[:, 0:1] == sid).all(), "Window crossed session_id boundary"


def test_05_window_labels_match_any_positive_rule() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    pkt_labels = r["label"].to_numpy(dtype=np.int64)[idx_mat]
    expected_win_labels = (pkt_labels.sum(axis=1) >= 1).astype(np.int64)
    assert np.array_equal(W["label"].to_numpy(dtype=np.int64), expected_win_labels)


def test_06_and_07_splits_have_zero_group_or_packet_leakage() -> None:
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    folds_art = read_json(ARTIFACTS / "folds.json")

    for scheme in ["locgo_10fold", "sgkf_5fold"]:
        assert folds_art[scheme]["leakage_verification"]["all_folds_zero_packet_overlap"] is True
        for f in folds_art[scheme]["folds"]:
            fit_g = set(f["fit_groups"])
            val_g = set(f["val_groups"])
            test_g = set(f["test_groups"])
            assert fit_g.isdisjoint(val_g)
            assert fit_g.isdisjoint(test_g)
            assert val_g.isdisjoint(test_g)

            p_fit = set(np.unique(idx_mat[W["capture_group"].isin(fit_g)]).tolist())
            p_val = set(np.unique(idx_mat[W["capture_group"].isin(val_g)]).tolist())
            p_test = set(np.unique(idx_mat[W["capture_group"].isin(test_g)]).tolist())
            assert p_fit.isdisjoint(p_test)
            assert p_val.isdisjoint(p_test)
            assert p_fit.isdisjoint(p_val)


def test_08_scaler_fits_on_training_only() -> None:
    rng = np.random.default_rng(42)
    X_train = rng.normal(loc=10.0, scale=2.0, size=(100, 20, 5)).astype(np.float32)
    X_test = rng.normal(loc=-50.0, scale=9.0, size=(50, 20, 5)).astype(np.float32)
    sc = SequenceScaler(["f1", "f2", "f3", "f4", "f5"]).fit(X_train)
    expected_mean = X_train.reshape(-1, 5).mean(axis=0)
    assert np.allclose(sc.mean_, expected_mean, atol=1e-4)
    Z_test = sc.transform(X_test)
    assert not np.allclose(Z_test.mean(axis=(0, 1)), 0.0, atol=1.0)


def test_09_prohibited_identifiers_absent_from_features() -> None:
    leak_art = read_json(ARTIFACTS / "leakage_audit.json")
    prohibited = set(leak_art["prohibited_identifier_columns"])
    for feat_list in [PACKET_FEATURES, SEQ_FEATURES, WINDOW_FEATURES]:
        overlap = prohibited.intersection(set(feat_list))
        assert len(overlap) == 0, f"Prohibited ID columns found in features: {overlap}"


def test_10_sequence_tensor_shapes_and_single_window_parity() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv", nrows=500)
    r_cols = packet_level_columns(r)
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")[:10]

    X_seq = sequence_tensor(r_cols, idx_mat, features=SEQ_FEATURES)
    X_win = window_aggregates(r_cols, idx_mat)
    assert X_seq.shape == (10, 20, len(SEQ_FEATURES))
    assert X_win.shape == (10, len(WINDOW_FEATURES))

    # Verify single-window runtime extraction matches batch extraction exactly
    for w_i in range(5):
        pkt_slice = r.iloc[idx_mat[w_i]][
            ["timestamp", "ts_ns", "dt_s", "func_code", "modbus_len", "register_start", "quantity", "packet_size"]
        ]
        s_seq, s_win, _ = extract_single_window_from_packets(pkt_slice, seq_features=SEQ_FEATURES)
        assert np.allclose(s_seq, X_seq[w_i : w_i + 1], equal_nan=True, atol=1e-5)
        assert np.allclose(s_win.to_numpy(), X_win.iloc[w_i : w_i + 1].to_numpy(), atol=1e-5)


def test_11_predictions_are_valid_probabilities() -> None:
    preds_df = pd.read_csv(ARTIFACTS / "predictions.csv")
    assert len(preds_df) == 119237
    score_cols = [c for c in preds_df.columns if c.startswith("score_")]
    assert len(score_cols) >= 6
    for col in score_cols:
        vals = preds_df[col].to_numpy()
        assert not np.isnan(vals).any(), f"NaN in {col}"
        assert (vals >= 0.0).all() and (vals <= 1.0).all(), f"Out-of-bounds score in {col}"


def test_12_model_d_removes_only_timing_features() -> None:
    diff = [f for f in SEQ_FEATURES if f not in SEQ_FEATURES_NO_TIMING]
    assert diff == SEQ_TIMING
    assert len(SEQ_FEATURES) - len(SEQ_FEATURES_NO_TIMING) == 2


def test_13_single_class_metrics_are_none_not_fabricated() -> None:
    y_norm_only = np.zeros(100, dtype=np.int64)
    scores = np.linspace(0.01, 0.20, 100)
    ev = evaluate_predictions(y_norm_only, scores, threshold=0.5)
    assert ev["single_class"] is True
    assert ev["roc_auc"] is None
    assert ev["pr_auc"] is None
    assert ev["recall"] is None
    assert ev["precision"] is None
    assert ev["f1"] is None
    assert ev["fpr"] == 0.0
    assert ev["specificity"] == 1.0

    # Also verify in saved metrics.json for normal-only LOCGO folds (e.g. G01_0122_normal4)
    metrics_art = read_json(ARTIFACTS / "metrics.json")
    g01_fold = metrics_art["models"]["Model_C_LSTM_Full"]["locgo_10fold"]["per_fold"][0]
    assert g01_fold["test_groups"] == ["G01_0122_normal4"]
    assert g01_fold["at_0_5"]["roc_auc"] is None
    assert g01_fold["at_0_5"]["pr_auc"] is None
    assert g01_fold["at_0_5"]["f1"] is None
    assert g01_fold["at_0_5"]["fpr"] is not None


def test_14_saved_models_reload_and_reproduce_predictions() -> None:
    ex_art = read_json(ARTIFACTS / "example_sequences.json")
    tp_ex = ex_art["examples"]["true_positive_cat1_modbus_len3_signature"]
    tn_ex = ex_art["examples"]["true_negative_routine_polling"]

    eng1 = C2InferenceEngine().load()
    eng2 = C2InferenceEngine().load()

    res1 = eng1.score_window(tp_ex["packets"], session_id=tp_ex["session_id"])
    res2 = eng2.score_window(tp_ex["packets"], session_id=tp_ex["session_id"])
    assert np.isclose(res1["score"], res2["score"], atol=1e-7)
    assert res1["prediction"] == 1

    res_tn = eng1.score_window(tn_ex["packets"], session_id=tn_ex["session_id"])
    assert res_tn["prediction"] == 0


def test_15_contract_and_fastapi_endpoints() -> None:
    client = TestClient(app)

    r_health = client.get("/health")
    assert r_health.status_code == 200
    h_json = r_health.json()
    assert h_json["status"] == "ok"
    assert h_json["module"] == "C2_RECON_DETECTION"

    r_metrics = client.get("/metrics")
    assert r_metrics.status_code == 200
    assert "evaluation_metrics" in r_metrics.json()

    r_ex = client.get("/examples")
    assert r_ex.status_code == 200
    ex_data = r_ex.json()["examples"]["true_positive_cat1_modbus_len3_signature"]

    r_dash = client.get("/dashboard-data")
    assert r_dash.status_code == 200
    d_json = r_dash.json()
    assert "models" in d_json
    assert "detected_packets_feed" in d_json
    assert "inspected_windows" in d_json
    assert len(d_json["detected_packets_feed"]) > 50

    r_pkts = client.get("/detected-packets?verdict=TP&limit=25")
    assert r_pkts.status_code == 200
    p_json = r_pkts.json()
    assert p_json["total_matching"] > 0
    assert all(row["verdict_lstm_c"] == "TP" for row in p_json["packets"])

    r_pred = client.post(
        "/predict",
        json={
            "session_id": ex_data["session_id"],
            "model_version": "c2-lstm-v1",
            "include_attribution": True,
            "packets": ex_data["packets"],
        },
    )
    assert r_pred.status_code == 200
    c_json = r_pred.json()
    required_keys = {
        "module",
        "attack_type",
        "window_start",
        "window_end",
        "session_id",
        "sequence_length",
        "prediction",
        "score",
        "score_type",
        "calibrated",
        "threshold",
        "severity",
        "top_indicators",
        "model_version",
        "latency_ms",
    }
    assert required_keys.issubset(set(c_json.keys()))
    assert c_json["module"] == "C2_RECON_DETECTION"
    assert c_json["attack_type"] == "Reconnaissance"
    assert c_json["sequence_length"] == 20
    assert c_json["prediction"] == 1
    assert c_json["calibrated"] is False
    assert c_json["latency_ms"] > 0.0


def test_16_latency_artifact_has_positive_measurements() -> None:
    lat = read_json(ARTIFACTS / "latency.json")
    for k, v in lat["single_window_inference_only_ms"].items():
        assert v["mean_ms"] > 0.0, f"Non-positive latency for {k}"
        assert v["p95_ms"] > 0.0
        assert v["p99_ms"] < 100.0, f"{k} exceeded 100ms target"
    for k, v in lat["single_window_end_to_end_ms"].items():
        assert v["mean_ms"] > 0.0
        assert v["p99_ms"] < 100.0
