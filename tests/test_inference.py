# Check inference behavior using software fixtures and existing evidence.
import copy

import joblib
import numpy as np
import pandas as pd
import pytest

from src.event_builder import build_events
from src.feature_engineering import build_features
from src.inference import predict_csv, predict_events, prediction_records
from src.preprocessing import preprocess_frame
from src.training import fit_model, save_model


# Check that training reload inference and invalid rows.
@pytest.mark.parametrize("kind", ["baseline", "contextual"])
def test_training_reload_inference_and_invalid_rows(events, raw, cfg, tmp_path, kind):
    artifact = fit_model(events, events.copy(), cfg, kind)
    save_model(artifact, tmp_path)
    restored = joblib.load(tmp_path / "model.joblib")
    first = predict_events(events, restored)
    second = predict_events(events, restored)
    assert first.prediction.isin(cfg_classes := ["Normal", "Command_Response_Injection"]).all()
    assert first.confidence.between(0, 1).all()
    assert set(restored["pipeline"].classes_) == set(cfg_classes)
    pd.testing.assert_series_equal(first.prediction, second.prediction)
    assert np.array_equal(first.confidence, second.confidence)
    changed_labels = raw.copy()
    changed_labels["attack_category"] = "untrusted_upload_label"
    predicted, _ = predict_csv(changed_labels, restored)
    assert predicted.prediction.tolist() == first.prediction.tolist()
    changed_labels.loc[0, "modbus_func_code"] = 999
    predicted, health = predict_csv(changed_labels, restored)
    assert health["malformed"] == 1
    assert pd.isna(predicted.iloc[0].prediction)
    assert prediction_records(predicted)[0]["confidence"] is None


# Check that three class pipeline without architecture change.
def test_three_class_pipeline_without_architecture_change(raw, cfg):
    final = copy.deepcopy(cfg)
    final["model_mode"] = "final_three_class"
    final["dataset"]["verified_labels"] = True
    final["dataset"]["label_evidence"] = "synthetic unit-test fixture, not research evidence"
    raw["attack_category"] = ["Normal"] * 16 + ["Command_Injection"] * 16 + ["Response_Injection"] * 16
    events = build_events(preprocess_frame(raw, final, "fixture"), final)
    artifact = fit_model(events, events.copy(), final, "contextual")
    output = predict_events(events, artifact)
    assert set(artifact["pipeline"].classes_) == {"Normal", "Command_Injection", "Response_Injection"}
    assert output.confidence.between(0, 1).all()
    assert output.model_mode.eq("final_three_class").all()


# Check that imputer is fitted only on training.
def test_imputer_is_fitted_only_on_training(events, cfg):
    train, val = events.copy(), events.copy()
    train["modbus_val"] = np.nan
    val["modbus_val"] = 987654
    artifact = fit_model(train, val, cfg, "baseline")
    index = list(build_features(train, cfg, "baseline")).index("value")
    assert artifact["pipeline"].named_steps["imputer"].statistics_[index] == 0
