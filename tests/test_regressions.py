# Check regressions behavior using software fixtures and existing evidence.
import copy

import pandas as pd
import pytest
import yaml

from src.event_builder import build_events
from src.inference import predict_csv
from src.preprocessing import preprocess_frame, split_events
from src.training import fit_model
from src.utils import load_config


# Check that inference ignores aliased labels.
def test_inference_ignores_aliased_labels(raw, events, cfg):
    cfg["dataset"]["column_map"] = {"Original Label": "attack_category"}
    artifact = fit_model(events, events.copy(), cfg, "baseline")
    raw = raw.rename(columns={"attack_category": "Original Label"})
    raw["Original Label"] = "not-a-training-label"
    output, health = predict_csv(raw, artifact)
    assert health["processed"] == len(raw)
    assert output.prediction.notna().all()


# Check that same capture across files stays together.
def test_same_capture_across_files_stays_together(raw, cfg):
    frames = []
    for capture in range(12):
        for part in range(2):
            sample = raw.copy()
            sample["file_source"] = f"capture-{capture}"
            frames.append(preprocess_frame(sample, cfg, f"file-{capture}-{part}"))
    result, _ = split_events(pd.concat(frames, ignore_index=True), cfg)
    assert result.groupby("file_source").partition.nunique().eq(1).all()


# Check that scenarios reset context without splitting capture.
def test_scenarios_reset_context_without_splitting_capture(raw, cfg):
    raw["scenario_id"] = ["first"] * 24 + ["second"] * 24
    prepared = preprocess_frame(raw, cfg, "fixture")
    assert prepared.group_id.nunique() == 1
    events = build_events(prepared, cfg)
    assert events.context_id.nunique() == 2


# Check that final mode requires label evidence.
def test_final_mode_requires_label_evidence(cfg, tmp_path):
    final = copy.deepcopy(cfg)
    final["model_mode"] = "final_three_class"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(final))
    with pytest.raises(ValueError, match="label_evidence"):
        load_config(path)


# Check that all malformed input has no predictions.
def test_all_malformed_input_has_no_predictions(raw, events, cfg):
    artifact = fit_model(events, events.copy(), cfg, "baseline")
    raw["modbus_func_code"] = 999
    result, health = predict_csv(raw, artifact)
    assert health["processed"] == 0
    assert health["malformed"] == len(raw)
    assert result.prediction.isna().all()
