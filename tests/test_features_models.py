# Tests: feature derivation, context boundaries, past-only features,
# training-only profiles, leakage columns, fold-specific fitting, model loading.
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data.pairing import pair_events
from src.features.builder import (
    CONTEXT_GROUPS,
    ISOLATED_GROUPS,
    build_stat_free_features,
    group_features,
)
from src.features.profile import apply_profile, fit_profile
from src.inference.predict import FeatureSchemaError, ModelLoadError, load_artifacts, preprocess_raw
from src.utils.config import FORBIDDEN_FEATURE_COLUMNS, MODELS_DIR
from src.utils.io import read_json
from tests.conftest import mk_row


def _events(rows):
    """Raw rows -> paired events -> stat-free features."""
    packets, _, _ = preprocess_raw(pd.DataFrame(rows))
    events, _, _ = pair_events(packets)
    events["event_id"] = events["capture_id"] + ":" + events["source_row"].astype(str)
    return build_stat_free_features(events)


def _stream(n=6, fc_cycle=(3, 6, 3, 6, 3, 6)):
    rows, t, f = [], 100.0, 1
    for i in range(n):
        rows.append(mk_row(t, f, 1, i + 1, fc_cycle[i], ref=10 + i, val=i))
        rows.append(mk_row(t + 0.05, f + 1, 0, i + 1, fc_cycle[i], ref=10 + i, val=i))
        t += 1.0
        f += 2
    return rows


def test_feature_derivations_previous_function_and_transition():
    F = _events(_stream()).sort_values("timestamp").reset_index(drop=True)
    assert F.loc[0, "first_in_stream"] == 1
    assert F.loc[1, "prev_fc"] == 3 and F.loc[1, "read_to_write"] == 1  # FC3 then FC6
    assert F.loc[2, "write_to_write"] == 0


def test_features_use_only_past_events():
    rows = _stream()
    full = _events(rows).sort_values("timestamp").reset_index(drop=True)
    # Drop every event after index 3: features of events 0..3 must not change.
    head = _events(rows[:8]).sort_values("timestamp").reset_index(drop=True)
    cols = group_features(CONTEXT_GROUPS)
    cols = [c for c in cols if c in head.columns and c in full.columns]
    a = head[cols].astype(float).to_numpy()
    b = full.loc[: len(head) - 1, cols].astype(float).to_numpy()
    assert np.allclose(np.nan_to_num(a, nan=-9), np.nan_to_num(b, nan=-9))


def test_context_windows_do_not_cross_captures():
    r1 = _stream(3, (3, 3, 3))
    r2 = [dict(r, frame_number=r["frame_number"] - 100) for r in _stream(3, (6, 6, 6))]  # frame reset -> new capture
    for r in r2:
        r["timestamp"] += 1000
    F = _events(r1 + r2)
    first_of_second = F[F["capture_id"] != F["capture_id"].iloc[0]].sort_values("timestamp").iloc[0]
    assert first_of_second["first_in_stream"] == 1  # context starts fresh in a new capture


def test_baseline_features_are_current_event_only():
    inv = pd.read_csv(MODELS_DIR.parent / "results" / "feature_audit" / "feature_inventory.csv")
    base = inv[inv["baseline_usage"] == "used"]
    assert set(base["current_or_past_only"]) == {"current event only"}


def test_forbidden_columns_absent_from_every_feature_list():
    for model in ("baseline", "contextual"):
        names = read_json(MODELS_DIR / model / "feature_names.json")
        assert not set(names) & set(FORBIDDEN_FEATURE_COLUMNS)
    all_defined = group_features(ISOLATED_GROUPS) + group_features(CONTEXT_GROUPS)
    assert not set(all_defined) & set(FORBIDDEN_FEATURE_COLUMNS)


def test_profile_learns_from_training_rows_only():
    F = _events(_stream()).copy()
    F["class_id"] = 0
    train, other = F.iloc[:3], F.iloc[3:]
    stats = fit_profile(train)
    seen = set(stats["normal_access_counts"])
    unseen = {f"{int(f)}:{int(r)}" for f, r in zip(other["func_code"], other["ref_num"])} - seen
    assert unseen, "fixture must contain combinations absent from the training rows"
    applied = apply_profile(other, stats)
    assert applied["access_combo_unseen"].sum() >= 1
    assert stats["fitted_on_rows"] == 3


def test_fold_specific_fitting_differs_between_folds():
    F = _events(_stream()).copy()
    F["class_id"] = 0
    s1, s2 = fit_profile(F.iloc[:2]), fit_profile(F.iloc[2:])
    assert s1["normal_access_counts"] != s2["normal_access_counts"]


def test_train_code_fits_profile_inside_each_fold():
    src = (MODELS_DIR.parent / "src" / "models" / "train.py").read_text()
    loop = src[src.index("for i, (tr, va) in enumerate(folds):\n                # Fold-specific") :]
    assert "fit_profile(F.iloc[tr])" in loop[:400]
    assert "TEST_PARQUET" not in src


@pytest.mark.parametrize("model", ["baseline", "contextual"])
def test_models_load_with_correct_schema(model):
    art = load_artifacts(model)
    assert type(art["clf"]).__name__ == "RandomForestClassifier"
    assert [int(c) for c in art["clf"].classes_] == [0, 1]
    assert art["clf"].n_features_in_ == len(art["features"])
    assert art["manifest"]["test_partition_used"] is False
    assert art["clf"].random_state == 42


def test_missing_and_corrupt_model_errors(tmp_path):
    with pytest.raises(ModelLoadError):
        load_artifacts("contextual", models_dir=tmp_path)
    d = tmp_path / "contextual"
    d.mkdir()
    for name in ("feature_names.json", "feature_stats.json", "training_manifest.json"):
        (d / name).write_text("{}")
    (d / "contextual_rf.joblib").write_bytes(b"not a model")
    (d / "model_checksums.json").write_text('{"contextual_rf.joblib": "0"}')
    with pytest.raises(ModelLoadError):
        load_artifacts("contextual", models_dir=tmp_path)


def test_feature_schema_mismatch_detected(tmp_path, monkeypatch):
    import shutil

    shutil.copytree(MODELS_DIR / "contextual", tmp_path / "contextual")
    (tmp_path / "contextual" / "feature_names.json").write_text('["func_code"]')
    with pytest.raises(FeatureSchemaError):
        load_artifacts("contextual", models_dir=tmp_path)


def test_saved_models_and_oof_reference_dev_only():
    split = read_json(MODELS_DIR.parent / "data" / "manifests" / "split_manifest.json")
    oof = pd.read_parquet(MODELS_DIR.parent / "data" / "validation" / "cv_validation_predictions.parquet")
    assert set(oof["capture_id"]) <= set(split["train_captures"])
    assert not set(oof["capture_id"]) & set(split["test_captures"])
