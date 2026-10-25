# Check context features behavior using software fixtures and existing evidence.
import numpy as np
import pandas as pd
import pytest

from src.event_builder import build_events
from src.feature_engineering import build_features, feature_names
from src.leakage_guard import validate_features
from src.preprocessing import preprocess_frame


# Check that baseline has no context.
def test_baseline_has_no_context(events, cfg):
    x = build_features(events, cfg, "baseline")
    assert len(x.columns) == 22
    assert not any("previous" in c or "rolling" in c or "pair" in c for c in x)


# Check that future values do not change past features.
def test_future_values_do_not_change_past_features(events, cfg):
    before = build_features(events, cfg)
    changed = events.copy()
    changed.loc[30:, "modbus_val"] = 9999
    after = build_features(changed, cfg)
    pd.testing.assert_frame_equal(before.iloc[:30], after.iloc[:30])


# Check that window uses previous events only.
def test_window_uses_previous_events_only(events, cfg):
    features = build_features(events, cfg)
    assert features.loc[24, "recent_write_ratio_3"] == 0
    assert features.loc[25, "recent_write_ratio_3"] == pytest.approx(1 / 3)
    assert features.loc[0, "previous_function_code_missing"] == 1


# Check that context does not cross sessions.
def test_context_does_not_cross_sessions(events, cfg):
    events.loc[24:, "context_id"] = "second-session"
    features = build_features(events, cfg)
    assert np.isnan(features.loc[24, "previous_function_code"])
    assert np.isnan(features.loc[24, "inter_arrival_time"])


# Check that context does not cross partitions.
def test_context_does_not_cross_partitions(events, cfg):
    events["partition"] = ["train"] * 24 + ["test"] * 24
    features = build_features(events, cfg)
    assert np.isnan(features.loc[24, "previous_function_code"])


# Check that missingness features.
def test_missingness_features(events, cfg):
    events["modbus_val"] = np.nan
    features = build_features(events, cfg)
    assert features.value_missing.eq(1).all()


# Check that toggles remove groups.
def test_toggles_remove_groups(events, cfg):
    cfg["features"]["value"] = False
    names = feature_names(cfg, "contextual")
    assert "value" in names and "value_delta" not in names
    assert list(build_features(events, cfg)) == names


# Check that whitelist rejects leakage.
@pytest.mark.parametrize(
    "forbidden", ["target", "attack_category", "src_ip", "timestamp", "mbtcp_trans_id", "arbitrary_extra"]
)
def test_whitelist_rejects_leakage(events, cfg, forbidden):
    features = build_features(events, cfg, "baseline")
    features[forbidden] = 1
    with pytest.raises(ValueError, match="Leakage guard"):
        validate_features(features, cfg, "baseline")


# Check that pairing is causal and partial.
def test_pairing_is_causal_and_partial(raw, cfg):
    event = build_events(preprocess_frame(raw, cfg, "fixture"), cfg)
    assert event.loc[0, "pair_status"] == "pending_at_observation"
    assert np.isnan(event.loc[0, "has_matching_pair"])
    assert event.loc[1, "has_matching_pair"] == 1
    assert event.loc[1, "response_delay"] == pytest.approx(0.1, abs=1e-6)
    prefix = build_events(preprocess_frame(raw.head(1), cfg, "fixture"), cfg)
    assert prefix.loc[0, "pair_status"] == event.loc[0, "pair_status"]


# Check that pairing missing endpoints is unavailable.
def test_pairing_missing_endpoints_is_unavailable(raw, cfg):
    raw = raw.drop(columns=["src_ip", "dst_ip"])
    events = build_events(preprocess_frame(raw, cfg, "fixture"), cfg)
    assert events.pair_status.eq("unavailable").all()


# Check that ambiguous transaction is not invented.
def test_ambiguous_transaction_is_not_invented(raw, cfg):
    raw = raw.iloc[:3].copy()
    raw.loc[1, ["src_ip", "dst_ip", "src_port", "dst_port", "is_request"]] = ["client", "server", 1200, 502, 1]
    raw.loc[2, ["src_ip", "dst_ip", "src_port", "dst_port", "is_request"]] = ["server", "client", 502, 1200, 0]
    raw["mbtcp_trans_id"] = 1
    events = build_events(preprocess_frame(raw, cfg, "fixture"), cfg)
    assert events.loc[2, "pair_status"] == "ambiguous_transaction"
