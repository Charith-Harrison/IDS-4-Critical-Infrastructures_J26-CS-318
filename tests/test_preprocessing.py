import pandas as pd

from src.event_builder import build_events
from src.preprocessing import preprocess_frame, split_events


def test_chronological_sort_and_original_ids(raw, cfg):
    raw = raw.iloc[::-1].copy()
    events = build_events(preprocess_frame(raw, cfg, "fixture"), cfg)
    assert events.timestamp.is_monotonic_increasing
    assert events.iloc[0].source_row == len(raw) - 1


def test_groups_do_not_overlap(cfg, raw):
    frames = []
    for i in range(12):
        sample = raw.copy()
        sample["file_source"] = f"capture-{i}"
        frames.append(preprocess_frame(sample, cfg, str(i)))
    data, manifest = split_events(pd.concat(frames, ignore_index=True), cfg)
    groups = {p: set(frame.group_id) for p, frame in data.groupby("partition")}
    assert not groups["train"] & groups["test"]
    assert not groups["train"] & groups["validation"]
    assert not groups["validation"] & groups["test"]
    repeat, _ = split_events(pd.concat(frames, ignore_index=True), cfg)
    assert repeat.partition.tolist() == data.partition.tolist()
    assert manifest["strategy"].startswith("group")


def test_reset_groups_are_marked_inferred(raw, cfg):
    raw = raw.drop(columns="file_source")
    raw.loc[24:, "frame_number"] -= 24
    result = preprocess_frame(raw, cfg, "fixture")
    assert result.group_id.nunique() == 2
    assert result.group_method.eq("inferred_frame_or_time_reset").all()
