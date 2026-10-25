"""Offline checks for membership and conservative observation-copy audits."""
import json

from component3_preparation.c3prep.audit import extraction_dirs, source_group_containment, uid_membership


def test_uid_domain_rejects_noncanonical_and_missing_events():
    ranges = {"view": {"events": 3, "recording_id": "run", "partition": "candidate_train"}}
    assert uid_membership("view:e3", ranges)["recording_id"] == "run"
    for uid in ("view:e0", "view:e4", "view:e03", "view:e-1", "other:e1", "view:ex", None):
        assert uid_membership(uid, ranges) is None


def test_unpublished_or_unreconciled_extraction_is_never_consumed(tmp_path):
    for name, passed in (("active.tmp", True), ("failed", False), ("ready", True)):
        folder = tmp_path / "extraction" / name
        folder.mkdir(parents=True)
        (folder / "events.parquet").write_bytes(b"not a real footer; selection must not read it")
        (folder / "checkpoint.json").write_text(json.dumps({"reconciliation_passed": passed}))
    assert [p.name for p in extraction_dirs(tmp_path)] == ["ready"]


def source_fixture(tmp_path, second_timestamp):
    groups = {"groups": [
        {"recording_id": "first", "views": [{"chunks": [{"path": "a.pcap"}]}]},
        {"recording_id": "second", "views": [{"chunks": [{"path": "b.pcap"}]}]},
    ], "sampled_duplicate_observations": [
        {"sha256_frame": "same frame content", "observations": [
            {"path": "a.pcap", "frame": 1, "ts_us": 100},
            {"path": "b.pcap", "frame": 1, "ts_us": second_timestamp},
        ]}
    ]}
    (tmp_path / "group_sources.json").write_text(json.dumps(groups))
    inventory = {"files": [{"path": p, "format": "pcap", "sha256": p} for p in ("a.pcap", "b.pcap")]}
    (tmp_path / "inventory.json").write_text(json.dumps(inventory))


def test_identical_content_at_distant_times_is_not_a_mirror_copy(tmp_path):
    source_fixture(tmp_path, 100_000_000)
    report = source_group_containment(tmp_path)
    assert report["all_known_source_copy_relationships_contained"]
    assert report["time_linked_sampled_mirror_clusters"] == []
    assert report["signatures_recurring_at_separate_times"] == 1


def test_time_linked_cross_group_mirror_is_reported_not_silently_accepted(tmp_path):
    source_fixture(tmp_path, 110)
    report = source_group_containment(tmp_path)
    assert not report["all_known_source_copy_relationships_contained"]
    assert report["sampled_mirror_cross_group_clusters"] == 1


def test_selected_source_cannot_claim_a_different_parent_group(tmp_path):
    source_fixture(tmp_path, 100_000_000)
    report = source_group_containment(tmp_path, selected_sources=[
        {"recording_id": "second", "source_paths": ["a.pcap"]}])
    assert not report["all_known_source_copy_relationships_contained"]
    assert report["selected_source_membership_conflicts"][0]["path"] == "a.pcap"
