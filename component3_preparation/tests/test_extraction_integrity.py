from component3_preparation.c3prep.integrity import extraction_output_hashes, output_integrity_valid


def test_resume_rejects_same_filename_with_changed_bytes(tmp_path):
    for name in ("events.parquet", "connections.parquet", "accounting.json"):
        (tmp_path / name).write_bytes(b"original published bytes")
    signature = extraction_output_hashes(tmp_path)
    assert output_integrity_valid(tmp_path, signature)
    (tmp_path / "events.parquet").write_bytes(b"corrupted or partial bytes")
    assert not output_integrity_valid(tmp_path, signature)


def test_resume_checks_optional_retrans_audit_and_required_files(tmp_path):
    for name in ("events.parquet", "connections.parquet", "accounting.json"):
        (tmp_path / name).write_bytes(b"published")
    original = extraction_output_hashes(tmp_path)
    (tmp_path / "suppressed_observations.parquet").write_bytes(b"new unaccounted observations")
    assert not output_integrity_valid(tmp_path, original)
    signature = extraction_output_hashes(tmp_path)
    assert output_integrity_valid(tmp_path, signature)
    (tmp_path / "connections.parquet").unlink()
    assert not output_integrity_valid(tmp_path, signature)


def test_resume_missing_or_untrusted_output_map_is_rejected(tmp_path):
    assert not output_integrity_valid(tmp_path, None)
    assert not output_integrity_valid(tmp_path, {"../../unrelated": "hash"})
