"""Content integrity for extraction-owned artifacts, independent of later audits."""
from __future__ import annotations

import hashlib
from pathlib import Path

REQUIRED_OUTPUTS = {"events.parquet", "connections.parquet", "accounting.json"}
OPTIONAL_OUTPUTS = {"suppressed_observations.parquet"}


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extraction_output_hashes(directory):
    directory = Path(directory)
    if any(not (directory / name).is_file() for name in REQUIRED_OUTPUTS):
        raise FileNotFoundError("Extraction is missing a required published artifact")
    names = REQUIRED_OUTPUTS | {name for name in OPTIONAL_OUTPUTS if (directory / name).is_file()}
    return {name: file_sha256(directory / name) for name in sorted(names)}


def output_integrity_valid(directory, recorded_hashes):
    if not isinstance(recorded_hashes, dict):
        return False
    # Only the explicit owned names are ever read from untrusted checkpoint data.
    if not REQUIRED_OUTPUTS <= recorded_hashes.keys() <= REQUIRED_OUTPUTS | OPTIONAL_OUTPUTS:
        return False
    try:
        actual = extraction_output_hashes(directory)
    except OSError:
        return False
    return actual == recorded_hashes
