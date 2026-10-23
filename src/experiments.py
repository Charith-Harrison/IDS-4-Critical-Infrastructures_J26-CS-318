"""Preserve prior experiments automatically when configuration or source data changes."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.utils import ROOT, checksum, config_digest, read_json, save_json


def archive_if_changed(cfg: dict, root: Path = ROOT) -> Path | None:
    """Move generated outputs only; raw inputs, docs, code and Git are never moved.

    A new configuration is a new experiment, not a new independent test dataset.
    This preserves the evidence while allowing the documented dataset-switch flow.
    """
    root = root.resolve()
    manifest_path = root / "data/manifests/preprocessing.json"
    if not manifest_path.exists():
        return None
    old = read_json(manifest_path)
    changed = old["configuration_hash"] != config_digest(cfg)
    if not changed:
        for item in old["inputs"]:
            path = Path(item["input_file"])
            path = path if path.is_absolute() else root / path
            if not path.exists() or checksum(path) != item["sha256"]:
                changed = True
                break
    if not changed:
        return None
    destination = root / "experiments" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    for relative in ["models", "results", "data/processed", "data/manifests"]:
        source = (root / relative).resolve()
        target = (destination / relative).resolve()
        if not source.is_relative_to(root) or not target.is_relative_to(destination):
            raise ValueError("Experiment archive path escaped the project root")
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))
    (destination / "config.yaml").write_text(yaml.safe_dump(old["configuration"], sort_keys=False), encoding="utf-8")
    save_json(
        destination / "archive_note.json",
        {
            "reason": "Configuration or input checksum changed",
            "old_configuration_hash": old["configuration_hash"],
            "new_configuration_hash": config_digest(cfg),
            "warning": "Archiving does not restore holdout independence. Use new independent data for final conclusions.",
        },
    )
    return destination
