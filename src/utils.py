# Share configuration, paths, hashes, JSON conversion, and logging for the older workflow.
"""Configuration, provenance, and project-relative I/O shared by all commands."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.0.0-preliminary"
FEATURE_VERSION = "context-causal-v2"
PREPROCESSING_VERSION = "direct-labels-v2"
BINARY_NOTE = (
    "The current dataset combines command and response injection under one attack label. "
    "Separate command-injection and response-injection classification will be enabled "
    "when the verified three-class dataset is integrated."
)


# Load the project configuration and reject unsupported task modes.
def load_config(path: str | Path | None = None) -> dict:
    """Read one authoritative configuration; reject unsupported modes early."""
    cfg = yaml.safe_load(Path(path or ROOT / "config/config.yaml").read_text(encoding="utf-8"))
    if cfg["model_mode"] not in {"temporary_binary", "final_three_class"}:
        raise ValueError("model_mode must be temporary_binary or final_three_class")
    windows = cfg["features"]["windows"]
    if not windows or any(not isinstance(w, int) or w < 1 for w in windows):
        raise ValueError("Context windows must be positive integers")
    if cfg["model_mode"] == "final_three_class":
        if not cfg["dataset"].get("verified_labels") or not cfg["dataset"].get("label_evidence"):
            raise ValueError("Final mode requires verified_labels: true and a label_evidence reference")
    return cfg


# Resolve a configured path relative to the project root.
def project_path(path: str | Path) -> Path:
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


# Record the current time in the format used by this workflow.
def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Hash file bytes so later checks can detect a changed input or model.
def checksum(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


# Hash the configuration to identify exactly which settings produced an artifact.
def config_digest(cfg: dict) -> str:
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()


# Convert supported Python and NumPy values for JSON output.
def _json_default(value: Any):
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, (Path, datetime)):
        return str(value)
    raise TypeError(type(value).__name__)


# Write structured results to disk using the project's JSON conversion rules.
def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=_json_default, allow_nan=False), encoding="utf-8")


# Read a saved JSON document.
def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# Return the configured logger for progress and error messages.
def logger(name: str) -> logging.Logger:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    return logging.getLogger(name)
