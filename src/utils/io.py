"""Small I/O helpers: checksums, JSON writing with numpy support."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 hex digest of a file (streamed, memory-safe)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _Encoder(json.JSONEncoder):
    """Serialise numpy scalars/arrays and Paths that json cannot handle."""

    def default(self, o: Any) -> Any:  # noqa: D102
        if isinstance(o, np.integer):
            return int(o)
        if isinstance(o, np.floating):
            return None if np.isnan(o) else float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, Path):
            return o.as_posix()
        return super().default(o)


def write_json(obj: Any, path: str | Path) -> None:
    """Write *obj* as indented JSON, creating parent folders."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, cls=_Encoder)


def read_json(path: str | Path) -> Any:
    """Read a JSON file."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
