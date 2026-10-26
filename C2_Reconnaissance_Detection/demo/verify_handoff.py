"""Check that the extracted handoff package is complete and unchanged (standard library only).

Reads <repo>/HANDOFF_MANIFEST.json and re-hashes every listed file. Exit code 0 = all present and identical.
"""
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    mp = REPO / "HANDOFF_MANIFEST.json"
    if not mp.exists():
        print("HANDOFF_MANIFEST.json not found in the repository root: extract C2_handoff_package.zip there.")
        return 1
    m = json.loads(mp.read_text())
    missing = [f for f in m["files"] if not (REPO / f).is_file()]
    changed = [f for f, v in m["files"].items() if f not in missing and sha(REPO / f) != v["sha256"]]
    print(f"handoff files: {len(m['files']) - len(missing) - len(changed)}/{len(m['files'])} present and identical"
          f" (package built for commit {m['git']['commit'][:10]} on {m['git']['branch']})")
    for f in (missing + changed)[:10]:
        print(("  missing: " if f in missing else "  changed: ") + f)
    return 0 if not missing and not changed else 1


if __name__ == "__main__":
    sys.exit(main())
