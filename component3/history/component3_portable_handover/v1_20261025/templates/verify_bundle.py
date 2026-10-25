"""Verify the portable delivery with standard-library Python; no Docker or traffic."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def verify(root=ROOT):
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or later is required")
    root = Path(root).resolve()
    manifest = json.loads((root / "BUNDLE_MANIFEST.json").read_text(encoding="utf8"))
    for name, expected in manifest["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise RuntimeError("Missing or unsafe delivery member: " + name)
        if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
            raise RuntimeError("Delivery file changed/corrupt: " + name)
    main = root / "component3_main_collection/v1_20261025"
    frozen = json.loads((main / "frozen/freeze_manifest.json").read_text(encoding="utf8"))
    current = {}
    for path in main.rglob("*"):
        rel = path.relative_to(main)
        if not path.is_file() or rel.parts[0] == "evidence" or "__pycache__" in rel.parts:
            continue
        if rel.as_posix() in ("frozen/freeze_manifest.json", "image_identity.json"):
            continue
        if path.suffix in (".py", ".ps1", ".json") or path.name in ("Dockerfile", ".dockerignore", ".gitignore"):
            current[rel.as_posix()] = digest(path)
    if current != frozen["source_configuration_sha256"]:
        raise RuntimeError("Frozen source inventory differs; do not edit/refreeze")
    bundle_id = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if bundle_id != frozen["bundle_id"] or bundle_id != manifest["source_bundle_id"]:
        raise RuntimeError("Frozen source bundle identity differs")
    image = json.loads((main / "image_identity.json").read_text(encoding="utf8"))
    if image["image_id"] != manifest["image_id"] or image["source_bundle_id"] != bundle_id:
        raise RuntimeError("Image receipt disagrees with portable manifest")
    print(json.dumps({"status": "PORTABLE_FILES_VERIFIED", "files": len(manifest["files"]),
                      "frozen_source_files": len(current), "source_bundle_id": bundle_id,
                      "image_id": image["image_id"], "traffic_generated": False}, indent=2))
    return manifest


if __name__ == "__main__":
    try:
        verify()
    except (OSError, ValueError, RuntimeError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        raise SystemExit(2)
