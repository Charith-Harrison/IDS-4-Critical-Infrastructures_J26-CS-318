"""Create an intact return ZIP after ALL_104_VALIDATED. Never collect or preprocess."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE_ID = "1fe2b0eb6f44807bc6759d3f3e998ce5064047516585d9e8e313f01b24050663"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def export(output, destination=None):
    output = output.resolve()
    if (output / "collector.lock").exists():
        raise ValueError("Collector lock exists. Wait for clean completion; do not archive active output")
    final = read(output / "collection_complete.json")
    state = read(output / "collection_state.json")
    session = read(output / "collection_manifest.json")
    if (final["status"] != "ALL_104_VALIDATED" or state["status"] != "ALL_104_VALIDATED"
            or state["validated_completed"] != 104 or len(final["completed"]) != 104
            or final["source_bundle_id"] != SOURCE_ID
            or final["collection_id"] != session["collection_id"]):
        raise ValueError("A complete intact 104-run collection is required, not a partial transfer")
    for qid, record in final["completed"].items():
        folder = (output / record["attempt"]).resolve()
        if not folder.is_relative_to(output):
            raise ValueError("Unsafe accepted-attempt path")
        receipt_path = folder / "completion.json"
        if sha(receipt_path) != record["completion_sha256"]:
            raise ValueError("Final index/receipt hash differs: " + qid)
        receipt = read(receipt_path)
        if (receipt["status"] != "VALIDATED" or receipt["planned_run_id"] != qid
                or receipt["collection_id"] != final["collection_id"]
                or receipt["source_bundle_id"] != SOURCE_ID or receipt["image_id"] != session["image_id"]):
            raise ValueError("Accepted identity differs: " + qid)
        for name, expected in receipt["artifact_sha256"].items():
            if "/" in name or "\\" in name or ":" in name or name in (".", ".."):
                raise ValueError("Unsafe sealed artifact path")
            path = (folder / name).resolve()
            if not path.is_relative_to(folder) or sha(path) != expected:
                raise ValueError("Sealed artifact hash differs: " + qid + "/" + name)
    if destination is None:
        destination = ROOT / ("C3_RESULTS_" + final["collection_id"][:12] + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".zip")
    destination = destination.resolve()
    if destination.is_relative_to(output):
        raise ValueError("Return ZIP must be outside the collection directory")
    if destination.exists() or destination.with_suffix(destination.suffix + ".sha256").exists():
        raise ValueError("Destination already exists; choose a new name")
    paths = sorted(p for p in output.rglob("*") if p.is_file())
    before = {}
    for path in paths:
        if not path.resolve().is_relative_to(output):
            raise ValueError("Symlink escapes collection directory")
        before[path.relative_to(output).as_posix()] = sha(path)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as archive:
        for path in paths:
            archive.write(path, "collection/" + path.relative_to(output).as_posix())
        archive.writestr("RETURN_MANIFEST.json", json.dumps({
            "collection_id": final["collection_id"], "source_bundle_id": SOURCE_ID,
            "status": "ALL_104_VALIDATED", "file_sha256": before,
            "note": "Contains all attempts including failures; only sealed indexed attempts are accepted",
        }, indent=2) + "\n")
        archive.write(ROOT / "BUNDLE_MANIFEST.json", "delivery/BUNDLE_MANIFEST.json")
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError("Return ZIP CRC verification failed; do not send it")
    for rel, expected in before.items():
        if sha(output / rel) != expected:
            raise ValueError("Collection changed during export; do not send this ZIP")
    checksum = sha(destination)
    destination.with_suffix(destination.suffix + ".sha256").write_text(checksum + "  " + destination.name + "\n", encoding="ascii")
    print(json.dumps({"status": "RETURN_ZIP_VERIFIED", "zip": str(destination), "bytes": destination.stat().st_size,
                      "sha256": checksum, "collection_id": final["collection_id"], "accepted_runs": 104}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "component3_collection_runs/main-frozen-v1-20261025")
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        export(args.output, args.destination)
    except (OSError, ValueError, KeyError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        raise SystemExit(2)
