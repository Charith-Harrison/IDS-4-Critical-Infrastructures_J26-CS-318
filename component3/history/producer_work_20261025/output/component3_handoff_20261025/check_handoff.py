"""Read-only transfer integrity check; does not generate features or inspect test payloads."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inside(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Manifest path escapes root: " + relative)
    return path


def main(root):
    root = root.resolve()
    manifest = read(root / "RETURN_MANIFEST.json")
    collection = root / "collection"
    entries = manifest["file_sha256"]
    for number, (relative, expected) in enumerate(entries.items(), 1):
        if sha(inside(collection, relative)) != expected:
            raise ValueError("Transfer checksum mismatch: " + relative)
        if number % 250 == 0:
            print(f"Checked {number}/{len(entries)} original files", flush=True)
    supplemental = root / "handoff/REFERENCE_MANIFEST.json"
    if supplemental.exists():
        for relative, expected in read(supplemental)["file_sha256"].items():
            if sha(inside(root, relative)) != expected:
                raise ValueError("Companion checksum mismatch: " + relative)
    final = read(collection / "collection_complete.json")
    if (final["status"] != "ALL_104_VALIDATED" or len(final["completed"]) != 104
            or final["collection_id"] != manifest["collection_id"]):
        raise ValueError("Incomplete or mismatched collection")
    counts, roles, accepted, groups = Counter(), Counter(), set(), set()
    for qid, record in final["completed"].items():
        folder = inside(collection, record["attempt"])
        if folder.name in accepted or record["related_group"] in groups:
            raise ValueError("Repeated accepted attempt or related group")
        accepted.add(folder.name)
        groups.add(record["related_group"])
        receipt = read(folder / "completion.json")
        if (sha(folder / "completion.json") != record["completion_sha256"]
                or receipt["status"] != "VALIDATED" or receipt["planned_run_id"] != qid
                or receipt["collection_id"] != final["collection_id"]):
            raise ValueError("Accepted receipt differs: " + qid)
        counts.update(receipt["label_counts"])
        roles[record["intended_evaluation_role"]] += 1
    expected = Counter(normal=247906, command_injection=720, response_injection=1440)
    if counts != expected:
        raise ValueError("Unexpected sealed label counts")
    print(json.dumps({"status": "TRANSFER_HASHES_AND_RECEIPTS_VERIFIED",
                      "accepted_runs": len(accepted), "label_counts": dict(counts),
                      "intended_roles": dict(roles),
                      "note": "Integrity check only; full wire/replay command is in START_HERE.md. No preprocessing or model run."}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    main(parser.parse_args().root)
