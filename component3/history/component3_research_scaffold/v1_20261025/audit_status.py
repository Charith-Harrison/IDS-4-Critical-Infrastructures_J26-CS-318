"""Bounded read-only operational audit; write a new snapshot in this package only.

Reads sealed receipts/counts, evidence hashes and reports. Does not parse model
observations, decode new sources, create features, start Docker or accept a run.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import unittest
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MAIN = REPO / "component3_main_collection/v1_20261025"
OUTPUT = REPO / "component3_collection_runs/main-frozen-v1-20261025"
HISTORY = (
    "README.md",
    "component3_preparation/INVENTORY.md",
    "component3_preparation/FEASIBILITY.md",
    "component3_preparation/LABEL_POLICY.md",
    "component3_preparation/SPLIT_VALIDATION.md",
    "component3_preparation/REFERENCE_AUDIT.md",
    "component3_reassessment/v1_20261024/DECISION_REPORT.md",
    "component3_reassessment/v1_20261024/PROPOSED_POLICY.md",
    "component3_main_design/v1_20261025/DECISION.md",
    "component3_testbed_v02/evidence/qualification_summary.json",
    "component3_testbed_v03/evidence/engineering_summary.json",
    "component3_testbed_v03/ENGINEERING_REPORT.md",
    "component3_testbed_pilot/DATASET_CARD.md",
    "component3_testbed_pilot/BUILD_STATUS.md",
    "component3_preparation/output/reference_review/IT23150270_Rathnayaka K.H..json",
    "component3_preparation/output/reference_review/IT4010-TAF-2026 J26-CS-318 (1).json",
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def child(folder, name):
    # Never trust a manifest to name another directory, including on Windows.
    if not name or "/" in name or "\\" in name or ":" in name or name in {".", ".."}:
        raise ValueError("Unsafe artifact name")
    path = folder / name
    if not path.resolve().is_relative_to(folder.resolve()):
        raise ValueError("Artifact escapes its source directory")
    return path


def snapshot():
    inputs, checks = {}, []

    def watch(path):
        path = path.resolve()
        if not path.is_relative_to(REPO):
            raise ValueError("Only repository evidence is permitted")
        key = path.relative_to(REPO).as_posix()
        digest = sha(path)
        if key in inputs and inputs[key]["sha256"] != digest:
            raise ValueError("Input changed during snapshot: " + key)
        inputs[key] = {"sha256": digest, "bytes": path.stat().st_size}
        return digest

    frozen = read(MAIN / "frozen/freeze_manifest.json")
    watch(MAIN / "frozen/freeze_manifest.json")
    watch(MAIN / "image_identity.json")
    for name, expected in frozen["source_configuration_sha256"].items():
        path = MAIN / name
        if not path.resolve().is_relative_to(MAIN.resolve()):
            raise ValueError("Unsafe frozen package path")
        if watch(path) != expected:
            raise ValueError("Frozen package hash mismatch: " + name)
    checks.append("Frozen manifest-listed source/configuration files match")
    for name in HISTORY:
        watch(REPO / name)
    roster = read(MAIN / "frozen/main_roster.json")["runs"]
    planned = {row["planned_run_id"]: row for row in roster}
    state = read(OUTPUT / "collection_state.json")
    watch(OUTPUT / "collection_state.json")
    session = read(OUTPUT / "collection_manifest.json")
    watch(OUTPUT / "collection_manifest.json")
    if session["source_bundle_id"] != frozen["bundle_id"]:
        raise ValueError("Collection source identity disagrees with freeze")
    attempts, accepted, totals, errors = [], [], Counter(), []
    for folder in sorted(OUTPUT.glob("MX*")):
        if not folder.is_dir():
            continue
        item = {"attempt": folder.name, "accepted_sealed_receipt": False}
        request = read(folder / "attempt_request.json")
        watch(folder / "attempt_request.json")
        qid = request["planned_run_id"]
        if qid not in planned or request["collection_id"] != session["collection_id"]:
            raise ValueError("Attempt outside this frozen roster/collection")
        item.update(planned_run_id=qid, intended_role=planned[qid]["intended_evaluation_role"],
                    related_group=planned[qid]["prospective_related_group"])
        for name in ("capture.log", "validation_report.json", "attempt_disposition.json",
                     "run_manifest.json", "host_execution.json", "planned_run.json"):
            path = folder / name
            if path.exists():
                watch(path)
        log_path = folder / "capture.log"
        if log_path.exists():
            log = log_path.read_text(encoding="utf-8")
            drops = re.findall(r"(?m)^\s*(\d+) packets dropped by kernel\s*$", log)
            item["kernel_drop_footer_values"] = list(map(int, drops))
            item["capture_log"] = log
        report_path = folder / "validation_report.json"
        report = read(report_path) if report_path.exists() else {}
        item["validation_status"] = report.get("status", "MISSING")
        item["validation_errors"] = report.get("errors", [])
        completion = folder / "completion.json"
        if completion.exists():
            receipt = read(completion)
            watch(completion)
            if (receipt["planned_run_id"] != qid or receipt["status"] != "VALIDATED"
                    or receipt["collection_id"] != session["collection_id"]
                    or receipt["source_bundle_id"] != session["source_bundle_id"]
                    or receipt["image_id"] != session["image_id"]):
                raise ValueError("Sealed receipt identity differs")
            for name, expected in receipt["artifact_sha256"].items():
                if watch(child(folder, name)) != expected:
                    raise ValueError("Sealed artifact hash mismatch: " + folder.name + "/" + name)
            if report.get("status") != "PASSED" or report.get("accepted_labels") is not True:
                raise ValueError("Receipt conflicts with validation report")
            if receipt["label_counts"] != report["label_counts"]:
                raise ValueError("Receipt/report counts differ")
            if qid in accepted:
                raise ValueError("Two accepted attempts for the same planned ID")
            accepted.append(qid)
            totals.update(receipt["label_counts"])
            item.update(accepted_sealed_receipt=True, label_counts=receipt["label_counts"],
                        validated_at=receipt["validated_at_utc"])
        elif (folder / "run_manifest.json").exists():
            # Verify saved failed/interrupted evidence hashes without accepting any labels.
            manifest = read(folder / "run_manifest.json")
            for name, expected in manifest.get("input_sha256", {}).items():
                if watch(child(folder, name)) != expected:
                    raise ValueError("Unaccepted evidence changed: " + folder.name + "/" + name)
        if not item["accepted_sealed_receipt"] and (folder / "verified_labels.jsonl").exists():
            errors.append("Unsealed annotations require review: " + folder.name)
        attempts.append(item)
    if len(accepted) != state["validated_completed"]:
        errors.append("State counter disagrees with intact sealed receipts")
    checks.append("Accepted receipt artifacts hashed; reports/counts/identities agree")
    checks.append("Unaccepted saved input hashes checked; no labels promoted")
    for path in HERE.iterdir():
        if path.is_file() and path.suffix in {".py", ".md", ".json"}:
            watch(path)
    # Tests below never import or read any real observation file.
    sys.path.insert(0, str(HERE))
    buffer = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_contracts.py")
    result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
    if not result.wasSuccessful():
        errors.append("Synthetic contract tests failed")
    for name, record in inputs.items():
        if sha(REPO / name) != record["sha256"]:
            raise ValueError("Input changed before snapshot completion: " + name)
    payload = dict(
        purpose="SCAFFOLD_AND_OPERATIONAL_EVIDENCE_ONLY", created_at_utc=datetime.now(timezone.utc).isoformat(),
        timezone_for_user="Asia/Colombo", repository=str(REPO),
        original_cic_root=str(REPO / "data/raw/Modbus Dataset"),
        original_cic_root_exists=(REPO / "data/raw/Modbus Dataset").is_dir(),
        raw_cic_rehashed_or_reextracted=False,
        source_bundle_id=frozen["bundle_id"], image_id=session["image_id"],
        current_state=state, validated_planned_ids=accepted, expected_runs=len(roster),
        accepted_label_counts=dict(totals), accepted_message_total=sum(totals.values()),
        attempts=attempts, checks=checks, input_provenance=inputs,
        synthetic_tests=dict(tests_run=result.testsRun, passed=result.wasSuccessful(), output=buffer.getvalue()),
        errors=errors, preprocessing_or_training_performed=False,
        final_model_datasets_created=False, existing_frozen_source_or_collection_output_modified=False,
        limitations=["Does not rerun wire/state validator; hashes link to previous validation",
                     "Historical CIC/qualification totals supported by cited reports, not re-extraction",
                     "No historical CPU/IO trace; kernel-drop cause cannot be established",
                     "Snapshot of a stopped collector; later user retries will change live status"],
        exact_command_from_repository_root=r".\.venv\Scripts\python.exe -B .\component3_research_scaffold\v1_20261025\audit_status.py",
    )
    target = HERE / "evidence" / ("snapshot-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    target.mkdir(parents=True, exist_ok=False)
    (target / "snapshot.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"snapshot": str(target / "snapshot.json"), "validated": len(accepted),
                      "accepted_label_counts": dict(totals), "synthetic_tests": result.testsRun,
                      "tests_passed": result.wasSuccessful(), "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(snapshot())
