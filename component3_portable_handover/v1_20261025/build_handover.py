"""Assemble a portable fresh-collection delivery without changing frozen inputs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MAIN = REPO / "component3_main_collection/v1_20261025"
ARCHIVE_SHA = "2630bc09d1124842ef356be58c341003ac1256117f99f45fdbdab0aa63257ed1"
EXTRAS = (
    "frozen/freeze_manifest.json", "image_identity.json", "INSTRUCTIONS.md", "READINESS.md",
    "evidence/manual-runtime.tar", "evidence/manual-runtime.tar.sha256",
    "evidence/preparation_checks.json", "evidence/qualification_recheck.json",
    "evidence/protected_after.json",
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def record(path):
    return {"bytes": path.stat().st_size, "sha256": sha(path)}


def source_inventory():
    inventory = {}
    for path in MAIN.rglob("*"):
        rel = path.relative_to(MAIN)
        if not path.is_file() or rel.parts[0] == "evidence" or "__pycache__" in rel.parts:
            continue
        if rel.as_posix() in ("frozen/freeze_manifest.json", "image_identity.json"):
            continue
        if path.suffix in (".py", ".ps1", ".json") or path.name in ("Dockerfile", ".dockerignore", ".gitignore"):
            inventory[rel.as_posix()] = sha(path)
    return inventory


def build():
    frozen = read(MAIN / "frozen/freeze_manifest.json")
    before = source_inventory()
    if before != frozen["source_configuration_sha256"]:
        raise ValueError("Frozen source changed; never refreeze for a portable delivery")
    identity = read(MAIN / "image_identity.json")
    runtime = MAIN / "evidence/manual-runtime.tar"
    if sha(runtime) != ARCHIVE_SHA:
        raise ValueError("Saved runtime archive differs from qualified handover")
    # Read metadata only, never unpack/run the runtime during archive inspection.
    with tarfile.open(runtime, "r:") as saved:
        outer_index = read_tar_json(saved, "index.json")
        if sum(item["digest"] == identity["image_id"] for item in outer_index["manifests"]) != 1:
            raise ValueError("Saved OCI index does not name the frozen image identity")
        image_index = read_blob_json(saved, identity["image_id"])
        platforms = [item for item in image_index["manifests"]
                     if item.get("platform") == {"architecture": "amd64", "os": "linux"}]
        if len(platforms) != 1:
            raise ValueError("Saved image index lacks one unambiguous linux/amd64 image")
        platform_manifest = read_blob_json(saved, platforms[0]["digest"])
        config_digest = platform_manifest["config"]["digest"]
        platform_config = read_blob_json(saved, config_digest)
        if platform_config["os"] != "linux" or platform_config["architecture"] != "amd64":
            raise ValueError("Runtime platform config differs")
        members = read_tar_json(saved, "manifest.json")
        expected_config = "blobs/sha256/" + config_digest.split(":", 1)[1]
        if sum(item["Config"] == expected_config for item in members) != 1:
            raise ValueError("Docker-save metadata disagrees with the OCI platform config")
    token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    work = HERE / ".build" / token
    delivery = work / "Component3_Modbus_Collector"
    target = delivery / "component3_main_collection/v1_20261025"
    target.mkdir(parents=True, exist_ok=False)
    provenance = {}
    for name in sorted(set(before) | set(EXTRAS)):
        original = MAIN / name
        copied = target / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        source_record = record(original)
        shutil.copyfile(original, copied)
        if record(copied) != source_record:
            raise ValueError("Copy mismatch: " + name)
        provenance[original.relative_to(REPO).as_posix()] = source_record
    for original in sorted((HERE / "templates").iterdir()):
        if original.is_file():
            shutil.copyfile(original, delivery / original.name)
            provenance[original.relative_to(REPO).as_posix()] = record(original)
    files = {p.relative_to(delivery).as_posix(): record(p)
             for p in sorted(delivery.rglob("*")) if p.is_file()}
    manifest = dict(
        format_version=1, purpose="PORTABLE_FRESH_FROZEN_MAIN_COLLECTION_ONLY",
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        user_date="2026-10-25", user_timezone="Asia/Colombo",
        source_bundle_id=frozen["bundle_id"], image_id=identity["image_id"],
        runtime_archive_sha256=ARCHIVE_SHA, platform="linux/amd64 container, Windows x86_64 host walkthrough",
        fresh_planned_runs=104, existing_recordings_included=0,
        preprocessing_or_training_included=False, qualification_for_model_work=False,
        metadata_note="Frozen READINESS/protocol fields are historical preparation status, not live output status",
        prerequisites_not_bundled=["Python 3.11+", "Docker Desktop/Engine with Linux containers, containerd image store and compose plugin"],
        image_identity_kind="OCI image index, not legacy image config ID",
        image_platform_manifest=platforms[0]["digest"], image_config_digest=config_digest,
        excluded=["CIC raw tree", "all prior measured captures/labels", "all partial main collection/state/locks",
                  "MSU and external datasets", "models", "virtual environments", ".git", "credentials"],
        scientific_limit="Same planned seeds on another PC are related reruns, not extra independent samples",
        files=files,
    )
    save(delivery / "BUNDLE_MANIFEST.json", manifest)
    artifacts = HERE / "artifacts"
    artifacts.mkdir(exist_ok=True)
    destination = artifacts / ("Component3_Modbus_Collector_v1_20261025_" + token + ".zip")
    with zipfile.ZipFile(destination, "x", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
        for path in sorted(delivery.rglob("*")):
            if path.is_file():
                archive.write(path, "Component3_Modbus_Collector/" + path.relative_to(delivery).as_posix())
    extracted = work / "verification"
    extracted.mkdir()
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError("Delivery ZIP CRC check failed")
        # The ZIP was just built from our allow-list; check paths before extraction.
        for name in archive.namelist():
            if not (extracted / name).resolve().is_relative_to(extracted.resolve()):
                raise ValueError("Unsafe ZIP member")
        archive.extractall(extracted)
    clone = extracted / "Component3_Modbus_Collector"
    check = subprocess.run([sys.executable, "-B", str(clone / "verify_bundle.py")],
                           capture_output=True, text=True)
    if check.returncode:
        raise ValueError("Extracted delivery verification failed: " + check.stdout + check.stderr)
    test_tmp = work / "test-temporary-files"
    test_tmp.mkdir()
    environment = dict(os.environ, TEMP=str(test_tmp), TMP=str(test_tmp), TMPDIR=str(test_tmp), PYTHONDONTWRITEBYTECODE="1")
    tests = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=clone / "component3_main_collection/v1_20261025", env=environment,
                           capture_output=True, text=True)
    save(work / "offline_test_execution.json", dict(command=tests.args, cwd=str(clone / "component3_main_collection/v1_20261025"),
                                                   exit_code=tests.returncode, stdout=tests.stdout, stderr=tests.stderr,
                                                   traffic_generated=False))
    if tests.returncode:
        raise ValueError("Extracted launcher offline tests failed; inspect " + str(work / "offline_test_execution.json"))
    if source_inventory() != before or sha(runtime) != ARCHIVE_SHA:
        raise ValueError("Frozen input changed during packaging")
    for name, expected in provenance.items():
        if record(REPO / name) != expected:
            raise ValueError("Packaging input changed: " + name)
    checksum = sha(destination)
    sidecar = destination.with_suffix(".zip.sha256")
    sidecar.write_text(checksum + "  " + destination.name + "\n", encoding="ascii")
    report = dict(status="ZIP_INTEGRITY_AND_EXTRACTED_OFFLINE_TESTS_PASSED", zip=str(destination),
                  zip_bytes=destination.stat().st_size, zip_sha256=checksum, checksum_file=str(sidecar),
                  included_files=len(files)+1, frozen_files=len(before), source_inputs=provenance,
                  builder=record(Path(__file__)), exact_command=r".\.venv\Scripts\python.exe -B .\component3_portable_handover\v1_20261025\build_handover.py",
                  delivery_verifier_stdout=check.stdout, offline_tests=read(work / "offline_test_execution.json"),
                  extracted_root=str(clone), build_root=str(work),
                  archive_image_index_and_platform_config_verified=True, no_main_collection_started=True,
                  physical_second_pc_tested=False, original_frozen_sources_unchanged=True,
                  note="No claim the existing recorder is fixed or faster; actual receiver captures must validate")
    report_path = artifacts / (destination.stem + ".verification.json")
    save(report_path, report)
    print(json.dumps({key: report[key] for key in ("status", "zip", "zip_bytes", "zip_sha256", "included_files", "extracted_root")}, indent=2))
    print("VERIFICATION_REPORT=" + str(report_path))


def read_tar_json(archive, name):
    source = archive.extractfile(name)
    if source is None:
        raise ValueError("Missing runtime archive metadata: " + name)
    return json.load(source)


def read_blob_json(archive, digest):
    algorithm, value = digest.split(":", 1)
    if algorithm != "sha256" or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("Unsafe archive digest")
    source = archive.extractfile("blobs/sha256/" + value)
    if source is None:
        raise ValueError("Missing image blob")
    payload = source.read()
    if hashlib.sha256(payload).hexdigest() != value:
        raise ValueError("Image metadata blob hash differs")
    return json.loads(payload)


def save(path, data):
    with path.open("x", encoding="utf8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    build()
