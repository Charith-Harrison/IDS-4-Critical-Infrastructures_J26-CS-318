"""Complete canonical CIC view chains, with source/config/code keyed resume."""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import re
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from .extract import extract_chain
from .integrity import extraction_output_hashes, output_integrity_valid
from .pilot import DEFAULT_CONFIG, peak_memory_bytes

VIEWS = {
    "benign_ied1b": ("cic_benign_january", "benign/ied1b/ied1b-network-capture"),
    "external_bridge": ("cic_external_february", "attack/external/network-wide"),
    "scada_ied1a": ("cic_compromised_scada_march", "attack/compromised-scada/ied1a/ied1a-network-captures"),
    "ied_ied1b": ("cic_compromised_ied_march", "attack/compromised-ied/ied1b/ied1b-network-captures"),
}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def progress(view, chunk, frames, elapsed):
    print(json.dumps({"view": view, "chunk_complete": chunk, "frames": frames,
                      "elapsed_s": round(elapsed, 2)}), flush=True)


def extract_view(view, repo, cfg, seal_only=False):
    repo = Path(repo)
    raw = repo / "data/raw/Modbus Dataset"
    output = repo / "component3_preparation/output/extraction" / view
    rec, folder = VIEWS[view]
    paths = list((raw / folder).glob("*.pcap"))
    if not paths:
        raise FileNotFoundError(folder)
    chunks = sorted([(int(re.search(r"-(\d+)\.pcap$", p.name).group(1)), p) for p in paths])
    fingerprints = [{"chunk": n, "path": p.relative_to(raw).as_posix(), "bytes": p.stat().st_size,
                     "sha256": sha256_file(p)} for n, p in chunks]
    code_paths = [Path(__file__).with_name(x) for x in ("extract.py", "modbus.py", "pcapio.py")]
    code_hashes = {p.name: sha256_file(p) for p in code_paths}
    contract = {"view_id": view, "recording_id": rec, "sources": fingerprints,
                "config": cfg, "code_sha256": code_hashes}
    signature = hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()
    checkpoint_path = output / "checkpoint.json"
    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        matching = (checkpoint.get("signature") == signature
                    and checkpoint.get("reconciliation_passed") is True
                    and checkpoint.get("source_hashes_unchanged") is True)
        if seal_only:
            if not matching:
                raise RuntimeError(f"Cannot seal mismatched source/config/code checkpoint for {view}")
            if "output_sha256" in checkpoint:
                if not output_integrity_valid(output, checkpoint["output_sha256"]):
                    raise RuntimeError(f"Cannot re-seal corrupted previously sealed outputs for {view}")
                print(json.dumps({"view": view, "status": "existing_output_integrity_already_verified"}), flush=True)
                return checkpoint
            # This explicit migration is only for the completed first extraction.
            # Ordinary resume never trusts presence alone or silently seals output.
            checkpoint["output_sha256"] = extraction_output_hashes(output)
            checkpoint["checkpoint_version"] = 2
            checkpoint["integrity_sealed_after_first_run"] = True
            checkpoint_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
            print(json.dumps({"view": view, "status": "existing_output_integrity_sealed"}), flush=True)
            return checkpoint
        if matching and output_integrity_valid(output, checkpoint.get("output_sha256")):
            print(json.dumps({"view": view, "status": "verified_checkpoint_reused"}), flush=True)
            return checkpoint
        print(json.dumps({"view": view, "status": "checkpoint_integrity_or_signature_invalidated"}), flush=True)
    if seal_only:
        raise FileNotFoundError(f"No completed checkpoint to seal for {view}")
    output.parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"view": view, "status": "extracting", "chunks": len(chunks),
                      "source_bytes": sum(x["bytes"] for x in fingerprints)}), flush=True)
    acc = extract_chain(rec, view, [(n, str(p)) for n, p in chunks], cfg, str(output), progress)
    reconciled = all(acc[x] for x in ("check_bytes_captured_eq_dup_plus_delivered",
                                    "check_bytes_delivered_eq_records", "check_frames_accounted"))
    post_hashes = [sha256_file(p) for n, p in chunks]
    unchanged = post_hashes == [p["sha256"] for p in fingerprints]
    checkpoint = {"signature": signature, "contract": contract, "source_hashes_unchanged": unchanged,
                  "reconciliation_passed": reconciled, "peak_working_set_bytes": peak_memory_bytes(),
                  "output_bytes": sum(p.stat().st_size for p in output.glob("*") if p.is_file()),
                  "accounting": acc, "checkpoint_version": 2,
                  "output_sha256": extraction_output_hashes(output)}
    checkpoint_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
    if not reconciled or not unchanged:
        raise RuntimeError(f"Source/reconciliation gate failed for {view}; records remain auditable")
    print(json.dumps({"view": view, "status": "complete", "records": acc.get("records_adu", 0),
                      "reconciliation_passed": reconciled, "source_hashes_unchanged": unchanged}), flush=True)
    return checkpoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--views", nargs="+", choices=VIEWS, default=list(VIEWS))
    parser.add_argument("--workers", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--seal-existing", action="store_true", help="Explicitly seal completed first-run outputs after source/config/code revalidation")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    cfg = json.loads(args.config.read_text()) if args.config else DEFAULT_CONFIG
    free = shutil.disk_usage(repo).free
    if free < 5 * 1024 ** 3:
        raise RuntimeError("Less than5GiB free for extraction outputs")
    pilot = repo / "component3_preparation/output/pilot/pilot_report.json"
    if not pilot.exists() or not json.loads(pilot.read_text())["all_pilot_assertions_passed"]:
        raise RuntimeError("Run validated pilot first")
    with ProcessPoolExecutor(max_workers=args.workers, mp_context=multiprocessing.get_context("spawn")) as pool:
        jobs = {pool.submit(extract_view, view, str(repo), cfg, args.seal_existing): view for view in args.views}
        for job in as_completed(jobs):
            job.result()
    print(json.dumps({"all_requested_views_completed": args.views}), flush=True)


if __name__ == "__main__":
    main()
