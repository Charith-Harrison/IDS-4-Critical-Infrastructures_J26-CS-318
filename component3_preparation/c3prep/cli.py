"""Local CIC-only stage1 commands. Run from the repository root."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from contextlib import contextmanager

from .audit import build_partitions, extraction_dirs, sha256, validate_extraction, write_json
from .pairing import build_pairs


REPO = Path(__file__).resolve().parents[2]
OUTPUT = REPO / "component3_preparation/output"
RAW = REPO / "data/raw/Modbus Dataset"


@contextmanager
def pair_lock(directory):
    """OS lock prevents two audit invocations replacing the same work database."""
    with (directory / "pairing.lock").open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            handle.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_pair_audit(output=OUTPUT, views=None):
    reports = {}
    for directory in extraction_dirs(output):
        if views is not None and directory.name not in views:
            continue
        events = directory / "events.parquet"
        pairs = directory / "pairs.parquet"
        code = Path(__file__).with_name("pairing.py")
        contract = {"events_sha256": sha256(events), "pairing_code_sha256": sha256(code), "max_pending": 8192}
        signature = hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()
        checkpoint_path = directory / "pair_checkpoint.json"
        old = json.loads(checkpoint_path.read_text()) if checkpoint_path.exists() else {}
        if old.get("signature") == signature and pairs.exists() and sha256(pairs) == old.get("output_sha256"):
            reports[directory.name] = old["report"]
            print(f"pair audit {directory.name}: verified checkpoint reused", flush=True)
            continue
        print(f"pair audit {directory.name}: starting", flush=True)
        with pair_lock(directory):
            report = build_pairs(events, pairs)
        write_json(directory / "pair_report.json", report)
        write_json(checkpoint_path, {"signature": signature, "contract": contract, "output_sha256": sha256(pairs), "report": report})
        reports[directory.name] = report
        print(f"pair audit {directory.name}: {report['relation_counts']}", flush=True)
    write_json(Path(output) / "pair_report.json", reports)
    return reports


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, default=REPO / "component3_preparation/config.json")
    ap.add_argument("command", choices=["inventory", "logs", "pilot", "extract", "pair", "annotate", "split", "verify", "reports", "all"])
    ap.add_argument("--workers", type=int, default=2, choices=[1, 2, 3])
    args = ap.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    commands = [args.command] if args.command != "all" else ["inventory", "logs", "pilot", "extract", "pair", "annotate", "split", "verify", "reports"]
    for cmd in commands:
        if cmd == "inventory":
            from .inventory import run_inventory
            run_inventory(RAW, OUTPUT)
        elif cmd == "logs":
            from .logs import run_logs
            run_logs(RAW, OUTPUT)
        elif cmd == "pilot":
            from .pilot import DEFAULT_CONFIG, run_pilot
            if json.loads(args.config.read_text()) != DEFAULT_CONFIG:
                raise ValueError("The bounded pilot validates the versioned default profile. Revise and revalidate the pilot explicitly before using a different extraction profile.")
            report = run_pilot(REPO)
            if report is not None and not report["all_pilot_assertions_passed"]:
                raise RuntimeError("Pilot gate did not pass")
        elif cmd == "extract":
            subprocess.run([sys.executable, "-m", "component3_preparation.c3prep.run_extraction", "--config", str(args.config.resolve()), "--workers", str(args.workers)], cwd=REPO, check=True)
        elif cmd == "pair":
            run_pair_audit()
        elif cmd == "annotate":
            from .labels import run_labels
            run_labels(OUTPUT)
        elif cmd == "split":
            build_partitions(OUTPUT)
        elif cmd == "verify":
            report = validate_extraction(OUTPUT, RAW, rehash=True)
            if not report["source_immutability"] or not report["all_row_and_accounting_checks_pass"]:
                raise RuntimeError("See quality_report.json: extraction verification failed")
        elif cmd == "reports":
            from .reports import render_reports
            render_reports(OUTPUT)
        print(f"stage1 {cmd}: complete", flush=True)


if __name__ == "__main__":
    main()
