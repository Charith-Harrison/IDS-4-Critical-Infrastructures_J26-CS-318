from pathlib import Path
import argparse
import json
from .pilot import run_pilot


def main():
    parser = argparse.ArgumentParser(description="Small isolated Modbus feasibility pilot; no ML")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "smoke"):
        p = sub.add_parser(command)
        p.add_argument("--output", type=Path, default=Path("outputs"))
        p.add_argument("--seed", type=int, default=4010)
        p.add_argument("--groups", type=int, default=2)
    for command in ("verify", "explain"):
        p = sub.add_parser(command)
        p.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    if args.command == "explain":
        from .explain import explain_run
        print(explain_run(args.run_directory))
        return 0
    if args.command == "verify":
        from .capture_validation import validate_capture
        report = validate_capture(args.run_directory)
        print(json.dumps(report, indent=2))
        passed = report.get("passed", report.get("status") in ("PASS", "PASSED", "VERIFIED"))
        return 0 if passed else 2
    folder = run_pilot(args.output, args.seed, args.groups, captured=args.command == "run")
    print(f"Output directory: {folder}", flush=True)
    if args.command == "smoke":
        print("SMOKE ONLY: actual local TCP exercised; no packet capture or verified dataset produced.")
    else:
        print("Read validation_report.json. Pilot verification is not proof of research generalization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
