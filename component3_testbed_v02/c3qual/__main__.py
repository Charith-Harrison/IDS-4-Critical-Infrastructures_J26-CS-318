import argparse
import json
from pathlib import Path
from .config import planned


def main():
    parser = argparse.ArgumentParser(description='Component 3 v0.2 unscored qualification only; no ML')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('identity')
    p = sub.add_parser('check')
    p.add_argument('--planned-run', choices=['Q01', 'Q02', 'Q03', 'Q04'], required=True)
    p = sub.add_parser('run')
    p.add_argument('--planned-run', choices=['Q01', 'Q02', 'Q03', 'Q04'], required=True)
    p.add_argument('--output', type=Path, default=Path('/output'))
    p = sub.add_parser('verify')
    p.add_argument('run_directory', type=Path)
    args = parser.parse_args()
    if args.command == 'identity':
        from .config import source_hashes
        print(json.dumps(source_hashes(), sort_keys=True))
        return 0
    if args.command == 'check':
        from .scenarios import build
        config = planned(args.planned_run)
        episodes = build(config['seed'], config['map'], config['values'], config['schedule'])
        print(json.dumps(dict(status='CONFIG_SUPPORTED_NO_COLLECTION', config=config, episodes=len(episodes),
                              transactions=sum(len(ep['steps']) for ep in episodes)), indent=2))
        return 0
    if args.command == 'verify':
        from .validation import validate
        report = validate(args.run_directory)
        print(json.dumps({k: report[k] for k in ('status', 'errors', 'accepted_labels')}, indent=2))
        return 0 if report['status'] == 'PASSED' else 2
    from .runner import run
    folder, report = run(args.output, args.planned_run)
    print(json.dumps(dict(run_directory=str(folder), status=report['status'],
                          messages=report['message_count'], labels=report['label_counts']), indent=2), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
