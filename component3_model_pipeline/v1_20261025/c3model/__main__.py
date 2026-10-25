import argparse
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description='Verified Component3 raw -> development -> locked evaluation')
    parser.add_argument('stage', choices=['verify','prepare','train','freeze','evaluate-final'])
    parser.add_argument('--source', type=Path)
    parser.add_argument('--artifacts', type=Path, default=Path(__file__).resolve().parent.parent/'artifacts')
    args = parser.parse_args()
    if args.source is None:
        repo = Path(__file__).resolve().parents[3]
        args.source = repo/'producer_work_20261025/C3/Component3_Modbus_Collector/component3_collection_runs/main-frozen-v1-20261025'
    from . import experiment as e
    args.artifacts.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(args.artifacts).free / 1024**3
    print(f'Stage={args.stage} | source={args.source} | free={free:.2f}GiB', flush=True)
    if free < 1: raise ValueError('Keep at least1GiB working reserve')
    if args.stage == 'verify': result=e.admission_report(e.verify_collection(args.source))
    elif args.stage == 'prepare': result=e.prepare(args.source,args.artifacts)
    elif args.stage == 'train': result=e.train(args.source,args.artifacts)
    elif args.stage == 'freeze': result=e.freeze(args.source,args.artifacts)
    else: result=e.final_evaluation(args.source,args.artifacts)
    print(json.dumps(result,indent=2), flush=True)


if __name__ == '__main__': main()
