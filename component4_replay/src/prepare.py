"""Prepare NEW versioned outputs without fitting a model or assigning partitions."""
import argparse
import json
import platform
from pathlib import Path
import pandas as pd
from .load_data import load_data, digest
from .reconstruct_transactions import reconstruct_transactions
from .features import extract_features, SCHEMA_VERSION, CURRENT, CONTEXT

ROOT=Path(__file__).resolve().parents[2]


def prepare(config, out):
    if Path(out).exists(): raise FileExistsError(f'Choose a NEW output directory: {out}')
    if config.get('schema_version')!=SCHEMA_VERSION or config.get('decision_point')!='request_arrival':
        raise ValueError('Unsupported schema or decision point')
    paths=[Path(config[k]) if Path(config[k]).is_absolute() else ROOT/config[k] for k in ['normal_csv','replay_csv']]
    if digest(paths[0])==digest(paths[1]): raise ValueError('Same dataset supplied twice')
    frames=[load_data(p,config['observed_boundary_gap_seconds']) for p in paths]
    messages=pd.concat(frames,ignore_index=True)
    tx,orphans=reconstruct_transactions(messages,config['pair_timeout_seconds'])
    f=extract_features(tx,config['history_size'],config['window_seconds'])
    summary=dict(schema_version=SCHEMA_VERSION,decision_point='request_arrival',
                 inputs=[dict(path=str(p.resolve()),sha256=digest(p)) for p in paths],
                 config=config,python=platform.python_version(),pandas=pd.__version__,
                 source_code_sha256={p.name:digest(p) for p in sorted(Path(__file__).parent.glob('*.py'))},
                 message_rows=len(messages),request_observations=len(tx),
                 positive_message_rows=int(messages.is_attack.eq(1).sum()),
                 positive_request_observations=int(tx.request_label_target.eq(1).sum()),
                 match_status=tx.match_status.value_counts().to_dict(),
                 unmatched_or_ambiguous_responses=len(orphans),
                 label_conflicts=int(tx.label_conflict.sum()),right_censored=int(tx.right_censored.sum()),
                 session_proxy_count=int(messages.session_proxy_id.nunique()),
                 observed_segments=int(messages.segment_id.nunique()),
                 independent_campaigns=None,independent_evaluation='UNSUPPORTED without externally verified recording/campaign manifest',
                 current_features=CURRENT,context_features=CONTEXT)
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    compression={'method':'gzip','mtime':0}
    tx.to_csv(out/'transactions.csv.gz',index=False,compression=compression)
    f.to_csv(out/'request_features.csv.gz',index=False,compression=compression)
    orphans.to_csv(out/'unpaired_responses.csv.gz',index=False,compression=compression)
    segments=messages.groupby('segment_id',sort=False).agg(input_csv=('input_csv','first'),
                source_pcap=('source_pcap','first'),start=('timestamp','min'),end=('timestamp','max'),
                messages=('timestamp','size'),positives=('is_attack',lambda s:int(s.eq(1).sum())))
    segments.to_csv(out/'observed_segments.csv')
    summary['outputs']={p.name:digest(p) for p in sorted(out.iterdir()) if p.is_file()}
    (out/'metadata.json').write_text(json.dumps(summary,indent=2,allow_nan=False),encoding='utf-8')
    return summary


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--config',default=str(ROOT/'component4_replay/configs/baseline.json'))
    ap.add_argument('--out',required=True); args=ap.parse_args()
    summary=prepare(json.loads(Path(args.config).read_text(encoding='utf-8')),args.out)
    print(json.dumps(summary,indent=2))


if __name__=='__main__': main()
