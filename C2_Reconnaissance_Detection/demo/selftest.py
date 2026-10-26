"""Self-test of the frozen pipeline on this machine (run by setup_c2_demo.ps1).

1. Demo bundle integrity: every file matches bundle_manifest.json.
2. Every upload sample (CSV and Parquet) is scored by the frozen pipeline and compared with the saved held-out test
   scores: scores must agree to 1e-6 and alerts must agree except exact threshold ties (score == threshold).
3. Every prepared replay run is re-scored the same way.
Exit code 0 = PASS.
"""
from __future__ import annotations

import hashlib
import json
import sys

import numpy as np
import pandas as pd

from inference import BUNDLE, MODELS, FrozenPipeline

TOL, TIE = 1e-6, 1e-9


def compare(p, live, ref):
    x = live[["adu_id"] + MODELS].merge(ref, on="adu_id", suffixes=("", "_ref"))
    if len(x) != len(ref):
        return False, f"{len(x)} of {len(ref)} reference requests scored"
    worst, bad = 0.0, 0
    for m in MODELS:
        d = (x[m] - x[f"{m}_ref"]).abs().max()
        worst = max(worst, float(d))
        dis = (x[m] > p.thresholds[m]) != (x[f"{m}_ref"] > p.thresholds[m])
        bad += int((dis & ((x[f"{m}_ref"] - p.thresholds[m]).abs() > TIE)).sum())
    return worst <= TOL and bad == 0, f"max|diff| {worst:.1e}, non-tie alert disagreements {bad}"


def main():
    ok = True
    man = json.loads((BUNDLE / "bundle_manifest.json").read_text())
    changed = [f for f, h in man["files"].items()
               if not (BUNDLE / f).is_file() or hashlib.sha256((BUNDLE / f).read_bytes()).hexdigest() != h]
    print(f"bundle integrity: {len(man['files']) - len(changed)}/{len(man['files'])} files OK")
    ok &= not changed
    p = FrozenPipeline()
    for ref_path in sorted((BUNDLE / "samples").glob("*.reference_scores.csv")):
        name = ref_path.name.replace(".reference_scores.csv", "")
        ref = pd.read_csv(ref_path)
        for ext, reader in ((".csv", pd.read_csv), (".parquet", pd.read_parquet)):
            good, msg = compare(p, p.score(reader(BUNDLE / "samples" / f"{name}{ext}")), ref)
            print(f"sample {name}{ext}: {'PASS' if good else 'FAIL'} ({msg})")
            ok &= good
    for info in json.loads((BUNDLE / "runs" / "index.json").read_text()):
        rows = json.loads((BUNDLE / "runs" / f"{info['run_id']}.json").read_text())["rows"]
        ref = pd.DataFrame({"adu_id": rows["adu_id"], **{m: rows["saved_scores"][m] for m in MODELS}})
        good, msg = compare(p, p.score(pd.read_csv(BUNDLE / "runs" / f"{info['run_id']}.csv")), ref)
        print(f"replay run {info['run_id']}: {'PASS' if good else 'FAIL'} ({msg})")
        ok &= good
    print("SELF-TEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
