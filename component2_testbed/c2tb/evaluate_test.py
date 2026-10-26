"""One-shot test evaluation with the frozen models and thresholds (MODELLING_PLAN.md section 7).

Refuses to run twice for the same population (an opening log is written before any score exists).
H1: scenario-balanced recall gain of each history model (B1, B2, B3, L) over A on recon vs revisiting normal:
    per recon run recall at the frozen threshold, mean within each recon scenario, mean over scenarios; the gain is
    paired per run.  95 % CIs: run bootstrap stratified by scenario (2,000 resamples).
H2: one-pass normal FPR at the frozen threshold, and ROC-AUC recon vs one-pass normal.
Primary population = targets with full 20-request context; all targets reported as secondary.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score

from c2tb import model_data
from c2tb.train_models import CFG, MI, OUT, TB, Net, load, rep, scale, seq, lstm_score

MODELS = ["A", "B1", "B2", "B3", "L"]
HISTORY = ["B1", "B2", "B3", "L"]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def score(part):
    X, W, meta, B3 = load(part)
    rows = np.arange(len(meta))
    s = pd.DataFrame({"adu_id": meta.adu_id})
    for m in ["A", "B1", "B2", "B3"]:
        clf = joblib.load(OUT / f"model_{m}.joblib")
        s[m] = np.concatenate([clf.predict_proba(rep(m, X, W, B3, rows[i:i + 50000]))[:, 1]
                               for i in range(0, len(rows), 50000)])
    ck = torch.load(OUT / "model_L.pt", weights_only=False)
    net = Net(X.shape[1], ck["hidden"])
    net.load_state_dict(ck["state"])
    s["L"] = np.concatenate([lstm_score(net, scale(seq(X, W, rows[i:i + 50000]), ck["mu"], ck["sd"]))
                             for i in range(0, len(rows), 50000)])
    return meta, s


def balanced_recall(per_run):
    return per_run.groupby("scenario").rate.mean().mean()


def h1(meta, s, thr, mask, rng_seed, n):
    d = meta[mask & (meta.stratum == "recon").to_numpy()].copy()
    for m in MODELS:
        d[m] = s[m].to_numpy()[mask & (meta.stratum == "recon").to_numpy()] > thr[m]
    pr = d.groupby("run_id").agg(scenario=("gt_scenario_id", "first"), **{m: (m, "mean") for m in MODELS})
    rng = np.random.default_rng(rng_seed)
    groups = {sc: g.index.to_numpy() for sc, g in pr.groupby("scenario")}
    boots = []
    for _ in range(n):
        idx = np.concatenate([rng.choice(v, len(v), replace=True) for v in groups.values()])
        b = pr.loc[idx]
        boots.append({m: b.groupby("scenario")[m].mean().mean() for m in MODELS})
    boots = pd.DataFrame(boots)
    point = {m: float(pr.groupby("scenario")[m].mean().mean()) for m in MODELS}
    ci = lambda v: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
    out = {"recon_runs": int(len(pr)), "runs_per_scenario": pr.scenario.value_counts().sort_index().to_dict(),
           "scenario_balanced_recall": {m: {"value": round(point[m], 4), "ci95": ci(boots[m])} for m in MODELS},
           "gain_over_A": {m: {"value": round(point[m] - point["A"], 4), "ci95": ci(boots[m] - boots["A"]),
                               "ci_excludes_0": bool(np.percentile(boots[m] - boots["A"], 2.5) > 0)} for m in HISTORY},
           "per_scenario_recall_descriptive": pr.groupby("scenario")[MODELS].mean().round(4).to_dict("index")}
    return out


def rates(meta, s, thr, mask, n, seed):
    out = {}
    for m in MODELS:
        d = meta[mask].assign(alert=s[m].to_numpy()[mask] > thr[m])
        r = {}
        for st in ["recon", "revisiting_normal", "one_pass_normal", "legitimate_lead_in", "background"]:
            g = d[d.stratum == st].groupby("run_id").alert.agg(["sum", "count"])
            if g.empty:
                continue
            rng = np.random.default_rng(seed)
            v = [g.loc[rng.choice(g.index, len(g))].pipe(lambda x: x["sum"].sum() / x["count"].sum()) for _ in range(n)]
            r[st] = {"rate": round(float(g["sum"].sum() / g["count"].sum()), 4), "requests": int(g["count"].sum()),
                     "runs": int(len(g)), "ci95": [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]}
        for neg in ["revisiting_normal", "one_pass_normal"]:
            dd = d[d.stratum.isin(["recon", neg])]
            r[f"auc_recon_vs_{neg}"] = round(float(roc_auc_score(dd.gt_label_recon, s[m].to_numpy()[mask][
                d.stratum.isin(["recon", neg]).to_numpy()])), 4)
        out[m] = r
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--open-test", required=True, choices=sorted(model_data.SEALED))
    part = ap.parse_args().open_test
    log_p = OUT / f"opened_{part}.json"
    if log_p.exists():
        raise SystemExit(f"{part} was already opened at {json.loads(log_p.read_text())['opened_utc']}; one shot only")
    frozen = {p.name: sha(p) for p in sorted(OUT.glob("model_*")) + [OUT / "thresholds.json", OUT / "selected.json"]}
    frozen.update({"configs/models_v1.json": sha(TB / "configs/models_v1.json"), "MODELLING_PLAN.md": sha(TB / "MODELLING_PLAN.md")})
    log_p.write_text(json.dumps({"partition": part, "opened_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                                 "frozen_artifact_sha256": frozen}, indent=1))
    model_data.build(TB, CFG["collection"], part, part, CFG)
    thr = json.loads((OUT / "thresholds.json").read_text())
    meta, s = score(part)
    s.to_parquet(OUT / f"{part}_scores.parquet", index=False)
    B = CFG["bootstrap"]
    full, allt = meta.full_context.to_numpy(), np.ones(len(meta), bool)
    res = {"partition": part, "thresholds_frozen": thr, "requests": int(len(meta)), "runs": int(meta.run_id.nunique()),
           "H1_primary_full_context": h1(meta, s, thr, full, B["seed"], B["resamples"]),
           "H1_secondary_all_targets": h1(meta, s, thr, allt, B["seed"], B["resamples"]),
           "rates_full_context": rates(meta, s, thr, full, B["resamples"], B["seed"]),
           "rates_all_targets": rates(meta, s, thr, allt, B["resamples"], B["seed"])}
    (OUT / f"{part}_report.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: res[k] for k in ("requests", "runs")}, indent=1))
