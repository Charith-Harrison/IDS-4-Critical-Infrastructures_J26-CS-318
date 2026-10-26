"""Final run-count calculation from the observed v3 run-level variance (frozen-protocol evidence).

Run-grouped out-of-fold scores (same folds as diagnostics.py) for a history RF and a current-message RF on the
actor-only view.  The operating threshold gives 5 % FPR on revisiting-normal requests.  Each run then contributes one
run-level value per stratum (runs, not requests, are the independent unit).  Required runs per stratum follow
n = ceil((t_{0.975,n-1} * sd / h)^2), iterated, with prespecified half-widths h.
"""
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier

from c2tb.diagnostics import build_contexts, cv_scores, load, run_folds, sk_model

coll = Path(sys.argv[1])
runs, df = load(coll)
fold = run_folds(runs)
dfh, _ = build_contexts(df)
hist = [c for c in dfh if c.startswith("h_")]
act = dfh[dfh.gt_phase != "background_hmi"].reset_index(drop=True)
rf = lambda nc, cc: sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1, random_state=0), nc, cc)
scores = {"history": cv_scores(act, fold, rf(hist, [])),
          "current_without_tid": cv_scores(act, fold, rf(["address", "quantity", "mbap_len", "frame_len"],
                                                          ["wire_fc", "unit"]))}
# Frozen strata (FINAL_COLLECTION_PROTOCOL.md section 3).  Background HMI is evaluated separately (all phases).
task = act.gt_phase == "normal_workload"
sc2 = act.run_scenario_id.str[:2]
act["stratum"] = np.select(
    [act.gt_label_recon == 1, task & sc2.isin(["N1", "N2", "N3", "N4"]), task & sc2.isin(["N5", "N6", "N7", "N8"])],
    ["recon", "revisiting_normal", "one_pass_normal"], default="legitimate_lead_in")
TARGET_FPR = 0.05
H = {"recon_recall": 0.10, "revisiting_fpr": 0.03, "one_pass_fpr": 0.10, "recall_gain_history_minus_current": 0.10}


def n_required(sd, h):
    n = 2
    while True:
        t = stats.t.ppf(0.975, n - 1)
        if math.ceil((t * sd / h) ** 2) <= n:
            return n
        n += 1


out = {"source_collection": coll.name, "unit_of_analysis": "run", "target_fpr_revisiting": TARGET_FPR,
       "half_widths": H, "models": {}}
per_run_tables = []
for name, s in scores.items():
    act["score"] = s
    thr = float(np.quantile(act.score[act.stratum == "revisiting_normal"], 1 - TARGET_FPR))  # request-level 5 % FPR
    act["alert"] = act.score > thr
    per_run = (act.groupby(["run_id", "run_scenario_id", "stratum"]).alert.mean().rename(f"rate_{name}")
               .reset_index())
    per_run_tables.append(per_run.set_index(["run_id", "run_scenario_id", "stratum"]))
    m = {}
    for st, key in (("recon", "recon_recall"), ("revisiting_normal", "revisiting_fpr"),
                    ("one_pass_normal", "one_pass_fpr"), ("legitimate_lead_in", "lead_in_fpr")):
        v = per_run[per_run.stratum == st][f"rate_{name}"]
        m[key] = {"runs": int(len(v)), "mean": round(float(v.mean()), 4), "sd_between_runs": round(float(v.std(ddof=1)), 4)}
    out["models"][name] = {"threshold": thr, "per_run": m}
pr = pd.concat(per_run_tables, axis=1).reset_index()
diff = pr[pr.stratum == "recon"]
d = diff.rate_history - diff.rate_current_without_tid
out["paired_recall_gain"] = {"runs": int(len(d)), "mean": round(float(d.mean()), 4),
                             "sd_between_runs": round(float(d.std(ddof=1)), 4)}
req = {}
hm = out["models"]["history"]["per_run"]
req["recon_runs_for_recall"] = n_required(max(hm["recon_recall"]["sd_between_runs"],
                                              out["models"]["current_without_tid"]["per_run"]["recon_recall"]["sd_between_runs"]),
                                          H["recon_recall"])
req["revisiting_normal_runs_for_fpr"] = n_required(hm["revisiting_fpr"]["sd_between_runs"], H["revisiting_fpr"])
req["one_pass_runs_for_fpr"] = n_required(hm["one_pass_fpr"]["sd_between_runs"], H["one_pass_fpr"])
req["recon_runs_for_paired_gain"] = n_required(out["paired_recall_gain"]["sd_between_runs"],
                                               H["recall_gain_history_minus_current"])
out["required_test_runs_per_test_population"] = req
pr.to_csv(sys.argv[2], index=False)
print(json.dumps(out, indent=1))
