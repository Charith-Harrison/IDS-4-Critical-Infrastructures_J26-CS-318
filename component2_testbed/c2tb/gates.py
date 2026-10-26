"""Frozen collection-level gates only (FINAL_COLLECTION_PROTOCOL.md section 6) - no history models, no training.

G1 value coverage, G2 same-site joint-shape coverage (per site), G3 current-message models without raw TID (pooled and
per site, run-grouped 5-fold CV), plus the reported raw-TID variants.  Reuses the frozen definitions in
diagnostics.py; only the coverage computation is re-implemented per run (instead of per request) for scale.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from c2tb.diagnostics import (CURRENT_FIELDS, GATES, SHAPE, cv_scores, load, lookup_scores, run_folds, sk_model,
                              summarize, within_fold_auc)

coll = Path(sys.argv[1])
out = coll / "analysis"
out.mkdir(exist_ok=True)
runs, df = load(coll)
runs = runs[runs.completion_state == "accepted"]
df["shape"] = df[SHAPE].astype(str).agg("|".join, axis=1)
recon, normal = df[df.gt_label_recon == 1], df[df.gt_label_recon == 0]

# G1 (pooled): value coverage
g1 = {f: float(recon[f].isin(set(normal[f])).mean()) for f in ["wire_fc", "unit", "quantity", "mbap_len", "frame_len"]}
addr_seen = set(map(tuple, normal[["site_id", "wire_fc", "unit", "address"]].to_numpy()))
g1_addr = float(np.mean([tuple(x) in addr_seen for x in recon[["site_id", "wire_fc", "unit", "address"]].to_numpy()]))
G1 = {"values": g1, "address_per_site_fc_unit": g1_addr,
      "pass": all(v >= GATES["G1_value_coverage_min"] for v in g1.values()) and g1_addr >= GATES["G1_address_coverage_min"]}

# G2 (per site): recon shape present in normal traffic of OTHER runs of the same site
runs_with = normal.groupby(["site_id", "shape"]).run_id.agg(lambda s: set(s.unique()))
hits = [bool(runs_with.get((s, sh), set()) - {rid}) for s, sh, rid in recon[["site_id", "shape", "run_id"]].to_numpy()]
by_site = recon.assign(hit=hits).groupby("site_id").hit.mean().round(4).to_dict()
G2 = {"by_site": by_site, "pooled": float(np.mean(hits)),
      "pass": min(by_site.values()) >= GATES["G2_joint_shape_other_runs_min"]}

# G3: current-message models, raw TID excluded (gated) and included (reported)
num, cat = ["address", "quantity", "mbap_len", "frame_len"], ["wire_fc", "unit"]
rf = lambda cols: sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1, random_state=0), cols, cat)
gated = {**{f"lookup[{c}]": (lambda tr, te, c=c: lookup_scores(tr, te, [c])) for c in CURRENT_FIELDS if c != "tid"},
         "lookup[joint_shape]": lambda tr, te: lookup_scores(tr, te, SHAPE),
         "decision_tree_d6": sk_model(lambda: DecisionTreeClassifier(max_depth=6, random_state=0), num, cat),
         "logistic_regression": sk_model(lambda: LogisticRegression(max_iter=2000), num, cat, scale=True),
         "random_forest": rf(num)}
raw_tid = {"RAW_TID_lookup[tid]": lambda tr, te: lookup_scores(tr, te, ["tid"]),
           "RAW_TID_decision_tree_d6": sk_model(lambda: DecisionTreeClassifier(max_depth=6, random_state=0),
                                                num + ["tid"], cat),
           "RAW_TID_random_forest": rf(num + ["tid"])}


rows = []
for scope in ["pooled", "A", "B", "C"]:
    d = df if scope == "pooled" else df[df.site_id == scope]
    d = d.reset_index(drop=True)
    r = runs if scope == "pooled" else runs[runs.site_id == scope]
    fold = run_folds(r)
    for name, fn in {**gated, **raw_tid}.items():
        s = cv_scores(d, fold, fn)
        rows.append({"scope": scope, "model": name, "group": "raw_tid_reported" if name.startswith("RAW_TID") else "gated",
                     **{k: round(v, 4) for k, v in summarize(d.gt_label_recon.to_numpy(), s).items()},
                     **within_fold_auc(d, fold, s)})
        print(scope, name, rows[-1]["roc_auc"], rows[-1]["within_fold_auc_mean"], flush=True)
g3 = pd.DataFrame(rows)
g3.to_csv(out / "gate_G3_current_message_models.csv", index=False)
gm = g3[g3.group == "gated"]
viol = gm[(gm.roc_auc > GATES["G3_auc_max"]) | (gm.oracle_balanced_accuracy > GATES["G3_balanced_accuracy_max"])
          | (gm.within_fold_auc_mean > GATES["G3_within_fold_auc_mean_max"])]
G3 = {"thresholds": {k: GATES[k] for k in ("G3_auc_max", "G3_balanced_accuracy_max", "G3_within_fold_auc_mean_max")},
      "max_by_scope": gm.groupby("scope")[["roc_auc", "oracle_balanced_accuracy", "within_fold_auc_mean"]].max().to_dict("index"),
      "violations": viol[["scope", "model", "roc_auc", "oracle_balanced_accuracy", "within_fold_auc_mean"]].to_dict("records"),
      "pass": viol.empty}
rt = g3[g3.group == "raw_tid_reported"]
rt_viol = rt[(rt.roc_auc > GATES["G3_auc_max"]) | (rt.oracle_balanced_accuracy > GATES["G3_balanced_accuracy_max"])
             | (rt.within_fold_auc_mean > GATES["G3_within_fold_auc_mean_max"])]
G3_TID = {"max_by_scope": rt.groupby("scope")[["roc_auc", "oracle_balanced_accuracy", "within_fold_auc_mean"]].max().to_dict("index"),
          "would_violate_G3_thresholds": rt_viol[["scope", "model", "roc_auc", "oracle_balanced_accuracy",
                                                  "within_fold_auc_mean"]].to_dict("records"),
          "within_thresholds": rt_viol.empty, "status": "reported, not gated (raw TID is never a predictor)"}
res = {"collection_id": coll.name, "accepted_runs": int(len(runs)), "requests": int(len(df)), "recon_requests": int(len(recon)),
       "G1": G1, "G2": G2, "G3": G3, "G3_raw_TID_variant": G3_TID, "all_gates_pass": G1["pass"] and G2["pass"] and G3["pass"]}
(out / "collection_gates.json").write_text(json.dumps(res, indent=1, default=str))
print(json.dumps(res, indent=1, default=str))
