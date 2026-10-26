"""Collection-level pilot diagnostics: acceptance manifest, current-message overlap, pre-specified gates,
causal context construction and the (informative-only) history-signal check.

Order of operations follows PILOT_PROTOCOL.md: runs are accepted first, labels come from the ledger join, and
contexts are built only afterwards, strictly within (run, client IP, server IP) streams.  Nothing here trains or
evaluates the final LSTM.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

CURRENT_FIELDS = ["wire_fc", "unit", "address", "quantity", "mbap_len", "frame_len", "tid"]
SHAPE = ["wire_fc", "unit", "address", "quantity", "mbap_len", "frame_len"]
NOT_PREDICTORS = ["run_id", "adu_id", "pcap_file", "frame_number", "end_frame_number", "pcap_record_offset",
                  "src_ip", "src_port", "dst_ip", "dst_port", "ts_ns", "adu_hex", "response_hex"]
CONTEXT_LEN = 20
IDLE_RESET_S = 60.0
GATES = {"G1_value_coverage_min": 1.0, "G1_address_coverage_min": 0.95, "G2_joint_shape_other_runs_min": 0.90,
         "G3_auc_max": 0.80, "G3_balanced_accuracy_max": 0.75,
         # FINAL_COLLECTION_PROTOCOL.md section 6: within-fold limit; raw TID excluded from gated models
         "G3_within_fold_auc_mean_max": 0.70}


# ------------------------------------------------------------------ loading / acceptance

def load(coll: Path):
    rows, reqs = [], []
    man = json.loads((coll / "collection_manifest.json").read_text())
    for r in man["schedule"]:
        rid = r["run_id"]
        acc_p = coll / "derived" / rid / "acceptance.json"
        rm = json.loads((coll / "runs" / rid / "run_manifest.json").read_text())
        acc = json.loads(acc_p.read_text()) if acc_p.exists() else {"completion_state": "not_processed",
                                                                     "failure_reason": ["not_processed"]}
        row = {"collection_id": coll.name, "run_id": rid, "scenario_id": rm["scenario_id"], "family": rm["family"],
               "replicate": r["replicate"], "site_id": rm.get("site_id") or "default", "run_seed": rm["run_seed"], "server_seed": rm.get("server_seed"),
               "actor_ip": rm["clients"]["actor"]["ip"], "background_ip": rm["clients"]["background_hmi"]["ip"],
               "target_ip": rm["target"]["ip"], "planned_start_epoch_ns": rm.get("planned_start_epoch_ns"),
               "end_wall_utc": rm.get("end_wall_utc"), "capture_file": f"runs/{rid}/capture.pcap",
               "capture_sha256": rm["raw_files"].get("capture.pcap", {}).get("sha256"),
               "collection_state": rm["collection_state"], "completion_state": acc["completion_state"],
               "failure_reason": ";".join(acc["failure_reason"] or []) or None,
               "recon_targets_selected": len(rm.get("recon_targets_selected", []))}
        if acc["completion_state"] == "accepted":
            q = pd.read_parquet(coll / "derived" / rid / "requests_labeled.parquet")
            q["site_id"] = row["site_id"]
            q["run_scenario_id"] = rm["scenario_id"]
            row.update(requests=len(q), recon_requests=int(q.gt_label_recon.sum()),
                       first_request_ns=int(q.ts_ns.min()), last_request_ns=int(q.ts_ns.max()))
            reqs.append(q)
        rows.append(row)
    return pd.DataFrame(rows), pd.concat(reqs, ignore_index=True)


# ------------------------------------------------------------------ folds and metrics

def run_folds(runs: pd.DataFrame, k=5, seed=20261025):
    """Pre-specified: recon and normal runs shuffled separately and dealt round-robin into k folds."""
    rng = random.Random(seed)
    fold = {}
    for fam in ("normal", "recon"):
        ids = sorted(runs[(runs.family == fam) & (runs.completion_state == "accepted")].run_id)
        rng.shuffle(ids)
        for i, rid in enumerate(ids):
            fold[rid] = i % k
    return fold


def oracle_balanced_accuracy(y, s):
    fpr, tpr, _ = roc_curve(y, s)
    return float(np.max((tpr + (1 - fpr)) / 2))


def summarize(y, s):
    return {"roc_auc": float(roc_auc_score(y, s)), "oracle_balanced_accuracy": oracle_balanced_accuracy(y, s)}


def within_fold_auc(df, fold, s):
    """Mean/min/max AUC computed inside each held-out fold; immune to fold-constant score shifts that distort
    pooled AUC when the true signal is weak."""
    f, y = df.run_id.map(fold).to_numpy(), df.gt_label_recon.to_numpy()
    per = [roc_auc_score(y[f == k], s[f == k]) for k in sorted(set(f)) if len(set(y[f == k])) > 1]
    return {"within_fold_auc_mean": round(float(np.mean(per)), 4), "within_fold_auc_min": round(float(min(per)), 4),
            "within_fold_auc_max": round(float(max(per)), 4)}


def lookup_scores(train, test, cols, alpha=1.0):
    key_tr = train[cols].astype(str).agg("|".join, axis=1)
    key_te = test[cols].astype(str).agg("|".join, axis=1)
    g = train.groupby(key_tr).gt_label_recon.agg(["sum", "count"])
    prior = train.gt_label_recon.mean()
    p = (g["sum"] + alpha * prior) / (g["count"] + alpha)
    return key_te.map(p).fillna(prior).to_numpy()


def design(df, numeric, categorical):
    X = df[numeric].astype(float)
    for c in categorical:
        for v in (1, 2, 3, 4) if c == "wire_fc" else (1, 2, 3, 5, 7):  # all configured unit IDs (sites A-C)
            X[f"{c}={v}"] = (df[c] == v).astype(float)
    return X


def cv_scores(df, fold, model_fn):
    s = np.full(len(df), np.nan)
    f = df.run_id.map(fold).to_numpy()
    for k in sorted(set(f)):
        tr, te = f != k, f == k
        s[te] = model_fn(df[tr], df[te])
    return s


def sk_model(make, numeric, categorical, scale=False):
    def fn(tr, te):
        Xtr, Xte = design(tr, numeric, categorical), design(te, numeric, categorical)
        if scale:
            sc = StandardScaler().fit(Xtr)
            Xtr, Xte = sc.transform(Xtr), sc.transform(Xte)
        m = make().fit(Xtr, tr.gt_label_recon)
        return m.predict_proba(Xte)[:, 1]
    return fn


def per_scenario(df, s):
    out = {}
    normal = df.gt_label_recon == 0
    for sc in sorted(df[df.gt_label_recon == 1].gt_scenario_id.unique()):
        m = normal | ((df.gt_label_recon == 1) & (df.gt_scenario_id == sc))
        out[sc] = round(float(roc_auc_score(df.gt_label_recon[m], s[m.to_numpy()])), 4)
    return out


# ------------------------------------------------------------------ overlap

def overlap_tables(df):
    n, r = df[df.gt_label_recon == 0], df[df.gt_label_recon == 1]
    rows = []
    for c in CURRENT_FIELDS + ["src_ip", "response_frame_len"]:
        pn, pr = n[c].value_counts(normalize=True), r[c].value_counts(normalize=True)
        ovl = float(pd.concat([pn, pr], axis=1).fillna(0).min(axis=1).sum())
        rows.append({"field": c, "group": "identity" if c == "src_ip" else
                     ("response_side" if c.startswith("response") else "current_request"),
                     "normal_distinct": int(n[c].nunique()), "recon_distinct": int(r[c].nunique()),
                     "recon_requests_value_seen_in_normal": float(r[c].isin(set(n[c])).mean()),
                     "overlap_coefficient": round(ovl, 4),
                     "normal_values_top": json.dumps({str(k): round(v, 3) for k, v in pn.head(6).items()}),
                     "recon_values_top": json.dumps({str(k): round(v, 3) for k, v in pr.head(6).items()})})
    addr_key = ["wire_fc", "unit", "address"]
    seen = set(map(tuple, n[addr_key].to_numpy()))
    rows.append({"field": "(wire_fc,unit,address)", "group": "current_request",
                 "normal_distinct": len(seen), "recon_distinct": int(r[addr_key].drop_duplicates().shape[0]),
                 "recon_requests_value_seen_in_normal": float(np.mean([tuple(x) in seen for x in r[addr_key].to_numpy()])),
                 "overlap_coefficient": None, "normal_values_top": None, "recon_values_top": None})
    return pd.DataFrame(rows)


def joint_shape_coverage(df):
    out = {}
    shape = df[SHAPE].astype(str).agg("|".join, axis=1)
    norm = df.gt_label_recon == 0
    recon = df[df.gt_label_recon == 1]
    by_run = {rid: set(shape[norm & (df.run_id == rid)]) for rid in df.run_id.unique()}
    site_of = df.groupby("run_id").site_id.first()
    hit_same_site = []
    all_norm = set(shape[norm])
    hit_other = []
    hit_other_normal_family = []
    fam = df.groupby("run_id").gt_label_recon.max()
    for i in recon.index:
        rid = df.at[i, "run_id"]
        others = set().union(*[v for k, v in by_run.items() if k != rid])
        hit_other.append(shape[i] in others)
        same = set().union(*[v for k, v in by_run.items() if k != rid and site_of[k] == site_of[rid]])
        hit_same_site.append(shape[i] in same)
        nf = set().union(*[v for k, v in by_run.items() if k != rid and fam[k] == 0])
        hit_other_normal_family.append(shape[i] in nf)
    out["recon_requests"] = int(len(recon))
    out["recon_shape_seen_in_any_normal"] = float(np.mean([shape[i] in all_norm for i in recon.index]))
    out["recon_shape_seen_in_normal_of_other_runs"] = float(np.mean(hit_other))
    out["recon_shape_seen_in_normal_of_other_runs_same_site"] = float(np.mean(hit_same_site))
    out["same_site_by_site"] = (recon.assign(hit=hit_same_site).groupby("site_id").hit.mean().round(4).to_dict())
    out["recon_shape_seen_in_normal_of_other_normal_family_runs"] = float(np.mean(hit_other_normal_family))
    rs = recon.assign(hit=hit_other).groupby("gt_scenario_id").hit.mean().round(4).to_dict()
    out["by_scenario_seen_in_normal_of_other_runs"] = rs
    out["distinct_recon_shapes"] = int(shape[recon.index].nunique())
    out["distinct_normal_shapes"] = int(len(all_norm))
    return out


# ------------------------------------------------------------------ causal contexts and history statistics

def build_contexts(df):
    """Per (run, client IP, server IP) stream, ordered by capture time; context = last <=20 requests ending at the
    target, reset after an idle gap.  Returns per-request context membership and history statistics."""
    tcol = "ts_corr_ns" if "ts_corr_ns" in df else "ts_ns"  # clock-step corrected timeline when available
    df = df.sort_values(["run_id", "src_ip", "dst_ip", tcol, "frame_number"]).reset_index(drop=True)
    df["stream_id"] = df.run_id + "|" + df.src_ip + "->" + df.dst_ip
    out_ctx, feats = [], []
    for sid, g in df.groupby("stream_id", sort=False):
        idx = g.index.to_numpy()
        ts = g[tcol].to_numpy()
        keys = list(zip(g.unit, g.wire_fc, g.address, g.quantity))
        seen, novel, seg_start = set(), [], 0
        for j in range(len(g)):
            if j and (ts[j] - ts[j - 1]) / 1e9 > IDLE_RESET_S:
                seg_start, seen = j, set()
            novel.append(keys[j] not in seen)
            seen.add(keys[j])
            lo = max(seg_start, j - CONTEXT_LEN + 1)
            w = list(range(lo, j + 1))
            out_ctx.append({"adu_id": g.adu_id.iat[j], "stream_id": sid, "context_len": len(w),
                            "full_context": len(w) == CONTEXT_LEN,
                            "context_adu_ids": [g.adu_id.iat[x] for x in w]})
            wk = [keys[x] for x in w]
            u = [k[0] for k in wk]
            fcs = [k[1] for k in wk]
            a = np.array([k[2] for k in wk], float)
            q = [k[3] for k in wk]
            pairs = list(zip(wk[:-1], wk[1:]))
            iat = np.diff(ts[w]) / 1e9
            feats.append({
                "adu_id": g.adu_id.iat[j],
                "h_context_len": len(w),
                "h_unique_target_frac": len(set(wk)) / len(w),
                "h_current_first_seen": float(novel[j]),
                "h_first_seen_frac": float(np.mean([novel[x] for x in w])),
                "h_ascending_step_frac": float(np.mean([(p[0], p[1]) == (c[0], c[1]) and c[2] - p[2] == p[3]
                                                        for p, c in pairs])) if pairs else 0.0,
                "h_mean_abs_addr_delta": float(np.mean(np.abs(np.diff(a)))) if len(a) > 1 else 0.0,
                "h_fc_transition_frac": float(np.mean([x != y for x, y in zip(fcs[:-1], fcs[1:])])) if pairs else 0.0,
                "h_unit_transition_frac": float(np.mean([x != y for x, y in zip(u[:-1], u[1:])])) if pairs else 0.0,
                "h_distinct_tables": len(set(zip(u, fcs))),
                "h_distinct_quantities": len(set(q)),
                "h_iat_mean_log": float(np.log10(iat.mean() + 1e-6)) if len(iat) else 0.0,
                "h_iat_cv": float(iat.std() / (iat.mean() + 1e-9)) if len(iat) > 1 else 0.0,
                "h_iat_min_log": float(np.log10(iat.min() + 1e-6)) if len(iat) else 0.0,
            })
    ctx = pd.DataFrame(out_ctx)
    return df.merge(pd.DataFrame(feats), on="adu_id"), ctx


def check_contexts(df, ctx):
    pos = {a: i for i, a in enumerate(df.adu_id)}
    bad = {"cross_run": 0, "cross_stream": 0, "non_monotonic_time": 0, "target_not_last": 0, "too_long": 0}
    for r in ctx.itertuples():
        ids = r.context_adu_ids
        rows = df.iloc[[pos[a] for a in ids]]
        bad["cross_run"] += rows.run_id.nunique() != 1
        bad["cross_stream"] += rows.stream_id.nunique() != 1
        bad["non_monotonic_time"] += not rows["ts_corr_ns" if "ts_corr_ns" in rows else "ts_ns"].is_monotonic_increasing
        bad["target_not_last"] += ids[-1] != r.adu_id
        bad["too_long"] += len(ids) > CONTEXT_LEN
    return {k: int(v) for k, v in bad.items()}


# ------------------------------------------------------------------ main

def main(coll: Path):
    out = coll / "analysis"
    out.mkdir(exist_ok=True)
    runs, df = load(coll)
    runs.to_csv(out / "acceptance_manifest.csv", index=False)
    accepted = runs[runs.completion_state == "accepted"]
    fold = run_folds(runs)
    runs["cv_fold"] = runs.run_id.map(fold)
    runs.to_csv(out / "acceptance_manifest.csv", index=False)

    ov = overlap_tables(df)
    ov.to_csv(out / "current_message_overlap.csv", index=False)
    js = joint_shape_coverage(df)

    y = df.gt_label_recon.to_numpy()
    models = {}
    for c in CURRENT_FIELDS:
        if c != "tid":
            models[f"lookup[{c}]"] = lambda tr, te, c=c: lookup_scores(tr, te, [c])
    models["lookup[joint_shape]"] = lambda tr, te: lookup_scores(tr, te, SHAPE)
    num, cat = ["address", "quantity", "mbap_len", "frame_len"], ["wire_fc", "unit"]  # raw TID never a predictor
    models["decision_tree_d6"] = sk_model(lambda: DecisionTreeClassifier(max_depth=6, random_state=0), num, cat)
    models["logistic_regression"] = sk_model(lambda: LogisticRegression(max_iter=2000), num, cat, scale=True)
    models["random_forest"] = sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1,
                                                                      random_state=0), num, cat)
    def unseen_shape_rule(tr, te):
        seen = set(tr[tr.gt_label_recon == 0][SHAPE].astype(str).agg("|".join, axis=1))
        return (~te[SHAPE].astype(str).agg("|".join, axis=1).isin(seen)).astype(float).to_numpy()

    diag_models = {
        "DIAG_rule_shape_unseen_in_training_normal": unseen_shape_rule,
        "RAW_TID_lookup[tid]": lambda tr, te: lookup_scores(tr, te, ["tid"]),
        "RAW_TID_decision_tree_d6": sk_model(lambda: DecisionTreeClassifier(max_depth=6, random_state=0),
                                             num + ["tid"], cat),
        "RAW_TID_random_forest": sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1,
                                                                         random_state=0), num + ["tid"], cat),
        "DIAG_identity_lookup[src_ip]": lambda tr, te: lookup_scores(tr, te, ["src_ip"]),
        "DIAG_response_lookup[response_frame_len]": lambda tr, te: lookup_scores(tr, te, ["response_frame_len"]),
    }
    static_rows = []
    for name, fn in {**models, **diag_models}.items():
        s = cv_scores(df, fold, fn)
        row = {"model": name, "group": "gate_current_message" if name in models else
               ("reported_raw_tid_variant" if name.startswith("RAW_TID") else "diagnostic_not_gated"),
               **{k: round(v, 4) for k, v in summarize(y, s).items()}, **within_fold_auc(df, fold, s)}
        row["auc_by_recon_scenario"] = json.dumps(per_scenario(df, s))
        static_rows.append(row)
    static = pd.DataFrame(static_rows)
    static.to_csv(out / "current_message_models.csv", index=False)

    # gates
    cur = ov[ov.group == "current_request"].set_index("field")
    g1_fields = ["wire_fc", "unit", "quantity", "mbap_len", "frame_len"]
    g1 = {f: float(cur.loc[f, "recon_requests_value_seen_in_normal"]) for f in g1_fields}
    g1_addr = float(cur.loc["(wire_fc,unit,address)", "recon_requests_value_seen_in_normal"])
    gated = static[static.group == "gate_current_message"]
    gates = {
        "thresholds": GATES,
        "G1": {"values": g1, "address_per_fc_unit": g1_addr,
               "pass": all(v >= GATES["G1_value_coverage_min"] for v in g1.values())
               and g1_addr >= GATES["G1_address_coverage_min"]},
        "G2": {"value_any_site": js["recon_shape_seen_in_normal_of_other_runs"],
               "value_same_site": js["recon_shape_seen_in_normal_of_other_runs_same_site"],
               "by_site_same_site": js["same_site_by_site"],
               "pass": min(js["same_site_by_site"].values()) >= GATES["G2_joint_shape_other_runs_min"]},
        "G3": {"max_auc": float(gated.roc_auc.max()), "max_auc_model": gated.loc[gated.roc_auc.idxmax(), "model"],
               "max_balanced_accuracy": float(gated.oracle_balanced_accuracy.max()),
               "max_balanced_accuracy_model": gated.loc[gated.oracle_balanced_accuracy.idxmax(), "model"],
               "max_within_fold_auc_mean": float(gated.within_fold_auc_mean.max()),
               "pass": bool(gated.roc_auc.max() <= GATES["G3_auc_max"]
                            and gated.oracle_balanced_accuracy.max() <= GATES["G3_balanced_accuracy_max"]
                            and gated.within_fold_auc_mean.max() <= GATES["G3_within_fold_auc_mean_max"])},
        "G3_raw_tid_reported": static[static.group == "reported_raw_tid_variant"][
            ["model", "roc_auc", "oracle_balanced_accuracy", "within_fold_auc_mean"]].to_dict("records"),
    }
    gates["all_pass"] = gates["G1"]["pass"] and gates["G2"]["pass"] and gates["G3"]["pass"]

    # contexts are built only now, after acceptance and label join
    dfh, ctx = build_contexts(df)
    integrity = check_contexts(dfh, ctx)
    ctx.to_parquet(out / "causal_context_index.parquet", index=False)
    hist_cols = [c for c in dfh.columns if c.startswith("h_")]
    hist_rows = []
    yh = dfh.gt_label_recon.to_numpy()
    hist_models = {
        "history_tree_d4": sk_model(lambda: DecisionTreeClassifier(max_depth=4, random_state=0), hist_cols, []),
        "history_random_forest": sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1,
                                                                         random_state=0), hist_cols, []),
        "current_plus_history_random_forest": sk_model(
            lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1, random_state=0), num + hist_cols, cat),
    }
    for name, fn in hist_models.items():
        s = cv_scores(dfh, fold, fn)
        thr = np.quantile(s[yh == 0], 0.95)
        rec5 = dfh[yh == 1].assign(hit=s[yh == 1] > thr).groupby("gt_scenario_id").hit.mean().round(3).to_dict()
        hist_rows.append({"model": name, **{k: round(v, 4) for k, v in summarize(yh, s).items()},
                          "auc_by_recon_scenario": json.dumps(per_scenario(dfh, s)),
                          "recall_at_pooled_normal_fpr_5pct_by_scenario": json.dumps(rec5),
                          "fpr5_threshold_note": "threshold from pooled out-of-fold normal scores (optimistic)"})
    hist = pd.DataFrame(hist_rows)
    hist.to_csv(out / "history_signal_diagnostic.csv", index=False)
    single = []
    for c in hist_cols:  # untrained single-statistic separability (direction-free), pooled
        a = roc_auc_score(yh, dfh[c])
        single.append({"feature": c, "auc_direction_free": round(max(a, 1 - a), 4),
                       "higher_means_recon": a >= 0.5, **{f"auc[{sc}]": v for sc, v in
                                                          per_scenario(dfh, dfh[c].to_numpy()).items()}})
    pd.DataFrame(single).sort_values("auc_direction_free", ascending=False).to_csv(
        out / "history_single_feature_auc.csv", index=False)

    # Hard-negative view: drop the high-rate background HMI stream and compare recon only with the actor host's
    # legitimate activity (normal workloads and the pre-recon lead-in).  Same run-grouped folds.
    act = dfh[dfh.gt_phase != "background_hmi"].reset_index(drop=True)
    ya = act.gt_label_recon.to_numpy()
    hard = []
    for c in hist_cols:
        a = roc_auc_score(ya, act[c])
        hard.append({"model_or_feature": c, "kind": "single_feature_untrained", "roc_auc": round(max(a, 1 - a), 4)})
    timing = [c for c in hist_cols if c.startswith("h_iat")]
    for name, cols in (("history_random_forest", hist_cols),
                       ("history_random_forest_without_timing", [c for c in hist_cols if c not in timing]),
                       ("timing_only_random_forest", timing)):
        s = cv_scores(act, fold, sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1,
                                                                         random_state=0), cols, []))
        hard.append({"model_or_feature": name, "kind": "run_grouped_cv",
                     **{k: round(v, 4) for k, v in summarize(ya, s).items()}, **within_fold_auc(act, fold, s),
                     "auc_by_recon_scenario": json.dumps(per_scenario(act, s))})
    for name, fn in (("current_message_random_forest", models["random_forest"]),
                     ("current_message_lookup[joint_shape]", models["lookup[joint_shape]"])):
        s = cv_scores(act, fold, fn)
        hard.append({"model_or_feature": name, "kind": "run_grouped_cv",
                     **{k: round(v, 4) for k, v in summarize(ya, s).items()}, **within_fold_auc(act, fold, s)})
    pd.DataFrame(hard).to_csv(out / "hard_negative_actor_only_diagnostic.csv", index=False)

    one_pass = sorted(s for s in act.run_scenario_id.unique() if s.split("_")[0] in ("N5", "N6", "N7", "N8"))
    if one_pass:
        # Recon vs legitimate one-pass coverage workloads only (Amendment A).
        op = act[(act.gt_label_recon == 1) | ((act.gt_phase == "normal_workload") & act.run_scenario_id.isin(one_pass))]
        op = op.reset_index(drop=True)
        yo = op.gt_label_recon.to_numpy()
        rows = []
        variants = {"history_random_forest": (hist_cols, []),
                    "history_random_forest_without_timing": ([c for c in hist_cols if c not in timing], []),
                    "timing_only_random_forest": (timing, []),
                    "current_message_random_forest": (num, cat)}
        scores = {}
        for name, (nc, cc) in variants.items():
            sc = cv_scores(op, fold, sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1,
                                                                            random_state=0), nc, cc))
            scores[name] = sc
            rows.append({"view": "recon_vs_one_pass_cv", "model": name,
                         **{k: round(v, 4) for k, v in summarize(yo, sc).items()}, **within_fold_auc(op, fold, sc)})
        for c in hist_cols:
            a = roc_auc_score(yo, op[c])
            rows.append({"view": "recon_vs_one_pass_single_feature", "model": c, "roc_auc": round(max(a, 1 - a), 4)})
        pd.DataFrame(rows).to_csv(out / "hard_negative_one_pass_diagnostic.csv", index=False)
        pair = []
        sc = scores["history_random_forest"]
        for r_s in sorted(op[yo == 1].gt_scenario_id.unique()):
            for n_s in one_pass:
                m = ((yo == 1) & (op.gt_scenario_id == r_s)) | ((yo == 0) & (op.run_scenario_id == n_s))
                pair.append({"recon_scenario": r_s, "one_pass_scenario": n_s,
                             "history_rf_auc": round(float(roc_auc_score(yo[m], sc[m.to_numpy()])), 4)})
        pd.DataFrame(pair).pivot(index="recon_scenario", columns="one_pass_scenario", values="history_rf_auc").to_csv(
            out / "hard_negative_pairwise_history_auc.csv")

    sites = sorted(act.site_id.unique())
    if len(sites) > 1:
        rows = []
        for held in sites:
            tr, te = act[act.site_id != held], act[act.site_id == held]
            for name, (nc, cc) in {"history_random_forest": (hist_cols, []),
                                   "history_random_forest_without_timing": ([c for c in hist_cols if c not in timing], []),
                                   "current_message_random_forest": (num, cat)}.items():
                sc = sk_model(lambda: RandomForestClassifier(200, min_samples_leaf=5, n_jobs=-1, random_state=0),
                              nc, cc)(tr, te)
                rows.append({"held_out_site": held, "model": name, "view": "actor_only",
                             **{k: round(v, 4) for k, v in summarize(te.gt_label_recon, sc).items()}})
        pd.DataFrame(rows).to_csv(out / "leave_one_site_out_diagnostic.csv", index=False)
    desc = dfh.groupby(["gt_label_recon", "gt_phase"])[hist_cols].median().round(3)
    desc.to_csv(out / "history_feature_medians_by_phase.csv")
    rd = dfh[dfh.gt_label_recon == 1].groupby("gt_scenario_id")[hist_cols].median().round(3)
    rd.to_csv(out / "history_feature_medians_by_recon_scenario.csv")

    keep = [c for c in dfh.columns if c not in ("context_adu_ids",)]
    dfh[keep].to_parquet(out / "pilot_requests_labeled_with_history.parquet", index=False)

    summary = {
        "collection_id": coll.name,
        "runs_total": int(len(runs)), "runs_accepted": int(len(accepted)),
        "runs_rejected": runs[runs.completion_state != "accepted"][["run_id", "failure_reason"]].to_dict("records"),
        "accepted_runs_by_scenario": accepted.scenario_id.value_counts().sort_index().to_dict(),
        "requests": int(len(df)), "recon_requests": int(y.sum()),
        "requests_by_phase": df.groupby(["gt_role", "gt_phase"]).size().rename("n").reset_index().to_dict("records"),
        "joint_shape_coverage": js, "gates": gates,
        "context_integrity_violations": integrity,
        "contexts": {"total": int(len(ctx)), "full_20": int(ctx.full_context.sum()),
                     "recon_targets_full_20": int(dfh[(dfh.gt_label_recon == 1)].h_context_len.eq(CONTEXT_LEN).sum()),
                     "recon_targets_partial": int(dfh[(dfh.gt_label_recon == 1)].h_context_len.lt(CONTEXT_LEN).sum())},
        "cv_folds": {str(k): sorted(r for r, f in fold.items() if f == k) for k in sorted(set(fold.values()))},
        "predictor_exclusions": {"never_predictors": NOT_PREDICTORS,
                                 "ground_truth_and_ledger_columns": "all gt_* and ledger_* columns"},
    }
    (out / "pilot_summary.json").write_text(json.dumps(summary, indent=1, default=str))
    print(json.dumps({"gates": gates, "joint_shape": js, "integrity": integrity}, indent=1, default=str))
    print(static[["model", "roc_auc", "oracle_balanced_accuracy"]].to_string())
    print(hist[["model", "roc_auc", "oracle_balanced_accuracy"]].to_string())


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collection-dir", required=True)
    main(Path(p.parse_args().collection_dir))
