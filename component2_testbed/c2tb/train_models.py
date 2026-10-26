"""Fit, select and threshold the five frozen representations (MODELLING_PLAN.md sections 3-6).

Uses only the train and validation partitions built by model_data.py; never loads a test partition.
Outputs (data/final_v1/models/): cv_selection.csv, selected.json, thresholds.json, validation_scores.parquet,
validation_report.json, fitted models.
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

from c2tb.representations import A_COLS, NUMERIC, rep, scale, seq  # noqa: F401  (moved, unchanged)

TB = Path(__file__).resolve().parents[1]
CFG = json.loads((TB / "configs/models_v1.json").read_text())
MI = TB / "data" / CFG["collection"] / "model_inputs"
OUT = TB / "data" / CFG["collection"] / "models"
OUT.mkdir(parents=True, exist_ok=True)
torch.set_num_threads(16)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def load(part):
    d = MI / part
    meta = pd.read_parquet(d / "meta.parquet")
    b3 = pd.read_parquet(d / "b3.parquet")
    assert (b3.adu_id.values == meta.adu_id.values).all()
    return np.load(d / "steps.npy"), np.load(d / "windows.npy"), meta, b3.drop(columns="adu_id").to_numpy(np.float32)


def folds(meta, rows):
    """Run-grouped folds dealt within site x scenario (frozen seed)."""
    rng = random.Random(CFG["cv"]["seed"])
    runs = meta.iloc[rows].groupby("run_id")[["site_id", "run_scenario_id"]].first()
    f, i = {}, 0
    for _, g in runs.groupby(["site_id", "run_scenario_id"]):
        ids = sorted(g.index)
        rng.shuffle(ids)
        for r in ids:  # one counter across groups: with 4 runs per group, i % 5 per group would leave fold 4 empty
            f[r] = i % CFG["cv"]["folds"]
            i += 1
    return meta.run_id.map(f).to_numpy()


def sel_mask(meta):
    return (meta.full_context & meta.stratum.isin(["recon", "revisiting_normal"])).to_numpy()


# ------------------------------------------------------------------ LSTM

class Net(torch.nn.Module):
    def __init__(self, d, h):
        super().__init__()
        self.lstm = torch.nn.LSTM(d, h, batch_first=True)
        self.drop = torch.nn.Dropout(CFG["lstm"]["dropout"])
        self.head = torch.nn.Linear(h, 1)

    def forward(self, x):
        o, _ = self.lstm(x)
        return self.head(self.drop(o[:, -1])).squeeze(-1)   # last step is always the real target request


def scaler(S):
    real = S[:, :, 18] > 0
    v = S[:, :, NUMERIC][real]
    return v.mean(0), v.std(0) + 1e-6


def lstm_fit(S, y, h, lr, epochs, S_es=None, y_es=None, m_es=None):
    torch.manual_seed(CFG["lstm"]["seed"])
    net = Net(S.shape[2], h)
    opt = torch.optim.Adam(net.parameters(), lr=lr)
    pos_w = torch.tensor((y == 0).sum() / max((y == 1).sum(), 1), dtype=torch.float32)
    lossf = torch.nn.BCEWithLogitsLoss(pos_weight=pos_w)
    Xt, yt = torch.tensor(S), torch.tensor(y, dtype=torch.float32)
    g = torch.Generator().manual_seed(CFG["lstm"]["seed"])
    best, best_ep, bad, best_state = -1, 0, 0, None
    for ep in range(1, epochs + 1):
        net.train()
        perm = torch.randperm(len(Xt), generator=g)
        for i in range(0, len(perm), CFG["lstm"]["batch_size"]):
            b = perm[i:i + CFG["lstm"]["batch_size"]]
            opt.zero_grad()
            lossf(net(Xt[b]), yt[b]).backward()
            opt.step()
        if S_es is not None:
            sc = lstm_score(net, S_es)
            auc = roc_auc_score(y_es[m_es], sc[m_es])
            if auc > best:
                best, best_ep, bad = auc, ep, 0
                best_state = {k: v.clone() for k, v in net.state_dict().items()}
            else:
                bad += 1
                if bad >= CFG["lstm"]["patience"]:
                    break
    if best_state is not None:
        net.load_state_dict(best_state)
    return net, best_ep or epochs


def lstm_score(net, S):
    net.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(S), 8192):
            out.append(torch.sigmoid(net(torch.tensor(S[i:i + 8192]))).numpy())
    return np.concatenate(out)


# ------------------------------------------------------------------ selection on train

def rf_make(p):
    return RandomForestClassifier(CFG["rf"]["n_estimators"], min_samples_leaf=p["min_samples_leaf"],
                                  max_features=p["max_features"], class_weight="balanced", n_jobs=-1,
                                  random_state=CFG["rf"]["random_state"])


def main():
    X, W, meta, B3 = load("train")
    tp = np.where(meta.train_population.to_numpy())[0]
    fold = folds(meta, tp)
    y = meta.gt_label_recon.to_numpy()
    sm = sel_mask(meta)
    rows_cv = []
    selected = {}
    grid_rf = [{"min_samples_leaf": l, "max_features": f} for l in CFG["rf"]["grid"]["min_samples_leaf"]
               for f in CFG["rf"]["grid"]["max_features"]]
    for name in ["A", "B2", "B3", "B1"]:
        Z = rep(name, X, W, B3, tp)
        for p in grid_rf:
            aucs = []
            for k in range(CFG["cv"]["folds"]):
                tr, te = fold[tp] != k, (fold[tp] == k) & sm[tp]
                m = rf_make(p).fit(Z[tr], y[tp][tr])
                aucs.append(roc_auc_score(y[tp][te], m.predict_proba(Z[te])[:, 1]))
            rows_cv.append({"model": name, **{k: str(v) for k, v in p.items()}, "within_fold_auc_mean": np.mean(aucs),
                            "fold_aucs": json.dumps([round(a, 4) for a in aucs])})
            log(name, p, round(np.mean(aucs), 4))
        best = max((r for r in rows_cv if r["model"] == name), key=lambda r: r["within_fold_auc_mean"])
        mf = best["max_features"]
        selected[name] = {"min_samples_leaf": int(best["min_samples_leaf"]),
                          "max_features": float(mf) if mf != "sqrt" else "sqrt", "cv_auc": best["within_fold_auc_mean"]}
    # LSTM
    S_all = seq(X, W, tp)
    run_ids = meta.run_id.to_numpy()[tp]
    for h in CFG["lstm"]["grid"]["hidden"]:
        for lr in CFG["lstm"]["grid"]["lr"]:
            aucs, eps = [], []
            for k in range(CFG["cv"]["folds"]):
                tr_idx = np.where(fold[tp] != k)[0]
                te_idx = np.where((fold[tp] == k) & sm[tp])[0]
                tr_runs = sorted(set(run_ids[tr_idx]))
                random.Random(CFG["lstm"]["seed"] + k).shuffle(tr_runs)
                es_runs = set(tr_runs[:max(1, int(len(tr_runs) * CFG["lstm"]["inner_early_stop_fraction_of_train_runs"]))])
                es = np.isin(run_ids[tr_idx], list(es_runs))
                fit_i, es_i = tr_idx[~es], tr_idx[es]
                mu, sd = scaler(S_all[fit_i])
                net, ep = lstm_fit(scale(S_all[fit_i], mu, sd), y[tp][fit_i], h, lr, CFG["lstm"]["max_epochs"],
                                   scale(S_all[es_i], mu, sd), y[tp][es_i], sm[tp][es_i])
                sc = lstm_score(net, scale(S_all[te_idx], mu, sd))
                aucs.append(roc_auc_score(y[tp][te_idx], sc))
                eps.append(ep)
            rows_cv.append({"model": "L", "hidden": h, "lr": lr, "within_fold_auc_mean": np.mean(aucs),
                            "fold_aucs": json.dumps([round(a, 4) for a in aucs]), "best_epochs": json.dumps(eps)})
            log("L", h, lr, round(np.mean(aucs), 4), eps)
    best = max((r for r in rows_cv if r["model"] == "L"), key=lambda r: r["within_fold_auc_mean"])
    selected["L"] = {"hidden": int(best["hidden"]), "lr": float(best["lr"]), "cv_auc": best["within_fold_auc_mean"],
                     "epochs": int(np.median(json.loads(best["best_epochs"])))}
    pd.DataFrame(rows_cv).to_csv(OUT / "cv_selection.csv", index=False)
    (OUT / "selected.json").write_text(json.dumps(selected, indent=1))
    log("selected", selected)

    # final fit on all train runs, score validation
    Xv, Wv, mv, B3v = load("validation")
    allv = np.arange(len(mv))
    scores = pd.DataFrame({"adu_id": mv.adu_id})
    for name in ["A", "B1", "B2", "B3"]:
        p = selected[name]
        m = rf_make(p).fit(rep(name, X, W, B3, tp), y[tp])
        joblib.dump(m, OUT / f"model_{name}.joblib", compress=3)
        scores[name] = np.concatenate([m.predict_proba(rep(name, Xv, Wv, B3v, allv[i:i + 50000]))[:, 1]
                                       for i in range(0, len(allv), 50000)])
        log("final", name)
    p = selected["L"]
    mu, sd = scaler(S_all)
    net, _ = lstm_fit(scale(S_all, mu, sd), y[tp], p["hidden"], p["lr"], p["epochs"])
    torch.save({"state": net.state_dict(), "mu": mu, "sd": sd, **p}, OUT / "model_L.pt")
    scores["L"] = np.concatenate([lstm_score(net, scale(seq(Xv, Wv, allv[i:i + 50000]), mu, sd))
                                  for i in range(0, len(allv), 50000)])
    log("final L")
    scores.to_parquet(OUT / "validation_scores.parquet", index=False)

    # operating point on validation revisiting-normal task requests
    nr = (mv.stratum == "revisiting_normal").to_numpy()
    thr = {m: float(np.quantile(scores[m].to_numpy()[nr], 1 - CFG["operating_point"]["fpr"])) for m in "A B1 B2 B3 L".split()}
    (OUT / "thresholds.json").write_text(json.dumps(thr, indent=1))
    report(mv, scores, thr)


def boot_ci(per_run, fn, n, seed):
    rng = np.random.default_rng(seed)
    runs = per_run.index.to_numpy()
    vals = []
    for _ in range(n):
        s = rng.choice(runs, len(runs), replace=True)
        vals.append(fn(per_run.loc[s]))
    return [round(float(np.nanpercentile(vals, 2.5)), 4), round(float(np.nanpercentile(vals, 97.5)), 4)]


def report(mv, scores, thr):
    B = CFG["bootstrap"]
    rep_ = {"partition": "validation", "thresholds": thr, "models": {}}
    for scope, mask in (("full_context", mv.full_context.to_numpy()), ("all_targets", np.ones(len(mv), bool))):
        for m in "A B1 B2 B3 L".split():
            d = mv[mask].assign(score=scores[m].to_numpy()[mask])
            d["alert"] = d.score > thr[m]
            res = {}
            for st in ["recon", "revisiting_normal", "one_pass_normal", "legitimate_lead_in", "background"]:
                g = d[d.stratum == st].groupby("run_id").alert.agg(["sum", "count"])
                if g.empty:
                    continue
                rate = lambda x: x["sum"].sum() / x["count"].sum()
                res[("recall_" if st == "recon" else "fpr_") + st] = {
                    "value": round(float(rate(g)), 4), "requests": int(g["count"].sum()), "runs": int(len(g)),
                    "ci95_run_bootstrap": boot_ci(g, rate, B["resamples"], B["seed"])}
            for neg in ["revisiting_normal", "one_pass_normal"]:
                dd = d[d.stratum.isin(["recon", neg])]
                res[f"auc_recon_vs_{neg}"] = round(float(roc_auc_score(dd.gt_label_recon, dd.score)), 4)
            rep_["models"].setdefault(m, {})[scope] = res
    (OUT / "validation_report.json").write_text(json.dumps(rep_, indent=1))
    log("validation report written")


if __name__ == "__main__":
    main()
