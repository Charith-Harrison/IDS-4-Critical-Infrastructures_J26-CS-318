"""Training: leakage-controlled grouped CV, final fit, saving and verification.

* Reads ONLY data/splits/train.parquet (via the test-path guard).
* Per CV fold, profile statistics are fitted on fold-training rows only.
* After model selection, statistics and models are refitted on the full 80%.
* The final 20% partition is never opened.
"""

from __future__ import annotations

import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold

from src.data.pairing import pair_events
from src.features.builder import (
    CONTEXT_GROUPS,
    FEATURE_GROUPS,
    ISOLATED_GROUPS,
    build_stat_free_features,
    group_features,
)
from src.features.profile import apply_profile, fit_profile
from src.utils.config import (
    BINARY_LIMITATION,
    CLASS_NAMES,
    FEATURE_SCHEMA_VERSION,
    LABEL_MAPPING,
    MODEL_VERSION,
    MODELS_DIR,
    PROGRESS_DIR,
    RANDOM_STATE,
    TRAIN_PARQUET,
    VALIDATION_DIR,
    get_logger,
    read_parquet_safe,
)
from src.utils.io import read_json, sha256_file, write_json

log = get_logger("train")
N_FOLDS = 5
# Computationally modest grid shared by both models (same folds, same grid).
GRID = [
    {
        "n_estimators": 100,
        "max_depth": None,
        "min_samples_leaf": 1,
        "max_features": "sqrt",
        "class_weight": "balanced_subsample",
    },
    {"n_estimators": 100, "max_depth": 12, "min_samples_leaf": 5, "max_features": "sqrt", "class_weight": "balanced"},
    {
        "n_estimators": 100,
        "max_depth": 20,
        "min_samples_leaf": 2,
        "max_features": 0.5,
        "class_weight": "balanced_subsample",
    },
]


def load_dev_features() -> pd.DataFrame:
    """Dev packets -> paired events -> stat-free features (labelled rows kept)."""
    packets = read_parquet_safe(TRAIN_PARQUET)
    events, _, _ = pair_events(packets)
    events["event_id"] = events["capture_id"] + ":" + events["source_row"].astype(str)
    return build_stat_free_features(events)


def _metrics(y, pred, prob) -> dict:
    """Per-class and macro metrics for the binary problem."""
    p, r, f, _ = precision_recall_fscore_support(y, pred, labels=[0, 1], zero_division=0)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp = cm[0]
    out = {
        "macro_precision": float(p.mean()),
        "macro_recall": float(r.mean()),
        "macro_f1": float(f.mean()),
        "per_class": {
            CLASS_NAMES[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i])} for i in (0, 1)
        },
        "false_positive_rate": float(fp / max(tn + fp, 1)),
        "confusion_matrix": cm.tolist(),
        "support": {CLASS_NAMES[i]: int((y == i).sum()) for i in (0, 1)},
    }
    if len(np.unique(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, prob))
        out["pr_auc"] = float(average_precision_score(y, prob))
    return out


def _rf(params: dict) -> RandomForestClassifier:
    """Random Forest with the fixed project seed."""
    return RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1, **params)


def run_cv(F: pd.DataFrame, feats: dict[str, list[str]]) -> dict:
    """Grouped CV over the dev partition with fold-specific profile fitting."""
    y = F["class_id"].astype(int).to_numpy()
    groups = F["capture_id"].to_numpy()
    folds = list(StratifiedGroupKFold(N_FOLDS, shuffle=True, random_state=RANDOM_STATE).split(F, y, groups))
    fold_info = []
    for i, (tr, va) in enumerate(folds):
        fold_info.append(
            {
                "fold": i,
                "train_captures": sorted(set(groups[tr])),
                "val_captures": sorted(set(groups[va])),
                "val_class_counts": {CLASS_NAMES[c]: int((y[va] == c).sum()) for c in (0, 1)},
            }
        )
        assert not set(groups[tr]) & set(groups[va]), "capture leaked across folds"
    results: dict = {"folds": fold_info, "search": []}
    oof_store: dict = {}
    for model_name, cols in feats.items():
        for gi, params in enumerate(GRID):
            oof = np.full(len(F), np.nan)
            t0 = time.time()
            fold_f1 = []
            for i, (tr, va) in enumerate(folds):
                # Fold-specific statistics: fitted ONLY on fold-training rows.
                stats = fit_profile(F.iloc[tr])
                Xtr = apply_profile(F.iloc[tr], stats)[cols]
                Xva = apply_profile(F.iloc[va], stats)[cols]
                clf = _rf(params).fit(Xtr, y[tr])
                oof[va] = clf.predict_proba(Xva)[:, 1]
                fold_f1.append(_metrics(y[va], (oof[va] >= 0.5).astype(int), oof[va])["macro_f1"])
            m = _metrics(y, (oof >= 0.5).astype(int), oof)
            rec = {
                "model": model_name,
                "config_id": gi,
                "params": params,
                "pooled_oof": m,
                "fold_macro_f1": fold_f1,
                "seconds": time.time() - t0,
            }
            results["search"].append(rec)
            oof_store[(model_name, gi)] = oof
            log.info("%s cfg%d macroF1=%.4f (%.0fs)", model_name, gi, m["macro_f1"], rec["seconds"])
    results["_oof"] = oof_store
    results["_folds"] = folds
    return results


def circularity_diagnostics(F: pd.DataFrame, folds, params: dict) -> dict:
    """Quantify how much the label rule is reproduced by its own inputs.

    (a) Rule: 'write whose function/register is unseen in fold-train normal
        traffic' scored out-of-fold - this mirrors the label construction.
    (b) Diagnostic RF without register/value/access information.
    Both are diagnostics on the dev partition only (never the test split).
    """
    y = F["class_id"].astype(int).to_numpy()
    rule = np.full(len(F), np.nan)
    oof_b = np.full(len(F), np.nan)
    drop = set(
        FEATURE_GROUPS["ACCESS"]
        + FEATURE_GROUPS["VALUE"]
        + ["ref_num", "prev_ref", "write_value", "distinct_ref_prev_k", "same_ref_writes_prev_k"]
    )
    cols = [c for c in group_features(CONTEXT_GROUPS) if c not in drop]
    for tr, va in folds:
        stats = fit_profile(F.iloc[tr])
        Xva = apply_profile(F.iloc[va], stats)
        rule[va] = Xva["access_write_unseen"].to_numpy()
        Xtr = apply_profile(F.iloc[tr], stats)[cols]
        clf = _rf(params).fit(Xtr, y[tr])
        oof_b[va] = clf.predict_proba(Xva[cols])[:, 1]
    return {
        "rule_unseen_write_equals_label_rule": _metrics(y, rule.astype(int), rule),
        "rf_without_register_value_access_features": _metrics(y, (oof_b >= 0.5).astype(int), oof_b),
        "features_removed_in_diagnostic": sorted(drop),
        "interpretation": (
            "High scores for the rule show the labels are largely reproducible from "
            "function code + register novelty, i.e. results partly restate the labelling rule. "
            "The diagnostic RF shows how much signal remains from behaviour alone."
        ),
    }


def select_columns(F: pd.DataFrame) -> tuple[dict[str, list[str]], list[str]]:
    """Feature lists per model; zero-variance columns on dev are dropped."""
    stats = fit_profile(F)
    X = apply_profile(F, stats)
    base = group_features(ISOLATED_GROUPS)
    ctx = group_features(CONTEXT_GROUPS)
    const = [c for c in ctx if X[c].nunique(dropna=False) <= 1]
    feats = {"baseline": [c for c in base if c not in const], "contextual": [c for c in ctx if c not in const]}
    return feats, const


def latency_ms(clf, X: pd.DataFrame) -> dict:
    """Validation inference latency: single-event and per-event batch time."""
    single = []
    for i in range(min(200, len(X))):
        t = time.perf_counter()
        clf.predict_proba(X.iloc[[i]])
        single.append((time.perf_counter() - t) * 1000)
    t = time.perf_counter()
    clf.predict_proba(X.iloc[:5000])
    batch = (time.perf_counter() - t) * 1000 / min(5000, len(X))
    return {
        "single_median_ms": float(np.median(single)),
        "single_p95_ms": float(np.percentile(single, 95)),
        "batch_per_event_ms": float(batch),
    }


def train_all() -> dict:
    """Run CV, select hyper-parameters, refit on full dev, save artefacts."""
    t_start = time.time()
    F_all = load_dev_features()
    F = F_all[F_all["class_id"].notna()].reset_index(drop=True)
    feats, const = select_columns(F)
    log.info(
        "dev labelled events=%d features baseline=%d contextual=%d",
        len(F),
        len(feats["baseline"]),
        len(feats["contextual"]),
    )
    cv = run_cv(F, feats)
    best = {}
    for m in feats:
        cand = [r for r in cv["search"] if r["model"] == m]
        best[m] = max(cand, key=lambda r: r["pooled_oof"]["macro_f1"])
    diag = circularity_diagnostics(F, cv["_folds"], best["contextual"]["params"])
    write_json(diag, PROGRESS_DIR / "circularity_diagnostics.json")

    # Out-of-fold predictions for the selected config of each model.
    rows = []
    folds = cv["_folds"]
    fold_of = np.zeros(len(F), dtype=int)
    for i, (_, va) in enumerate(folds):
        fold_of[va] = i
    y = F["class_id"].astype(int).to_numpy()
    for m in feats:
        p1 = cv["_oof"][(m, best[m]["config_id"])]
        rows.append(
            pd.DataFrame(
                {
                    "event_id": F["event_id"],
                    "capture_id": F["capture_id"],
                    "fold": fold_of,
                    "actual_class": [CLASS_NAMES[v] for v in y],
                    "predicted_class": [CLASS_NAMES[int(v)] for v in (p1 >= 0.5)],
                    "normal_probability": 1 - p1,
                    "command_injection_probability": p1,
                    "confidence": np.maximum(p1, 1 - p1),
                    "model_name": m,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                }
            )
        )
    oof_df = pd.concat(rows, ignore_index=True)
    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    oof_df.to_parquet(VALIDATION_DIR / "cv_validation_predictions.parquet", index=False)

    # Final refit on the full 80% (statistics refitted on the full 80%).
    stats = fit_profile(F)
    X_full = apply_profile(F, stats)
    manifest_models = {}
    for m, folder, fname in (
        ("baseline", "baseline", "baseline_random_forest.joblib"),
        ("contextual", "contextual", "contextual_rf.joblib"),
    ):
        cols = feats[m]
        t0 = time.time()
        clf = _rf(best[m]["params"]).fit(X_full[cols], y)
        secs = time.time() - t0
        out_dir = MODELS_DIR / folder
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, out_dir / fname)
        write_json(cols, out_dir / "feature_names.json")
        write_json(
            {
                g: [c for c in FEATURE_GROUPS[g] if c in cols]
                for g in (ISOLATED_GROUPS if m == "baseline" else CONTEXT_GROUPS)
            },
            out_dir / "feature_groups.json",
        )
        write_json(
            stats if m == "contextual" else {"note": "baseline uses current-event fields only; no fitted statistics"},
            out_dir / "feature_stats.json",
        )
        write_json(best[m]["params"], out_dir / "hyperparameters.json")
        write_json({"classes": LABEL_MAPPING}, out_dir / "label_mapping.json")
        lat = latency_ms(clf, X_full[cols])
        write_json(
            {
                "model": m,
                "model_version": MODEL_VERSION,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "trained_on": "data/splits/train.parquet (capture-grouped 80% development partition)",
                "test_partition_used": False,
                "training_rows": int(len(F)),
                "classes": [int(c) for c in clf.classes_],
                "n_features": len(cols),
                "dropped_constant_features": const,
                "random_state": RANDOM_STATE,
                "training_seconds": secs,
                "validation_inference_latency": lat,
                "limitation": BINARY_LIMITATION,
            },
            out_dir / "training_manifest.json",
        )
        write_json({fname: sha256_file(out_dir / fname)}, out_dir / "model_checksums.json")
        manifest_models[m] = {"path": f"models/{folder}/{fname}", "training_seconds": secs, "latency": lat}

    summary = {
        "label": "Preliminary cross-validation results - final test evaluation pending.",
        "cv_design": f"StratifiedGroupKFold(n_splits={N_FOLDS}, shuffle, seed {RANDOM_STATE}) grouped by capture_id; profile statistics, clip thresholds and imputation values refitted on fold-training rows in every fold",
        "folds": cv["folds"],
        "search": [{k: v for k, v in r.items()} for r in cv["search"]],
        "selected": {
            m: {
                "config_id": best[m]["config_id"],
                "params": best[m]["params"],
                "pooled_oof": best[m]["pooled_oof"],
                "fold_macro_f1": best[m]["fold_macro_f1"],
            }
            for m in best
        },
        "feature_counts": {m: len(c) for m, c in feats.items()},
        "models": manifest_models,
        "dropped_constant_features": const,
        "total_seconds": time.time() - t_start,
        "supported_classes": LABEL_MAPPING,
    }
    write_json(summary, VALIDATION_DIR.parent.parent / "results" / "validation" / "cv_metrics.json")
    write_json({"label": summary["label"], "selected": summary["selected"]}, PROGRESS_DIR / "preliminary_metrics.json")
    return summary


def verify_models() -> dict:
    """Load both saved models and check type, classes, features, forbidden cols."""
    from src.utils.config import FORBIDDEN_FEATURE_COLUMNS

    out = {}
    for m, folder, fname in (
        ("baseline", "baseline", "baseline_random_forest.joblib"),
        ("contextual", "contextual", "contextual_rf.joblib"),
    ):
        d = MODELS_DIR / folder
        clf = joblib.load(d / fname)
        names = read_json(d / "feature_names.json")
        checks = {
            "object_type": type(clf).__name__,
            "classes": [int(c) for c in clf.classes_],
            "feature_count_matches": int(clf.n_features_in_) == len(names),
            "forbidden_columns_present": sorted(set(names) & set(FORBIDDEN_FEATURE_COLUMNS)),
            "checksum_matches": sha256_file(d / fname) == read_json(d / "model_checksums.json")[fname],
            "test_partition_used": read_json(d / "training_manifest.json")["test_partition_used"],
        }
        out[m] = checks
    write_json(out, MODELS_DIR / "model_verification.json")
    return out
