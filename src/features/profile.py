"""Training-derived (fitted) statistics and the features that use them.

fit_profile() must only ever see FOLD-TRAINING (or full development) rows.
apply_profile() then adds ACCESS / VALUE-range features and applies clipping
and imputation using the stored statistics. The same JSON dict is saved as
feature_stats.json and reused by inference.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Continuous columns that get fitted clip thresholds (99.9th percentile).
CLIP_COLUMNS = [
    "iat",
    "iat_mean_prev_k",
    "iat_min_prev_k",
    "time_since_last_write",
    "time_since_last_read",
    "response_delay",
    "value_delta",
    "value_rate",
    "events_last_1s",
    "events_last_10s",
    "writes_last_1s",
]
# Columns where NaN means "no earlier event": filled with the fitted clip max.
FILL_COLUMNS = [
    "iat",
    "iat_mean_prev_k",
    "iat_min_prev_k",
    "time_since_last_write",
    "time_since_last_read",
]


def _combo(fc: pd.Series, ref: pd.Series) -> pd.Series:
    """String key 'function:register' used by the access profile."""
    return fc.astype(int).astype(str) + ":" + ref.astype(int).astype(str)


def fit_profile(train: pd.DataFrame) -> dict:
    """Learn the normal-access profile, value ranges, clips and fills.

    *train* must contain stat-free features plus class_id; only rows with
    class_id == 0 contribute to the normal-access profile.
    """
    normal = train[train["class_id"] == 0]
    combos = _combo(normal["func_code"], normal["ref_num"])
    counts = combos.value_counts().to_dict()
    nw = normal[normal["is_write"] == 1]
    ranges = {}
    for key, g in nw.groupby(_combo(nw["func_code"], nw["ref_num"])):
        ranges[key] = [float(g["write_value"].min()), float(g["write_value"].max())]
    clips = {}
    for col in CLIP_COLUMNS:
        s = train[col]
        s = s[s >= 0] if col != "iat" else s.dropna()
        clips[col] = float(s.quantile(0.999)) if len(s) else 0.0
    iat_n = normal["iat"].dropna()
    return {
        "normal_access_counts": {k: int(v) for k, v in counts.items()},
        "normal_write_value_ranges": ranges,
        "clip_thresholds": clips,
        "fill_values": {c: clips[c] for c in FILL_COLUMNS},
        "iat_normal_p05": float(iat_n.quantile(0.05)) if len(iat_n) else 0.0,
        "fitted_on_rows": int(len(train)),
        "fitted_on_normal_rows": int(len(normal)),
    }


def apply_profile(feats: pd.DataFrame, stats: dict) -> pd.DataFrame:
    """Add fitted features and apply imputation/clipping with stored stats."""
    out = feats.copy()
    key = _combo(out["func_code"], out["ref_num"])
    counts = key.map(stats["normal_access_counts"])
    out["access_combo_unseen"] = counts.isna().astype(int)
    out["access_combo_normal_count_log"] = np.log1p(counts.fillna(0))
    out["access_write_unseen"] = ((out["is_write"] == 1) & counts.isna()).astype(int)
    rng = key.map(stats["normal_write_value_ranges"])
    lo = rng.map(lambda r: r[0] if isinstance(r, list) else np.nan)
    hi = rng.map(lambda r: r[1] if isinstance(r, list) else np.nan)
    known = lo.notna() & (out["is_write"] == 1)
    outside = ((out["write_value"] < lo) | (out["write_value"] > hi)).astype(int)
    out["value_outside_normal_range"] = np.where(known, outside, -1)
    for col, fill in stats["fill_values"].items():
        out[col] = out[col].fillna(fill)
    for col, cap in stats["clip_thresholds"].items():
        out[col] = out[col].clip(upper=cap)
    return out
