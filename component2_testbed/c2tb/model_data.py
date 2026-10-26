"""Model inputs for the frozen modelling plan (MODELLING_PLAN.md section 2).

Test partitions are sealed: a run's partition is read from its frozen plan (hash-checked against the frozen
manifest) and test runs are refused unless `--open-test <partition>` is given.

Per partition this writes data/final_v1/model_inputs/<partition>/:
  steps.npy    (N, 19) float32 per-request step features, computed causally per stream
  windows.npy  (N, 20) int32 row indices of the 20-request context ending at each row (-1 = padding)
  meta.parquet one row per request: ids, stratum, label, full-context flag, training-population flag
  b3.parquet   pre-specified pilot history statistics (diagnostics.build_contexts)
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from c2tb.diagnostics import build_contexts

SEALED = {"test_in_site", "test_out_of_site"}
L = 20
UNITS = [1, 2, 3, 5, 7]
STEP_FEATURES = ([f"fc_{f}" for f in (1, 2, 3, 4)] + [f"unit_{u}" for u in UNITS] +
                 ["address", "log2_quantity", "mbap_len", "frame_len", "same_table", "addr_step_q",
                  "contiguous_ascending", "first_seen", "log10_iat", "mask"])
REVISITING, ONE_PASS = ("N1", "N2", "N3", "N4"), ("N5", "N6", "N7", "N8")


def partition_runs(tb: Path, coll: str, partition: str, open_test: str | None):
    if partition in SEALED and open_test != partition:
        raise PermissionError(f"{partition} is sealed (MODELLING_PLAN.md section 1); pass --open-test {partition}")
    man = json.loads((tb / "final/frozen/frozen_plan_manifest.json").read_text())
    out = []
    for r in man["schedule"]:
        if r["partition"] != partition:
            continue
        plan_path = tb / "data" / coll / "runs" / r["run_id"] / "plan.json"
        if hashlib.sha256(plan_path.read_bytes()).hexdigest() != r["frozen_plan"]["sha256"]:
            raise RuntimeError(f"plan hash mismatch for {r['run_id']}")
        acc = json.loads((tb / "data" / coll / "derived" / r["run_id"] / "acceptance.json").read_text())
        if acc["completion_state"] == "accepted":
            out.append(r)
    return out


def stratum(df):
    sc = df.run_scenario_id.str[:2]
    return np.select(
        [df.gt_label_recon == 1, df.gt_phase == "background_hmi",
         (df.gt_phase == "normal_workload") & sc.isin(REVISITING), (df.gt_phase == "normal_workload") & sc.isin(ONE_PASS)],
        ["recon", "background", "revisiting_normal", "one_pass_normal"], default="legitimate_lead_in")


def run_frame(tb, coll, r):
    q = pd.read_parquet(tb / "data" / coll / "derived" / r["run_id"] / "requests_labeled.parquet")
    q["site_id"], q["run_scenario_id"], q["partition"] = r["site_id"], r["scenario_id"], r["partition"]
    return q


def step_features(df):
    """df sorted by (stream, ts_corr_ns, frame_number); returns (N,19) features and segment ids."""
    df = df.copy()
    df["stream"] = df.run_id + "|" + df.src_ip + "->" + df.dst_ip
    t = df.ts_corr_ns.to_numpy()
    new_stream = df.stream.ne(df.stream.shift()).to_numpy()
    gap = np.r_[np.inf, np.diff(t) / 1e9]
    seg = np.cumsum(new_stream | (gap > 60.0))
    first = ~pd.Series(list(zip(seg, df.unit, df.wire_fc, df.address, df.quantity))).duplicated().to_numpy()
    seg_start = np.r_[True, seg[1:] != seg[:-1]]
    prev_same = ~seg_start & (df.unit.to_numpy() == np.r_[-1, df.unit.to_numpy()[:-1]]) & \
                (df.wire_fc.to_numpy() == np.r_[-1, df.wire_fc.to_numpy()[:-1]])
    addr = df.address.to_numpy().astype(float)
    qty = df.quantity.to_numpy().astype(float)
    prev_addr, prev_q = np.r_[0, addr[:-1]], np.r_[1, qty[:-1]]
    step = np.where(prev_same, (addr - prev_addr) / np.maximum(prev_q, 1), 0.0)
    iat = np.where(seg_start, 0.0, np.clip(np.log10(np.maximum(gap, 1e-9)), -4, 2))
    X = np.column_stack(
        [(df.wire_fc == f).to_numpy() for f in (1, 2, 3, 4)] + [(df.unit == u).to_numpy() for u in UNITS] +
        [addr, np.log2(qty), df.mbap_len.to_numpy(), df.frame_len.to_numpy(), prev_same, step,
         prev_same & (addr - prev_addr == prev_q), first, iat, np.ones(len(df))]).astype(np.float32)
    return X, seg


def windows(seg):
    n = len(seg)
    pos = np.arange(n)
    seg_first = pd.Series(pos).groupby(seg).transform("min").to_numpy()
    W = np.full((n, L), -1, np.int32)
    for k in range(L):
        idx = pos - (L - 1 - k)
        W[:, k] = np.where(idx >= seg_first, idx, -1)
    return W


def build(tb: Path, coll: str, partition: str, open_test: str | None, cfg: dict):
    runs = partition_runs(tb, coll, partition, open_test)
    df = pd.concat([run_frame(tb, coll, r) for r in runs], ignore_index=True)
    df = df.sort_values(["run_id", "src_ip", "dst_ip", "ts_corr_ns", "frame_number"]).reset_index(drop=True)
    X, seg = step_features(df)
    W = windows(seg)
    rng = np.random.default_rng(cfg["background_sample_seed"])
    st = stratum(df)
    in_train_pop = (st != "background") | (rng.random(len(df)) < cfg["background_train_fraction"])
    meta = df[["adu_id", "run_id", "site_id", "run_scenario_id", "partition", "gt_phase", "gt_scenario_id",
               "gt_label_recon", "clock_ambiguous"]].copy()
    meta["stratum"] = st
    meta["full_context"] = (W >= 0).all(axis=1)
    meta["train_population"] = in_train_pop
    parts = []
    for rid, g in df.groupby("run_id", sort=False):  # frozen pilot statistics, per run to bound memory
        h, _ = build_contexts(g.reset_index(drop=True))
        parts.append(h[["adu_id"] + [c for c in h if c.startswith("h_")]])
    b3 = meta[["adu_id"]].merge(pd.concat(parts), on="adu_id", how="left")
    out = tb / "data" / coll / "model_inputs" / partition
    out.mkdir(parents=True, exist_ok=True)
    np.save(out / "steps.npy", X)
    np.save(out / "windows.npy", W)
    meta.to_parquet(out / "meta.parquet", index=False)
    b3.to_parquet(out / "b3.parquet", index=False)
    summary = {"partition": partition, "runs": len(runs), "requests": int(len(df)),
               "by_stratum": meta.stratum.value_counts().to_dict(),
               "full_context_by_stratum": meta[meta.full_context].stratum.value_counts().to_dict(),
               "train_population": int(in_train_pop.sum()), "step_features": STEP_FEATURES,
               "b3_missing": int(b3.isna().any(axis=1).sum())}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--partition", required=True)
    ap.add_argument("--open-test", default=None)
    a = ap.parse_args()
    tb = Path(__file__).resolve().parents[1]
    cfg = json.loads((tb / "configs/models_v1.json").read_text())
    print(json.dumps(build(tb, cfg["collection"], a.partition, a.open_test, cfg), indent=1))
