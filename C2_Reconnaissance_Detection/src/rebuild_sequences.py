"""Rebuild a clean chronological window dataset from packet-level data (Rebuilt Variant).

Steps (nothing dropped silently - every exclusion is counted and saved):
  1. assign each packet to an independent capture group (config.capture_groups);
  2. exclude non-placeable files (config.excluded_files) and duplicate interface views;
  3. within each stream = (capture_group, session_id) sort chronologically (stable on row_index);
  4. recompute inter-packet time from nanosecond timestamps and compare with supplied time_delta;
  5. build windows (length L, stride S) that never cross stream boundaries;
  6. derive window labels with the verified supplied rule (any positive packet), keeping counts.

Outputs (data/rebuilt_sequences/):
  packets_rebuilt.csv   - kept packets in stream/chronological order with source row_index
  packet_exclusions.csv - row_index + reason for every excluded packet
  windows.csv           - one row per window (metadata, labels)
  window_index.npy      - (n_windows, L) int32 positions into packets_rebuilt.csv
  artifacts/rebuild_report.json
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, load_config, resolve, write_json  # noqa: E402
from io_data import load_packets  # noqa: E402

CONTENT = ["src_ip", "dst_ip", "unit_id", "func_code", "modbus_len", "register_start", "quantity", "packet_size"]


def assign_groups(p: pd.DataFrame, cfg: dict) -> pd.Series:
    f2g = {f: g for g, fs in cfg["capture_groups"].items() for f in fs}
    return p.file_source.map(f2g)


def duplicate_view_mask(p: pd.DataFrame, cfg: dict) -> tuple[np.ndarray, dict]:
    """Within multi-file groups keep one file per session_id (largest; tie -> name). Returns drop mask."""
    drop = np.zeros(len(p), dtype=bool)
    report = {}
    multi = [g for g, fs in cfg["capture_groups"].items() if len(fs) > 1]
    tol = int(cfg["duplicate_views"]["near_duplicate_tolerance_ns"])
    for g in multi:
        d = p[p.capture_group == g]
        for sid, ds in d.groupby("session_id"):
            counts = ds.file_source.value_counts()
            if len(counts) < 2:
                continue
            keep_file = sorted(counts.index, key=lambda f: (-counts[f], f))[0]
            dropped = ds[ds.file_source != keep_file]
            kept = ds[ds.file_source == keep_file]
            drop[dropped.index.to_numpy()] = True
            # verify dropped packets are near-duplicates of kept packets (same content, |dt|<=tol)
            kk = kept.assign(t=kept.ts_ns.astype("int64")).sort_values("t")
            dd = dropped.assign(t=dropped.ts_ns.astype("int64")).sort_values("t")
            mm = pd.merge_asof(dd, kk[["t"] + CONTENT + ["label"]].rename(columns={"label": "label_kept"}),
                               on="t", by=CONTENT, direction="nearest", tolerance=tol)
            report[f"{g}|{sid}"] = {
                "file_counts": counts.to_dict(), "kept_file": keep_file,
                "dropped_packets": int(len(dropped)),
                "dropped_with_near_duplicate_in_kept": int(mm.label_kept.notna().sum()),
                "dropped_positive_packets": int(dropped.label.sum()),
                "dropped_positive_with_positive_duplicate": int(((mm.label == 1) & (mm.label_kept == 1)).sum()),
                "label_disagreement_with_duplicate": int(((mm.label_kept.notna()) & (mm.label != mm.label_kept)).sum()),
            }
    return drop, report


def timing_audit(p: pd.DataFrame) -> dict:
    """Compare supplied time_delta with recomputations under several hypotheses."""
    out = {}
    t = p.ts_ns.astype("float64")
    sup = p.time_delta.to_numpy()
    hyps = {}
    d = p.groupby("session_id").ts_ns.diff().astype("float64") / 1e9
    hyps["supplied_order_by_session_raw"] = d
    hyps["supplied_order_by_session_clip0"] = d.clip(lower=0)
    d2 = p.groupby(["session_id", "file_source"]).ts_ns.diff().astype("float64") / 1e9
    hyps["supplied_order_by_session_file_clip0"] = d2.clip(lower=0)
    q = p.sort_values(["session_id", "ts_ns", "row_index"])
    d3 = (q.groupby("session_id").ts_ns.diff().astype("float64") / 1e9).reindex(p.index)
    hyps["chronological_by_session"] = d3
    for k, v in hyps.items():
        v = v.to_numpy()
        ok = ~np.isnan(v)
        out[k] = {"agree_within_1us": float(np.mean(np.abs(v[ok] - sup[ok]) <= 1e-6)),
                  "compared": int(ok.sum())}
    out["supplied_time_delta_zero_fraction"] = float(np.mean(sup == 0))
    out["supplied_time_delta_max_s"] = float(np.max(sup))
    out["units_inference"] = ("Supplied time_delta matches nanosecond-timestamp differences expressed in SECONDS "
                              "where they agree (e.g. 5e-06 == 5 microseconds between consecutive rows).")
    return out


def build_windows(r: pd.DataFrame, L: int, S: int) -> tuple[pd.DataFrame, np.ndarray]:
    idx_list, meta = [], []
    pos = np.arange(len(r))
    lab = r.label.to_numpy()
    c1 = r.is_fc5_len3.to_numpy()
    tns = r.ts_ns.to_numpy(dtype=np.int64)
    rid = r.row_index.to_numpy()
    for (g, sid), ix in r.groupby(["capture_group", "session_id"], sort=True).indices.items():
        ix = np.sort(ix)
        n = len(ix)
        for k, a in enumerate(range(0, n - L + 1, S)):
            w = ix[a:a + L]
            idx_list.append(pos[w])
            npos = int(lab[w].sum())
            meta.append((g, sid, f"{g}|{sid}", k, int(tns[w[0]]), int(tns[w[-1]]), int(rid[w[0]]), int(rid[w[-1]]),
                         npos, npos / L, int(npos > 0), int(c1[w].sum())))
    cols = ["capture_group", "session_id", "stream_id", "window_in_stream", "start_ns", "end_ns",
            "first_row_index", "last_row_index", "n_pos_packets", "pos_packet_fraction", "label",
            "n_fc5_len3_packets"]
    W = pd.DataFrame(meta, columns=cols)
    W.insert(0, "window_id", [f"w{i:06d}" for i in range(len(W))])
    W["window_start_utc"] = pd.to_datetime(W.start_ns, utc=True).astype(str)
    W["window_end_utc"] = pd.to_datetime(W.end_ns, utc=True).astype(str)
    return W, np.vstack(idx_list).astype(np.int32)


def rebuild(cfg: dict | None = None, packets: pd.DataFrame | None = None, write: bool = True):
    cfg = cfg or load_config()
    L, S = int(cfg["windowing"]["window_length"]), int(cfg["windowing"]["stride"])
    p = packets if packets is not None else load_packets()
    p = p.copy()
    p["capture_group"] = assign_groups(p, cfg)
    p["is_fc5_len3"] = p.func_code.eq(5) & p.modbus_len.eq(3)
    excl = pd.Series("", index=p.index)
    excl[p.file_source.isin(list(cfg.get("excluded_files", {}).keys()))] = "excluded_file"
    excl[(excl == "") & p.capture_group.isna()] = "file_not_in_any_capture_group"
    excl[(excl == "") & p.ts_ns.isna()] = "unparseable_timestamp"
    ok = excl == ""
    drop, dup_report = duplicate_view_mask(p[ok], cfg)
    dup_idx = p[ok].index[drop]
    excl[dup_idx] = "duplicate_interface_view"
    timing = timing_audit(p[p.ts_ns.notna()])

    r = p[excl == ""].copy()
    r["ts_ns"] = r.ts_ns.astype("int64")
    r = r.sort_values(["capture_group", "session_id", "ts_ns", "row_index"], kind="mergesort").reset_index(drop=True)
    r["dt_s"] = r.groupby(["capture_group", "session_id"]).ts_ns.diff() / 1e9  # first packet of stream -> NaN
    assert (r.dt_s.dropna() >= 0).all(), "chronological sort failed"
    W, I = build_windows(r, L, S)

    # stream-level statistics
    st = r.groupby(["capture_group", "session_id"]).agg(packets=("label", "size"), recon_packets=("label", "sum"))
    wst = W.groupby(["capture_group", "session_id"]).agg(windows=("label", "size"), recon_windows=("label", "sum"))
    st = st.join(wst, how="left").fillna(0).astype(int)
    grp = W.groupby("capture_group").agg(windows=("label", "size"), recon_windows=("label", "sum"),
                                         windows_with_fc5_len3=("n_fc5_len3_packets", lambda x: int((x > 0).sum())))
    pk = r.groupby("capture_group").agg(packets=("label", "size"), recon_packets=("label", "sum"),
                                        fc5_len3_packets=("is_fc5_len3", "sum"),
                                        start_ns=("ts_ns", "min"), end_ns=("ts_ns", "max"),
                                        n_streams=("session_id", "nunique"))
    grp = pk.join(grp)
    grp["start_utc"] = pd.to_datetime(grp.start_ns, utc=True).astype(str)
    grp["end_utc"] = pd.to_datetime(grp.end_ns, utc=True).astype(str)
    grp = grp.drop(columns=["start_ns", "end_ns"])
    supplied_vs_recomputed = r.dropna(subset=["dt_s"])
    report = {
        "window_length": L, "stride": S, "label_rule": cfg["windowing"]["label_rule"],
        "packets_input": len(p),
        "packets_kept": len(r),
        "exclusions": excl[excl != ""].value_counts().to_dict(),
        "duplicate_view_report": dup_report,
        "timing_audit": timing,
        "rebuilt_dt_vs_supplied_time_delta": {
            "agree_within_1us": float(np.mean(np.abs(supplied_vs_recomputed.dt_s - supplied_vs_recomputed.time_delta) <= 1e-6)),
            "median_abs_diff_s": float(np.median(np.abs(supplied_vs_recomputed.dt_s - supplied_vs_recomputed.time_delta))),
            "rebuilt_dt_quantiles_s": supplied_vs_recomputed.dt_s.quantile([0, .01, .25, .5, .75, .99, 1]).to_dict(),
        },
        "windows": len(W), "window_label_counts": W.label.value_counts().to_dict(),
        "windows_cross_stream_boundary": 0,
        "per_group": grp.reset_index().to_dict(orient="records"),
        "per_stream": st.reset_index().to_dict(orient="records"),
    }
    # verification: every window inside one stream and chronologically ordered
    gcode = r.capture_group.astype("category").cat.codes.to_numpy()
    scode = r.session_id.astype("category").cat.codes.to_numpy()
    assert (gcode[I] == gcode[I[:, :1]]).all() and (scode[I] == scode[I[:, :1]]).all(), "window crosses stream"
    assert (np.diff(r.ts_ns.to_numpy()[I], axis=1) >= 0).all(), "window not chronological"
    if write:
        out = resolve(cfg["paths"]["rebuilt_dir"])
        out.mkdir(parents=True, exist_ok=True)
        keep_cols = ["row_index", "timestamp", "ts_ns", "capture_group", "session_id", "file_source", "src_ip",
                     "dst_ip", "unit_id", "func_code", "modbus_len", "register_start", "quantity", "packet_size",
                     "time_delta", "dt_s", "label", "is_fc5_len3"]
        r[keep_cols].to_csv(out / "packets_rebuilt.csv", index=False)
        pd.DataFrame({"row_index": p.row_index[excl != ""], "reason": excl[excl != ""]}).to_csv(
            out / "packet_exclusions.csv", index=False)
        W.to_csv(out / "windows.csv", index=False)
        np.save(out / "window_index.npy", I)
        write_json(report, ARTIFACTS / "rebuild_report.json")
    return r, W, I, report


def main():
    r, W, I, rep = rebuild()
    print({k: rep[k] for k in ["packets_input", "packets_kept", "exclusions", "windows", "window_label_counts"]})
    print(pd.DataFrame(rep["per_group"]).to_string())
    print(rep["timing_audit"])
    print(rep["rebuilt_dt_vs_supplied_time_delta"])
    for k, v in rep["duplicate_view_report"].items():
        print(k, v)


if __name__ == "__main__":
    main()
