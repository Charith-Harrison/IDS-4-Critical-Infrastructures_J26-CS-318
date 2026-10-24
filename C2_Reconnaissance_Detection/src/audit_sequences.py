"""Audit the As-Provided Sequence Variant (recon_sequences_ALL) against the packet file.

Determines programmatically (not from filenames/memory):
  * which packet columns the 7 per-timestep features correspond to, and their order;
  * the stride and windowing unit (session_id, supplied row order);
  * the window label rule;
  * window start/end timestamp consistency and chronology.
Output: artifacts/sequence_audit.json
"""
from __future__ import annotations

import sys
from itertools import permutations
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, write_json  # noqa: E402
from io_data import load_packets, load_sequences  # noqa: E402

CANDIDATE_COLS = ["unit_id", "func_code", "modbus_len", "register_start", "quantity", "packet_size",
                  "time_delta", "sequence_position", "label"]


def main():
    p = load_packets()
    s, X = load_sequences()
    L = int(s.window_length.iloc[0])
    out = {"n_sequences": len(s), "tensor_shape": list(X.shape)}

    # 1) feature identification on the first window of the first session: which packet column
    #    matches each feature position across ALL windows (checked after stride is known).
    sess0 = s.session_id.iloc[0]
    P0 = p[p.session_id == sess0]
    first = X[0]
    col_match = {}
    for j in range(X.shape[2]):
        col_match[j] = [c for c in CANDIDATE_COLS
                        if np.allclose(P0[c].to_numpy(dtype=float)[:L], first[:, j], atol=1e-9)]
    out["feature_position_candidates_first_window"] = col_match

    # 2) stride: per session, k-th window vs packets [k*stride : k*stride+L] in supplied row order
    feat_cols = ["unit_id", "func_code", "modbus_len", "register_start", "quantity", "packet_size", "time_delta"]
    stride_hits = {}
    for stride in range(1, L + 1):
        ok = 0
        tot = 0
        for sid, idx in list(s.groupby("session_id").indices.items())[:3]:
            P = p.loc[p.session_id == sid, feat_cols].to_numpy(dtype=float)
            for k, i in enumerate(idx[:50]):
                a = k * stride
                tot += 1
                if a + L <= len(P) and np.allclose(P[a:a + L], X[i], atol=1e-9):
                    ok += 1
        stride_hits[stride] = ok / tot
    stride = max(stride_hits, key=stride_hits.get)
    out["stride_match_rate_sample"] = stride_hits
    out["inferred_stride"] = stride

    # 3) full verification with inferred stride, feature order, label rule, timestamps
    n_feat_match = 0
    rule_hits = {"any_positive": 0, "last_packet": 0, "majority": 0, "first_packet": 0}
    ts_start_match = ts_end_match = 0
    pos_counts = np.zeros(len(s), dtype=int)
    windows_per_session = {}
    chron_violations = 0
    for sid, idx in s.groupby("session_id").indices.items():
        Pd = p[p.session_id == sid]
        P = Pd[feat_cols].to_numpy(dtype=float)
        lab = Pd.label.to_numpy()
        ts = Pd.timestamp.to_numpy()
        tns = Pd.ts_ns.to_numpy(dtype="float64")
        n_expected = (len(P) - L) // stride + 1
        windows_per_session[sid] = {"packets": len(P), "windows": len(idx), "expected_full_windows": n_expected,
                                    "dropped_tail_packets": len(P) - ((n_expected - 1) * stride + L)}
        for k, i in enumerate(idx):
            a = k * stride
            w = slice(a, a + L)
            if np.allclose(P[w], X[i], atol=1e-9):
                n_feat_match += 1
            lw = lab[w]
            pos_counts[i] = lw.sum()
            y = s.label.iat[i]
            rule_hits["any_positive"] += int(y == int(lw.max()))
            rule_hits["last_packet"] += int(y == int(lw[-1]))
            rule_hits["first_packet"] += int(y == int(lw[0]))
            rule_hits["majority"] += int(y == int(lw.mean() > 0.5))
            ts_start_match += int(s.window_start_time.iat[i] == ts[a])
            ts_end_match += int(s.window_end_time.iat[i] == ts[a + L - 1])
            chron_violations += int((np.diff(tns[w]) < 0).any())
    n = len(s)
    out.update({
        "feature_order_verified": feat_cols if n_feat_match == n else None,
        "windows_matching_packet_rows_with_inferred_stride": n_feat_match,
        "label_rule_agreement": {k: v / n for k, v in rule_hits.items()},
        "window_start_time_equals_first_packet_timestamp": ts_start_match / n,
        "window_end_time_equals_last_packet_timestamp": ts_end_match / n,
        "windows_with_any_backward_time_step": chron_violations,
        "windows_with_start_after_end": int((s.start_ns > s.end_ns).sum()),
        "windows_spanning_multiple_file_sources": None,
        "positive_packets_per_positive_window": pd.Series(pos_counts[s.label.to_numpy() == 1]).describe().to_dict(),
        "windows_per_session": windows_per_session,
        "overlap_packets_between_consecutive_windows": L - stride,
        "overlap_fraction": (L - stride) / L,
    })
    # windows spanning multiple capture files (supplied order)
    multi = 0
    span_days = []
    for sid, idx in s.groupby("session_id").indices.items():
        Pd = p[p.session_id == sid]
        fs = Pd.file_source.to_numpy()
        tns = Pd.ts_ns.to_numpy(dtype="float64")
        for k, i in enumerate(idx):
            a = k * stride
            multi += int(len(set(fs[a:a + L])) > 1)
            span_days.append((np.nanmax(tns[a:a + L]) - np.nanmin(tns[a:a + L])) / 86400e9)
    out["windows_spanning_multiple_file_sources"] = multi
    out["window_time_span_days"] = pd.Series(span_days).describe().to_dict()
    out["windows_spanning_more_than_1_hour"] = int((np.array(span_days) > 1 / 24).sum())
    write_json(out, ARTIFACTS / "sequence_audit.json")
    for k, v in out.items():
        if k != "windows_per_session":
            print(k, ":", v)


if __name__ == "__main__":
    main()
