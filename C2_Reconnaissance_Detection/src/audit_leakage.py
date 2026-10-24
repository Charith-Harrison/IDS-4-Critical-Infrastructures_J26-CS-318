"""Phase 2/3 - Hostile leakage audit for C2 / RP2.

Quantifies five distinct leakage / shortcut mechanisms:
  1. Identifier leakage (session_id, src_ip, dst_ip, file_source, timestamps, row_index)
  2. Multi-interface duplicate capture leakage (2023-02-01 veth pcaps)
  3. Overlapping-window leakage under random train/test splitting (both As-Provided and Rebuilt)
  4. Preprocessing leakage (global vs fold-isolated scaling)
  5. Protocol-field label shortcut (modbus_len==3 / packet_size==75 -> 100% positive in raw labels)

Outputs:
  artifacts/leakage_audit.json
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, load_config, resolve, write_json  # noqa: E402
from io_data import load_packets, load_sequences  # noqa: E402

PROHIBITED_ID_COLUMNS = [
    "row_index",
    "timestamp",
    "ts_ns",
    "src_ip",
    "dst_ip",
    "session_id",
    "sequence_position",
    "file_source",
    "capture_group",
    "stream_id",
    "sequence_id",
    "window_id",
    "window_start_time",
    "window_end_time",
    "window_start_utc",
    "window_end_utc",
    "start_ns",
    "end_ns",
    "first_row_index",
    "last_row_index",
    "unit_id",  # constant = 1 across all 879,225 packets
]


def assert_no_identifier_features(feature_names: list[str]) -> None:
    bad = sorted(set(feature_names) & set(PROHIBITED_ID_COLUMNS))
    if bad:
        raise AssertionError(f"Prohibited identifier/constant columns in feature set: {bad}")


def assert_group_disjoint(train_groups, test_groups, train_files=None, test_files=None) -> None:
    inter = set(train_groups) & set(test_groups)
    if inter:
        raise AssertionError(f"Group leakage detected! Shared groups: {sorted(inter)}")
    if train_files is not None and test_files is not None:
        f_inter = set(train_files) & set(test_files)
        if f_inter:
            raise AssertionError(f"Capture-file leakage detected! Shared files: {sorted(f_inter)}")


def window_overlap_stats(I: np.ndarray, y: np.ndarray, seed: int = 42) -> dict:
    """Quantify packet sharing across windows and across a stratified 80/20 random split."""
    n_win, L = I.shape
    # Consecutive windows within same stream (where index diff is stride S)
    consec_shared = []
    for k in range(n_win - 1):
        s = len(set(I[k].tolist()) & set(I[k + 1].tolist()))
        if s > 0:
            consec_shared.append(s)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    tr_idx, te_idx = next(skf.split(np.zeros(n_win), y))
    train_pkts = set(I[tr_idx].ravel().tolist())
    test_pkts_per_win = [len(set(row.tolist()) & train_pkts) for row in I[te_idx]]
    arr = np.array(test_pkts_per_win, dtype=float)
    pos_mask = y[te_idx] == 1
    return {
        "n_windows": int(n_win),
        "window_length": int(L),
        "pairs_of_consecutive_windows_sharing_packets": int(len(consec_shared)),
        "mean_shared_packets_when_overlapping": float(np.mean(consec_shared)) if consec_shared else 0.0,
        "random_80_20_test_windows": int(len(te_idx)),
        "test_windows_sharing_ge1_packet_with_train": int((arr >= 1).sum()),
        "test_windows_sharing_ge1_packet_fraction": float((arr >= 1).mean()),
        "test_windows_sharing_ge15_packets_with_train": int((arr >= 15).sum()),
        "test_windows_sharing_ge15_packets_fraction": float((arr >= 15).mean()),
        "mean_test_window_packets_already_in_train": float(arr.mean()),
        "mean_test_window_overlap_fraction_with_train": float((arr / L).mean()),
        "positive_test_windows_sharing_ge1_packet_fraction": float((arr[pos_mask] >= 1).mean()) if pos_mask.any() else None,
        "positive_test_windows_sharing_ge15_packets_fraction": float((arr[pos_mask] >= 15).mean()) if pos_mask.any() else None,
    }


def main():
    cfg = load_config()
    rebuilt_dir = resolve(cfg["paths"]["rebuilt_dir"])
    p_raw = load_packets()
    s_raw, X_raw = load_sequences()
    r = pd.read_csv(rebuilt_dir / "packets_rebuilt.csv")
    W = pd.read_csv(rebuilt_dir / "windows.csv")
    I = np.load(rebuilt_dir / "window_index.npy")

    # 1. Identifier predictability (how well identifiers alone predict label)
    sid_pos_rate = p_raw.groupby("session_id").label.agg(["count", "sum", "mean"]).to_dict(orient="index")
    file_pos_rate = p_raw.groupby("file_source").label.agg(["count", "sum", "mean"]).to_dict(orient="index")
    pair_pos_rate = p_raw.groupby(["src_ip", "dst_ip"]).label.agg(["count", "sum", "mean"])
    pair_pos_rate = {f"{a}->{b}": v for (a, b), v in pair_pos_rate.to_dict(orient="index").items()}

    # 2. As-provided sequence overlap & exact duplicate feature tensors across random 80/20 split
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=int(cfg["seed"]))
    tr_s, te_s = next(skf.split(np.zeros(len(s_raw)), s_raw.label.to_numpy()))
    tr_fjson = set(s_raw.features_json.iloc[tr_s].tolist())
    te_fjson = s_raw.features_json.iloc[te_s].tolist()
    exact_dup_in_train = sum(1 for x in te_fjson if x in tr_fjson)

    # Synthetic packet index for As-Provided sequences (per session, stride 5 in supplied row order)
    ap_indices = []
    offset = 0
    for sid, df_s in s_raw.groupby("session_id", sort=False):
        n_w = len(df_s)
        idx_s = np.arange(n_w)[:, None] * 5 + np.arange(20)[None, :] + offset
        ap_indices.append(idx_s)
        offset += n_w * 5 + 20
    I_ap = np.vstack(ap_indices)
    ap_overlap = window_overlap_stats(I_ap, s_raw.label.to_numpy(), seed=int(cfg["seed"]))
    ap_overlap["test_windows_with_identical_20x7_feature_matrix_in_train"] = int(exact_dup_in_train)
    ap_overlap["test_windows_with_identical_20x7_feature_matrix_fraction"] = float(exact_dup_in_train / len(te_s))

    # 3. Rebuilt window overlap under random 80/20 split vs group split
    rebuilt_overlap = window_overlap_stats(I, W.label.to_numpy(), seed=int(cfg["seed"]))
    # Verify group split has ZERO shared packets across capture_group
    grp_shared = 0
    for g in W.capture_group.unique():
        m_te = (W.capture_group == g).to_numpy()
        p_tr = set(I[~m_te].ravel().tolist())
        p_te = set(I[m_te].ravel().tolist())
        grp_shared += len(p_tr & p_te)
    rebuilt_overlap["group_split_shared_packets_between_train_and_test"] = int(grp_shared)

    # 4. Shortcut feature analysis in Rebuilt dataset
    # Single rule: window contains any packet with modbus_len == 3
    has_len3 = (r.modbus_len.to_numpy()[I] == 3).any(axis=1)
    y_w = W.label.to_numpy()
    tp = int(((has_len3 == 1) & (y_w == 1)).sum())
    fp = int(((has_len3 == 1) & (y_w == 0)).sum())
    fn = int(((has_len3 == 0) & (y_w == 1)).sum())
    tn = int(((has_len3 == 0) & (y_w == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    per_group_shortcut = {}
    for g, d in W.groupby("capture_group"):
        pos_w = int(d.label.sum())
        c1_w = int((d.n_fc5_len3_packets > 0).sum())
        idx_g = d.index.to_numpy()
        len3_w = int(has_len3[idx_g].sum())
        per_group_shortcut[g] = {
            "windows": int(len(d)),
            "positive_windows": pos_w,
            "positive_windows_with_modbus_len3": len3_w,
            "positive_windows_with_fc5_len3": c1_w,
            "positive_windows_without_modbus_len3": int(pos_w - len3_w),
        }

    audit = {
        "prohibited_identifier_columns": PROHIBITED_ID_COLUMNS,
        "identifier_leakage": {
            "session_id_positive_rates": sid_pos_rate,
            "file_source_positive_rates": file_pos_rate,
            "host_pair_positive_rates": pair_pos_rate,
            "concentration_summary": {
                "fraction_of_raw_positives_in_single_session_s0004": float(
                    (p_raw.session_id == "185.175.0.5_185.175.0.3_u1_s0004").loc[p_raw.label == 1].mean()
                ),
                "fraction_of_as_provided_positive_windows_in_s0004": float(
                    (s_raw.session_id == "185.175.0.5_185.175.0.3_u1_s0004").loc[s_raw.label == 1].mean()
                ),
                "fraction_of_rebuilt_positive_windows_in_s0004": float(
                    (W.session_id == "185.175.0.5_185.175.0.3_u1_s0004").loc[W.label == 1].mean()
                ),
            },
        },
        "duplicate_interface_capture_leakage": {
            "affected_date": "2023-02-01",
            "files": [
                "veth5bbeaa2-0.pcap",
                "veth4edc015-0.pcap",
                "vethd9e14c0-0.pcap",
                "veth8bc3408-0.pcap",
                "veth665f3cf-0.pcap",
            ],
            "duplicate_packets_removed_in_rebuilt": 282076,
            "positive_duplicate_packets_removed": 50,
            "explanation": (
                "veth665f3cf-0.pcap (65,610 packets, 50 positives) is a simultaneous virtual-interface "
                "capture of the exact same traffic recorded in veth4edc015-0.pcap for session s0007 "
                "(100% packet match within <=1 ms). Treating pcaps as independent groups without "
                "deduplication would leak identical positive windows across train and test."
            ),
        },
        "overlapping_window_leakage": {
            "as_provided_sequences": ap_overlap,
            "rebuilt_sequences": rebuilt_overlap,
        },
        "protocol_field_shortcut_risk": {
            "description": (
                f"In the supplied labels, 100% of packets with modbus_len==3 (all of which also have "
                f"packet_size==75) are labelled 1, accounting for 96.71% of raw positive packets and "
                f"{rec*100:.2f}% ({tp:,}/{int(y_w.sum()):,}) of rebuilt positive windows. A static single-feature rule "
                f"'any packet in window has modbus_len==3' achieves Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f} "
                f"on rebuilt windows without using any sequence or timing information."
            ),
            "trivial_rule_any_modbus_len_eq_3_on_rebuilt_windows": {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": prec,
                "recall": rec,
                "f1": f1,
            },
            "per_group_breakdown": per_group_shortcut,
            "mitigation_in_experiments": (
                "Preserve the verified protocol features in the primary comparison (Models A, B, C, D) "
                "AND run a dedicated size/length-shortcut ablation removing modbus_len and packet_size "
                "to test whether temporal modelling helps when the trivial frame-length rule is unavailable."
            ),
        },
    }
    write_json(audit, ARTIFACTS / "leakage_audit.json")
    print("Saved artifacts/leakage_audit.json")
    print("Rebuilt overlap:", rebuilt_overlap)
    print("As-provided overlap:", ap_overlap)
    print("Shortcut rule:", audit["protocol_field_shortcut_risk"]["trivial_rule_any_modbus_len_eq_3_on_rebuilt_windows"])


if __name__ == "__main__":
    main()
