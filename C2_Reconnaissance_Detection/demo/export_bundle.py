"""Export the offline demo bundle from the frozen Component 2 outputs (run once, in the c2-recon-model image).

Writes C2_Reconnaissance_Detection/demo_bundle/:
  models/   frozen RF models (copied), LSTM weights as NumPy arrays (exact copy of model_L.pt tensors), thresholds
  runs/     prepared HELD-OUT test runs: <id>.csv = pipeline input (parsed requests, no labels),
            <id>.json = run info, ground truth, saved test predictions and saved B3 history features
  reports/  final reports, gates, collection status, aggregated validation evidence, CIC audit facts
  bundle_manifest.json  SHA-256 of every bundle file and of the sources it was copied from
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import torch

REPO = Path(__file__).resolve().parents[2]
TB = REPO / "component2_testbed"
FR = REPO / "component2_forensic_review"
DATA = TB / "data" / "final_v1"
OUT = REPO / "C2_Reconnaissance_Detection" / "demo_bundle"
MODELS = ["A", "B1", "B2", "B3", "L"]
RUNS = [  # held-out test runs only (never train/validation)
    ("final_v1-r086", "Reconnaissance: sequential scan"),
    ("final_v1-r049", "Reconnaissance: function-code probe"),
    ("final_v1-r020", "Reconnaissance: unit probe (unseen Site C)"),
    ("final_v1-r053", "Reconnaissance: sequential scan (unseen Site C)"),
    ("final_v1-r200", "Legitimate one-pass: configuration backup"),
    ("final_v1-r018", "Legitimate one-pass: HMI cold start"),
    ("final_v1-r095", "Revisiting normal: fixed polling"),
    ("final_v1-r026", "Revisiting normal: maintenance"),
]
INPUT_COLS = ["run_id", "adu_id", "frame_number", "ts_corr_ns", "src_ip", "src_port", "dst_ip", "dst_port", "tid",
              "unit", "wire_fc", "address", "quantity", "mbap_len", "frame_len", "adu_hex"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def j(p):
    return json.loads(Path(p).read_text())


def export_models():
    d = OUT / "models"
    d.mkdir(parents=True, exist_ok=True)
    src = DATA / "models"
    for m in ["A", "B1", "B2", "B3"]:
        shutil.copy2(src / f"model_{m}.joblib", d / f"model_{m}.joblib")
    ck = torch.load(src / "model_L.pt", weights_only=False)
    st = {k: v.numpy() for k, v in ck["state"].items()}
    np.savez(d / "model_L_weights.npz", w_ih=st["lstm.weight_ih_l0"], w_hh=st["lstm.weight_hh_l0"],
             b_ih=st["lstm.bias_ih_l0"], b_hh=st["lstm.bias_hh_l0"], head_w=st["head.weight"], head_b=st["head.bias"],
             mu=np.asarray(ck["mu"]), sd=np.asarray(ck["sd"]), hidden=np.asarray(ck["hidden"]))
    for f in ["thresholds.json", "selected.json"]:
        shutil.copy2(TB / "final/results" / f, d / f)
    return {f"model_{m}.joblib": sha(src / f"model_{m}.joblib") for m in ["A", "B1", "B2", "B3"]} | \
        {"model_L.pt": sha(src / "model_L.pt")}


def export_runs():
    d = OUT / "runs"
    d.mkdir(parents=True, exist_ok=True)
    man = {r["run_id"]: r for r in j(TB / "final/frozen/frozen_plan_manifest.json")["schedule"]}
    index = []
    for run_id, caption in RUNS:
        part = man[run_id]["partition"]
        assert part.startswith("test"), run_id
        q = pd.read_parquet(DATA / f"derived/{run_id}/requests_labeled.parquet")
        q = q.sort_values(["ts_corr_ns", "frame_number"]).reset_index(drop=True)
        q[INPUT_COLS].to_csv(d / f"{run_id}.csv", index=False)
        sc = pd.read_parquet(DATA / f"models/{part}_scores.parquet")
        meta = pd.read_parquet(DATA / f"model_inputs/{part}/meta.parquet")
        b3 = pd.read_parquet(DATA / f"model_inputs/{part}/b3.parquet")
        h_cols = [c for c in b3 if c.startswith("h_")]
        x = q[["adu_id"]].merge(sc, on="adu_id").merge(meta[["adu_id", "stratum", "full_context"]], on="adu_id") \
            .merge(b3, on="adu_id")
        assert len(x) == len(q)
        rm = j(DATA / f"runs/{run_id}/run_manifest.json")
        acc = j(DATA / f"derived/{run_id}/acceptance.json")
        tsk = j(DATA / f"derived/{run_id}/tshark_check.json")
        t0 = int(q.ts_corr_ns.min())
        rows = {
            "adu_id": q.adu_id.tolist(), "t": ((q.ts_corr_ns - t0) / 1e9).round(4).tolist(),
            "role": q.gt_role.tolist(), "phase": q.gt_phase.tolist(), "gt_scenario": q.gt_scenario_id.tolist(),
            "recon": q.gt_label_recon.astype(int).tolist(),
            "response_hex": q.response_hex.tolist(), "latency_us": q.response_latency_us.round(1).tolist(),
            "stratum": x.stratum.tolist(), "full_context": x.full_context.astype(bool).tolist(),
            "saved_scores": {m: x[m].tolist() for m in MODELS},  # full precision: RF scores tie at thresholds
            "saved_b3": {c: x[c].tolist() for c in h_cols},
        }
        info = {"run_id": run_id, "caption": caption, "partition": part, "site": rm["site_id"],
                "scenario": rm["scenario_id"], "group": man[run_id]["group"], "target_ip": rm["target"]["ip"],
                "hmi_ip": rm["clients"]["background_hmi"]["ip"], "actor_ip": rm["clients"]["actor"]["ip"],
                "requests": int(len(q)), "recon_requests": int(q.gt_label_recon.sum()),
                "pcap": {"file": f"component2_testbed/data/final_v1/runs/{run_id}/capture.pcap",
                         "sha256": rm["raw_files"]["capture.pcap"]["sha256"], "bytes": rm["raw_files"]["capture.pcap"]["bytes"]},
                "tshark_adus_checked": tsk["adus_checked"], "tshark_mismatches": tsk["mismatches"],
                "acceptance": acc["completion_state"], "clock_steps": acc["checks"]["clock_evidence"]["n_steps"]}
        (d / f"{run_id}.json").write_text(json.dumps({"info": info, "rows": rows}, separators=(",", ":")))
        index.append(info)
    (d / "index.json").write_text(json.dumps(index, indent=1))


def validation_evidence():
    status = j(TB / "final/collection_status.json")
    acc_files = sorted((DATA / "derived").glob("*/acceptance.json"))
    tot = {"runs_processed": 0, "adus_checked_vs_tshark": 0, "tshark_mismatches": 0, "ledger_wire_1to1_pass": 0,
           "no_cross_run_traffic_pass": 0, "accepted": 0}
    for f in acc_files:
        if f.parent.name.endswith("-retry1"):
            continue
        a = j(f)
        t = j(f.parent / "tshark_check.json")
        c = a["checks"]
        tot["runs_processed"] += 1
        tot["adus_checked_vs_tshark"] += t["adus_checked"]
        tot["tshark_mismatches"] += t["mismatches"]
        tot["ledger_wire_1to1_pass"] += int(c["every_wire_request_matched_to_ledger"]["pass"] and
                                            c["every_ledger_action_matched_to_wire"]["pass"])
        tot["no_cross_run_traffic_pass"] += int(c["no_cross_run_traffic"]["pass"])
        tot["accepted"] += int(a["completion_state"] == "accepted")
    leak = {}
    for part in ["train", "validation", "test_in_site", "test_out_of_site"]:
        meta = pd.read_parquet(DATA / f"model_inputs/{part}/meta.parquet")
        W = np.load(DATA / f"model_inputs/{part}/windows.npy")
        runs = meta.run_id.to_numpy()
        member = np.where(W >= 0, W, np.arange(len(W))[:, None])
        cross = (runs[member] != runs[:, None]).any(axis=1).sum()
        future = (member > np.arange(len(W))[:, None]).any(axis=1).sum()
        leak[part] = {"targets": int(len(W)), "windows_crossing_runs": int(cross), "windows_with_future_requests": int(future),
                      "last_member_is_target": bool((W[:, -1] == np.arange(len(W))).all())}
    return {"collection_status": status, "per_run_totals": tot, "context_integrity": leak}


def cic_facts():
    lab = j(FR / "evidence/final_label_summary.json")
    seq = j(FR / "legacy_sequence_audit.json")
    sf = j(FR / "split_feasibility.json")["raw_recon_request_evidence"]
    sc = pd.read_csv(FR / "shortcut_analysis.csv")
    rule = sc[(sc.corpus == "legacy") & (sc.rule_or_model == "modbus_len_eq_3")].set_index("level")
    return {"legacy_packet_rows": seq["packet_rows"], "legacy_windows": seq["sequence_windows"],
            "legacy_positive_rows": lab["all_original_positive_rows"], "positive_label_states": lab["label_state_counts"],
            "windows_with_backward_time": seq["windows_with_backward_transition"],
            "windows_crossing_source_file": seq["windows_cross_source_file"],
            "len3_rule_packet_F1": round(float(rule.loc["packet", "F1"]), 4),
            "len3_rule_window_F1": round(float(rule.loc["window", "F1"]), 4),
            "recovered_recon_candidates": sf["raw_source_verified_candidate_rows"],
            "recovered_supported": sf["label_state_counts"]["supported_contextual"],
            "recovered_ambiguous": sf["label_state_counts"]["ambiguous"],
            "source": "component2_forensic_review/ (FULL_FINDINGS_REPORT.md)"}


def export_reports():
    d = OUT / "reports"
    d.mkdir(parents=True, exist_ok=True)
    for f in ["validation_report.json", "test_in_site_report.json", "test_out_of_site_report.json",
              "collection_gates.json", "cv_selection.csv", "opened_test_in_site.json", "opened_test_out_of_site.json"]:
        shutil.copy2(TB / "final/results" / f, d / f)
    (d / "validation_evidence.json").write_text(json.dumps(validation_evidence(), indent=1))
    (d / "cic_audit_facts.json").write_text(json.dumps(cic_facts(), indent=1))
    pil = {}
    for v in ["v1", "v2", "v3"]:
        s = j(TB / f"data/pilot_{v}_20261025/analysis/pilot_summary.json")
        pil[v] = {"runs_total": s["runs_total"], "runs_accepted": s["runs_accepted"], "G1": s["gates"]["G1"]["pass"],
                  "G2": s["gates"]["G2"]["pass"], "G3": s["gates"]["G3"]["pass"]}
    (d / "pilots.json").write_text(json.dumps(pil, indent=1))


if __name__ == "__main__":
    if OUT.exists():
        shutil.rmtree(OUT)
    src_hashes = export_models()
    export_runs()
    export_reports()
    files = {str(p.relative_to(OUT)).replace("\\", "/"): sha(p) for p in sorted(OUT.rglob("*")) if p.is_file()}
    (OUT / "bundle_manifest.json").write_text(json.dumps(
        {"collection": "final_v1", "source_model_sha256": src_hashes, "files": files}, indent=1))
    print(f"bundle: {len(files)} files, {sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file()) / 1e6:.1f} MB")
