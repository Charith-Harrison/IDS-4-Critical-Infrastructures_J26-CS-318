"""Compare the same frozen plans collected serially vs with 2 parallel workers (disposable benchmark)."""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

tb = Path("/repo/component2_testbed")
res = {"runs": {}, "criteria": {}}
for mode in ("bench_serial", "bench_parallel"):
    for d in sorted((tb / "data" / mode / "derived").iterdir()):
        acc = json.loads((d / "acceptance.json").read_text())
        q = pd.read_parquet(d / "requests_labeled.parquet")
        q = q.sort_values(["src_ip", "ts_corr_ns"])
        iat = q.groupby("src_ip").ts_corr_ns.diff().dropna() / 1e6
        sched_iat = q.groupby("src_ip").ledger_scheduled_ns.diff().dropna() / 1e6
        res["runs"][f"{mode}/{d.name}"] = {
            "state": acc["completion_state"], "failures": acc["failure_reason"],
            "drops_ok": acc["checks"]["capture_zero_drops"]["pass"],
            "no_cross_run_traffic": acc["checks"]["no_cross_run_traffic"]["pass"],
            "ledger_1to1": acc["checks"]["every_wire_request_matched_to_ledger"]["pass"]
                           and acc["checks"]["every_ledger_action_matched_to_wire"]["pass"],
            "clock_ok": acc["checks"]["capture_after_send_same_clock_corrected"]["pass"],
            "clock_steps": acc["checks"]["clock_evidence"]["n_steps"],
            "clock_ambiguous_fraction": acc["checks"]["clock_evidence"]["ambiguous_fraction"],
            "requests": int(len(q)),
            "send_minus_schedule_ms_p50_p99_max": [round(float(x), 3) for x in
                ((q.ledger_send_ns - q.ledger_scheduled_ns) / 1e6).quantile([.5, .99, 1.0])],
            "response_latency_us_p50_p99": [round(float(x), 1) for x in q.response_latency_us.astype(float).quantile([.5, .99])],
            "capture_minus_send_us_p50_p99": [round(float(x), 1) for x in
                ((q.ts_corr_ns - q.ledger_send_corr_ns).astype(float) / 1000).quantile([.5, .99])],
            "iat_minus_scheduled_iat_ms_max_abs": round(float((iat.values - sched_iat.values).__abs__().max()), 3),
        }
stats = pd.read_csv(tb / "final/bench/parallel_docker_stats.csv", header=None, names=["t", "name", "cpu", "mem"])
stats["cpu"] = stats.cpu.str.rstrip("%").astype(float)
stats["mem_mib"] = stats.mem.str.split("/").str[0].str.strip().map(
    lambda s: float(s[:-3]) * (1024 if s.endswith("GiB") else 1) if s.endswith("iB") else float(s[:-1]) / 1024)
per_t = stats.groupby("t").agg(cpu=("cpu", "sum"), mem=("mem_mib", "sum"))
res["resources_parallel"] = {"samples": int(len(per_t)), "total_container_cpu_percent_p50_max":
                             [round(float(per_t.cpu.median()), 1), round(float(per_t.cpu.max()), 1)],
                             "total_container_mem_mib_max": round(float(per_t.mem.max()), 1),
                             "host_cpus": 20, "host_mem_gib": 15.4,
                             "note": "docker stats CPU% is per-core (100% = one core)"}
r = res["runs"]
pairs = [(k.split("/")[1].split("-r")[1], k) for k in r]
s_ = {k.split("-r")[1]: v for k, v in r.items() if k.startswith("bench_serial")}
p_ = {k.split("-r")[1]: v for k, v in r.items() if k.startswith("bench_parallel")}
res["criteria"] = {
    "zero_capture_drops": all(v["drops_ok"] for v in p_.values()),
    "no_cross_run_traffic": all(v["no_cross_run_traffic"] for v in p_.values()),
    "ledger_pcap_1to1": all(v["ledger_1to1"] for v in p_.values()),
    "clock_correction_valid": all(v["clock_ok"] for v in p_.values()),
    "all_runs_accepted": all(v["state"] == "accepted" for v in r.values()),
    "same_request_counts_as_serial": all(p_[k]["requests"] == s_[k]["requests"] for k in s_),
    "schedule_fidelity_p99_send_lag_ms_below_2": all(v["send_minus_schedule_ms_p50_p99_max"][1] < 2 for v in p_.values()),
    "response_latency_p99_within_2x_serial": all(p_[k]["response_latency_us_p50_p99"][1] <= 2 * s_[k]["response_latency_us_p50_p99"][1] + 200 for k in s_),
    "cpu_headroom_peak_below_50pct_of_host": res["resources_parallel"]["total_container_cpu_percent_p50_max"][1] < 0.5 * 20 * 100,
    "mem_peak_below_25pct_of_host": res["resources_parallel"]["total_container_mem_mib_max"] < 0.25 * 15.4 * 1024,
}
res["decision"] = "use 2 workers" if all(res["criteria"].values()) else "collect serially"
print(json.dumps(res, indent=1))
