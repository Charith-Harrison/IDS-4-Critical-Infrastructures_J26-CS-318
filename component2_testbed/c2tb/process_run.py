"""Per-run processing: parse PCAP -> tshark cross-check -> ledger join -> run acceptance.

Raw evidence in data/<collection>/runs/<run_id>/ is only read.  Derived outputs go to
data/<collection>/derived/<run_id>/.  Labels come exclusively from the ledger via an identity join
(client IP, client TCP port, transaction ID, exact request ADU bytes); no packet feature value is used to label.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd

from c2tb.parse_pcap import extract_adus, pair_responses

TSHARK_FIELDS = ["frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "mbtcp.trans_id",
                 "mbtcp.unit_id", "mbtcp.len", "modbus.func_code", "modbus.reference_num", "modbus.word_cnt",
                 "modbus.bit_cnt", "modbus.exception_code", "frame.len"]


class ClockCorrection:
    """Piecewise wall-clock offset from clockmon samples.  The corrected timeline removes measured steps of the VM
    wall clock (offset = wall - monotonic, referenced to the first sample); raw timestamps are never altered.
    Timestamps within one sampling interval of a step cannot be assigned unambiguously and are flagged."""
    STEP_NS = 200_000

    def __init__(self, ck: pd.DataFrame):
        ck = ck.sort_values("mono_ns").reset_index(drop=True)
        self.w = ck.wall_ns.to_numpy()
        self.o = (ck.wall_ns - ck.mono_ns).to_numpy()
        self.o_ref = self.o[0]
        d = np.diff(self.o)
        self.step_after = np.abs(d) >= self.STEP_NS          # step between sample i and i+1
        self.steps = [{"wall_ns": int(self.w[i + 1]), "step_us": float(d[i] / 1000)} for i in np.where(self.step_after)[0]]

    def apply(self, ts):
        ts = np.asarray(ts, dtype="int64")
        i = np.searchsorted(self.w, ts, side="right") - 1
        inside = (i >= 0) & (i < len(self.w) - 1)
        ic = np.clip(i, 0, len(self.w) - 2)
        near = np.zeros(len(ts), bool)
        for k in (-1, 0, 1):
            j = np.clip(ic + k, 0, len(self.step_after) - 1)
            near |= self.step_after[j]
        frac = (ts - self.w[ic]) / np.maximum(self.w[ic + 1] - self.w[ic], 1)
        off = self.o[ic] + np.where(self.step_after[ic], 0, (self.o[ic + 1] - self.o[ic]) * frac)
        return (ts - (off - self.o_ref)).astype("int64"), (near | ~inside)

    def apply_nullable(self, ts: pd.Series):
        """Missing timestamps (e.g. a request without a response) stay missing and are not flagged."""
        ok = ts.notna().to_numpy()
        out = pd.Series(pd.NA, index=ts.index, dtype="Int64")
        amb = np.zeros(len(ts), bool)
        if ok.any():
            c, a = self.apply(ts[ok].astype("int64"))
            out[ok] = c
            amb[ok] = a
        return out, amb

    def covers(self, t0, t1):
        return bool(self.w[0] <= t0 and self.w[-1] >= t1)

    def summary(self):
        dur = (self.w[-1] - self.w[0]) / 1e9
        return {"samples": int(len(self.w)), "duration_s": round(dur, 3), "steps": self.steps,
                "n_steps": len(self.steps),
                "net_offset_change_us": float((self.o[-1] - self.o[0]) / 1000),
                "max_interval_ms": float(np.diff(self.w).max() / 1e6)}


def tshark_table(pcap: Path) -> pd.DataFrame:
    cmd = ["tshark", "-r", str(pcap), "-Y", "mbtcp", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=|", *sum([["-e", f] for f in TSHARK_FIELDS], [])]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = [line.split("\t") for line in out.splitlines() if line.strip()]
    return pd.DataFrame(rows, columns=TSHARK_FIELDS)


def tshark_check(adus: pd.DataFrame, pcap: Path) -> dict:
    """Compare every parsed ADU with tshark's independent dissection of the frame completing that ADU."""
    ts = tshark_table(pcap)
    multi = ts[ts["mbtcp.trans_id"].str.contains(r"\|", regex=True)]
    ts = ts.set_index(ts["frame.number"].astype(int))
    mism, checked = [], 0
    for r in adus.itertuples():
        f = r.end_frame_number
        if f not in ts.index:
            mism.append({"adu_id": r.adu_id, "issue": "frame_not_dissected_as_modbus_by_tshark"})
            continue
        t = ts.loc[f]
        exp = {"ip.src": r.src_ip, "tcp.srcport": str(r.src_port), "ip.dst": r.dst_ip, "tcp.dstport": str(r.dst_port),
               "mbtcp.trans_id": str(r.tid), "mbtcp.unit_id": str(r.unit), "mbtcp.len": str(r.mbap_len),
               "modbus.func_code": str(r.base_fc)}
        if r.direction == "request":
            exp["modbus.reference_num"] = str(r.address)
            exp["modbus.bit_cnt" if r.base_fc in (1, 2) else "modbus.word_cnt"] = str(r.quantity)
        elif r.is_exception:
            exp["modbus.exception_code"] = str(r.exception_code)
        if r.end_frame_number == r.frame_number:
            exp["frame.len"] = str(r.frame_len)
        bad = {k: (v, t[k]) for k, v in exp.items() if t[k] != v}
        checked += 1
        if bad:
            mism.append({"adu_id": r.adu_id, "issue": "field_mismatch", "fields": bad})
    return {"tshark_modbus_frames": int(len(ts)), "parsed_adus": int(len(adus)), "adus_checked": checked,
            "frames_with_multiple_adus": int(len(multi)), "mismatches": len(mism), "mismatch_examples": mism[:20],
            "fields_compared": "endpoints, ports, TID, unit, MBAP length, base FC, request address/quantity, "
                               "exception code, frame length"}


def load_ledgers(run_dir: Path) -> tuple[pd.DataFrame, list]:
    acts, events = [], []
    for p in sorted(run_dir.glob("ledger_*.jsonl")):
        for line in p.read_text().splitlines():
            d = json.loads(line)
            d["ledger_file"] = p.name
            (acts if d["event"] == "action" else events).append(d)
    return pd.DataFrame(acts), events


def main(collection_dir: Path, run_id: str):
    run_dir = collection_dir / "runs" / run_id
    out = collection_dir / "derived" / run_id
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((run_dir / "run_manifest.json").read_text())
    plan = json.loads((run_dir / "plan.json").read_text())
    checks, failures = {}, []

    def gate(name, ok, detail=None):
        checks[name] = {"pass": bool(ok), "detail": detail}
        if not ok:
            failures.append(name)

    gate("collection_completed", manifest["collection_state"] == "collected", manifest["collection_error"])
    if manifest["collection_state"] != "collected":
        return finish(out, manifest, checks, failures)
    log = (run_dir / "tcpdump.log").read_text()
    dropped = [int(x) for x in re.findall(r"(\d+) packets dropped by (?:kernel|interface)", log)]
    gate("capture_zero_drops", dropped and max(dropped) == 0, log.strip().splitlines()[-3:])

    adus, stats = extract_adus(run_dir / "capture.pcap", run_id)
    gate("linktype_ethernet", stats["linktype"] == 1, stats["linktype"])
    run_ips = {manifest["target"]["ip"], *(c["ip"] for c in manifest["clients"].values())}
    gate("no_cross_run_traffic", set(stats["tcp_ip_endpoints"]) <= run_ips,
         {"observed": stats["tcp_ip_endpoints"], "expected": sorted(run_ips)})
    gate("no_tcp_retransmission_gap_or_truncation",
         not any(stats["tcp_anomalies"].get(k) for k in ("retransmitted_or_overlapping_segment",
                                                         "gap_or_out_of_order_segment", "truncated_payload",
                                                         "stream_without_syn", "syn_after_data_same_4tuple")),
         stats["tcp_anomalies"])
    gate("no_unframed_trailing_bytes", stats["trailing_unframed_bytes"] == 0, stats["trailing_unframed_bytes"])
    tsk = tshark_check(adus, run_dir / "capture.pcap")
    gate("parser_agrees_with_tshark_all_adus", tsk["mismatches"] == 0 and tsk["adus_checked"] == len(adus),
         {k: tsk[k] for k in ("adus_checked", "mismatches")})
    (out / "tshark_check.json").write_text(json.dumps(tsk, indent=1, default=str))

    req = pair_responses(adus)
    gate("every_request_has_response", (req.response_pairing != "unmatched").all(),
         int((req.response_pairing == "unmatched").sum()))
    gate("no_unmatched_responses", req.attrs["unmatched_responses"] == 0, req.attrs["unmatched_responses"])
    gate("no_exception_responses", not req.response_is_exception.astype("boolean").fillna(False).astype(bool).any(),
         int(req.response_is_exception.astype("boolean").fillna(False).astype(bool).sum()))

    led, events = load_ledgers(run_dir)
    planned = {k: len(v["actions"]) for k, v in plan["clients"].items()}
    executed = led.groupby("client").size().to_dict()
    gate("all_planned_actions_executed", planned == executed, {"planned": planned, "executed": executed})
    gate("ledger_status_all_ok", (led.status == "ok").all(), led.status.value_counts().to_dict())
    gate("no_reconnects", not any(e["event"] == "reconnect" for e in events))
    params = plan["actor_scenario_parameters"]
    if plan["family"] == "recon":
        gate("recon_plan_not_truncated", params.get("truncated_recon_targets", 0) == 0,
             params.get("truncated_recon_targets"))
        gate("recon_actions_present", (led.role == "recon").sum() > 0, int((led.role == "recon").sum()))

    key_w = list(zip(req.src_ip, req.src_port, req.tid, req.adu_hex))
    key_l = list(zip(led.local_ip, led.local_port, led.tid, led.request_hex))
    kw, kl = pd.Series(key_w).value_counts(), pd.Series(key_l).value_counts()
    gate("join_keys_unique", (kw.max() == 1) and (kl.max() == 1), {"max_wire": int(kw.max()), "max_ledger": int(kl.max())})
    lk = led.assign(_k=key_l).set_index("_k")
    req["_k"] = key_w
    matched = req["_k"].isin(lk.index)
    gate("every_wire_request_matched_to_ledger", matched.all(), int((~matched).sum()))
    gate("every_ledger_action_matched_to_wire", pd.Series(key_l).isin(set(key_w)).all(),
         int((~pd.Series(key_l).isin(set(key_w))).sum()))
    gt_cols = {"role": "gt_role", "phase": "gt_phase", "scenario_id": "gt_scenario_id", "client": "gt_client",
               "action_index": "gt_action_index", "intent": "gt_intent", "scheduled_ns": "ledger_scheduled_ns",
               "send_ns": "ledger_send_ns", "recv_ns": "ledger_recv_ns", "response_hex": "ledger_response_hex",
               "unit": "ledger_unit", "fc": "ledger_fc", "address": "ledger_address", "quantity": "ledger_quantity"}
    for src, dst in gt_cols.items():
        req[dst] = req["_k"].map(lk[src]) if src in lk else None
    req = req.drop(columns="_k")
    req["gt_label_recon"] = (req.gt_role == "recon").astype(int)
    intent_ok = ((req.ledger_unit == req.unit) & (req.ledger_fc == req.wire_fc) &
                 (req.ledger_address == req.address) & (req.ledger_quantity == req.quantity))
    gate("wire_fields_equal_ledger_intent", intent_ok.all(), int((~intent_ok).sum()))
    gate("wire_response_equals_client_received", (req.ledger_response_hex == req.response_hex).all(),
         int((req.ledger_response_hex != req.response_hex).sum()))
    cap_minus_send = (req.ts_ns - req.ledger_send_ns) / 1000
    lag = (req.ledger_send_ns - req.ledger_scheduled_ns) / 1e6
    checks["timing_evidence"] = {
        "capture_minus_client_send_us": cap_minus_send.describe(percentiles=[.01, .5, .99]).round(1).to_dict(),
        "send_minus_schedule_ms": lag.describe(percentiles=[.5, .99]).round(2).to_dict()}

    clock = run_dir / "clock.jsonl"
    if not clock.exists():  # v1/v2: no clock log, raw wall-clock check as originally specified
        req["ts_corr_ns"], req["clock_ambiguous"] = req.ts_ns, False
        gate("capture_after_send_same_clock", (cap_minus_send >= 0).all() and (cap_minus_send < 100_000).all(),
             checks["timing_evidence"]["capture_minus_client_send_us"])
    else:  # v3+: Amendment A, PILOT_PROTOCOL.md
        ck = pd.DataFrame([json.loads(x) for x in clock.read_text().splitlines() if x.strip()])
        corr = ClockCorrection(ck)
        req["ts_corr_ns"], req["clock_ambiguous"] = corr.apply(req.ts_ns)
        req["response_ts_corr_ns"], amb_r = corr.apply_nullable(req.response_ts_ns)
        req["ledger_send_corr_ns"], amb_s = corr.apply_nullable(req.ledger_send_ns)
        req["clock_ambiguous"] |= amb_r | amb_s
        adus["ts_corr_ns"], adus["clock_ambiguous"] = corr.apply(adus.ts_ns)
        ok = ~req.clock_ambiguous
        cms = (req.ts_corr_ns - req.ledger_send_corr_ns)[ok] / 1000
        span_s = (req.ts_ns.max() - req.ts_ns.min()) / 1e9
        checks["clock_evidence"] = {**corr.summary(), "ambiguous_requests": int(req.clock_ambiguous.sum()),
                                    "ambiguous_fraction": float(req.clock_ambiguous.mean()),
                                    "capture_minus_send_corrected_us":
                                        cms.describe(percentiles=[.01, .5, .99]).round(1).to_dict()}
        gate("vm_clock_monitored_covering_run", corr.covers(req.ts_ns.min(), req.ts_ns.max()), corr.summary())
        gate("capture_after_send_same_clock_corrected", (cms >= 0).all() and (cms < 100_000).all(),
             checks["clock_evidence"]["capture_minus_send_corrected_us"])
        gate("clock_ambiguous_requests_at_most_1pct", req.clock_ambiguous.mean() <= 0.01,
             float(req.clock_ambiguous.mean()))

    adus.to_parquet(out / "adus.parquet", index=False)
    req.to_parquet(out / "requests_labeled.parquet", index=False)
    stats["requests"] = int(len(req))
    stats["recon_requests"] = int(req.gt_label_recon.sum())
    (out / "parse_stats.json").write_text(json.dumps(stats, indent=1, default=str))
    return finish(out, manifest, checks, failures)


def finish(out, manifest, checks, failures):
    acc = {"run_id": manifest["run_id"], "scenario_id": manifest["scenario_id"], "family": manifest["family"],
           "completion_state": "accepted" if not failures else "rejected",
           "failure_reason": failures or None, "checks": checks}
    (out / "acceptance.json").write_text(json.dumps(acc, indent=1, default=str))
    return acc


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collection-dir", required=True)
    p.add_argument("--run-id", nargs="*")
    a = p.parse_args()
    cd = Path(a.collection_dir)
    run_ids = a.run_id or sorted(x.name for x in (cd / "runs").iterdir())
    for rid in run_ids:
        acc = main(cd, rid)
        print(rid, acc["scenario_id"], acc["completion_state"], acc["failure_reason"] or "")
