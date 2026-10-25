"""Evidence annotations only: original CIC log joins, no model preprocessing.

All accepted mechanism labels require unique packet/log correspondence. Source
folders, function codes, missing requests, and exception/malformed flags alone
never create an injection target. Full source rows are retained in logs.parquet.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import time

import pyarrow as pa
import pyarrow.parquet as pq

TOLERANCE_US = 25_000
OFFSETS_US = (0, -10_800_000_000, 10_800_000_000)
SENSITIVITY_US = (0, 1000, 5000, 25000)
EVENT_COLS = ["event_uid", "recording_id", "view_id", "conn_uid", "protocol_role", "record_kind",
              "client_ip", "server_ip", "mbap_trans_id", "func_code", "address", "single_value",
              "ts_first_us", "ts_complete_us", "parse_status", "reasm_after_gap"]
ANNOTATION_SCHEMA = pa.schema([
    ("event_uid", pa.string()), ("recording_id", pa.string()), ("view_id", pa.string()),
    ("component_label", pa.string()), ("annotation_state", pa.string()), ("label_method", pa.string()),
    ("label_evidence_refs", pa.list_(pa.string())), ("original_attack_names", pa.list_(pa.string())),
    ("matched_log_signature_ids", pa.list_(pa.string())), ("candidate_log_signature_ids", pa.list_(pa.string())),
    ("associated_attack_request_uid", pa.string()), ("associated_response_attack_uid", pa.string()),
    ("reason", pa.string()),
])
MATCH_SCHEMA = pa.schema([
    ("event_uid", pa.string()), ("recording_id", pa.string()), ("view_id", pa.string()),
    ("log_signature_id", pa.string()), ("log_event_id", pa.string()),
    ("attack_original", pa.string()), ("family", pa.string()),
    ("candidate_clock_offset_us", pa.int64()), ("residual_us", pa.int64()),
    ("behavior_supported", pa.bool_()), ("status", pa.string()),
])
SIG_SCHEMA = pa.schema([
    ("log_signature_id", pa.string()), ("recording_id", pa.string()), ("source_event_id", pa.string()),
    ("source_path", pa.string()), ("source_sheet", pa.string()), ("source_row", pa.int64()),
    ("timestamp_us_candidate_utc", pa.int64()), ("target_ip", pa.string()), ("transaction_id", pa.int64()),
    ("attack_original", pa.string()), ("family", pa.string()), ("coil_address", pa.int64()),
    ("repeated_source_row_count", pa.int64()), ("status", pa.string()),
])


def load_log_index(output):
    """Collapse identical annotation signatures, not legitimate wire observations."""
    cols = ["event_id", "recording_id", "source_path", "source_sheet", "source_row", "timestamp_us",
            "target_ip", "transaction_id", "wire_tid_valid", "attack_original", "family",
            "completion", "coil_address", "evidence_eligibility"]
    signatures, total = {}, Counter()
    for batch in pq.ParquetFile(Path(output) / "logs.parquet").iter_batches(batch_size=25_000, columns=cols):
        for row in batch.to_pylist():
            total["source_rows"] += 1
            if row["evidence_eligibility"] == "superseded_time_damaged_csv_version":
                total["superseded_time_damaged_csv_rows"] += 1
                continue
            if row["completion"]:
                total["completion_rows_not_direct_injection_labels"] += 1
                continue
            if not row["wire_tid_valid"] or row["timestamp_us"] is None or row["target_ip"] is None:
                total["missing_time_target_or_valid_wire_tid"] += 1
                continue
            # Literal attack content remains part of identity; conflicting log names stay distinct.
            key = (row["recording_id"], row["timestamp_us"], row["target_ip"], row["transaction_id"], row["attack_original"])
            if key in signatures:
                signatures[key]["repeated_source_row_count"] += 1
                continue
            digest = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()[:24]
            signatures[key] = dict(log_signature_id="logsig:" + digest, recording_id=row["recording_id"],
                                   source_event_id=row["event_id"], source_path=row["source_path"],
                                   source_sheet=row["source_sheet"], source_row=row["source_row"],
                                   timestamp_us_candidate_utc=row["timestamp_us"], target_ip=row["target_ip"],
                                   transaction_id=row["transaction_id"], attack_original=row["attack_original"],
                                   family=row["family"], coil_address=row["coil_address"],
                                   repeated_source_row_count=1, status="candidate_log_evidence")
    by_id = {r["log_signature_id"]: r for r in signatures.values()}
    index = defaultdict(list)
    for row in by_id.values():
        role = "response" if row["family"] in ("false_data_injection", "delay_response") else "request"
        index[(row["recording_id"], row["target_ip"], row["transaction_id"], role)].append(row)
    for key, values in index.items():
        values.sort(key=lambda r: (r["timestamp_us_candidate_utc"], r["log_signature_id"]))
        index[key] = ([r["timestamp_us_candidate_utc"] for r in values], values)
    total["distinct_candidate_log_signatures"] = len(by_id)
    return index, by_id, total


def risk_connections(path):
    if not Path(path).exists():
        return set()
    pf = pq.ParquetFile(path)
    names = pf.schema_arrow.names
    cols = [c for c in ("conn_uid", "retrans_conflicts", "unverified_retrans_segments") if c in names]
    bad = set()
    for batch in pf.iter_batches(batch_size=30_000, columns=cols):
        for row in batch.to_pylist():
            if row.get("retrans_conflicts", 0) or row.get("unverified_retrans_segments", 0):
                bad.add(row["conn_uid"])
    return bad


def event_matches(event, index):
    if event["record_kind"] != "adu" or event["mbap_trans_id"] is None or event["ts_complete_us"] is None:
        return
    role = event["protocol_role"]
    target = event["server_ip"] if role == "request" else event["client_ip"]
    entry = index.get((event["recording_id"], target, event["mbap_trans_id"], role))
    if entry is None:
        return
    times, logs = entry
    for offset in OFFSETS_US:
        when = event["ts_complete_us"] - offset
        lo, hi = bisect_left(times, when - TOLERANCE_US), bisect_right(times, when + TOLERANCE_US)
        for log in logs[lo:hi]:
            family = log["family"]
            behavior = False
            if family == "false_data_injection":
                behavior = role == "response" and event["func_code"] is not None
            elif family == "brute_force_or_specific_coil":
                behavior = (role == "request" and event["func_code"] == 5
                            and event["address"] == log["coil_address"])
            yield dict(event_uid=event["event_uid"], recording_id=event["recording_id"], view_id=event["view_id"],
                       log_signature_id=log["log_signature_id"], log_event_id=log["source_event_id"],
                       attack_original=log["attack_original"], family=family,
                       candidate_clock_offset_us=offset,
                       residual_us=event["ts_complete_us"] - (log["timestamp_us_candidate_utc"] + offset),
                       behavior_supported=behavior, status="candidate_exact_target_tid_time_requires_uniqueness_and_pair_audit")


def candidate_rows(path):
    for batch in pq.ParquetFile(path).iter_batches(batch_size=25_000):
        yield from batch.to_pylist()


def candidate_groups(path):
    """The candidate stream preserves input event order; no whole table in RAM."""
    import itertools
    for uid, matches in itertools.groupby(candidate_rows(path), key=lambda m: m["event_uid"]):
        yield uid, [m for m in matches if m["candidate_clock_offset_us"] == 0]


def augment_annotation_quality(output, report):
    """Compact actual annotation/shape audit; no model features or data changes."""
    output = Path(output)
    example_report = {}
    for view_name, view_report in report["views"].items():
        view = output / "extraction" / view_name
        unknown = pq.read_table(view / "annotations.parquet", columns=["original_attack_names"],
                                filters=[("annotation_state", "=", "unknown_or_ambiguous")])
        core_withheld = 0
        for row in unknown.to_pylist():
            if any("brute force" in name.lower() or "false data injection" in name.lower() for name in row["original_attack_names"]):
                core_withheld += 1
        previous = view_report.pop("ambiguous_core_candidate_events_quarantined", 0)
        view_report.setdefault("multiple_individually_unique_core_log_candidates_event_count", previous)
        view_report["ambiguous_core_candidate_events_quarantined"] = core_withheld
        view_report["ambiguity_definition"] = "Core log association exists but a target is withheld; this includes many-to-many burst matches, not only multiple individually unique candidates."
        targets = pq.read_table(view / "annotations.parquet", columns=["event_uid", "component_label"],
                                filters=[("component_label", "in", ["command_injection", "response_injection"])])
        target_by_uid = {r["event_uid"]: r["component_label"] for r in targets.to_pylist()}
        detail = {}
        if target_by_uid:
            names = pq.ParquetFile(view / "events.parquet").schema_arrow.names
            cols = [c for c in ("event_uid", "first_chunk", "first_frame", "last_chunk", "last_frame", "ts_complete_us",
                                "mbap_trans_id", "func_code", "address", "single_value", "reg_values", "parse_status",
                                "shape_reason", "adu_bytes", "client_ip", "server_ip") if c in names]
            events = pq.read_table(view / "events.parquet", columns=cols, filters=[("event_uid", "in", list(target_by_uid))]).to_pylist()
            for label in sorted(set(target_by_uid.values())):
                subset = [r for r in events if target_by_uid[r["event_uid"]] == label]
                pdu_counts = Counter(r["adu_bytes"][7:].hex() for r in subset if r.get("adu_bytes") is not None)
                examples = subset[:1]
                examples += [r for r in subset if r["parse_status"] == "ok" and r not in examples][:1]
                rendered = []
                for row in examples:
                    row = dict(row)
                    data = row.pop("adu_bytes", None)
                    row["adu_hex"] = data.hex() if data is not None else None
                    rendered.append(row)
                detail[label] = {"events": len(subset), "parse_status_counts": dict(Counter(r["parse_status"] for r in subset)),
                                 "pdu_hex_counts": dict(pdu_counts), "examples": rendered}
        example_report[view_name] = detail
        (view / "label_report.json").write_text(json.dumps(view_report, indent=2), encoding="utf8")
    (output / "label_examples.json").write_text(json.dumps(example_report, indent=2), encoding="utf8")
    return example_report


def run_labels(output, tolerance_us=TOLERANCE_US):
    if tolerance_us != TOLERANCE_US:
        raise ValueError("Tolerance is frozen at25000us in this evidence policy; revise policy/version explicitly.")
    output = Path(output)
    t0 = time.monotonic()
    index, signatures, global_counts = load_log_index(output)
    views = []
    for path in sorted((output / "extraction").glob("*/events.parquet")):
        view = path.parent
        if view.name.endswith(".tmp"):
            continue
        checkpoint = view / "checkpoint.json"
        if not checkpoint.exists() or not json.loads(checkpoint.read_text(encoding="utf8")).get("reconciliation_passed"):
            continue
        if not (view / "pairs.parquet").exists():
            raise RuntimeError(f"Pair audit must complete before annotation: {view}")
        views.append(view)
    if not views:
        raise RuntimeError("No published, reconciled extraction chains with pair audits available.")
    candidate_files = {}
    by_log, all_by_log = Counter(), Counter()
    by_log_sensitivity = Counter()
    candidate_edge_counts = {}
    selected_scope = defaultdict(lambda: {"server_ips": set(), "client_ips": set(), "first_ts_us": None, "last_ts_us": None})
    for view in views:
        risk = risk_connections(view / "connections.parquet")
        path = view / "log_matches.parquet"
        buffer, edge_count = [], 0
        with pq.ParquetWriter(view / "log_matches.parquet.tmp", MATCH_SCHEMA, compression="zstd") as writer:
            for batch in pq.ParquetFile(view / "events.parquet").iter_batches(batch_size=30_000, columns=EVENT_COLS):
                for event in batch.to_pylist():
                    scope = selected_scope[event["recording_id"]]
                    scope["server_ips"].add(event["server_ip"])
                    scope["client_ips"].add(event["client_ip"])
                    ts = event["ts_complete_us"]
                    if ts is not None:
                        scope["first_ts_us"] = ts if scope["first_ts_us"] is None else min(ts, scope["first_ts_us"])
                        scope["last_ts_us"] = ts if scope["last_ts_us"] is None else max(ts, scope["last_ts_us"])
                    for match in event_matches(event, index):
                        if event["conn_uid"] in risk or event["reasm_after_gap"]:
                            match["status"] = "uncertain_stream_bytes_or_retransmission"
                        buffer.append(match)
                        edge_count += 1
                        key = (match["log_signature_id"], match["candidate_clock_offset_us"])
                        all_by_log[key] += 1
                        if match["behavior_supported"] and match["status"] != "uncertain_stream_bytes_or_retransmission":
                            by_log[key] += 1
                            if match["candidate_clock_offset_us"] == 0:
                                for tol in SENSITIVITY_US:
                                    if abs(match["residual_us"]) <= tol:
                                        by_log_sensitivity[(match["log_signature_id"], tol)] += 1
                        if len(buffer) >= 25_000:
                            writer.write_table(pa.Table.from_pylist(buffer, schema=MATCH_SCHEMA))
                            buffer.clear()
                if buffer:
                    writer.write_table(pa.Table.from_pylist(buffer, schema=MATCH_SCHEMA))
                    buffer.clear()
        (view / "log_matches.parquet.tmp").replace(path)
        candidate_files[view.name] = path
        candidate_edge_counts[view.name] = edge_count
        print(f"labels candidate scan {view.name}: {edge_count} streamed matches", flush=True)
    calibration = Counter()
    for (sig, offset), count in by_log.items():
        if count == 1:
            log = signatures[sig]
            calibration[(log["recording_id"], log["family"], offset)] += 1
    calibrated = set()
    for rec, fam, offset in calibration:
        if offset != 0:
            continue
        n = calibration[(rec, fam, 0)]
        other = max(calibration[(rec, fam, off)] for off in OFFSETS_US if off)
        if n >= 3 and n > other:
            calibrated.add((rec, fam))
    matched_signatures, accepted_signatures = set(), set()
    per_view = {}
    two_sided_sensitivity = Counter()
    for view in views:
        candidate_path = candidate_files[view.name]
        candidate_positive = {}
        ambiguous_core_candidate_events = set()
        contradictory_core_target_events = set()
        for uid, matches in candidate_groups(candidate_path):
            matched_signatures.update(m["log_signature_id"] for m in matches)
            for tol in SENSITIVITY_US:
                close = [m for m in matches if m["behavior_supported"] and abs(m["residual_us"]) <= tol
                         and m["status"] != "uncertain_stream_bytes_or_retransmission"]
                if len(close) == 1 and by_log_sensitivity[(close[0]["log_signature_id"], tol)] == 1:
                    two_sided_sensitivity[(close[0]["recording_id"], close[0]["family"], tol)] += 1
            supported = [m for m in matches if m["behavior_supported"]
                         and m["status"] != "uncertain_stream_bytes_or_retransmission"
                         and by_log[(m["log_signature_id"], 0)] == 1
                         and (m["recording_id"], m["family"]) in calibrated]
            if len(supported) == 1:
                fam = supported[0]["family"]
                if fam in ("false_data_injection", "brute_force_or_specific_coil"):
                    candidate_positive[uid] = supported[0]
            elif len(supported) > 1:
                ambiguous_core_candidate_events.add(uid)
                targets = {"response_injection" if m["family"] == "false_data_injection" else "command_injection" for m in supported}
                if len(targets) > 1:
                    contradictory_core_target_events.add(uid)
        paired_responses, association = {}, {}
        pair_path = view / "pairs.parquet"
        if pair_path.exists():
            cols = ["request_uid", "response_uid", "status", "reasons"]
            for batch in pq.ParquetFile(pair_path).iter_batches(batch_size=30_000, columns=cols):
                for pair in batch.to_pylist():
                    req, rsp = pair["request_uid"], pair["response_uid"]
                    if req and rsp and pair["status"] in ("matched", "matched_exception", "matched_inconsistent"):
                        if rsp in candidate_positive and candidate_positive[rsp]["family"] == "false_data_injection":
                            paired_responses[rsp] = req
                        if req in candidate_positive and candidate_positive[req]["family"] == "brute_force_or_specific_coil":
                            association[rsp] = req
        attacked_response_for_request = {req: rsp for rsp, req in paired_responses.items()}
        risk = risk_connections(view / "connections.parquet")
        counts, independent_episodes, rows = Counter(), defaultdict(set), []
        accepted = {}
        for uid, m in candidate_positive.items():
            if m["family"] != "false_data_injection" or uid in paired_responses:
                accepted[uid] = m
                accepted_signatures.add(m["log_signature_id"])
        match_groups = iter(candidate_groups(candidate_path))
        current_uid, current_matches = next(match_groups, (None, []))
        with pq.ParquetWriter(view / "annotations.parquet.tmp", ANNOTATION_SCHEMA, compression="zstd") as writer:
            for batch in pq.ParquetFile(view / "events.parquet").iter_batches(batch_size=30_000, columns=EVENT_COLS):
                for event in batch.to_pylist():
                    uid, rec = event["event_uid"], event["recording_id"]
                    if current_uid == uid:
                        matches = current_matches
                        current_uid, current_matches = next(match_groups, (None, []))
                    else:
                        matches = []
                    label = None
                    state, method, reason = "unlabelled", "no_supported_evidence", "No accepted event-level injection or normal evidence."
                    refs, names, sigs = [], [], []
                    if rec == "cic_benign_january":
                        if event["parse_status"] in ("ok", "exception") and event["conn_uid"] not in risk and not event["reasm_after_gap"]:
                            label, state = "normal", "supported_source_documentation"
                            method = "original_cic_benign_campaign_documentation"
                            reason = "Original README identifies this preserved capture campaign as legitimate communication; parser status separate."
                            refs = ["raw:README.md:Description/DataCollection", "raw-source-manifest"]
                        else:
                            state, reason = "unknown_or_ambiguous", "Benign source provenance retained; malformed/partial/uncertain stream bytes withheld from normal targets."
                    elif uid in accepted:
                        m = accepted[uid]
                        label = "response_injection" if m["family"] == "false_data_injection" else "command_injection"
                        state, method = "supported_log_packet_mechanism", "unique_log_target_tid_time_behavior_calibrated_zero_offset"
                        reason = "Direct response modification log with observed request/reply lineage." if label == "response_injection" else "Original brute-force coil log uniquely matches request target, wire TID, time, function and logged address."
                        refs, names, sigs = [m["log_event_id"]], [m["attack_original"]], [m["log_signature_id"]]
                        independent_episodes[label].add(m["log_signature_id"])
                    elif matches:
                        noncore = [m for m in matches if m["family"] not in ("false_data_injection", "brute_force_or_specific_coil")]
                        if len(matches) == len(noncore) == 1 and all_by_log[(noncore[0]["log_signature_id"], 0)] == 1:
                            state, method = "out_of_scope", "unique_original_log_transaction_association_other_mechanism"
                            reason = "Unique log association concerns an out-of-scope mechanism. Association alone does not prove this ADU malicious; component target withheld."
                        else:
                            state, method = "unknown_or_ambiguous", "candidate_log_association_only"
                            reason = "Target/TID/time association did not satisfy unique core-mechanism, clock, pair and stream-byte checks; other mechanisms not collapsed."
                    candidate_sigs = sorted({m["log_signature_id"] for m in matches})
                    if not names:
                        names = sorted({m["attack_original"] for m in matches})
                    rows.append(dict(event_uid=uid, recording_id=rec, view_id=event["view_id"],
                                     component_label=label, annotation_state=state, label_method=method,
                                     label_evidence_refs=refs, original_attack_names=names, matched_log_signature_ids=sigs,
                                     candidate_log_signature_ids=candidate_sigs,
                                     associated_attack_request_uid=association.get(uid),
                                     associated_response_attack_uid=attacked_response_for_request.get(uid),
                                     reason=reason))
                    counts["label:" + (label or "unlabelled")] += 1
                    counts["state:" + state] += 1
                    counts["events"] += 1
                writer.write_table(pa.Table.from_pylist(rows, schema=ANNOTATION_SCHEMA))
                rows.clear()
        (view / "annotations.parquet.tmp").replace(view / "annotations.parquet")
        buffer = []
        with pq.ParquetWriter(view / "log_matches.annotated.tmp", MATCH_SCHEMA, compression="zstd") as writer:
            for m in candidate_rows(candidate_path):
                if m["candidate_clock_offset_us"] != 0:
                    m["status"] = "clock_offset_comparison_only"
                elif m["event_uid"] in accepted and accepted[m["event_uid"]]["log_signature_id"] == m["log_signature_id"]:
                    m["status"] = "accepted_core_mechanism_evidence"
                elif by_log[(m["log_signature_id"], 0)] > 1:
                    m["status"] = "ambiguous_multiple_event_candidates"
                buffer.append(m)
                if len(buffer) >= 25_000:
                    writer.write_table(pa.Table.from_pylist(buffer, schema=MATCH_SCHEMA))
                    buffer.clear()
            if buffer:
                writer.write_table(pa.Table.from_pylist(buffer, schema=MATCH_SCHEMA))
        (view / "log_matches.annotated.tmp").replace(candidate_path)
        report = {"counts": dict(counts), "supported_log_packet_events_by_class": {k: len(v) for k, v in independent_episodes.items()},
                  "independence_policy": "Distinct log/packet events are NOT independent recordings. All campaign events remain in one parent group.",
                  "risk_connections_withheld_from_confident_labels": len(risk),
                  "candidate_edge_count": candidate_edge_counts[view.name],
                  "ambiguous_core_candidate_events_quarantined": len(ambiguous_core_candidate_events),
                  "contradictory_core_target_event_count": len(contradictory_core_target_events),
                  "conflict_policy": "No arbitrary target chosen for multiple supported log candidates; those events remain unknown_or_ambiguous."}
        (view / "label_report.json").write_text(json.dumps(report, indent=2), encoding="utf8")
        per_view[view.name] = report
        print(f"labels annotated {view.name}: {dict(counts)}", flush=True)
    log_states = Counter()
    for sid, log in signatures.items():
        scope = selected_scope.get(log["recording_id"])
        if sid in accepted_signatures:
            status = "accepted_core_mechanism_event_evidence"
        elif sid in matched_signatures:
            status = "candidate_only_or_ambiguous"
        elif scope is None:
            status = "no_selected_capture_campaign"
        elif log["timestamp_us_candidate_utc"] < scope["first_ts_us"] or log["timestamp_us_candidate_utc"] > scope["last_ts_us"]:
            status = "outside_selected_capture_interval_candidate_utc"
        elif log["target_ip"] not in scope["server_ips"] | scope["client_ips"]:
            status = "outside_selected_endpoint_scope_not_absent_from_raw_dataset"
        else:
            status = "unmatched_log_attempt_or_unverified_tid_semantics"
        log["status"] = status
        log_states[status] += 1
    pq.write_table(pa.Table.from_pylist(list(signatures.values()), schema=SIG_SCHEMA), output / "log_signatures.parquet", compression="zstd")
    residuals = defaultdict(list)
    dates = defaultdict(set)
    for candidate_path in candidate_files.values():
        for m in candidate_rows(candidate_path):
            if m["behavior_supported"] and by_log[(m["log_signature_id"], m["candidate_clock_offset_us"])] == 1:
                key = (m["recording_id"], m["family"], m["candidate_clock_offset_us"])
                residuals[key].append(m["residual_us"])
                from datetime import datetime, timezone
                dates[key].add(datetime.fromtimestamp(signatures[m["log_signature_id"]]["timestamp_us_candidate_utc"] / 1_000_000, timezone.utc).date().isoformat())
    calrows = []
    for (rec, fam, off), n in sorted(calibration.items()):
        values = residuals[(rec, fam, off)]
        calrows.append({"recording_id": rec, "family": fam, "offset_us": off, "unique_behavior_matches": n,
                        "zero_offset_calibrated": (rec, fam) in calibrated,
                        "residual_min_us": min(values) if values else None,
                        "residual_median_us": statistics.median(values) if values else None,
                        "residual_max_us": max(values) if values else None,
                        "source_log_dates_candidate_utc": sorted(dates[(rec, fam, off)]),
                        "tolerance_sensitivity_unique_candidates": {str(t): sum(abs(v) <= t for v in values) for t in (1000, 5000, 25000)}})
    report = {"policy_version": "cic-evidence-v1", "tolerance_us": TOLERANCE_US,
              "clock_offset_candidates_us": list(OFFSETS_US), "clock_calibration": calrows,
              "strict_candidate_uniqueness_sensitivity": [
                  {"recording_id": rec, "family": fam, "tolerance_us": tol, "two_sided_unique_candidate_pairs": n}
                  for (rec, fam, tol), n in sorted(two_sided_sensitivity.items())],
              "clock_scope_limit": "Zero offset accepted only for observed family/campaign with>=3unique behavior matches and more support than±3hours; no claim for all logs/clocks.",
              "source_log_counts": dict(global_counts), "signature_match_states": dict(log_states), "views": per_view,
              "selected_endpoint_scope": {k: {**v, "server_ips": sorted(v["server_ips"]), "client_ips": sorted(v["client_ips"])} for k, v in selected_scope.items()},
              "limitations": ["Naive log timezone is not independently documented.", "Brute-force log TID5/completion65535 semantics not assumed to enumerate literal wire TIDs.",
                              "Other attack mechanisms remain candidate evidence, not fabricated core labels.", "Distinct event evidence does not establish independent episodes or campaigns."],
              "elapsed_s": round(time.monotonic()-t0, 3)}
    report["accepted_target_shape_audit"] = augment_annotation_quality(output, report)
    (output / "label_report.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="component3_preparation/output")
    args = ap.parse_args()
    run_labels(args.output)
