"""Extraction quality and whole-recording candidate membership; no model inputs."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
import time

import pyarrow as pa
import pyarrow.parquet as pq


ASSIGNMENTS = {
    "cic_benign_january": "candidate_train",
    "cic_compromised_scada_march": "candidate_train",
    "cic_external_february": "candidate_validation",
    "cic_compromised_ied_march": "candidate_test",
}
MEMBER_SCHEMA = pa.schema([
    ("event_uid", pa.string()), ("recording_id", pa.string()), ("view_id", pa.string()),
    ("event_seq", pa.int64()), ("ts_complete_us", pa.int64()), ("partition", pa.string()),
])


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(8 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, default=str) + "\n", encoding="utf8")


def extraction_dirs(output):
    published = []
    for path in (Path(output) / "extraction").glob("*/events.parquet"):
        directory = path.parent
        if directory.name.endswith(".tmp"):
            continue
        checkpoint = directory / "checkpoint.json"
        if not checkpoint.is_file():
            continue
        metadata = json.loads(checkpoint.read_text(encoding="utf8"))
        if metadata.get("reconciliation_passed") is True:
            published.append(directory)
    return sorted(published)


def uid_membership(uid, ranges):
    """Exact membership after every view's canonical, contiguous UID domain passed.

    This is not prefix-only inference: build_partitions exhaustively checks that
    every integer from 1 through N occurs exactly once, in canonical UID form.
    The small range map then replaces one SQLite lookup per pair endpoint.
    """
    if not isinstance(uid, str) or ":e" not in uid:
        return None
    view, number = uid.rsplit(":e", 1)
    info = ranges.get(view)
    if info is None or not number.isdecimal():
        return None
    seq = int(number)
    if uid != f"{view}:e{seq}" or not 1 <= seq <= info["events"]:
        return None
    return info


def source_group_containment(output, tolerance_us=1_000, selected_sources=()):
    """Audit all source mappings and bounded, time-linked mirror observations.

    Equal frame bytes at distant times can be legitimate repeated content. Only
    distinct source paths sharing whole-frame bytes within the declared bounded
    capture-clock tolerance are mirror candidates. No raw event is removed here.
    """
    output = Path(output)
    mapping = json.loads((output / "group_sources.json").read_text(encoding="utf8"))
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf8"))
    source_groups = {}
    conflicts = []
    for group in mapping["groups"]:
        rec = group["recording_id"]
        for view in group["views"]:
            for chunk in view["chunks"]:
                source = chunk["path"]
                if source in source_groups and source_groups[source] != rec:
                    conflicts.append(source)
                source_groups[source] = rec
    captures = {f["path"] for f in inventory["files"] if f["format"] in ("pcap", "pcapng")}
    duplicate_files = defaultdict(list)
    for item in inventory["files"]:
        if item["path"] in captures:
            duplicate_files[item["sha256"]].append(item["path"])
    identical_file_crossings = []
    for digest, paths in duplicate_files.items():
        recs = {source_groups.get(p) for p in paths}
        if len(paths) > 1 and len(recs) > 1:
            identical_file_crossings.append({"sha256": digest, "paths": paths})
    selected_conflicts = []
    for table in selected_sources:
        for source in table.get("source_paths", []):
            if source_groups.get(source) != table["recording_id"]:
                selected_conflicts.append({"path": source, "extracted_recording_id": table["recording_id"],
                                           "inventory_recording_id": source_groups.get(source)})
    mirror_clusters = []
    recurring_content = 0
    for signature in mapping.get("sampled_duplicate_observations", []):
        ordered = sorted(signature["observations"], key=lambda o: o["ts_us"])
        clusters = []
        for observation in ordered:
            if not clusters or observation["ts_us"] - clusters[-1][0]["ts_us"] > tolerance_us:
                clusters.append([])
            clusters[-1].append(observation)
        recurring_content += len(clusters) > 1
        for cluster in clusters:
            if len({o["path"] for o in cluster}) < 2:
                continue
            recs = sorted({source_groups.get(o["path"], "UNMAPPED") for o in cluster})
            mirror_clusters.append({"sha256_frame": signature["sha256_frame"],
                                    "observations": cluster, "recording_ids": recs,
                                    "contained": len(recs) == 1 and recs[0] != "UNMAPPED"})
    return {
        "source_paths_mapped": len(source_groups), "capture_files": len(captures),
        "unmapped_capture_paths": sorted(captures - source_groups.keys()),
        "multiply_assigned_source_paths": sorted(set(conflicts)),
        "identical_capture_file_cross_group_copies": identical_file_crossings,
        "selected_source_membership_conflicts": selected_conflicts,
        "sampled_signature_count": len(mapping.get("sampled_duplicate_observations", [])),
        "mirror_clock_tolerance_us": tolerance_us,
        "time_linked_sampled_mirror_clusters": mirror_clusters,
        "sampled_mirror_cross_group_clusters": sum(not c["contained"] for c in mirror_clusters),
        "signatures_recurring_at_separate_times": recurring_content,
        "scope": mapping.get("duplicate_audit_scope", "bounded frame samples"),
        "interpretation": "Time-linked, byte-identical cross-view samples audit mirror containment; identical content recurring outside tolerance is not declared a duplicate observation. Absence of sampled overlap does not prove uniqueness. One selected canonical view per campaign avoids retaining simultaneous mirrored streams as independent research rows.",
        "special_source_assignment": mapping.get("special_source_assignment"),
        "all_known_source_copy_relationships_contained": not conflicts and not identical_file_crossings and not selected_conflicts
            and not (captures - source_groups.keys()) and all(c["contained"] for c in mirror_clusters),
    }


def build_partitions(output):
    output = Path(output)
    target = output / "partitions"
    target.mkdir(exist_ok=True)
    dbpath = target / "membership.sqlite.tmp"
    if dbpath.exists():
        dbpath.unlink()
    db = sqlite3.connect(dbpath)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA cache_size=-32768")
    db.execute("CREATE TABLE membership(uid TEXT PRIMARY KEY,rec TEXT,view TEXT,seq INTEGER,ts INTEGER,partition TEXT)")
    groups = defaultdict(lambda: {"events": 0, "labels": Counter(), "views": [], "first_us": None, "last_us": None})
    view_ranges = {}
    source_tables = []
    for directory in extraction_dirs(output):
        path = directory / "events.parquet"
        n = 0
        for batch in pq.ParquetFile(path).iter_batches(columns=["event_uid", "recording_id", "view_id", "event_seq", "ts_complete_us"]):
            values = []
            for r in batch.to_pylist():
                rec = r["recording_id"]
                partition = ASSIGNMENTS[rec]
                view = r["view_id"]
                info = view_ranges.setdefault(view, {"recording_id": rec, "partition": partition, "events": 0})
                if (view != directory.name or info["recording_id"] != rec
                        or r["event_seq"] != info["events"] + 1
                        or r["event_uid"] != f'{view}:e{r["event_seq"]}'):
                    raise ValueError(f"Noncanonical/duplicate/gapped event membership in {directory}")
                info["events"] += 1
                g = groups[rec]
                g["events"] += 1
                ts = r["ts_complete_us"]
                if ts is not None:
                    g["first_us"] = min(g["first_us"], ts) if g["first_us"] is not None else ts
                    g["last_us"] = max(g["last_us"], ts) if g["last_us"] is not None else ts
                values.append((r["event_uid"], rec, r["view_id"], r["event_seq"], ts, partition))
            db.executemany("INSERT INTO membership VALUES (?,?,?,?,?,?)", values)
            n += len(values)
        if not n:
            raise ValueError(f"Empty extraction cannot establish view membership: {directory}")
        rec = view_ranges[directory.name]["recording_id"]
        groups[rec]["views"].append(directory.name)
        annotations = directory / "annotations.parquet"
        annotation_count = 0
        if annotations.exists():
            schema = pq.ParquetFile(annotations).schema_arrow.names
            column = next(c for c in ("component_label", "target_label", "label") if c in schema)
            for batch in pq.ParquetFile(annotations).iter_batches(columns=["event_uid", "recording_id", "view_id", column]):
                for row in batch.to_pylist():
                    annotation_count += 1
                    if (row["event_uid"] != f"{directory.name}:e{annotation_count}"
                            or row["recording_id"] != rec or row["view_id"] != directory.name):
                        raise ValueError(f"Annotation/event membership mismatch in {directory}")
                    groups[rec]["labels"].update([row[column] or "unlabelled"])
        if annotation_count != n:
            raise ValueError(f"Expected one annotation per extracted event in {directory}: {annotation_count}/{n}")
        checkpoint = json.loads((directory / "checkpoint.json").read_text(encoding="utf8"))
        source_tables.append({"view_id": directory.name, "recording_id": rec, "events": n,
                              "events_path": path.relative_to(output).as_posix(), "sha256": sha256(path),
                              "annotation_path": annotations.relative_to(output).as_posix() if annotations.exists() else None,
                              "annotation_sha256": sha256(annotations) if annotations.exists() else None,
                              "annotation_count": annotation_count,
                              "source_paths": [s["path"] for s in checkpoint["contract"]["sources"]]})
    db.commit()
    db.execute("CREATE INDEX chronological ON membership(partition,ts,view,seq)")
    partitions = {}
    for part in sorted(set(ASSIGNMENTS.values())):
        writer = pq.ParquetWriter(target / f"{part}_membership.parquet.tmp", MEMBER_SCHEMA, compression="zstd")
        cur = db.execute("SELECT uid,rec,view,seq,ts,partition FROM membership WHERE partition=? ORDER BY ts,view,seq", (part,))
        n = 0
        previous = None
        while rows := cur.fetchmany(30000):
            buf = [dict(zip(MEMBER_SCHEMA.names, r)) for r in rows]
            for row in buf:
                ts = row["ts_complete_us"]
                if ts is not None:
                    assert previous is None or ts >= previous
                    previous = ts
            writer.write_table(pa.Table.from_pylist(buf, schema=MEMBER_SCHEMA))
            n += len(buf)
        writer.close()
        (target / f"{part}_membership.parquet.tmp").replace(target / f"{part}_membership.parquet")
        partitions[part] = {"events": n, "recording_ids": [g for g in groups if ASSIGNMENTS[g] == part],
                            "membership_file": f"partitions/{part}_membership.parquet"}
    class_groups = {c: [rec for rec, g in groups.items() if g["labels"].get(c, 0)]
                    for c in ("normal", "command_injection", "response_injection")}
    split_classes = {p: {c: sum(groups[g]["labels"].get(c, 0) for g in info["recording_ids"])
                        for c in class_groups} for p, info in partitions.items()}
    # Exhaustive endpoint membership against exhaustively validated contiguous domains.
    pair_crossings = 0
    missing_pair_ids = 0
    pair_relations = 0
    for directory in extraction_dirs(output):
        pairfile = directory / "pairs.parquet"
        for batch in pq.ParquetFile(pairfile).iter_batches(columns=["recording_id", "view_id", "request_uid", "response_uid", "candidate_request_uids"]):
            for r in batch.to_pylist():
                expected = ASSIGNMENTS[r["recording_id"]]
                ids = set([i for i in (r["request_uid"], r["response_uid"]) if i] + (r["candidate_request_uids"] or []))
                for uid in ids:
                    actual = uid_membership(uid, view_ranges)
                    if actual is None:
                        missing_pair_ids += 1
                    elif (actual["partition"] != expected or actual["recording_id"] != r["recording_id"]
                          or uid.rsplit(":e", 1)[0] != r["view_id"]):
                        pair_crossings += 1
                pair_relations += 1
    total = sum(g["events"] for g in groups.values())
    if not total:
        raise ValueError("No published, reconciled extraction is available for partitioning")
    copy_report = source_group_containment(output, selected_sources=source_tables)
    write_json(output / "duplicate_containment.json", copy_report)
    for part, info in partitions.items():
        info["row_fraction"] = info["events"] / total if total else None
        info["group_fraction"] = len(info["recording_ids"]) / len(groups) if groups else None
        info["class_counts"] = split_classes[part]
    groups_json = [{"recording_id": rec, "partition": ASSIGNMENTS[rec], **g,
                    "labels": dict(g["labels"])} for rec, g in groups.items()]
    manifest = {
        "status": "CANDIDATE_ONLY_UNSUPPORTED_INDEPENDENT_THREE_CLASS_EXPERIMENT",
        "strategy": "whole capture campaigns; fixed chronological scenario holdouts; never selected using model scores",
        "requested_fraction": [0.70, 0.15, 0.15], "groups": groups_json,
        "partitions": partitions, "class_bearing_groups": class_groups, "source_tables": source_tables,
        "pair_relations_checked": pair_relations, "pair_partition_crossings": pair_crossings,
        "missing_pair_event_ids": missing_pair_ids, "event_membership_count": total,
        "event_uid_ranges": view_ranges,
        "pair_membership_check": "Every event UID and contiguous per-view sequence checked exhaustively, then every pair/candidate endpoint checked against the exact canonical UID domain and its recording/view/partition. No per-endpoint SQLite queries.",
        "annotations_one_to_one_with_events": True,
        "duplicate_containment_report": "duplicate_containment.json",
        "known_source_copy_relationships_contained": copy_report["all_known_source_copy_relationships_contained"],
        "class_complete_each_partition": all(all(count > 0 for count in cls.values()) for cls in split_classes.values()),
        "boundary_policy": "Reset at recording/view/connection generations and observed gaps; retain entire selected chains. No context crosses partitions. No history/window materialized.",
        "future_horizons": {"candidate_event_lookbacks": [3, 5, 10], "maximum_time_lookback": "not yet specified by researcher", "label_horizon": "offline audit only; deployment decision contract must be selected later", "purge": "no shared campaigns; any future temporal subdivision or horizon change requires new boundary validation"},
        "limitation": "Four source capture campaigns share a simulated testbed. Days, rotation files, endpoints and individual attack logs do not create independent replications. Class-complete independent training/validation/test is not supported.",
    }
    assert pair_crossings == 0 and missing_pair_ids == 0
    write_json(output / "split_manifest.json", manifest)
    db.close()
    dbpath.unlink()
    return manifest


def validate_extraction(output, raw_root, rehash=True):
    output, raw_root = Path(output), Path(raw_root)
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf8"))
    checks, source_check = [], []
    t0 = time.monotonic()
    for item in inventory["files"]:
        p = raw_root / item["path"]
        ok = p.exists() and p.stat().st_size == item["bytes"]
        if rehash and ok:
            ok = sha256(p) == item["sha256"]
        source_check.append({"path": item["path"], "unchanged": ok, "sha256_rechecked": rehash})
    if rehash:
        write_json(output / "source_preservation.json", {"all_unchanged": all(x["unchanged"] for x in source_check),
                   "files": source_check, "elapsed_s": round(time.monotonic() - t0, 2)})
    summaries = []
    for directory in extraction_dirs(output):
        checkpoint = json.loads((directory / "checkpoint.json").read_text(encoding="utf8"))
        contract = checkpoint["contract"]
        chunks = {item["chunk"]: item for item in contract["sources"]}
        counters = Counter()
        fn = Counter()
        zeros = Counter()
        joint_distribution = Counter()
        response_injection_shape = Counter()
        annotations_path = directory / "annotations.parquet"
        annotation_rows = (
            (row for batch in pq.ParquetFile(annotations_path).iter_batches(
                batch_size=20000, columns=["event_uid", "recording_id", "view_id", "component_label", "annotation_state"])
             for row in batch.to_pylist())
            if annotations_path.exists() else iter(())
        )
        annotation_count = 0
        annotation_membership_errors = 0
        previous_seq = 0
        chronological_emission_reversals = 0
        previous_ts = None
        row_invariants = True
        for batch in pq.ParquetFile(directory / "events.parquet").iter_batches(batch_size=20000):
            for r in batch.to_pylist():
                annotation = next(annotation_rows, None)
                if annotation is None:
                    annotation_membership_errors += 1
                    label, state = "ANNOTATION_MISSING", "ANNOTATION_MISSING"
                else:
                    annotation_count += 1
                    annotation_membership_errors += any(
                        annotation[key] != r[key] for key in ("event_uid", "recording_id", "view_id"))
                    label = annotation["component_label"] or "unlabelled"
                    state = annotation["annotation_state"]
                joint_distribution[(label, state, r["parse_status"], r["func_code"], r["direction"])] += 1
                if label == "response_injection":
                    response_injection_shape[r["parse_status"]] += 1
                counters["records"] += 1
                counters["record_kind:" + r["record_kind"]] += 1
                counters["parse_status:" + r["parse_status"]] += 1
                counters["direction:" + r["direction"]] += 1
                fn[str(r["func_raw"])] += 1
                for col in ("address", "quantity", "single_value", "byte_count"):
                    if r[col] is None:
                        zeros[col + "_null"] += 1
                    elif r[col] == 0:
                        zeros[col + "_wire_zero"] += 1
                counters["segmented_records"] += r["n_segments"] > 1
                counters["cross_chunk_records"] += r["first_chunk"] != r["last_chunk"]
                counters["out_of_order_records"] += bool(r["reasm_ooo"])
                row_invariants &= r["event_seq"] == previous_seq + 1
                previous_seq = r["event_seq"]
                row_invariants &= r["event_uid"] == f'{r["view_id"]}:e{r["event_seq"]}'
                row_invariants &= r["view_id"] == contract["view_id"] == directory.name
                row_invariants &= r["recording_id"] == contract["recording_id"]
                row_invariants &= r["conn_uid"].startswith(r["view_id"] + ":c")
                row_invariants &= r["adu_len"] == len(r["adu_bytes"])
                row_invariants &= hashlib.sha256(r["adu_bytes"]).hexdigest() == r["adu_sha256"]
                row_invariants &= r["stream_off_end"] - r["stream_off_start"] == r["adu_len"]
                row_invariants &= bool(r["segment_refs"])
                row_invariants &= r["n_segments"] == len(r["segment_refs"] or [])
                covered = 0
                for seg in r["segment_refs"] or []:
                    row_invariants &= seg["pcap_offset"] >= 24 and seg["frame"] > 0
                    row_invariants &= 0 <= seg["event_byte_start"] < seg["event_byte_end"] <= r["adu_len"]
                    row_invariants &= seg["event_byte_start"] == covered
                    covered = seg["event_byte_end"]
                    source = chunks.get(seg["chunk"])
                    row_invariants &= source is not None and seg["pcap_offset"] < source["bytes"]
                row_invariants &= covered == r["adu_len"]
                row_invariants &= r["protocol_role"] == ("request" if r["direction"] == "c2s" else "response")
                if r["record_kind"] == "adu":
                    row_invariants &= r["pdu_bytes"] == r["adu_bytes"][7:]
                    row_invariants &= r["pdu_len"] == len(r["pdu_bytes"])
                ts = r["ts_complete_us"]
                if ts is not None and previous_ts is not None and ts < previous_ts:
                    chronological_emission_reversals += 1
                previous_ts = ts
        acc = json.loads((directory / "accounting.json").read_text())
        if next(annotation_rows, None) is not None:
            annotation_membership_errors += 1
        checks_ok = all(acc.get(k) is True for k in ("check_bytes_captured_eq_dup_plus_delivered", "check_bytes_delivered_eq_records", "check_frames_accounted"))
        record_count_ok = counters["records"] == sum(acc.get("records_" + kind, 0) for kind in ("adu", "nonframed", "incomplete"))
        checks.append({"view": directory.name, "record_invariants": row_invariants,
                       "accounting_checks": checks_ok, "record_count_reconciled": record_count_ok,
                       "annotation_membership_errors": annotation_membership_errors,
                       "annotations_one_to_one_with_events": annotation_membership_errors == 0 and annotation_count == counters["records"]})
        summaries.append({"view_id": directory.name, "counts": dict(counters), "function_raw_counts": dict(fn),
                          "zero_and_null_counts": dict(zeros), "emission_time_reversals": chronological_emission_reversals,
                          "class_parse_function_direction_distribution": [
                              {"component_label": key[0], "annotation_state": key[1], "parse_status": key[2],
                               "function_code": key[3], "direction": key[4], "count": value}
                              for key, value in sorted(joint_distribution.items(), key=lambda item: str(item[0]))],
                          "accepted_response_injection_parse_status_counts": dict(response_injection_shape),
                          "accepted_response_injection_shape_interpretation": "Counts distinguish malformed supported replies from structurally valid-looking replies; a structural status alone neither proves maliciousness nor establishes a need for machine learning.",
                          "ordering_note": "Decoder emission order can differ from event time due to buffered reassembly/finalization. Partition membership manifests explicitly sort completion times.",
                          "accounting": acc})
    report = {"source_immutability": all(x["unchanged"] for x in source_check), "source_hashes_rechecked": rehash,
              "checks": checks, "views": summaries,
              "all_row_and_accounting_checks_pass": bool(checks) and all(c["record_invariants"] and c["accounting_checks"] and c["record_count_reconciled"] and c["annotations_one_to_one_with_events"] for c in checks),
              "dataset_scope": "Only permitted original CIC sources. Old exports are diagnostic references only.",
              "stage_boundary": "No model preprocessing, model features/windows/matrices, fitted transformations, balancing, normal profiles or training executed."}
    write_json(output / "quality_report.json", report)
    return report
