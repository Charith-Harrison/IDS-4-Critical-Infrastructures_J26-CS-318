"""Preserve all original CIC CSV/XLSX log rows and expose conservative episodes.

Times remain timezone-naive evidence. ``timestamp_us`` is an explicit candidate
UTC interpretation for clock calibration, never an assertion of source timezone.
Original text/Excel serials are retained; no completion sentinel is wire-wrapped.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET
from zipfile import ZipFile

import pyarrow as pa
import pyarrow.parquet as pq

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
RNS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
M = "{" + NS["m"] + "}"
EPOCH_EXCEL = Decimal("25569")
SCHEMA = pa.schema([
    ("event_id", pa.string()), ("scenario", pa.string()), ("recording_id", pa.string()),
    ("source_path", pa.string()), ("source_sha256", pa.string()), ("source_sheet", pa.string()),
    ("source_row", pa.int64()), ("source_line", pa.int64()), ("timestamp_original", pa.string()),
    ("timestamp_us", pa.int64()), ("timestamp_status", pa.string()),
    ("timestamp_timezone", pa.string()), ("excel_date_system", pa.string()),
    ("excel_serial_original", pa.string()), ("excel_epoch_us_decimal", pa.string()),
    ("target_ip", pa.string()), ("attack_original", pa.string()), ("transaction_id_original", pa.string()),
    ("transaction_id", pa.int64()), ("wire_tid_valid", pa.bool_()),
    ("family", pa.string()), ("completion", pa.bool_()), ("coil_address", pa.int64()),
    ("evidence_eligibility", pa.string()), ("raw_fields_json", pa.string()),
])
EPISODE_SCHEMA = pa.schema([
    ("episode_id", pa.string()), ("scenario", pa.string()), ("recording_id", pa.string()),
    ("source_path", pa.string()), ("source_sheet", pa.string()), ("family", pa.string()),
    ("target_ip", pa.string()), ("start_event_id", pa.string()), ("end_event_id", pa.string()),
    ("start_ts_us", pa.int64()), ("end_ts_us", pa.int64()),
    ("start_transaction_id", pa.int64()), ("end_transaction_id", pa.int64()),
    ("coil_address", pa.int64()), ("attack_original", pa.string()), ("status", pa.string()),
])


def family(text):
    lower = text.lower()
    if "false data" in lower:
        return "false_data_injection"
    if "delay" in lower:
        return "delay_response"
    if "brute force" in lower or "specific coil" in lower:
        return "brute_force_or_specific_coil"
    if "length" in lower:
        return "length_manipulation"
    if "payload" in lower:
        return "loading_payloads"
    if "stack" in lower:
        return "stacking_frames"
    if "flood" in lower:
        return "query_flooding"
    if "replay" in lower:
        return "baseline_replay"
    if "recon" in lower:
        return "reconnaissance"
    return "unknown"


def parse_timestamp(text):
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is not None:
            return int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000), "explicit_timezone"
        delta = dt - datetime(1970, 1, 1)
        return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds, "full_naive_candidate_utc"
    except (ValueError, TypeError):
        return None, "truncated_or_unparsed"


def xlsx_rows(path):
    """Yield sheet/row/raw values + exact timestamp numeric serial without Excel."""
    with ZipFile(path) as z:
        strings = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            strings = ["".join(si.itertext()) for si in root.findall("m:si", NS)]
        workbook = ET.fromstring(z.read("xl/workbook.xml"))
        props = workbook.find("m:workbookPr", NS)
        date1904 = props is not None and props.get("date1904", "0").lower() in ("1", "true")
        relroot = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rels = {el.get("Id"): el.get("Target") for el in relroot}
        for sheet in workbook.findall("m:sheets/m:sheet", NS):
            target = rels[sheet.get(RNS + "id")]
            entry = "xl/" + target.lstrip("/") if not target.startswith("/") else target.lstrip("/")
            headers = None
            with z.open(entry) as fh:
                for event, row in ET.iterparse(fh, events=("end",)):
                    if row.tag != M + "row":
                        continue
                    cells, serial = {}, None
                    for c in row.findall("m:c", NS):
                        ref = c.get("r", "")
                        col = re.sub(r"\d", "", ref)
                        node = c.find("m:v", NS)
                        value = node.text if node is not None else ""
                        if c.get("t") == "s":
                            value = strings[int(value)] if value else ""
                        elif c.get("t") == "inlineStr":
                            value = "".join(c.itertext())
                        if col == "A" and c.get("t") not in ("s", "inlineStr"):
                            serial = value or None
                        cells[col] = value or ""
                    if headers is None:
                        headers = cells
                    else:
                        yield sheet.get("name"), int(row.get("r")), {headers.get(k, k): v for k, v in cells.items()}, serial, date1904
                    row.clear()


def make_row(rel, source_sha, values, row_number, sheet=None, serial=None, date1904=False, eligibility="candidate_evidence_requires_packet_match"):
    scenario = "benign" if rel.startswith("benign/") else rel.split("/")[1]
    rec = {"compromised-ied": "cic_compromised_ied_march", "compromised-scada": "cic_compromised_scada_march", "external": "cic_external_february"}[scenario]
    original = values.get("Timestamp", "")
    micros, status = parse_timestamp(original)
    exact_us = None
    if serial:
        # Standard Excel 1900 system includes the leap-year compatibility day.
        origin = Decimal("24107") if date1904 else EPOCH_EXCEL
        exact_us = (Decimal(serial) - origin) * Decimal("86400000000")
        micros = int(exact_us.to_integral_value(rounding=ROUND_HALF_EVEN))
        status = "excel_numeric_naive_candidate_utc_us_rounded_original_serial_preserved"
        original = serial
    attack = values.get("Attack", "")
    tid_orig = values.get("TransactionID")
    try:
        tid = int(tid_orig) if tid_orig not in (None, "") else None
    except ValueError:
        tid = None
    address = re.search(r"Address:\s*(\d+)", attack)
    event_id = "log:" + hashlib.sha256((rel + "|" + (sheet or "") + "|" + str(row_number)).encode()).hexdigest()[:24]
    return {"event_id": event_id, "scenario": scenario, "recording_id": rec,
            "source_path": rel, "source_sha256": source_sha, "source_sheet": sheet,
            "source_row": row_number, "source_line": row_number if sheet is None else None,
            "timestamp_original": original, "timestamp_us": micros, "timestamp_status": status,
            "timestamp_timezone": "unknown; timestamp_us is candidate UTC interpretation for calibration",
            "excel_date_system": ("1904" if date1904 else "1900") if serial else None,
            "excel_serial_original": serial, "excel_epoch_us_decimal": str(exact_us) if exact_us is not None else None,
            "target_ip": values.get("TargetIP") or None, "attack_original": attack,
            "transaction_id_original": tid_orig, "transaction_id": tid,
            "wire_tid_valid": tid is not None and 0 <= tid <= 65535,
            "family": family(attack), "completion": "complete" in attack.lower() or "sending response" in attack.lower(),
            "coil_address": int(address.group(1)) if address else None,
            "evidence_eligibility": eligibility, "raw_fields_json": json.dumps(values, ensure_ascii=False, separators=(",", ":"))}


def run_logs(raw_root, output):
    import csv
    raw_root, output = Path(raw_root).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in raw_root.rglob("*") if p.suffix.lower() in (".csv", ".xlsx"))
    rows, episodes = [], []
    per_source = []
    total = Counter()
    t0 = time.monotonic()
    out_path, ep_path = output / "logs.parquet", output / "log_episodes.parquet"
    # New files are published only after successful complete parsing.
    with pq.ParquetWriter(str(out_path) + ".tmp", SCHEMA, compression="zstd") as writer, pq.ParquetWriter(str(ep_path) + ".tmp", EPISODE_SCHEMA, compression="zstd") as ep_writer:
        def flush(force=False):
            if rows and (force or len(rows) >= 25_000):
                writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA))
                rows.clear()
            if episodes and (force or len(episodes) >= 25_000):
                ep_writer.write_table(pa.Table.from_pylist(episodes, schema=EPISODE_SCHEMA))
                episodes.clear()
        for path in files:
            rel = path.relative_to(raw_root).as_posix()
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            stats, seen = Counter(), set()
            pending = {}
            minimum, maximum = None, None
            if path.suffix.lower() == ".csv":
                eligibility = "superseded_time_damaged_csv_version" if rel.endswith("03-21-2023-1-original.csv") else "candidate_evidence_requires_packet_match"
                fh = path.open("r", encoding="utf-8-sig", newline="")
                reader = csv.DictReader(fh)
                source = ((None, i, values, None, False) for i, values in enumerate(reader, 2))
                headers = list(reader.fieldnames or [])
            else:
                eligibility = "candidate_evidence_requires_packet_match"
                source = xlsx_rows(path)
                fh = None
                headers = ["Timestamp", "TargetIP", "Attack", "TransactionID"]
            sheets = Counter()
            for sheet, num, values, serial, date1904 in source:
                row = make_row(rel, sha, values, num, sheet, serial, date1904, eligibility)
                rows.append(row)
                ts = row["timestamp_us"]
                stats["rows"] += 1
                stats["wire_tid_valid" if row["wire_tid_valid"] else "wire_tid_missing_or_outside_uint16"] += 1
                stats["family:" + row["family"]] += 1
                stats["timestamp:" + row["timestamp_status"]] += 1
                if sheet:
                    sheets[sheet] += 1
                if ts is not None:
                    minimum = ts if minimum is None else min(ts, minimum)
                    maximum = ts if maximum is None else max(ts, maximum)
                signature = (row["timestamp_original"], row["target_ip"], row["attack_original"], row["transaction_id_original"])
                if signature in seen:
                    stats["exact_signature_duplicate_excess"] += 1
                seen.add(signature)
                # Pair only source-adjacent family start/completion records; never invent broad windows.
                key = (sheet, row["target_ip"], row["family"])
                if row["completion"] and key in pending:
                    start = pending.pop(key)
                    if start["timestamp_us"] is not None and ts is not None and ts >= start["timestamp_us"]:
                        episodes.append({"episode_id": "episode:" + start["event_id"][4:], "scenario": row["scenario"],
                                         "recording_id": row["recording_id"], "source_path": rel, "source_sheet": sheet,
                                         "family": row["family"], "target_ip": row["target_ip"],
                                         "start_event_id": start["event_id"], "end_event_id": row["event_id"],
                                         "start_ts_us": start["timestamp_us"], "end_ts_us": ts,
                                         "start_transaction_id": start["transaction_id"], "end_transaction_id": row["transaction_id"],
                                         "coil_address": start["coil_address"], "attack_original": start["attack_original"],
                                         "status": "candidate_tool_interval_not_packet_ground_truth"})
                        stats["candidate_start_completion_intervals"] += 1
                elif not row["completion"]:
                    pending[key] = row
                flush()
            if fh:
                fh.close()
            summary = {"path": rel, "headers": headers, "first_ts_us_candidate_utc": minimum,
                       "last_ts_us_candidate_utc": maximum, "sheets": dict(sheets), **stats}
            per_source.append(summary)
            total.update(stats)
            print(f"logs {rel} rows={stats['rows']} elapsed={time.monotonic()-t0:.1f}s", flush=True)
        flush(True)
    Path(str(out_path) + ".tmp").replace(out_path)
    Path(str(ep_path) + ".tmp").replace(ep_path)
    summary = {"total": dict(total), "sources": per_source, "elapsed_s": round(time.monotonic()-t0, 3),
               "timezone_policy": "Naive times retain unknown timezone. Candidate UTC integers permit calibration; no fixed offset applied.",
               "tid_policy": "1048575 and all out-of-uint16 IDs preserved as original tool metadata; never modulo-reduced.",
               "duplicate_policy": "all original rows retained; signature repetition is not independent packet evidence",
               "version_policy": "March21 short-time CSV preserved but ineligible; workbook sheets retain full date/hour/serial. Reconciliation follows separately."}
    (output / "log_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
    reconcile_workbook_versions(output)
    return summary


def reconcile_workbook_versions(output):
    """Verify original CSV is a shortened timestamp view of XLSX IED4C sheet."""
    output = Path(output)
    cols = ["source_path", "source_sheet", "source_row", "timestamp_original", "timestamp_us",
            "target_ip", "attack_original", "transaction_id_original"]
    csv_rows, sheet_rows = [], []
    for batch in pq.ParquetFile(output / "logs.parquet").iter_batches(batch_size=30_000, columns=cols):
        for row in batch.to_pylist():
            if row["source_path"].endswith("03-21-2023-1-original.csv"):
                csv_rows.append(row)
            elif row["source_path"].endswith("03-21-2023-1-formatted.xlsx") and row["source_sheet"] == "To IED4C":
                sheet_rows.append(row)
    csv_rows.sort(key=lambda r: r["source_row"])
    sheet_rows.sort(key=lambda r: r["source_row"])
    fields_match = timestamp_match = 0
    mismatches = []
    for old, rich in zip(csv_rows, sheet_rows):
        same = all(old[k] == rich[k] for k in ("target_ip", "attack_original", "transaction_id_original"))
        fields_match += same
        # The CSV display is minutes:seconds.tenths; no date or hour survives.
        exact_us = (Decimal(rich["timestamp_original"]) - EPOCH_EXCEL) * Decimal("86400000000")
        tenth = int((exact_us / Decimal("100000")).to_integral_value(rounding=ROUND_HALF_UP))
        projected = f"{(tenth // 600) % 60:02d}:{(tenth % 600) / 10:04.1f}"
        time_same = old["timestamp_original"] == projected
        timestamp_match += time_same
        if (not same or not time_same) and len(mismatches) < 10:
            mismatches.append({"csv_row": old["source_row"], "xlsx_row": rich["source_row"],
                               "non_time_fields_match": same, "csv_timestamp": old["timestamp_original"],
                               "projected_xlsx_short_display": projected})
    result = {"csv_rows": len(csv_rows), "xlsx_ied4c_rows": len(sheet_rows),
              "rowwise_non_time_fields_matching": fields_match, "rowwise_short_display_timestamps_matching": timestamp_match,
              "status": ("verified_version_overlap" if len(csv_rows) == len(sheet_rows) == fields_match == timestamp_match
                         else "verified_non_time_version_overlap_with_display_rounding_differences" if len(csv_rows) == len(sheet_rows) == fields_match
                         else "partial_version_overlap"),
              "short_display_rounding_difference_rows": len(csv_rows) - timestamp_match,
              "policy": "Preserve both sources. Do not double-count the time-damaged CSV as new log evidence; use original XLSX full serial for candidate clock calibration.",
              "timestamp_precision_limit": "XLSX serial text and exact decimal epoch microseconds retained; integer timestamp_us is rounded for joins. Source timezone unknown.",
              "example_mismatches": mismatches}
    (output / "workbook_reconciliation.json").write_text(json.dumps(result, indent=2), encoding="utf8")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-root", default="data/raw/Modbus Dataset")
    ap.add_argument("--output", default="component3_preparation/output")
    args = ap.parse_args()
    run_logs(args.raw_root, args.output)
