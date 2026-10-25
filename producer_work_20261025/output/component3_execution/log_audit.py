"""Read-only CIC attack-log audit. No packet extraction, labels, or dataset split.

Usage: python log_audit.py --source 'G:/modbus cic 2023/Modbus Dataset' --output DIR
All log timestamps remain verbatim. No timezone or time-of-day repair is inferred.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib
import json
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET


def time_shape(value: str) -> str:
    if not value:
        return "empty"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?", value):
        return "full_naive_datetime"
    if re.fullmatch(r"\d{1,2}:\d{2}(?:\.\d+)?", value):
        return "truncated_mm_ss_or_unknown"
    return "other"


def family(attack: str) -> str:
    text = attack.lower()
    if text.startswith("recon"):
        return "reconnaissance"
    if "brute force" in text:
        return "brute_force_or_specific_coil"
    if "false data" in text:
        return "false_data_injection"
    if "length" in text:
        return "length_manipulation"
    if "delay" in text:
        return "delay_response"
    if "stack" in text:
        return "stacking_frames"
    if "flood" in text:
        return "query_flooding"
    if "payload" in text:
        return "loading_payloads"
    if "replay" in text or "baseline" in text:
        return "baseline_replay"
    return "other"


def audit(source: Path) -> dict:
    logs = []
    global_attacks = collections.Counter()
    global_families = collections.Counter()
    global_samples = collections.defaultdict(list)
    global_tids = collections.defaultdict(collections.Counter)
    global_bad_tid_samples = []
    global_signatures = collections.Counter()
    global_dates = collections.Counter()
    global_targets = collections.Counter()
    for path in sorted(source.rglob("*.csv")):
        raw = path.read_bytes()
        encoding = "utf-8-sig"
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            encoding = "cp1252"
            decoded = raw.decode(encoding)
        reader = csv.DictReader(decoded.splitlines())
        attacks = collections.Counter()
        families = collections.Counter()
        shapes = collections.Counter()
        precisions = collections.Counter()
        targets = collections.Counter()
        tid_stats = collections.Counter()
        signatures = collections.Counter()
        full_datetimes = []
        malformed = []
        first_rows = []
        events = 0
        complete_events = 0
        for line, row in enumerate(reader, start=2):
            events += 1
            if None in row or any(v is None for v in row.values()):
                if len(malformed) < 5:
                    malformed.append({"line": line, "row": row})
            ts = row.get("Timestamp", "") or ""
            attack = row.get("Attack", "") or ""
            target = row.get("TargetIP", "") or ""
            tid = row.get("TransactionID", "") or ""
            fam = family(attack)
            attacks[attack] += 1
            families[fam] += 1
            global_attacks[attack] += 1
            global_families[fam] += 1
            if "complete" in attack.lower():
                complete_events += 1
            shapes[time_shape(ts)] += 1
            if time_shape(ts) == "full_naive_datetime":
                full_datetimes.append(ts)
                global_dates[ts[:10]] += 1
            precisions[len(ts.split(".", 1)[1]) if "." in ts else 0] += 1
            targets[target or "<missing>"] += 1
            global_targets[target or "<missing>"] += 1
            sample = {"file": str(path.relative_to(source)), "line": line, **row}
            if len(first_rows) < 3:
                first_rows.append(sample)
            if len(global_samples[fam]) < 6 and (len(global_samples[fam]) < 3 or not any(s["file"] == sample["file"] for s in global_samples[fam])):
                global_samples[fam].append(sample)
            if not tid:
                tid_state = "missing"
            else:
                try:
                    tid_num = int(tid)
                    tid_state = "integer_uint16" if 0 <= tid_num <= 65535 else "integer_outside_uint16"
                    if tid_state == "integer_outside_uint16" and len(global_bad_tid_samples) < 12:
                        global_bad_tid_samples.append(sample)
                except ValueError:
                    tid_state = "non_integer"
            tid_stats[tid_state] += 1
            global_tids[fam][tid_state] += 1
            signature = tuple(row.get(k, "") or "" for k in ["Timestamp", "TargetIP", "Attack", "TransactionID"])
            signatures[signature] += 1
            global_signatures[signature] += 1
        logs.append({
            "path": str(path.relative_to(source)), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "encoding": encoding,
            "header": reader.fieldnames, "rows": events,
            "attack_counts": dict(attacks), "family_counts": dict(families),
            "timestamp_shapes": dict(shapes), "fractional_digits_counts": dict(precisions),
            "datetime_min_verbatim": min(full_datetimes) if full_datetimes else None,
            "datetime_max_verbatim": max(full_datetimes) if full_datetimes else None,
            "targets": dict(targets), "transaction_id_status": dict(tid_stats),
            "duplicate_exact_event_excess": sum(n - 1 for n in signatures.values()),
            "unique_event_signatures": len(signatures), "complete_event_rows": complete_events,
            "malformed_examples": malformed, "first_rows": first_rows,
        })
    return {
        "source": str(source), "operation": "read_only_log_and_readme_audit",
        "readme_sha256": hashlib.sha256((source / "README.md").read_bytes()).hexdigest(),
        "timestamp_policy": "Preserve text; timezone unknown; truncated times not repaired.",
        "csv_files": len(logs), "csv_bytes": sum(x["bytes"] for x in logs),
        "rows": sum(x["rows"] for x in logs),
        "attack_counts": dict(global_attacks), "family_counts": dict(global_families),
        "timestamp_dates": dict(global_dates), "targets": dict(global_targets),
        "transaction_id_status_by_family": {k: dict(v) for k, v in global_tids.items()},
        "duplicate_exact_event_excess_across_all_logs": sum(n - 1 for n in global_signatures.values()),
        "representative_rows_by_family": dict(global_samples),
        "transaction_id_outside_uint16_examples": global_bad_tid_samples,
        "logs": logs,
    }


def audit_workbooks(source: Path) -> list[dict]:
    """Inspect XLSX container XML without executing formulas/macros or changing source."""
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main", "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    workbooks = []
    for path in source.rglob("*.xlsx"):
        with zipfile.ZipFile(path) as archive:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            properties = workbook.find("m:workbookPr", ns)
            uses_1904 = properties is not None and properties.get("date1904") in ("1", "true")
            epoch = datetime.datetime(1904, 1, 1) if uses_1904 else datetime.datetime(1899, 12, 30)
            shared = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            strings = ["".join(item.itertext()) for item in shared]
            rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
            relations = {item.get("Id"): item.get("Target") for item in rels}
            styles = ET.fromstring(archive.read("xl/styles.xml"))
            cell_styles = styles.find("m:cellXfs", ns)
            sheets = []
            companion_csv = path.with_name(path.name.replace("-formatted.xlsx", "-original.csv"))
            csv_rows = []
            if companion_csv.exists():
                with companion_csv.open(encoding="utf-8-sig", newline="") as handle:
                    csv_rows = list(csv.DictReader(handle))
            for sheet in workbook.find("m:sheets", ns):
                target = relations[sheet.get("{" + ns["r"] + "}id")]
                member = target.lstrip("/") if target.startswith("/") else "xl/" + target
                root = ET.fromstring(archive.read(member))
                date_samples = []
                dates = collections.Counter()
                counts = collections.Counter()
                targets = collections.Counter()
                attack_counts = collections.Counter()
                timestamp_signatures = collections.Counter()
                row_count = 0
                csv_content_matches = 0
                csv_time_matches = 0
                csv_time_mismatch_examples = []
                converted_min = None
                converted_max = None
                for row in root.findall("m:sheetData/m:row", ns):
                    if row.get("r") == "1":
                        continue
                    values = {}
                    raw_time = None
                    for cell in row.findall("m:c", ns):
                        val = cell.find("m:v", ns)
                        if val is None:
                            continue
                        value = val.text or ""
                        column = re.sub(r"\d", "", cell.get("r"))
                        values[column] = strings[int(value)] if cell.get("t") == "s" else value
                        if column == "A":
                            raw_time = {"cell": cell.get("r"), "raw_value": value, "style_index": cell.get("s", "0"), "cell_type": cell.get("t", "numeric")}
                    if not values:
                        continue
                    row_count += 1
                    targets[values.get("B", "<missing>")] += 1
                    attack_counts[values.get("C", "<missing>")] += 1
                    if raw_time and raw_time["cell_type"] == "numeric":
                        # Convert exactly to nearest microsecond while retaining raw decimal.
                        microseconds = int((Decimal(raw_time["raw_value"]) * Decimal(86400000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
                        converted = epoch + datetime.timedelta(microseconds=microseconds)
                        converted_min = min(converted_min, converted) if converted_min else converted
                        converted_max = max(converted_max, converted) if converted_max else converted
                        dates[converted.date().isoformat()] += 1
                        counts["numeric_excel_serial_timestamp"] += 1
                        timestamp_signatures[tuple(values.get(k, "") for k in ["A", "B", "C", "D"])] += 1
                        if row_count <= len(csv_rows):
                            csv_row = csv_rows[row_count - 1]
                            if tuple(values.get(k, "") for k in ["B", "C", "D"]) == tuple(csv_row.get(k, "") for k in ["TargetIP", "Attack", "TransactionID"]):
                                csv_content_matches += 1
                            # Excel format 47 renders only mm:ss.0; compare its displayed precision.
                            # This is an overlap diagnostic, not reconstruction of any CSV time.
                            tenths = int((Decimal(raw_time["raw_value"]) * Decimal(864000)).to_integral_value(rounding=ROUND_HALF_EVEN))
                            minute = (tenths // 600) % 60
                            second = (tenths // 10) % 60
                            rendered = f"{minute:02d}:{second:02d}.{tenths % 10}"
                            if rendered == csv_row.get("Timestamp"):
                                csv_time_matches += 1
                            elif csv_content_matches and len(csv_time_mismatch_examples) < 5:
                                csv_time_mismatch_examples.append({"row": row_count + 1, "serial": raw_time["raw_value"], "converted_naive": converted.isoformat(" "), "csv_time": csv_row.get("Timestamp"), "diagnostic_render": rendered})
                        if len(date_samples) < 5:
                            style = cell_styles[int(raw_time["style_index"])] if cell_styles is not None else None
                            date_samples.append({**raw_time, "converted_naive_datetime": converted.isoformat(" "), "numFmtId": style.get("numFmtId") if style is not None else None, "target": values.get("B"), "attack": values.get("C"), "transaction_id": values.get("D")})
                    else:
                        counts["non_numeric_timestamp"] += 1
                sheets.append({"sheet": sheet.get("name"), "member": member, "rows": row_count, "timestamp_cell_types": dict(counts), "date_counts": dict(dates), "datetime_min_naive": converted_min.isoformat(" ") if converted_min else None, "datetime_max_naive": converted_max.isoformat(" ") if converted_max else None, "target_counts": dict(targets), "attack_counts": dict(attack_counts), "duplicate_raw_serial_event_excess": sum(n - 1 for n in timestamp_signatures.values()), "companion_csv_rowwise_content_matches": csv_content_matches, "companion_csv_rowwise_mm_ss_tenth_matches": csv_time_matches, "companion_csv_rows": len(csv_rows), "companion_csv_time_render_mismatch_examples": csv_time_mismatch_examples, "samples": date_samples})
            workbooks.append({"path": str(path.relative_to(source)), "bytes": path.stat().st_size, "date1904": uses_1904, "excel_epoch": epoch.date().isoformat(), "sheets": sheets, "interpretation": "Workbook retains numeric serial date+hour+subsecond values absent from CSV display strings. These are naive wall-clock timestamps; timezone alignment still requires capture evidence. Different sheets and CSV overlap must not be counted as independent events."})
    return workbooks


def write_report(result: dict, output: Path) -> None:
    lines = [
        "# Original CIC log evidence audit", "",
        "This audit reads the original README and attack CSV logs. It does not scan full PCAPs, extract a dataset, create ground-truth labels, or split data.", "",
        f"Source: `{result['source']}`", "",
        f"Found **{result['csv_files']} CSVs**, **{result['rows']:,} rows**, totaling **{result['csv_bytes']:,} bytes**.", "",
        "Log rows are tool events, not necessarily individual network messages. Completion rows, ranges, duplicates, malformed timestamps and oversized transaction IDs prevent a direct one-to-one label join.", "",
        "## Evidence and limits for component 3", "",
        "- The supplied README lists reconnaissance, query flooding, payload loading, response delay, length manipulation, false-data injection, stacked frames, brute-force writes and replay. It does not provide per-packet labels or attack implementation code.",
        "- The seven compromised-IED CSVs contain 676 events, all targeting `185.175.0.2`, the secure HMI according to the README. These include 54 literal `False Data Injection Attack` events on March 23–29, 2023, plus 50 delay-start and 50 response-send events. Their 16-bit transaction IDs and full naive millisecond timestamps make them strong candidates for targeted capture verification. A candidate is not yet a verified response-injection label.",
        "- The compromised-SCADA logs contain brute-force/specific-coil events and payload/length/stacking/replay activity directed at IEDs. These are candidates for command-side analysis, but attack names alone do not prove message direction or mechanism.",
        "- All six external attacker CSVs have only `Timestamp,Attack`. They lack `TargetIP` and `TransactionID`, despite the README's four-column dictionary. Missing values cannot be filled from documentation without packet evidence.",
        "- All CSV times are timezone-naive. Apparent fractional widths of one/two/three digits are literal decimal representations, often consistent with omitted trailing zeros; they do not themselves establish different clock accuracy. Never add a guessed UTC offset.",
        "- Folder dates are not always event dates: `03-12-2023-2.csv` and `03-12-2023-3.csv` contain March 13 events, overlapping the date in other log folders. Determine recording overlap from actual timestamps and packets, never folder names alone.",
        "- The March 21 CSV contains 8,306 rows for target `.8` with truncated `mm:ss.0` time strings. Its companion XLSX retains numeric date/hour/millisecond values, and additionally contains `.4` and `.5` sheets. Do not discard the day before checking the workbook; do not double-count overlapping CSV/workbook records.",
        f"- There are {result['duplicate_exact_event_excess_across_all_logs']:,} excess exact event signatures across the CSVs. Repeated same-millisecond tool-loop events may be real log behavior. This audit reports them; it does not remove them or assume each row is an independent packet.",
        "- Many completed reconnaissance/payload/length/stacking/flooding events have `TransactionID=1048575`, larger than a Modbus 16-bit transaction identifier. Such values cannot be joined as literal wire transaction IDs or silently reduced modulo 65536. Treat their semantics as unverified tool metadata until source code or packet evidence explains them.",
        "- `Baseline Replay: In position` is a state/event annotation, not proof that a replayed message was emitted at exactly that instant. Genuine PLC replies following injected writes also must not be relabelled response injection.",
        "- No source `.py` files or additional local attack implementation documentation were found under the dataset root during the initial metadata search. Mechanism confirmation requires captures or additional original code.", "",
        "## Safe next inspection on her machine", "",
        "1. Index capture headers/ranges and device viewpoints, preserving source paths and original timestamp precision.",
        "2. Check a few exact compromised-IED false-data/delay events against corresponding captures using target, direction, connection, transaction ID, time and bytes together. Establish clock alignment rather than using a broad blanket attack window.",
        "3. Check brute-force/specific-coil events against command requests and genuine acknowledgements, preserving the distinction.",
        "4. Create evidence records with matched/ambiguous/unmatched status. Only verified matches may become mechanism labels; unknown records remain unknown.",
        "5. Reconstruct recording/duplicate-viewpoint/dependency groups before selecting partitions. This audit itself creates no extraction, labels, partitions or model preprocessing.", "",
        "## Per-log inventory", "",
        "| Log | Rows | Timestamp shape | Missing/out-of-range TID | Exact duplicate excess |", "|---|---:|---|---|---:|",
    ]
    for item in result["logs"]:
        status = item["transaction_id_status"]
        problem = ", ".join(f"{key}={n}" for key, n in status.items() if key != "integer_uint16") or "0"
        lines.append(f"| `{item['path']}` | {item['rows']:,} | {item['timestamp_shapes']} | {problem} | {item['duplicate_exact_event_excess']:,} |")
    lines += ["", "## Attack family counts", "", "These families group literal tool-event names for auditing only; they are not attack-mechanism labels.", "", "| Literal family | Log rows |", "|---|---:|"]
    for fam, count in result["family_counts"].items():
        lines.append(f"| {fam} | {count:,} |")
    lines += ["", "## Literal attack names", "", "| Attack text | Rows |", "|---|---:|"]
    for attack, count in result["attack_counts"].items():
        lines.append(f"| `{attack}` | {count:,} |")
    lines += ["", "## Representative verbatim events", ""]
    for fam, rows in result["representative_rows_by_family"].items():
        lines += [f"### {fam}", "", "```json", json.dumps(rows, indent=2), "```", ""]
    lines += ["## Original workbook recovery evidence", "", "The XLSX file is inspected as zipped XML, without formulas, macros or edits. It retains numeric serial timestamps. The CSV's truncated display is therefore not proof that this day's date/hour precision is lost from all originals.", "", "```json", json.dumps(result["workbooks"], indent=2), "```", ""]
    (output / "LOG_EVIDENCE.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output == source or source in output.parents:
        raise SystemExit("Audit reports must not be written into the original dataset.")
    output.mkdir(parents=True, exist_ok=True)
    result = audit(source)
    result["workbooks"] = audit_workbooks(source)
    (output / "log_inventory.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_report(result, output)
    print(json.dumps({k: result[k] for k in ["csv_files", "rows", "csv_bytes", "family_counts", "transaction_id_status_by_family", "duplicate_exact_event_excess_across_all_logs"]}, indent=2))


if __name__ == "__main__":
    main()
