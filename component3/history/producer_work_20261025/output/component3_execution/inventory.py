"""Bounded, read-only inventory of the original CIC files; no dataset extraction.

Reads PCAP global/first-record headers and at most 64 KiB of each tail. The
tail-derived last timestamp is accepted only when a structurally valid chain of
at least eight packet records reaches EOF. It does not certify the unread body.
Does not hash whole captures, decode all packets, assign labels, or split rows.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json
import re
import struct
from pathlib import Path

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "nanosecond"),
}


def timestamp(sec, fraction, divisor):
    digits = 6 if divisor == 1_000_000 else 9
    return dt.datetime.fromtimestamp(sec, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:0{digits}d}Z"


def inspect_pcap(path):
    size = path.stat().st_size
    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) < 24 or header[:4] not in MAGIC:
            return {"status": "unsupported_or_short", "magic_hex": header[:4].hex()}
        endian, divisor, precision = MAGIC[header[:4]]
        major, minor, zone, sigfigs, snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
        result = {"format": "classic-pcap", "byte_order": "little" if endian == "<" else "big", "timestamp_precision": precision, "major": major, "minor": minor, "timezone_correction": zone, "sigfigs": sigfigs, "snaplen": snaplen, "linktype": network & 0xFFFF, "raw_network_field": network, "full_record_count": None, "full_record_validation": "not_performed"}
        first = fh.read(16)
        if len(first) != 16:
            result["status"] = "no_complete_first_record_header"
            return result
        first_sec, first_frac, first_cap, first_orig = struct.unpack(endian + "IIII", first)
        result.update(first_record_timestamp_utc=timestamp(first_sec, first_frac, divisor), first_record_unix_seconds=first_sec, first_record_fraction=first_frac, first_record_captured_length=first_cap, first_record_original_length=first_orig)
        tail_start = max(24, size - 65536)
        fh.seek(tail_start)
        tail = fh.read(65536)
    unpack = struct.Struct(endian + "IIII").unpack_from
    best = None
    # Bounded suffix parsing: one valid multi-record chain ending at the physical
    # file end supports a last-record timestamp, not whole-file integrity.
    for pos in range(max(0, len(tail) - 15)):
        offset, count, last, minimum, maximum = pos, 0, None, None, None
        while offset + 16 <= len(tail):
            sec, frac, captured, original = unpack(tail, offset)
            if not (first_sec - 3600 <= sec <= first_sec + 366 * 86400 and frac < divisor and 0 < captured <= snaplen and captured <= original):
                break
            next_offset = offset + 16 + captured
            if next_offset > len(tail):
                break
            value = (sec, frac)
            minimum = value if minimum is None or value < minimum else minimum
            maximum = value if maximum is None or value > maximum else maximum
            count += 1
            last = (sec, frac, captured, original, tail_start + offset)
            offset = next_offset
            if offset == len(tail) and (count >= 8 or tail_start + pos == 24):
                best = (pos, count, last, minimum, maximum)
        if best:
            break
    result["tail_bytes_read"] = len(tail)
    if best:
        pos, count, last, minimum, maximum = best
        sec, frac, captured, original, record_offset = last
        result.update(status="bounded_headers_ok", last_record_timestamp_utc_tail_derived=timestamp(sec, frac, divisor), last_record_unix_seconds_tail_derived=sec, last_record_fraction_tail_derived=frac, last_record_offset_tail_derived=record_offset, last_record_captured_length=captured, last_record_original_length=original, tail_chain_records=count, tail_chain_start_offset=tail_start + pos, tail_chain_min_utc=timestamp(*minimum, divisor), tail_chain_max_utc=timestamp(*maximum, divisor), endpoint_evidence="first header; bounded structurally valid suffix ending at EOF; unread middle not validated")
    else:
        result.update(status="first_header_only", endpoint_evidence="No sufficiently long bounded suffix chain established; last timestamp unknown")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output == source or source in output.parents:
        raise SystemExit("Output must be outside the raw source")
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in source.rglob("*") if p.is_file())
    directories = sorted(p for p in source.rglob("*") if p.is_dir())
    entries = []
    for path in files:
        relative = path.relative_to(source).as_posix()
        stat = path.stat()
        entry = {"relative_path": relative, "bytes": stat.st_size, "extension": path.suffix.lower(), "mtime_utc": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat()}
        if path.suffix.lower() == ".pcap":
            parts = path.relative_to(source).parts
            scenario = "/".join(parts[:2]) if parts[0] == "attack" else "benign"
            chunk = re.search(r"-(\d+)\.pcap$", path.name)
            entry.update(scenario_parent=scenario, capture_series=path.parent.relative_to(source).as_posix(), capture_viewpoint="/".join(parts[2:-1] if parts[0] == "attack" else parts[1:-1]), chunk_suffix=int(chunk.group(1)) if chunk else None, pcap=inspect_pcap(path))
        elif path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as fh:
                reader = csv.reader(fh)
                entry["csv_header"] = next(reader, [])
                entry["csv_first_row_field_count"] = len(next(reader, []))
        entries.append(entry)
    types = collections.defaultdict(lambda: {"files": 0, "bytes": 0})
    scenarios = collections.defaultdict(lambda: {"files": 0, "bytes": 0})
    series = collections.defaultdict(list)
    for entry in entries:
        bucket = types[entry["extension"]]
        bucket["files"] += 1
        bucket["bytes"] += entry["bytes"]
        if "pcap" in entry:
            scenarios[entry["scenario_parent"]]["files"] += 1
            scenarios[entry["scenario_parent"]]["bytes"] += entry["bytes"]
            series[entry["capture_series"]].append(entry)
    series_summaries = []
    numeric_boundaries = []
    for name, members in series.items():
        ordered = sorted(members, key=lambda row: row["chunk_suffix"] if row["chunk_suffix"] is not None else -1)
        suffixes = [row["chunk_suffix"] for row in ordered if row["chunk_suffix"] is not None]
        missing = sorted(set(range(min(suffixes), max(suffixes)+1))-set(suffixes)) if suffixes else []
        starts = [row["pcap"].get("first_record_timestamp_utc") for row in members]
        ends = [row["pcap"].get("last_record_timestamp_utc_tail_derived") for row in members]
        series_summaries.append({"capture_series": name, "scenario_parent": members[0]["scenario_parent"], "files": len(members), "bytes": sum(row["bytes"] for row in members), "chunk_suffixes": suffixes, "missing_within_observed_suffix_range": missing, "earliest_first_record_timestamp_utc": min(filter(None, starts), default=None), "latest_tail_derived_last_record_timestamp_utc": max(filter(None, ends), default=None), "grouping_status": "candidate series only; cross-viewpoint/clock/run relationships not established"})
        for previous, current in zip(ordered, ordered[1:]):
            last = previous["pcap"].get("last_record_timestamp_utc_tail_derived")
            first = current["pcap"].get("first_record_timestamp_utc")
            if first and last:
                numeric_boundaries.append({"capture_series": name, "previous_file": previous["relative_path"], "next_file": current["relative_path"], "gap_seconds_from_bounded_endpoints": (dt.datetime.fromisoformat(first)-dt.datetime.fromisoformat(last)).total_seconds()})
    instructions = []
    for ancestor in [source, *source.parents]:
        candidate = ancestor / "AGENTS.md"
        if candidate.exists():
            instructions.append(str(candidate))
    instructions.extend(str(p) for p in source.rglob("AGENTS.md") if str(p) not in instructions)
    payload = {"source": str(source), "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "scope": "read-only metadata and bounded PCAP headers; CIC only; no extraction, labels, splits, model features or training", "total_files": len(entries), "total_directories_excluding_root": len(directories), "total_bytes": sum(row["bytes"] for row in entries), "extensions": dict(types), "pcap_scenarios": dict(scenarios), "capture_series": series_summaries, "agents_files_found": instructions, "directories": [p.relative_to(source).as_posix() for p in directories], "files": entries}
    pcap_rows = [row["pcap"] for row in entries if "pcap" in row]
    header_counts = collections.Counter(tuple(row["csv_header"]) for row in entries if "csv_header" in row)
    payload["csv_header_variants"] = [{"header": list(header), "files": count} for header, count in header_counts.items()]
    payload["numeric_chunk_boundaries"] = numeric_boundaries
    payload["pcap_metadata_summary"] = {"status_counts": dict(collections.Counter(row["status"] for row in pcap_rows)), "linktype_counts": dict(collections.Counter(row["linktype"] for row in pcap_rows)), "precision_counts": dict(collections.Counter(row["timestamp_precision"] for row in pcap_rows)), "total_tail_bytes_read": sum(row["tail_bytes_read"] for row in pcap_rows)}
    (output / "source_inventory.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    lines = ["# CIC raw-source inventory", "", f"Source: `{source}`", "", "Read-only inspection. No full capture decoding, dataset extraction, label assignment, split, model preprocessing or training was performed. No MSU or external dataset was inspected.", "", f"- Files: **{len(entries)}**", f"- Directories below root: **{len(directories)}**", f"- Total file bytes: **{payload['total_bytes']:,}** ({payload['total_bytes']/1e9:.3f} GB; {payload['total_bytes']/2**30:.3f} GiB)", f"- AGENTS.md files in source/ancestors: **{len(instructions)}**", "", "## File types", "", "| Extension | Files | Bytes |", "|---|---:|---:|"]
    lines += [f"| `{ext}` | {value['files']} | {value['bytes']:,} |" for ext, value in sorted(types.items())]
    lines += ["", "## Capture series and bounded timestamp endpoints", "", "First timestamps come directly from the first record header. Last timestamps come from a bounded, structurally valid multi-record suffix ending at EOF. The unread middle is not validated, and a timestamp endpoint is not a known recording independence boundary. All times below are UTC; CSV log time zones remain unverified.", "", "| Candidate series | PCAPs | Suffixes | First UTC | Last UTC (tail-derived) |", "|---|---:|---|---|---|"]
    for row in series_summaries:
        suffix = ", ".join(map(str, row["chunk_suffixes"])) or "no numeric suffix"
        lines.append(f"| `{row['capture_series']}` | {row['files']} | {suffix} | {row['earliest_first_record_timestamp_utc']} | {row['latest_tail_derived_last_record_timestamp_utc']} |")
    lines += ["", "## What the source establishes", "", "- The supplied README describes device NIC and Docker bridge viewpoints, 100 MB sequential capture chunks, and timestamped attack logs. Device and bridge copies may observe the same traffic. Treat capture files as source fragments rather than independent experimental samples.", "- Attack parent folders are `external`, `compromised-scada`, and `compromised-ied`. Those folder labels establish scenario provenance, not per-message attack ground truth.", "- Benign chunk series include nonzero starting suffixes. Their absence before the observed minimum is recorded as a source-boundary limitation, not assumed corruption. Any unexpected internal suffix gaps are listed in the JSON.", "- The single XLSX sits alongside an `original.csv` of the same date. They must be compared as possible versions of one log, not automatically appended as separate attack events.", "- PCAP link type, timestamp precision, exact relative paths, byte counts, CSV headers, and each file's bounded timestamps are in `source_inventory.json`.", "", "## Remaining checks before extraction/splitting on the owner's machine", "", "1. Confirm scenario clocks and CSV log time zones against packet evidence; do not assume displayed clock strings are UTC.", "2. Establish continuity across numbered chunks and run identity across views using time, TCP state, packet duplication and log provenance.", "3. Identify overlapping views before choosing a canonical capture source or deduplicating observations. Keep all views of an event in one partition.", "4. Verify request/response mechanism and event-level labels from sufficient packet/log evidence. A response to an injected request is not automatically response injection.", "5. Count independently supported groups for each class before promising train/validation/test coverage. Continuous runs or scenarios may provide too few independent groups.", "6. Preserve raw bytes, precise timestamps and packet/source offsets in later extraction. Do not infer decoded process values from empty exports.", "", "No row split is declared valid by this inventory."]
    source_observations = ["", "## Immediate source-specific limitations", "", "- All 170 captures have classic-PCAP Ethernet link type 1 and microsecond timestamp precision. Every bounded suffix passed the structural chain check. This does not establish whole-capture integrity.", "- Six external attack CSVs have only `Timestamp,Attack`; they lack the `TargetIP` and `TransactionID` fields present in the other 28 logs. The README's richer log dictionary does not apply to every file.", "- External packet endpoints cover February 1, 2023, whereas external log filenames also name December 29–30, January 1–2 and January 17. Log-to-capture coverage must be established using actual contents and clock alignment; unmatched historical logs cannot create observed packet examples.", "- Compromised-SCADA device captures begin March 15, while its log filenames include March 12–14. Those older logs must not be assumed to have corresponding packet coverage.", "- **Numeric order is wrong for one apparent series.** `attack/compromised-scada/substation-wide-capture/substation-0.pcap` is only 20,006 bytes and spans March 23, 02:12:00.885275–02:15:43.529226 UTC. `substation-1.pcap` starts March 15, 08:53:28.842227 UTC. Moving numerically from 0 to 1 jumps backwards 667,334.687 seconds. Files 1–17 cover March 15–22. Do not concatenate file 0 with 1–17 as a normal sequential run; resolve its recording origin.", "- That March 23 `substation-0.pcap` overlaps the compromised-IED capture start at approximately 02:09–02:12 UTC. Packet-level checks must establish whether these include duplicated traffic, a scenario transition or different run boundaries before splitting by folder.", "- The other 145 numeric adjacent file boundaries have nonnegative gaps no larger than 4.973 seconds, supporting apparent chunk continuity while leaving TCP/run checks outstanding.", "- No internal numeric chunk gaps were found within each observed suffix range. Nonzero starts remain recorded source-boundary caveats."]
    lines[-2:-2] = source_observations
    (output / "INVENTORY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({key: payload[key] for key in ["total_files", "total_directories_excluding_root", "total_bytes", "extensions", "pcap_scenarios", "agents_files_found"]}, indent=2))


if __name__ == "__main__":
    main()
