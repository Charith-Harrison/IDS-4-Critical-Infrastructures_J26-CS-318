"""Read-only CIC source hashing, complete classic-PCAP record audit and grouping.

This module never decodes an ADU or reads datasets outside the explicit raw root.
The sampled frame signatures establish observation copies, not a global dedup.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import time

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def stamp(us):
    return datetime.fromtimestamp(us / 1_000_000, timezone.utc).isoformat() if us is not None else None


def source_run(rel, first_ts_us=None):
    if rel.startswith("benign/"):
        return "cic_benign_january"
    if rel.startswith("attack/external/"):
        return "cic_external_february"
    if rel.startswith("attack/compromised-ied/"):
        return "cic_compromised_ied_march"
    if rel == "attack/compromised-scada/substation-wide-capture/substation-0.pcap":
        return "cic_compromised_ied_march"
    return "cic_compromised_scada_march"


def inspect_file(path, relative, sample_size=64):
    t0 = time.monotonic()
    out = {"path": relative, "bytes": path.stat().st_size, "format": path.suffix.lower().lstrip(".")}
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        if out["bytes"] == 0:
            out["sha256"] = sha.hexdigest()
            return out
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            # Hash bounded slices rather than copying a whole mapping to Python.
            for off in range(0, len(buf), 8 << 20):
                sha.update(buf[off: off + (8 << 20)])
            out["sha256"] = sha.hexdigest()
            if path.suffix.lower() != ".pcap":
                return out
            if len(buf) < 24 or buf[:4] not in MAGIC:
                out["capture"] = {"status": "unsupported_or_short_header"}
                return out
            endian, ticks = MAGIC[buf[:4]]
            major, minor, zone, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHiIII", buf, 4)
            unpack = struct.Struct(endian + "IIII").unpack_from
            off, frame, prev = 24, 0, None
            first = last = minimum = maximum = None
            backwards = truncated = bad_ticks = 0
            head, tail = [], deque(maxlen=sample_size)
            errors = []
            while off + 16 <= len(buf):
                sec, frac, caplen, origlen = unpack(buf, off)
                end = off + 16 + caplen
                frame += 1
                if end > len(buf):
                    errors.append({"frame": frame, "offset": off, "reason": "truncated_record", "declared_caplen": caplen})
                    break
                ts = sec * 1_000_000 + (frac if ticks == 1_000_000 else frac // 1000)
                if first is None:
                    first = minimum = maximum = ts
                last = ts
                if prev is not None and ts < prev:
                    backwards += 1
                prev = ts
                minimum, maximum = min(minimum, ts), max(maximum, ts)
                truncated += caplen < origlen
                bad_ticks += frac >= ticks
                # Keep first and last 64 full frame observations and TCP summaries.
                if frame <= sample_size or end + (sample_size * 1000) >= len(buf):
                    data = buf[off + 16:end]
                    sample = {"frame": frame, "ts_us": ts, "offset": off,
                              "sha256_frame": hashlib.sha256(data).hexdigest()}
                    if frame <= sample_size:
                        head.append(sample)
                    tail.append(sample)
                # All tiny source frames are additionally represented in samples.
                elif len(buf) < 100_000:
                    data = buf[off + 16:end]
                    tail.append({"frame": frame, "ts_us": ts, "offset": off,
                                 "sha256_frame": hashlib.sha256(data).hexdigest()})
                off = end
            if off < len(buf) and not errors:
                errors.append({"offset": off, "reason": "partial_record_header", "remaining_bytes": len(buf) - off})
            out["capture"] = {
                "status": "verified_complete_record_chain" if not errors and not bad_ticks else "record_errors",
                "pcap_version": [major, minor], "linktype": linktype & 0x0fffffff,
                "ticks_per_second": ticks, "snaplen": snaplen, "timezone_header": zone,
                "frames": frame, "first_ts_us": first, "last_ts_us": last,
                "minimum_ts_us": minimum, "maximum_ts_us": maximum,
                "first_utc": stamp(first), "last_utc": stamp(last),
                "backwards_timestamp_frames": backwards, "capture_truncated_frames": truncated,
                "invalid_fraction_frames": bad_ticks, "errors": errors,
                "head_sample": head, "tail_sample": list(tail),
            }
    out["audit_elapsed_s"] = round(time.monotonic() - t0, 4)
    return out


def grouping(files):
    groups = defaultdict(lambda: {"views": defaultdict(list), "log_sources": []})
    for item in files:
        path = item["path"]
        if item["format"] == "pcap":
            rec = source_run(path, item["capture"].get("first_ts_us"))
            view = path.rsplit("/", 1)[0]
            groups[rec]["views"][view].append(item)
        elif item["format"] in ("csv", "xlsx"):
            groups[source_run(path)]["log_sources"].append(path)
    result = []
    sample_lookup = defaultdict(list)
    for item in files:
        cap = item.get("capture", {})
        for sample in cap.get("head_sample", []) + cap.get("tail_sample", []):
            sample_lookup[sample["sha256_frame"]].append((item["path"], sample["frame"], sample["ts_us"]))
    mirrors = []
    for sig, rows in sample_lookup.items():
        rows = sorted(set(rows), key=lambda r: (r[2], r[0], r[1]))
        # Equal bytes on different days can be legitimate repeated ARP/polling.
        # A sampled observation-copy candidate also needs coincident timestamps.
        clusters = []
        for row in rows:
            if not clusters or row[2] - clusters[-1][0][2] > 1000:
                clusters.append([row])
            else:
                clusters[-1].append(row)
        for cluster in clusters:
            if len({r[0].rsplit("/", 1)[0] for r in cluster}) > 1:
                mirrors.append({"sha256_frame": sig, "maximum_timestamp_spread_us": cluster[-1][2] - cluster[0][2],
                                "status": "identical_frame_bytes_coincident_viewpoint_observation_candidate",
                                "observations": [{"path": p, "frame": f, "ts_us": t} for p, f, t in cluster]})
    for group_id, g in sorted(groups.items()):
        views = []
        for view, members in sorted(g["views"].items()):
            ordered = sorted(members, key=lambda i: (i["capture"].get("first_ts_us", 0), i["path"]))
            boundaries = []
            for a, b in zip(ordered, ordered[1:]):
                boundaries.append({"before": a["path"], "after": b["path"],
                                   "gap_us": b["capture"]["first_ts_us"] - a["capture"]["last_ts_us"],
                                   "continuity_status": "chronological_rotation_candidate_tcp_continuity_to_be_audited"})
            views.append({"view_id": view.replace("/", "__"), "source_directory": view,
                          "chunks": [{"index": j, "path": it["path"], "sha256": it["sha256"],
                                      "first_ts_us": it["capture"]["first_ts_us"],
                                      "last_ts_us": it["capture"]["last_ts_us"]}
                                     for j, it in enumerate(ordered)], "boundaries": boundaries})
        result.append({"recording_id": group_id, "independent_recording_group": group_id,
                       "group_basis": "whole temporally separated CIC capture campaign; simultaneous viewpoints and rotations kept together",
                       "independence_limit": "separate capture campaigns do not prove independent physical processes or per-day attack episodes",
                       "views": views, "log_sources": sorted(g["log_sources"])})
    return {"groups": result, "sampled_duplicate_observations": mirrors,
            "duplicate_audit_scope": "bounded frame samples; equal frame bytes plus at most1000us timestamp spread across viewpoints. Equal bytes across distant times are NOT duplicate observations. No event rows deduplicated by these samples; absence is not proof of uniqueness.",
            "special_source_assignment": {
                "path": "attack/compromised-scada/substation-wide-capture/substation-0.pcap",
                "recording_id": "cic_compromised_ied_march",
                "basis": "March23 timestamp overlap; identical sampled frame signatures checked against IED-view sources",
                "status": "conservatively contained with overlapping IED campaign; inspect sampled duplicate evidence"}}


def run_inventory(raw_root, output, resume=True):
    raw_root, output = Path(raw_root).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = sorted(p for p in raw_root.rglob("*") if p.is_file())
    checkpoint = output / "inventory_checkpoint.jsonl"
    existing = {}
    if resume and checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf8").splitlines():
            try:
                row = json.loads(line)
                existing[row["path"]] = row
            except json.JSONDecodeError:
                pass
    files = []
    reused = 0
    t0 = time.monotonic()
    with checkpoint.open("a" if resume else "w", encoding="utf8", newline="\n") as cp:
        for i, path in enumerate(paths):
            rel = path.relative_to(raw_root).as_posix()
            row = existing.get(rel)
            # Cache is accepted only with exact mtime/size fingerprint; final verification rehashes sources separately.
            st = path.stat()
            if row is None or row["bytes"] != st.st_size or row.get("mtime_ns") != st.st_mtime_ns:
                row = inspect_file(path, rel)
                row["mtime_ns"] = st.st_mtime_ns
                cp.write(json.dumps(row, separators=(",", ":")) + "\n")
                cp.flush()
            else:
                reused += 1
            files.append(row)
            if i % 10 == 0 or i + 1 == len(paths):
                print(f"inventory {i+1}/{len(paths)} {rel} elapsed={time.monotonic()-t0:.1f}s", flush=True)
    extensions = {}
    for ext in sorted({f["format"] for f in files}):
        members = [f for f in files if f["format"] == ext]
        extensions[ext] = {"files": len(members), "bytes": sum(f["bytes"] for f in members)}
    inventory = {"raw_root": str(raw_root), "scope": "original CIC supplied root only",
                 "source_version": "CIC Modbus Dataset 2023 per original README; publisher checksums unavailable",
                 "files": files, "total_files": len(files), "total_bytes": sum(f["bytes"] for f in files),
                 "extensions": extensions, "elapsed_s": round(time.monotonic()-t0, 3),
                 "cached_sources_reused_this_invocation": reused,
                 "stored_capture_audit_elapsed_s": round(sum(f.get("audit_elapsed_s", 0) for f in files), 3)}
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf8")
    (output / "group_sources.json").write_text(json.dumps(grouping(files), indent=2), encoding="utf8")
    return inventory


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-root", default="data/raw/Modbus Dataset")
    ap.add_argument("--output", default="component3_preparation/output")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()
    run_inventory(args.raw_root, args.output, not args.no_resume)
