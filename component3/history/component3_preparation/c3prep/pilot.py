"""Reproducible bounded original-CIC parsing pilot; no model preprocessing."""
from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pyarrow
import pyarrow.parquet as pq

from .extract import extract_chain

DEFAULT_CONFIG = {
    "modbus_ports": [502], "conn_idle_timeout_s": 300, "closed_linger_s": 2,
    "max_open_connections": 20000, "max_ooo_segments": 128,
    "max_ooo_bytes": 262144, "max_pending_bytes": 70000,
    "max_frame_refs": 1000, "row_batch_size": 10000,
}


def peak_memory_bytes():
    """Windows process PeakWorkingSetSize (includes imported Arrow/runtime)."""
    if sys.platform != "win32":
        return None
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                    *[(x, ctypes.c_size_t) for x in (
                        "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                        "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                        "PagefileUsage", "PeakPagefileUsage")]]
    counter = Counters()
    counter.cb = ctypes.sizeof(counter)
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counter), counter.cb)
    return counter.PeakWorkingSetSize if ok else None


def run_pilot(repo=None):
    repo = Path(repo or Path(__file__).resolve().parents[2])
    raw = repo / "data/raw/Modbus Dataset"
    out = repo / "component3_preparation/output/pilot"
    out.mkdir(parents=True, exist_ok=True)
    tshark = Path("C:/Program Files/Wireshark/tshark.exe")
    registry = subprocess.run([str(tshark), "-G", "fields"], capture_output=True, text=True, check=True).stdout
    selected_registry = [line for line in registry.splitlines()
                         if "\tmbtcp." in line or "\tmodbus." in line]
    (out / "tshark_registry.tsv").write_text("\n".join(selected_registry) + "\n", encoding="utf-8")
    prefs = subprocess.run([str(tshark), "-G", "currentprefs"], capture_output=True, text=True, check=True).stdout
    (out / "tshark_reassembly_preferences.txt").write_text("\n".join(
        line for line in prefs.splitlines() if "mbtcp.desegment" in line
        or "tcp.desegment_tcp_streams" in line or "tcp.reassemble_out_of_order" in line) + "\n")
    report = {"stage": "protocol_extraction_pilot_only", "config": DEFAULT_CONFIG,
              "python": sys.version, "pyarrow": pyarrow.__version__,
              "tshark": subprocess.run([str(tshark), "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0],
              "free_disk_before_bytes": shutil.disk_usage(out).free, "chains": [], "examples": []}
    cases = [
        ("benign", "benign/scada-hmi/scada-hmi-network-capture/veth5bbeaa2-normal-13.pcap", 13, [5]),
        ("ied", "attack/compromised-ied/trust-scada-hmi/trust-scada-network-captures/veth3efd353-1.pcap", 1, [833140, 833142]),
    ]
    for name, rel, chunk, wanted in cases:
        started = time.monotonic()
        path = raw / rel
        acc = extract_chain(name, "pilot_" + name, [(chunk, str(path))], DEFAULT_CONFIG, str(out / name))
        elapsed = time.monotonic() - started
        assert all(acc[x] for x in ("check_bytes_captured_eq_dup_plus_delivered",
                                   "check_bytes_delivered_eq_records", "check_frames_accounted")), acc
        output_bytes = sum(p.stat().st_size for p in (out / name).glob("*"))
        report["chains"].append({"source": rel, "source_bytes": path.stat().st_size, "elapsed_s": elapsed,
                                 "output_bytes": output_bytes, "accounting": acc,
                                 "source_mib_per_second": path.stat().st_size / elapsed / 1048576})
        found = []
        for batch in pq.ParquetFile(out / name / "events.parquet").iter_batches():
            for row in batch.to_pylist():
                if row["first_frame"] in wanted:
                    found.append({k: (v.hex() if isinstance(v, bytes) else v) for k, v in row.items()})
        fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
                  "mbtcp.trans_id", "mbtcp.len", "modbus.func_code", "modbus.byte_cnt", "modbus.regval_uint16", "tcp.payload"]
        cmd = [str(tshark), "-r", str(path), "-c", str(max(wanted)), "-Y",
               " || ".join("frame.number == " + str(fr) for fr in wanted), "-T", "fields"]
        for field in fields:
            cmd += ["-e", field]
        independent = subprocess.run(cmd, capture_output=True, text=True, check=True)
        (out / (name + "_tshark_examples.tsv")).write_text("\t".join(fields) + "\n" + independent.stdout, encoding="utf-8")
        report["examples"].append({"source": rel, "decoded": found, "tshark_tsv": independent.stdout,
                                    "tshark_stderr": independent.stderr})
        if name == "benign":
            assert len(found) == 1 and found[0]["reg_values"] == [9]
            assert found[0]["pdu_bytes"] == "03020009"
        else:
            assert len(found) == 2 and all(row["mbap_trans_id"] == 7485 for row in found)
            reply = next(row for row in found if row["protocol_role"] == "response")
            assert reply["pdu_bytes"] == "01abcd" and reply["parse_status"] == "malformed"
    report["peak_working_set_bytes"] = peak_memory_bytes()
    report["total_output_bytes"] = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    report["all_pilot_assertions_passed"] = True
    (out / "pilot_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("all_pilot_assertions_passed", "peak_working_set_bytes", "total_output_bytes")}))
    return report


if __name__ == "__main__":
    run_pilot()
