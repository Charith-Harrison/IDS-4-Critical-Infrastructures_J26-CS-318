"""Actual local TCP traffic with explicit interventions and private audit state.

Only loopback15020 is used. A live captured run requires Linux/tcpdump;
the smoke command exercises TCP/protocol without producing verified labels.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import platform
import queue
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

from . import __version__
from .protocol import PLCState, make_adu, parse_adu, recv_adu, request, validate_pdu

HOST = "127.0.0.1"
PORT = 15020


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for piece in iter(lambda: f.read(1 << 20), b""):
            h.update(piece)
    return h.hexdigest()


class JsonLines:
    def __init__(self, path: Path):
        self.file = path.open("x", encoding="utf-8")

    def append(self, data: dict) -> None:
        self.file.write(json.dumps(data) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def build_episodes(seed: int, groups: int) -> list[dict]:
    if not 1 <= groups <= 5:
        raise ValueError("Feasibility pilot permits1..5 groups, not bulk collection")
    rng = random.Random(seed)
    episodes = []
    for group in range(groups):
        a, b = rng.sample(range(20, 181), 2)
        for name, mode, actual, reported in (
            ("normal", 1, a, a), ("normal", 1, b, b),
            ("command_injection", 0, a, a), ("command_injection", 0, b, b),
            ("response_injection", 1, a, b), ("response_injection", 1, b, a),
        ):
            episodes.append({"scenario": name, "group": group, "mode": mode,
                             "actual_setpoint": actual, "reported_setpoint": reported})
    rng.shuffle(episodes)
    for index, episode in enumerate(episodes):
        episode["episode_id"] = f"episode-{index:03d}"
    return episodes


class LabServer:
    def __init__(self, audit: JsonLines):
        self.audit = audit
        self.state = PLCState()
        self.overrides: dict[int, int] = {}
        self.errors: list[str] = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, PORT))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        try:
            conn, address = self.listener.accept()
            with conn:
                conn.settimeout(10)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while True:
                    try:
                        incoming = recv_adu(conn)
                    except EOFError:
                        break
                    tid, unit, pdu = parse_adu(incoming)
                    before = self.state.snapshot()
                    expected_pdu = self.state.handle(pdu)
                    expected = make_adu(tid, expected_pdu, unit)
                    wire = expected
                    override = self.overrides.pop(tid, None)
                    if override is not None:
                        if pdu != request(3, 1, 1):
                            raise ValueError("Override requires read of stored setpoint")
                        wire = make_adu(tid, bytes((3, 2)) + struct.pack("!H", override), unit)
                    validate_pdu(parse_adu(wire)[2], False)
                    after = self.state.snapshot()
                    record = {"tid": tid, "unit": unit, "request_adu_hex": incoming.hex(),
                              "expected_response_adu_hex": expected.hex(), "wire_response_adu_hex": wire.hex(),
                              "response_overridden": wire != expected, "server_observed_at_ns": time.time_ns(),
                              "peer_ip": address[0], "peer_port": address[1],
                              **{k + "_before": v for k, v in before.items()},
                              **{k + "_after": v for k, v in after.items()}}
                    self.audit.append(record)
                    conn.sendall(wire)
        except Exception as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            self.listener.close()

    def start(self):
        self.thread.start()

    def finish(self):
        self.thread.join(timeout=12)
        if self.thread.is_alive():
            raise RuntimeError("Server did not stop after client disconnect")
        if self.errors:
            raise RuntimeError("; ".join(self.errors))


class Capture:
    def __init__(self, folder: Path):
        if platform.system() != "Linux" or shutil.which("tcpdump") is None:
            raise RuntimeError("Captured pilot requires Linux/tcpdump. Use Docker, or smoke for code checks only.")
        self.log_path = folder / "capture.log"
        self.log = self.log_path.open("x", encoding="utf-8")
        self.lines = queue.Queue()
        self.process = subprocess.Popen(
            ["tcpdump", "-i", "lo", "-p", "-n", "-U", "-s", "0", "-Z", "root", "-w",
             str(folder / "capture.pcap"), "tcp", "port", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.reader = threading.Thread(target=self.drain, daemon=True)
        self.reader.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.2)
            except queue.Empty:
                if self.process.poll() is not None:
                    break
                continue
            if "listening on" in line:
                return
        self.stop()
        raise RuntimeError("tcpdump never confirmed capture readiness; read capture.log")

    def drain(self):
        for line in self.process.stderr:
            self.log.write(line)
            self.log.flush()
            self.lines.put(line)

    def stop(self) -> int:
        if self.process.poll() is None:
            # Allow libpcap to drain its bounded buffer before final statistics.
            time.sleep(1.2)
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=3)
        self.log.close()
        return self.process.returncode


def run_pilot(output: Path, seed: int = 4010, groups: int = 2, captured: bool = True,
              delay_range=(0.015, 0.035)) -> Path:
    if captured and os.environ.get("C3LAB_ISOLATED_DOCKER") != "1":
        raise RuntimeError("Use the supplied Docker launcher for captured runs; arbitrary-host capture is disabled")
    if captured:
        interfaces = {name for _, name in socket.if_nameindex()}
        if interfaces != {"lo"}:
            raise RuntimeError(f"Expected only loopback in network_mode:none; observed {interfaces}")
    episodes = build_episodes(seed, groups)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{'pilot' if captured else 'smoke'}-{timestamp}-{uuid.uuid4().hex[:8]}"
    output.mkdir(parents=True, exist_ok=True)
    folder = output / run_id
    folder.mkdir(exist_ok=False)
    manifest = {"schema_version": 1, "lab_version": __version__, "run_id": run_id, "seed": seed,
                "groups": groups, "purpose": "FEASIBILITY_PILOT_NOT_TRAINING_DATASET",
                "status": "STARTED", "capture_required": captured, "python": sys.version,
                "platform": platform.platform(), "server_host": HOST, "server_port": PORT,
                "isolation_requested": "docker-network-none" if captured else "local-loopback-smoke",
                "created_at_utc": timestamp, "episodes": len(episodes),
                "source_sha256": {p.name: file_hash(p) for p in Path(__file__).parent.glob("*.py")},
                "no_model_preprocessing_or_training": True,
                "implementation": "Minimal FC1/3/5/6 simulator; compromised-client request and compromised-server reply interventions"}
    save_json(folder / "run_manifest.json", manifest)
    ledger = JsonLines(folder / "application_ledger.jsonl")
    oracle = JsonLines(folder / "server_audit.jsonl")
    capture = None
    server = None
    observations = []
    rng = random.Random(seed ^ 0xC34010)
    tid = rng.randrange(1, 60000)
    offsets = {"client_to_server": 0, "server_to_client": 0}
    try:
        if captured:
            capture = Capture(folder)
        server = LabServer(oracle)
        server.start()
        with socket.create_connection((HOST, PORT), timeout=5) as client:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            local_ip, local_port = client.getsockname()
            manifest["client_port"] = local_port
            for ep in episodes:
                steps = [
                    ("set_mode", request(6, 0, ep["mode"])),
                    ("observe_mode", request(3, 0, 1)),
                    ("reset_coil", request(5, 1, 0)),
                    ("set_setpoint", request(6, 1, ep["actual_setpoint"])),
                    ("readback_target", request(3, 1, 1)),
                    ("coil_on_target", request(5, 1, 0xFF00)),
                    ("observe_coil", request(1, 1, 1)),
                    ("restore_coil", request(5, 1, 0)),
                    ("recovery_readback", request(3, 1, 1)),
                ]
                for step, pdu in steps:
                    tid = (tid + 1) & 0xFFFF
                    if step == "readback_target" and ep["scenario"] == "response_injection":
                        server.overrides[tid] = ep["reported_setpoint"]
                    sent = make_adu(tid, pdu)
                    time.sleep(rng.uniform(*delay_range))
                    client.sendall(sent)
                    sent_at = time.time_ns()
                    received = recv_adu(client)
                    received_at = time.time_ns()
                    rtid, runit, reply_pdu = parse_adu(received)
                    validate_pdu(reply_pdu, False)
                    if rtid != tid or runit != 1 or reply_pdu[0] != pdu[0]:
                        raise RuntimeError("Unexpected reply identity/function")
                    for role, direction, raw, observed_at in (
                        ("request", "client_to_server", sent, sent_at),
                        ("response", "server_to_client", received, received_at),
                    ):
                        label = "normal"
                        if role == "request" and step == "coil_on_target" and ep["scenario"] == "command_injection":
                            label = "command_injection"
                        if role == "response" and step == "readback_target" and ep["scenario"] == "response_injection":
                            label = "response_injection"
                        row = {"event_id": f"{run_id}:e{len(observations)}", "run_id": run_id,
                               "episode_id": ep["episode_id"], "scenario": ep["scenario"], "step": step,
                               "label": label, "role": role, "tid": tid, "unit": 1,
                               "adu_hex": raw.hex(), "pdu_hex": raw[7:].hex(), "direction": direction,
                               "stream_offset": offsets[direction], "observed_at_ns": observed_at,
                               "source_ip": local_ip if role == "request" else HOST,
                               "source_port": local_port if role == "request" else PORT,
                               "destination_ip": HOST if role == "request" else local_ip,
                               "destination_port": PORT if role == "request" else local_port,
                               "metadata_use": "AUDIT_ONLY_NOT_MODEL_INPUTS"}
                        offsets[direction] += len(raw)
                        observations.append(row)
                        ledger.append(row)
        server.finish()
        manifest["status"] = "CAPTURE_COLLECTED" if captured else "SMOKE_ONLY_NO_PCAP"
    except Exception as exc:
        manifest["status"] = "FAILED"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if capture is not None:
            manifest["capture_exit_code"] = capture.stop()
        ledger.close()
        if server and server.thread.is_alive():
            server.thread.join(timeout=0.2)
        oracle.close()
        manifest["observed_application_messages"] = len(observations)
        manifest["application_label_counts_not_yet_capture_verified"] = dict(Counter(r["label"] for r in observations))
        manifest["output_sha256"] = {p.name: file_hash(p) for p in folder.iterdir()
                                    if p.is_file() and p.name != "run_manifest.json"}
        save_json(folder / "run_manifest.json", manifest)
    if captured:
        from .capture_validation import validate_capture
        report = validate_capture(folder, PORT)
        passed = report.get("passed", report.get("status") in ("PASS", "PASSED", "VERIFIED"))
        if not passed:
            raise RuntimeError(f"Capture validation did not pass: {folder / 'validation_report.json'}")
    return folder
