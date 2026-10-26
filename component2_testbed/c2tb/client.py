"""Modbus/TCP master that executes one client's planned actions and writes the ground-truth action ledger.

One persistent TCP connection per client per run (reconnect only after an error, which is recorded).  Requests are
synchronous: the next request is sent only after the previous response or timeout.  Each ledger row is written
from the client's own knowledge of what it intended and sent, independently of the capture.
"""
from __future__ import annotations

import argparse
import json
import socket
import time

from c2tb.wire import decode_adu, decode_response_fields, encode_read_request


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def connect(server, port, timeout):
    s = socket.create_connection((server, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def main(args):
    plan = json.load(open(args.plan))
    client = plan["clients"][args.client]
    tid = client["tid_start"]
    start_ns = args.start_epoch_ns
    with open(args.ledger, "w") as led:
        def log(row):
            led.write(json.dumps(row) + "\n")
            led.flush()

        while time.time_ns() < start_ns - 500_000_000:
            time.sleep(0.05)
        sock = connect(args.server, args.port, args.timeout)
        local_ip, local_port = sock.getsockname()[:2]
        log({"event": "connect", "time_ns": time.time_ns(), "local_ip": local_ip, "local_port": local_port})
        for a in client["actions"]:
            sched_ns = start_ns + int(a["t"] * 1e9)
            while True:
                rem = (sched_ns - time.time_ns()) / 1e9
                if rem <= 0:
                    break
                time.sleep(min(rem, 0.05))
            req = encode_read_request(tid, a["unit"], a["fc"], a["address"], a["quantity"])
            row = {"event": "action", "run_id": plan["run_id"], "client": args.client,
                   "scenario_id": plan["scenario_id"], **a, "tid": tid & 0xFFFF,
                   "local_ip": local_ip, "local_port": local_port,
                   "scheduled_ns": sched_ns, "request_hex": req.hex()}
            try:
                row["send_ns"] = time.time_ns()
                sock.sendall(req)
                head = recv_exact(sock, 7)
                body = recv_exact(sock, int.from_bytes(head[4:6], "big") - 1)
                row["recv_ns"] = time.time_ns()
                resp = head + body
                d = decode_adu(resp)
                row.update(response_hex=resp.hex(), response_tid=d["tid"], response_fc=d["wire_fc"],
                           **decode_response_fields(d["pdu"]))
                row["status"] = "exception" if row["is_exception"] else (
                    "ok" if d["tid"] == tid & 0xFFFF else "tid_mismatch")
            except (OSError, ConnectionError) as e:
                row["status"] = "error"
                row["error"] = repr(e)
                log(row)
                try:
                    sock.close()
                except OSError:
                    pass
                sock = connect(args.server, args.port, args.timeout)
                local_ip, local_port = sock.getsockname()[:2]
                log({"event": "reconnect", "time_ns": time.time_ns(), "local_ip": local_ip, "local_port": local_port})
                tid += 1
                continue
            log(row)
            tid += 1
        sock.close()
        log({"event": "close", "time_ns": time.time_ns()})


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--plan", required=True)
    p.add_argument("--client", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--start-epoch-ns", type=int, required=True)
    p.add_argument("--timeout", type=float, default=2.0)
    main(p.parse_args())
