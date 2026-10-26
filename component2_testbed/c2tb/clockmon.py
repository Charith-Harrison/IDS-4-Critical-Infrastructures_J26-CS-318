"""Clock monitor sidecar: samples CLOCK_REALTIME and CLOCK_MONOTONIC of the shared Docker VM kernel.

tcpdump timestamps and client ledger times both use the VM wall clock.  A step or fast slew of that clock during a
run (e.g. VM time synchronisation) shows up as a change in (wall - monotonic) between consecutive samples.
"""
import argparse
import json
import signal
import sys
import time

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--period", type=float, default=0.1)
    a = p.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    with open(a.out, "w") as f:
        while True:
            m0 = time.monotonic_ns()
            w = time.time_ns()
            m1 = time.monotonic_ns()
            f.write(json.dumps({"wall_ns": w, "mono_ns": (m0 + m1) // 2, "read_span_ns": m1 - m0}) + "\n")
            f.flush()
            time.sleep(a.period)
