"""Target: pymodbus Modbus/TCP server hosting several unit IDs with a seeded, evolving process image.

Every table of every unit spans addresses 0..MAP_SIZE-1 (zero_mode, so wire address == datastore index).
Input registers and discrete inputs drift with a simple simulated process; holding registers and coils change
occasionally (set-point / mode changes).  The values only make responses realistic; they carry no label.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import time

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server import StartAsyncTcpServer

UNITS = [1, 2, 3]  # overridden by --units
MAP_SIZE = 64  # overridden by --map-size


def build_context(rng: random.Random):
    slaves = {}
    for unit in UNITS:
        slaves[unit] = ModbusSlaveContext(
            co=ModbusSequentialDataBlock(0, [rng.random() < 0.3 for _ in range(MAP_SIZE)]),
            di=ModbusSequentialDataBlock(0, [rng.random() < 0.5 for _ in range(MAP_SIZE)]),
            hr=ModbusSequentialDataBlock(0, [rng.randrange(0, 1000) for _ in range(MAP_SIZE)]),
            ir=ModbusSequentialDataBlock(0, [rng.randrange(0, 4000) for _ in range(MAP_SIZE)]),
            zero_mode=True,
        )
    return ModbusServerContext(slaves=slaves, single=False)


async def simulate_process(context, rng: random.Random, period_s: float = 0.25):
    phases = {(u, a): rng.uniform(0, 2 * math.pi) for u in UNITS for a in range(MAP_SIZE)}
    t0 = time.monotonic()
    while True:
        await asyncio.sleep(period_s)
        t = time.monotonic() - t0
        for unit in UNITS:
            slave = context[unit]
            ir = [int(2000 + 1500 * math.sin(0.05 * t + phases[(unit, a)]) + rng.randrange(-20, 21))
                  for a in range(MAP_SIZE)]
            slave.setValues(4, 0, ir)
            if rng.random() < 0.2:
                a = rng.randrange(MAP_SIZE)
                slave.setValues(2, a, [rng.random() < 0.5])
            if rng.random() < 0.02:
                a = rng.randrange(MAP_SIZE)
                slave.setValues(3, a, [rng.randrange(0, 1000)])


async def main(args):
    rng = random.Random(args.seed)
    context = build_context(rng)
    print(json.dumps({"event": "server_start", "seed": args.seed, "units": UNITS, "map_size": MAP_SIZE,
                      "time_ns": time.time_ns()}), flush=True)
    asyncio.create_task(simulate_process(context, random.Random(args.seed + 1)))
    await StartAsyncTcpServer(context=context, address=("0.0.0.0", args.port))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--map-size", type=int, default=64)
    p.add_argument("--units", default="1,2,3")
    args = p.parse_args()
    MAP_SIZE = args.map_size
    UNITS = [int(u) for u in args.units.split(",")]
    asyncio.run(main(args))
