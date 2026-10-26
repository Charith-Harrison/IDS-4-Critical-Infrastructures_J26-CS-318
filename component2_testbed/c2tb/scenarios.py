"""Deterministic scenario plans for the pilot.

A plan is generated from (scenario_id, seed, duration) only, before any traffic exists.  It fixes every intended
action (time offset, unit, function, address, quantity) and its ground-truth role/phase.  All normal and recon
scenarios draw request shapes from the same shared envelope (units, functions, quantities, aligned addresses), so
the difference between families lies in ordering, coverage, repetition and timing rather than in single messages.
"""
from __future__ import annotations

import random

UNITS = [1, 2, 3]
MAP_SIZE = 64
FUNCTIONS = [1, 2, 3, 4]
FUNCTION_WEIGHTS = [0.15, 0.15, 0.40, 0.30]
QUANTITIES = [1, 2, 4, 8]
QUANTITY_WEIGHTS = [0.55, 0.20, 0.15, 0.10]

NORMAL_SCENARIOS = ["N1_fixed_polling", "N2_variable_polling_bursts", "N3_maintenance_blocks", "N4_trend_watch"]
RECON_SCENARIOS = ["R1_sequential_scan", "R2_sparse_strided_scan", "R3_randomized_scan",
                   "R4_slow_jittered_scan", "R5_function_probe", "R6_unit_probe"]
ALL_SCENARIOS = NORMAL_SCENARIOS + RECON_SCENARIOS


def family_of(scenario_id: str) -> str:
    return "recon" if scenario_id.startswith("R") else "normal"


def pick_fc(rng):
    return rng.choices(FUNCTIONS, FUNCTION_WEIGHTS)[0]


def pick_q(rng):
    return rng.choices(QUANTITIES, QUANTITY_WEIGHTS)[0]


def aligned_addresses(q: int):
    return list(range(0, MAP_SIZE - q + 1, q))


def make_tag_list(rng, n, units):
    tags = set()
    while len(tags) < n:
        q = pick_q(rng)
        tags.add((rng.choice(units), pick_fc(rng), rng.choice(aligned_addresses(q)), q))
    tags = list(tags)
    if rng.random() < 0.5:
        tags.sort()            # drivers that sort tags by device/table/address
    else:
        rng.shuffle(tags)      # configured screen order
    return tags


class Plan:
    def __init__(self, role, phase):
        self.actions = []
        self.role = role
        self.phase = phase

    def add(self, t, tag, intent, role=None, phase=None):
        unit, fc, address, quantity = tag
        self.actions.append({"t": round(t, 6), "unit": unit, "fc": fc, "address": address, "quantity": quantity,
                             "role": role or self.role, "phase": phase or self.phase, "intent": intent})


# ---------------------------------------------------------------- normal workloads

def cyclic_polling(plan, rng, tags, t0, t_end, period_fn, gap=(0.004, 0.03), intent="poll_cycle"):
    t = t0
    cycle = 0
    while t < t_end:
        tc = t
        for tag in tags:
            if tc >= t_end:
                break
            plan.add(tc, tag, f"{intent}:{cycle}")
            tc += rng.uniform(*gap)
        t += period_fn(t)
        cycle += 1
    return plan


def maintenance(plan, rng, t0, t_end, units=UNITS, intent="maintenance"):
    """Engineering-tool style block reads with think pauses and revisits."""
    t = t0
    done_blocks = []
    while t < t_end:
        if done_blocks and rng.random() < 0.35:
            block = rng.choice(done_blocks)
        elif rng.random() < 0.15:
            # repeated reads of a few important registers
            imp = [(rng.choice(units), pick_fc(rng), rng.choice(aligned_addresses(1)), 1) for _ in range(rng.randint(1, 3))]
            for _ in range(rng.randint(2, 5)):
                for tag in imp:
                    plan.add(t, tag, f"{intent}:watch")
                    t += rng.uniform(0.05, 0.6)
            t += rng.uniform(1.0, 5.0)
            continue
        else:
            q = pick_q(rng)
            length = rng.choice([4, 8, 12, 16, 24])
            length = max(q, (length // q) * q)
            start = rng.choice([a for a in aligned_addresses(q) if a + length <= MAP_SIZE])
            block = (rng.choice(units), pick_fc(rng), start, length, q)
            done_blocks.append(block)
        unit, fc, start, length, q = block
        mode = rng.choice(["chunked_ascending", "chunked_configured_order"])
        addrs = list(range(start, start + length, q))
        if mode == "chunked_configured_order":
            rng.shuffle(addrs)
        for a in addrs:
            if t >= t_end:
                break
            plan.add(t, (unit, fc, a, q), f"{intent}:block:{mode}")
            t += rng.uniform(0.15, 1.2)
        t += rng.uniform(2.0, 8.0)
    return plan


def normal_actor(scenario_id, rng, t0, t_end, params):
    plan = Plan("normal", "normal_workload")
    if scenario_id == "N1_fixed_polling":
        tags = make_tag_list(rng, rng.randint(8, 16), UNITS)
        period = rng.uniform(0.5, 2.0)
        params.update(tags=tags, period_s=period)
        cyclic_polling(plan, rng, tags, t0, t_end, lambda t: period * rng.uniform(0.98, 1.02))
    elif scenario_id == "N2_variable_polling_bursts":
        tags = make_tag_list(rng, rng.randint(8, 16), UNITS)
        segments, t = [], t0
        while t < t_end:
            seg = (t, rng.uniform(8, 20), rng.uniform(0.3, 3.0))
            segments.append(seg)
            t += seg[1]

        def period_fn(tt):
            for s0, dur, per in segments:
                if s0 <= tt < s0 + dur:
                    return per * rng.uniform(0.85, 1.15)
            return segments[-1][2]
        params.update(tags=tags, period_segments=segments)
        cyclic_polling(plan, rng, tags, t0, t_end, period_fn)
        tb, bursts = t0 + rng.uniform(2, 8), []
        while tb < t_end:
            q = pick_q(rng)
            n = rng.randint(4, 12)
            unit, fc = rng.choice(UNITS), pick_fc(rng)
            start = rng.choice([a for a in aligned_addresses(q) if a + n * q <= MAP_SIZE] or [0])
            bursts.append((tb, unit, fc, start, n, q))
            tt = tb
            for k in range(n):
                a = start + k * q
                if a + q > MAP_SIZE or tt >= t_end:
                    break
                plan.add(tt, (unit, fc, a, q), "operator_screen_burst")
                tt += rng.uniform(0.01, 0.08)
            tb += rng.uniform(5, 15)
        params.update(bursts=bursts)
        plan.actions.sort(key=lambda a: a["t"])
    elif scenario_id == "N3_maintenance_blocks":
        maintenance(plan, rng, t0, t_end)
    elif scenario_id == "N4_trend_watch":
        tags = make_tag_list(rng, rng.randint(2, 5), UNITS)
        params.update(tags=tags)
        t = t0
        while t < t_end:
            end = min(t_end, t + rng.uniform(10, 25))
            period = rng.uniform(0.2, 0.6)
            cyclic_polling(plan, rng, tags, t, end, lambda tt: period * rng.uniform(0.9, 1.1), intent="trend")
            t = end + rng.uniform(1, 4)
    else:
        raise ValueError(scenario_id)
    return plan


# ---------------------------------------------------------------- reconnaissance workloads

def recon_interval_fn(rng, params):
    base = rng.uniform(0.05, 0.4)
    params["base_interval_s"] = base
    return lambda: base * rng.uniform(0.8, 1.2)


def recon_actor(scenario_id, rng, t0, t_end, params):
    plan = Plan("recon", "recon")
    targets = []  # ordered list of (unit, fc, address, q)
    if scenario_id == "R1_sequential_scan":
        tables = [(rng.choice(UNITS), pick_fc(rng), pick_q(rng)) for _ in range(rng.randint(1, 2))]
        for unit, fc, q in tables:
            targets += [(unit, fc, a, q) for a in aligned_addresses(q)]
        interval = recon_interval_fn(rng, params)
        params.update(tables=tables)
    elif scenario_id == "R2_sparse_strided_scan":
        tables = []
        for _ in range(rng.randint(2, 3)):
            q = pick_q(rng)
            stride = q * rng.choice([2, 4])
            offset = rng.randrange(0, stride, q)
            unit, fc = rng.choice(UNITS), pick_fc(rng)
            tables.append((unit, fc, q, stride, offset))
            targets += [(unit, fc, a, q) for a in range(offset, MAP_SIZE - q + 1, stride)]
        interval = recon_interval_fn(rng, params)
        params.update(tables=tables)
    elif scenario_id == "R3_randomized_scan":
        tables = [(rng.choice(UNITS), pick_fc(rng), pick_q(rng)) for _ in range(rng.randint(1, 2))]
        for unit, fc, q in tables:
            targets += [(unit, fc, a, q) for a in aligned_addresses(q)]
        rng.shuffle(targets)
        interval = recon_interval_fn(rng, params)
        params.update(tables=tables)
    elif scenario_id == "R4_slow_jittered_scan":
        unit, fc, q = rng.choice(UNITS), pick_fc(rng), pick_q(rng)
        starts = aligned_addresses(q)
        n = min(len(starts), 28)  # sized so a slow sweep completes inside the run
        i0 = rng.randrange(0, len(starts) - n + 1)
        targets = [(unit, fc, a, q) for a in starts[i0:i0 + n]]
        order = rng.choice(["ascending", "random"])
        if order == "random":
            rng.shuffle(targets)
        params.update(tables=[(unit, fc, q)], order=order, interval_range_s=(0.6, 2.5))
        interval = lambda: rng.uniform(0.6, 2.5)  # inside the normal polling-period range
    elif scenario_id == "R5_function_probe":
        unit, q = rng.choice(UNITS), pick_q(rng)
        n = rng.randint(10, 18)
        starts = aligned_addresses(q)
        i0 = rng.randrange(0, max(1, len(starts) - n))
        for a in starts[i0:i0 + n]:
            fcs = FUNCTIONS[:]
            rng.shuffle(fcs)
            targets += [(unit, fc, a, q) for fc in fcs]
        interval = recon_interval_fn(rng, params)
        params.update(unit=unit, quantity=q, addresses=starts[i0:i0 + n])
    elif scenario_id == "R6_unit_probe":
        fc, q = pick_fc(rng), pick_q(rng)
        n = rng.randint(12, 24)
        starts = aligned_addresses(q)
        i0 = rng.randrange(0, max(1, len(starts) - n))
        for a in starts[i0:i0 + n]:
            targets += [(u, fc, a, q) for u in UNITS]
        interval = recon_interval_fn(rng, params)
        params.update(fc=fc, quantity=q, addresses=starts[i0:i0 + n])
    else:
        raise ValueError(scenario_id)
    params["planned_recon_targets"] = len(targets)
    t = t0
    for k, tag in enumerate(targets):
        if t >= t_end:
            params["truncated_recon_targets"] = len(targets) - k
            break
        plan.add(t, tag, f"{scenario_id}:{k}")
        t += interval()
    params.setdefault("truncated_recon_targets", 0)
    return plan


# ---------------------------------------------------------------- run plan

def build_run_plan(run_id: str, scenario_id: str, seed: int, duration_s: float) -> dict:
    rng = random.Random(seed)
    # Background HMI poller, present in every run.
    bg_rng = random.Random(rng.getrandbits(64))
    bg_tags = make_tag_list(bg_rng, bg_rng.randint(18, 30), UNITS)
    bg_period = bg_rng.uniform(0.8, 1.6)
    bg = Plan("normal", "background_hmi")
    cyclic_polling(bg, bg_rng, bg_tags, bg_rng.uniform(0.2, 1.0), duration_s,
                   lambda t: bg_period * bg_rng.uniform(0.95, 1.05))
    actor_rng = random.Random(rng.getrandbits(64))
    params = {}
    a0 = actor_rng.uniform(2.0, 5.0)
    if family_of(scenario_id) == "normal":
        actor = normal_actor(scenario_id, actor_rng, a0, duration_s - 2.0, params)
    else:
        lead_end = a0 + actor_rng.uniform(8.0, 20.0)
        lead = maintenance(Plan("normal", "pre_recon_legitimate_activity"), actor_rng, a0, lead_end)
        params["leadin_end_s"] = lead_end
        rec = recon_actor(scenario_id, actor_rng, lead_end + actor_rng.uniform(0.5, 2.0), duration_s - 2.0, params)
        actor = Plan("mixed", "mixed")
        actor.actions = lead.actions + rec.actions
    clients = {}
    for name, plan, crng in (("background_hmi", bg, bg_rng), ("actor", actor, actor_rng)):
        acts = sorted(plan.actions, key=lambda a: a["t"])
        for i, a in enumerate(acts):
            a["action_index"] = i
        clients[name] = {"tid_start": crng.randrange(0, 65536), "actions": acts}
    selected = sorted({(a["unit"], a["fc"], a["address"], a["quantity"])
                       for a in clients["actor"]["actions"] if a["role"] == "recon"})
    return {
        "run_id": run_id, "scenario_id": scenario_id, "family": family_of(scenario_id), "seed": seed,
        "duration_s": duration_s, "server_seed": rng.getrandbits(31),
        "background": {"tags": bg_tags, "period_s": bg_period},
        "actor_scenario_parameters": params,
        "recon_targets_selected": selected,
        "clients": clients,
    }
