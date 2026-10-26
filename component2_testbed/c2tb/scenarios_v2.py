"""Scenario design v2 ("site envelope"): redesign after pilot v1 failed the joint-shape coverage gate.

Changes from v1 (scenarios.py, kept unchanged for reproducibility of the v1 collection):
* A fixed **site configuration** (shared by all runs of a collection, recorded in every manifest) assigns each
  (unit, table) a read granularity q in {1, 2, 4}.  Legitimate masters read each table at that granularity and the
  stealthy actor mimics it, so (unit, FC) fully determines quantity for *both* families.
* The map is 32 addresses per table, and the background HMI polls a large random subset (40-80 %) of every table
  each cycle, as a SCADA master/data concentrator does.  Across runs this covers the whole shape space.
* Function probing and unit probing use addresses aligned for every granularity (multiples of 4).
Everything else (families, phases, lead-in, timing ranges, ledger semantics) follows v1.
"""
from __future__ import annotations

import random

UNITS = [1, 2, 3]
MAP_SIZE = 32
FUNCTIONS = [1, 2, 3, 4]
FUNCTION_WEIGHTS = [0.15, 0.15, 0.40, 0.30]
GRANULARITIES = [1, 2, 4]
GRANULARITY_WEIGHTS = [0.5, 0.3, 0.2]

NORMAL_SCENARIOS = ["N1_fixed_polling", "N2_variable_polling_bursts", "N3_maintenance_blocks", "N4_trend_watch"]
RECON_SCENARIOS = ["R1_sequential_scan", "R2_sparse_strided_scan", "R3_randomized_scan",
                   "R4_slow_jittered_scan", "R5_function_probe", "R6_unit_probe"]
ALL_SCENARIOS = NORMAL_SCENARIOS + RECON_SCENARIOS
TABLES = [(u, fc) for u in UNITS for fc in FUNCTIONS]


def family_of(scenario_id: str) -> str:
    return "recon" if scenario_id.startswith("R") else "normal"


def build_site(site_seed: int) -> dict:
    rng = random.Random(site_seed)
    return {f"{u}:{fc}": rng.choices(GRANULARITIES, GRANULARITY_WEIGHTS)[0] for u, fc in TABLES}


class Site:
    def __init__(self, site: dict):
        self.q = {tuple(map(int, k.split(":"))): v for k, v in site.items()}

    def addrs(self, table):
        q = self.q[table]
        return list(range(0, MAP_SIZE - q + 1, q))

    def tag(self, table, address):
        return (table[0], table[1], address, self.q[table])

    def pick_table(self, rng, units=UNITS):
        return (rng.choice(units), rng.choices(FUNCTIONS, FUNCTION_WEIGHTS)[0])


class Plan:
    def __init__(self, role, phase):
        self.actions, self.role, self.phase = [], role, phase

    def add(self, t, tag, intent):
        unit, fc, address, quantity = tag
        self.actions.append({"t": round(t, 6), "unit": unit, "fc": fc, "address": address, "quantity": quantity,
                             "role": self.role, "phase": self.phase, "intent": intent})


def ordered(rng, tags):
    tags = list(tags)
    if rng.random() < 0.5:
        tags.sort()
    else:
        rng.shuffle(tags)
    return tags


def subset_tags(site, rng, tables, frac_range):
    tags = []
    for t in tables:
        a = site.addrs(t)
        k = max(1, round(len(a) * rng.uniform(*frac_range)))
        tags += [site.tag(t, x) for x in rng.sample(a, k)]
    return ordered(rng, tags)


def cyclic_polling(plan, rng, tags, t0, t_end, period_fn, gap=(0.004, 0.015), intent="poll_cycle"):
    t, cycle = t0, 0
    while t < t_end:
        tc = t
        for tag in tags:
            if tc >= t_end:
                break
            plan.add(tc, tag, f"{intent}:{cycle}")
            tc += rng.uniform(*gap)
        t = max(t + period_fn(t), tc + 0.05)
        cycle += 1


def maintenance(plan, site, rng, t0, t_end, intent="maintenance"):
    t, done = t0, []
    while t < t_end:
        if done and rng.random() < 0.35:
            table, addrs = rng.choice(done)
        elif rng.random() < 0.15:
            imp = [site.tag(tb, rng.choice(site.addrs(tb))) for tb in (site.pick_table(rng) for _ in range(rng.randint(1, 3)))]
            for _ in range(rng.randint(2, 5)):
                for tag in imp:
                    plan.add(t, tag, f"{intent}:watch")
                    t += rng.uniform(0.05, 0.6)
            t += rng.uniform(1.0, 5.0)
            continue
        else:
            table = site.pick_table(rng)
            a = site.addrs(table)
            n = min(len(a), rng.choice([2, 4, 6, 8, 12]))
            i0 = rng.randrange(0, len(a) - n + 1)
            addrs = a[i0:i0 + n]
            done.append((table, addrs))
        mode = rng.choice(["ascending", "configured_order"])
        seq = list(addrs) if mode == "ascending" else rng.sample(addrs, len(addrs))
        for x in seq:
            if t >= t_end:
                break
            plan.add(t, site.tag(table, x), f"{intent}:block:{mode}")
            t += rng.uniform(0.15, 1.2)
        t += rng.uniform(2.0, 8.0)


def normal_actor(scenario_id, site, rng, t0, t_end, params):
    plan = Plan("normal", "normal_workload")
    if scenario_id in ("N1_fixed_polling", "N2_variable_polling_bursts"):
        tables = rng.sample(TABLES, rng.randint(2, 4))
        tags = subset_tags(site, rng, tables, (0.5, 1.0))
        params.update(tables=tables, n_tags=len(tags))
        if scenario_id == "N1_fixed_polling":
            period = rng.uniform(0.8, 2.5)
            params["period_s"] = period
            cyclic_polling(plan, rng, tags, t0, t_end, lambda t: period * rng.uniform(0.98, 1.02))
        else:
            segments, t = [], t0
            while t < t_end:
                segments.append((t, rng.uniform(8, 20), rng.uniform(0.3, 3.0)))
                t += segments[-1][1]

            def period_fn(tt):
                for s0, dur, per in segments:
                    if s0 <= tt < s0 + dur:
                        return per * rng.uniform(0.85, 1.15)
                return segments[-1][2]
            cyclic_polling(plan, rng, tags, t0, t_end, period_fn)
            tb, bursts = t0 + rng.uniform(2, 8), []
            while tb < t_end:
                table = site.pick_table(rng)
                a = site.addrs(table)
                n = min(len(a), rng.randint(4, 12))
                i0 = rng.randrange(0, len(a) - n + 1)
                bursts.append((tb, table, a[i0], n))
                tt = tb
                for x in a[i0:i0 + n]:
                    if tt >= t_end:
                        break
                    plan.add(tt, site.tag(table, x), "operator_screen_burst")
                    tt += rng.uniform(0.01, 0.08)
                tb += rng.uniform(5, 15)
            params.update(period_segments=segments, bursts=bursts)
            plan.actions.sort(key=lambda x: x["t"])
    elif scenario_id == "N3_maintenance_blocks":
        maintenance(plan, site, rng, t0, t_end)
    elif scenario_id == "N4_trend_watch":
        tags = [site.tag(tb, rng.choice(site.addrs(tb))) for tb in (site.pick_table(rng) for _ in range(rng.randint(2, 5)))]
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


def recon_actor(scenario_id, site, rng, t0, t_end, params):
    plan = Plan("recon", "recon")
    targets = []
    base = rng.uniform(0.05, 0.4)
    profile = rng.choice(["steady", "poll_mimic_bursts"])
    params["timing_profile"] = profile
    if profile == "steady":
        interval = lambda: base * rng.uniform(0.8, 1.2)
    else:
        # v1 lesson: steady recon pacing never produced the 4-15 ms back-to-back gaps of legitimate poll cycles,
        # so minimum inter-request time alone separated families.  Mimic poll-cycle batches instead.
        state = {"left": rng.randint(4, 12)}

        def interval():
            state["left"] -= 1
            if state["left"] > 0:
                return rng.uniform(0.004, 0.015)
            state["left"] = rng.randint(4, 12)
            return rng.uniform(0.5, 3.0)
    common4 = list(range(0, MAP_SIZE, 4))  # aligned for every granularity
    if scenario_id in ("R1_sequential_scan", "R3_randomized_scan"):
        tables = [site.pick_table(rng) for _ in range(rng.randint(2, 4))]
        for tb in dict.fromkeys(tables):
            targets += [site.tag(tb, x) for x in site.addrs(tb)]
        if scenario_id == "R3_randomized_scan":
            rng.shuffle(targets)
        params.update(tables=list(dict.fromkeys(tables)), base_interval_s=base)
    elif scenario_id == "R2_sparse_strided_scan":
        tables = []
        for _ in range(rng.randint(3, 5)):
            tb = site.pick_table(rng)
            q = site.q[tb]
            stride = q * rng.choice([2, 4])
            off = rng.randrange(0, stride, q)
            tables.append((tb, stride, off))
            targets += [site.tag(tb, x) for x in range(off, MAP_SIZE - q + 1, stride)]
        params.update(tables=tables, base_interval_s=base)
    elif scenario_id == "R4_slow_jittered_scan":
        tables = list(dict.fromkeys(site.pick_table(rng) for _ in range(2)))
        for tb in tables:
            targets += [site.tag(tb, x) for x in site.addrs(tb)]
        targets = targets[:28]  # sized so a slow sweep completes inside the run
        order = rng.choice(["ascending", "random"])
        if order == "random":
            rng.shuffle(targets)
        params.update(tables=tables, order=order, interval_range_s=(0.6, 2.5))
        interval = lambda: rng.uniform(0.6, 2.5)
    elif scenario_id == "R5_function_probe":
        unit = rng.choice(UNITS)
        n = rng.randint(5, 8)
        i0 = rng.randrange(0, len(common4) - n + 1)
        for x in common4[i0:i0 + n]:
            fcs = FUNCTIONS[:]
            rng.shuffle(fcs)
            targets += [site.tag((unit, fc), x) for fc in fcs]
        params.update(unit=unit, addresses=common4[i0:i0 + n], base_interval_s=base)
    elif scenario_id == "R6_unit_probe":
        fc = rng.choices(FUNCTIONS, FUNCTION_WEIGHTS)[0]
        n = rng.randint(5, 8)
        i0 = rng.randrange(0, len(common4) - n + 1)
        for x in common4[i0:i0 + n]:
            targets += [site.tag((u, fc), x) for u in UNITS]
        params.update(fc=fc, addresses=common4[i0:i0 + n], base_interval_s=base)
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


def build_run_plan(run_id: str, scenario_id: str, seed: int, duration_s: float, site: dict) -> dict:
    s = Site(site)
    rng = random.Random(seed)
    bg_rng = random.Random(rng.getrandbits(64))
    bg_tags = subset_tags(s, bg_rng, TABLES, (0.4, 0.8))
    bg_period = bg_rng.uniform(2.0, 4.0)
    bg = Plan("normal", "background_hmi")
    cyclic_polling(bg, bg_rng, bg_tags, bg_rng.uniform(0.2, 1.0), duration_s,
                   lambda t: bg_period * bg_rng.uniform(0.95, 1.05))
    actor_rng = random.Random(rng.getrandbits(64))
    params = {}
    a0 = actor_rng.uniform(2.0, 5.0)
    if family_of(scenario_id) == "normal":
        actor_actions = normal_actor(scenario_id, s, actor_rng, a0, duration_s - 2.0, params).actions
    else:
        lead_end = a0 + actor_rng.uniform(8.0, 20.0)
        lead = Plan("normal", "pre_recon_legitimate_activity")
        maintenance(lead, s, actor_rng, a0, lead_end)
        params["leadin_end_s"] = lead_end
        rec = recon_actor(scenario_id, s, actor_rng, lead_end + actor_rng.uniform(0.5, 2.0), duration_s - 2.0, params)
        actor_actions = lead.actions + rec.actions
    clients = {}
    for name, acts, crng in (("background_hmi", bg.actions, bg_rng), ("actor", actor_actions, actor_rng)):
        acts = sorted(acts, key=lambda a: a["t"])
        for i, a in enumerate(acts):
            a["action_index"] = i
        clients[name] = {"tid_start": crng.randrange(0, 65536), "actions": acts}
    selected = sorted({(a["unit"], a["fc"], a["address"], a["quantity"])
                       for a in clients["actor"]["actions"] if a["role"] == "recon"})
    return {
        "run_id": run_id, "scenario_id": scenario_id, "family": family_of(scenario_id), "seed": seed,
        "duration_s": duration_s, "server_seed": rng.getrandbits(31), "scenario_design": "v2_site_envelope",
        "site": site, "map_size": MAP_SIZE,
        "background": {"n_tags": len(bg_tags), "period_s": bg_period, "tags": bg_tags},
        "actor_scenario_parameters": params, "recon_targets_selected": selected, "clients": clients,
    }
