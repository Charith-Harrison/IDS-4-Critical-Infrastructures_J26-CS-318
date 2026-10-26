"""Scenario design v3: v2 site envelope + legitimate one-pass coverage workloads (hard negatives) + two sites.

v2 (scenarios_v2.py, unchanged) showed that recon was separable mainly because it never revisits targets while
every legitimate pilot workload did.  Real plants also have legitimate one-pass coverage reads.  v3 adds four such
normal workloads, each mirroring a recon pattern, each preceded by the same maintenance lead-in that recon runs
have, and each paced with the same timing distributions as recon:

  N5_hmi_cold_start         HMI/driver (re)start reads every configured point of several tables once  ~ R1/R3
  N6_config_backup          engineering tool reads whole tables once, ascending, table by table        ~ R1
  N7_historian_backfill     historian gap-fill reads tables once in random or strided order             ~ R2/R3/R4
  N8_commissioning_checkout engineer checks the same points across units or across tables of a unit    ~ R5/R6

Expected outcome: some recon/normal pairs become behaviourally indistinguishable from observable traffic alone.
That is an honest boundary of the research question, not a defect to engineer away.
"""
from __future__ import annotations

import random

from c2tb import scenarios_v2 as v2
from c2tb.scenarios_v2 import (FUNCTIONS, FUNCTION_WEIGHTS, MAP_SIZE, TABLES, UNITS, Plan, Site, build_site,
                               cyclic_polling, maintenance, subset_tags)

ONE_PASS_SCENARIOS = ["N5_hmi_cold_start", "N6_config_backup", "N7_historian_backfill", "N8_commissioning_checkout"]
NORMAL_SCENARIOS = v2.NORMAL_SCENARIOS + ONE_PASS_SCENARIOS
RECON_SCENARIOS = v2.RECON_SCENARIOS
ALL_SCENARIOS = NORMAL_SCENARIOS + RECON_SCENARIOS
family_of = v2.family_of
__all__ = ["build_site", "build_run_plan", "ALL_SCENARIOS"]


def tool_interval(rng, params, slow=False):
    """Same pacing distributions as v2 recon_actor (duplicated, not imported, so v2 stays byte-identical)."""
    if slow:
        params.update(timing_profile="slow", interval_range_s=(0.6, 2.5))
        return lambda: rng.uniform(0.6, 2.5)
    base = rng.uniform(0.05, 0.4)
    profile = rng.choice(["steady", "poll_mimic_bursts"])
    params.update(timing_profile=profile, base_interval_s=base)
    if profile == "steady":
        return lambda: base * rng.uniform(0.8, 1.2)
    state = {"left": rng.randint(4, 12)}

    def interval():
        state["left"] -= 1
        if state["left"] > 0:
            return rng.uniform(0.004, 0.015)
        state["left"] = rng.randint(4, 12)
        return rng.uniform(0.5, 3.0)
    return interval


def one_pass_actor(scenario_id, site, rng, t0, t_end, params):
    plan = Plan("normal", "normal_workload")
    common4 = list(range(0, MAP_SIZE, 4))
    if scenario_id == "N5_hmi_cold_start":
        tables = list(dict.fromkeys(site.pick_table(rng) for _ in range(rng.randint(2, 4))))
        targets = subset_tags(site, rng, tables, (0.7, 1.0))  # configured points, sorted or configured order
        interval = tool_interval(rng, params)
        params.update(tables=tables)
    elif scenario_id == "N6_config_backup":
        tables = sorted(dict.fromkeys(site.pick_table(rng) for _ in range(rng.randint(2, 4))))
        targets = [site.tag(tb, x) for tb in tables for x in site.addrs(tb)]
        slow = rng.random() < 0.25  # throttled backup to spare the PLC
        interval = tool_interval(rng, params, slow=slow)
        if slow:
            targets = targets[:28]
        params.update(tables=tables)
    elif scenario_id == "N7_historian_backfill":
        mode = rng.choice(["random", "strided", "slow_random"])
        tables, targets = [], []
        for _ in range(rng.randint(2, 4)):
            tb = site.pick_table(rng)
            q = site.q[tb]
            if mode == "strided":
                stride = q * rng.choice([2, 4])
                off = rng.randrange(0, stride, q)
                targets += [site.tag(tb, x) for x in range(off, MAP_SIZE - q + 1, stride)]
            else:
                targets += [site.tag(tb, x) for x in site.addrs(tb)]
            tables.append(tb)
        if mode != "strided":
            rng.shuffle(targets)
        interval = tool_interval(rng, params, slow=mode == "slow_random")
        if mode == "slow_random":
            targets = targets[:28]
        params.update(tables=tables, mode=mode)
    elif scenario_id == "N8_commissioning_checkout":
        mode = rng.choice(["across_units", "across_functions"])
        n = rng.randint(5, 8)
        i0 = rng.randrange(0, len(common4) - n + 1)
        targets = []
        if mode == "across_units":
            fc = rng.choices(FUNCTIONS, FUNCTION_WEIGHTS)[0]
            for x in common4[i0:i0 + n]:
                targets += [site.tag((u, fc), x) for u in UNITS]
        else:
            unit = rng.choice(UNITS)
            for x in common4[i0:i0 + n]:
                fcs = FUNCTIONS[:]
                rng.shuffle(fcs)
                targets += [site.tag((unit, f), x) for f in fcs]
        interval = tool_interval(rng, params)
        params.update(mode=mode, addresses=common4[i0:i0 + n])
    else:
        raise ValueError(scenario_id)
    params["planned_one_pass_targets"] = len(targets)
    t = t0
    for k, tag in enumerate(targets):
        if t >= t_end:
            params["truncated_one_pass_targets"] = len(targets) - k
            break
        plan.add(t, tag, f"{scenario_id}:{k}")
        t += interval()
    params.setdefault("truncated_one_pass_targets", 0)
    return plan


def build_run_plan(run_id: str, scenario_id: str, seed: int, duration_s: float, site: dict, site_id: str) -> dict:
    if scenario_id not in ONE_PASS_SCENARIOS:
        plan = v2.build_run_plan(run_id, scenario_id, seed, duration_s, site)
    else:
        # Same structure and RNG stream layout as v2.build_run_plan; actor = lead-in + one-pass task.
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
        lead_end = a0 + actor_rng.uniform(8.0, 20.0)
        lead = Plan("normal", "pre_task_legitimate_activity")
        maintenance(lead, s, actor_rng, a0, lead_end)
        params["leadin_end_s"] = lead_end
        task = one_pass_actor(scenario_id, s, actor_rng, lead_end + actor_rng.uniform(0.5, 2.0), duration_s - 2.0,
                              params)
        clients = {}
        for name, acts, crng in (("background_hmi", bg.actions, bg_rng),
                                 ("actor", lead.actions + task.actions, actor_rng)):
            acts = sorted(acts, key=lambda a: a["t"])
            for i, a in enumerate(acts):
                a["action_index"] = i
            clients[name] = {"tid_start": crng.randrange(0, 65536), "actions": acts}
        plan = {
            "run_id": run_id, "scenario_id": scenario_id, "family": "normal", "seed": seed,
            "duration_s": duration_s, "server_seed": rng.getrandbits(31), "site": site, "map_size": MAP_SIZE,
            "background": {"n_tags": len(bg_tags), "period_s": bg_period, "tags": bg_tags},
            "actor_scenario_parameters": params, "recon_targets_selected": [], "clients": clients,
        }
    plan["scenario_design"] = "v3_one_pass_hard_negatives"
    plan["site_id"] = site_id
    return plan
