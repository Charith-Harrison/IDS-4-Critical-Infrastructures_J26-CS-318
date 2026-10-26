"""Frozen final-collection design: v3 scenarios + per-site geometry + end policy.

Behaviour is exactly scenarios_v3 (and therefore v2 for N1-N4/R1-R6).  Two things are added:

* Site geometry.  v2/v3 read UNITS / MAP_SIZE / TABLES as module globals at call time; `site_geometry` sets them for
  the duration of one plan build and restores them afterwards.  Sites A and B use the v3 geometry (units 1-3, 32
  addresses), so their plans are identical to v3 plans for the same seed.  Site C changes units and map size.
* End policy.  A run ends `tail_s` after the actor's last planned action (never later than the horizon).  Background
  actions after that point are dropped from the plan; nothing the actor does changes.
"""
from __future__ import annotations

from contextlib import contextmanager

from c2tb import scenarios_v2 as v2
from c2tb import scenarios_v3 as v3


@contextmanager
def site_geometry(units, map_size):
    saved = (v2.UNITS, v2.MAP_SIZE, v2.TABLES, v3.UNITS, v3.MAP_SIZE, v3.TABLES)
    saved_default = v2.Site.pick_table.__defaults__  # `units=UNITS` is bound at definition time
    tables = [(u, fc) for u in units for fc in v2.FUNCTIONS]
    v2.UNITS, v2.MAP_SIZE, v2.TABLES = list(units), map_size, tables
    v3.UNITS, v3.MAP_SIZE, v3.TABLES = list(units), map_size, tables
    v2.Site.pick_table.__defaults__ = (list(units),)
    try:
        yield
    finally:
        v2.UNITS, v2.MAP_SIZE, v2.TABLES, v3.UNITS, v3.MAP_SIZE, v3.TABLES = saved
        v2.Site.pick_table.__defaults__ = saved_default


def build_run_plan(run_id, scenario_id, seed, horizon_s, site, tail_s):
    with site_geometry(site["units"], site["map_size"]):
        granularity = v2.build_site(site["site_seed"])
        plan = v3.build_run_plan(run_id, scenario_id, seed, horizon_s, granularity, site["site_id"])
    actor_last = max(a["t"] for a in plan["clients"]["actor"]["actions"])
    end = min(horizon_s, actor_last + tail_s)
    bg = plan["clients"]["background_hmi"]
    bg["actions"] = [a for a in bg["actions"] if a["t"] <= end]
    plan.update(scenario_design="final_v1", units=site["units"], map_size=site["map_size"],
                horizon_s=horizon_s, effective_duration_s=round(end, 3), end_policy=f"actor_last_plus_{tail_s}s")
    return plan
