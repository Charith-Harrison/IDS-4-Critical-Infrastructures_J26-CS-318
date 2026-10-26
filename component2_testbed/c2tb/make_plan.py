"""Write a run plan JSON (executed inside the testbed image so plan generation uses the pinned Python)."""
import argparse
import json

from c2tb import scenarios, scenarios_v2, scenarios_v3

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", required=True)
    p.add_argument("--scenario", required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--design", default="v1")
    p.add_argument("--site-seed", type=int, default=None)
    p.add_argument("--site-id", default="default")
    a = p.parse_args()
    if a.design == "v3_one_pass_hard_negatives":
        plan = scenarios_v3.build_run_plan(a.run_id, a.scenario, a.seed, a.duration,
                                           scenarios_v3.build_site(a.site_seed), a.site_id)
    elif a.design == "v2_site_envelope":
        plan = scenarios_v2.build_run_plan(a.run_id, a.scenario, a.seed, a.duration, scenarios_v2.build_site(a.site_seed))
    else:
        plan = scenarios.build_run_plan(a.run_id, a.scenario, a.seed, a.duration)
        plan.update(scenario_design="v1", map_size=scenarios.MAP_SIZE)
    with open(a.out, "w") as f:
        json.dump(plan, f, indent=1)
