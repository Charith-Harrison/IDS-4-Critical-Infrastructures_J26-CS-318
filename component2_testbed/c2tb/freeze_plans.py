"""Pre-generate every frozen run plan before collection.

Allocation: for every (site, partition, scenario group, scenario) the configured number of runs is created; seeds
come from one seeded generator; the execution order is a seeded shuffle of all runs so that site, partition and
scenario are not confounded with collection time or parallel worker.  Each plan is written once and hashed; the
orchestrator refuses a plan whose hash differs.  Partition membership is fixed here, before any traffic exists.
"""
import argparse
import hashlib
import json
import random
from pathlib import Path

from c2tb.scenarios_final import build_run_plan

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--only-runs", default=None, help="comma list of site:partition:scenario (benchmark use)")
    a = ap.parse_args()
    cfg = json.loads(Path(a.config).read_text())
    rng = random.Random(cfg["collection_seed"])
    runs = []
    for site_id, parts in cfg["runs_per_scenario"].items():
        for part, groups in parts.items():
            for group, n in groups.items():
                for sc in cfg["scenario_groups"][group]:
                    runs += [{"site_id": site_id, "partition": part, "group": group, "scenario_id": sc, "replicate": i}
                             for i in range(n)]
    if a.only_runs:
        want = [tuple(x.split(":")) for x in a.only_runs.split(",")]
        runs = [next(r for r in runs if (r["site_id"], r["partition"], r["scenario_id"]) == w) for w in want]
    for r in runs:
        r["seed"] = rng.getrandbits(31)
    rng.shuffle(runs)
    out = Path(a.out_dir)
    (out / "plans").mkdir(parents=True, exist_ok=True)
    schedule = []
    for i, r in enumerate(runs, 1):
        run_id = f"{cfg['collection_id']}-r{i:03d}"
        site = cfg["sites"][r["site_id"]]
        plan = build_run_plan(run_id, r["scenario_id"], r["seed"], cfg["horizon_s"], site, cfg["end_tail_s"])
        plan.update(partition=r["partition"], scenario_group=r["group"])
        p = out / "plans" / f"{run_id}.json"
        p.write_text(json.dumps(plan, indent=1))
        rel = str(p).replace("\\", "/")
        schedule.append({"run_id": run_id, **r, "site": site,
                         "effective_duration_s": plan["effective_duration_s"],
                         "planned_requests": sum(len(c["actions"]) for c in plan["clients"].values()),
                         "frozen_plan": {"path": rel, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}})
    manifest = {"config_id": cfg["config_id"], "collection_id": cfg["collection_id"], "n_runs": len(schedule),
                "schedule": schedule}
    (out / "frozen_plan_manifest.json").write_text(json.dumps(manifest, indent=1))
    print(len(schedule), "plans written")
