"""Host-side orchestrator: executes each run as a separately initialised acquisition in Docker.

Per run: fresh internal network -> target server (seeded state) -> passive tcpdump in the target's namespace ->
two client containers with random IPs executing the pre-generated plan -> stop capture -> collect logs ->
hash and write-protect raw evidence -> run manifest.  Uses only the Python standard library on the host.

Usage:  python run_pilot.py --config configs/pilot_v1.json [--only N] [--collection-id ID]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import stat
import subprocess
import sys
import time
from pathlib import Path

TB = Path(__file__).resolve().parent
REPO = TB.parent


def sh(cmd, check=True, timeout=None):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}: {r.stderr.strip()}")
    return r.stdout.strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def software_versions(image: str) -> dict:
    code = {str(p.relative_to(TB)).replace("\\", "/"): sha256(p) for p in sorted((TB / "c2tb").glob("*.py"))}
    code["run_pilot.py"] = sha256(TB / "run_pilot.py")
    probe = ("import sys,pymodbus,pandas,sklearn,numpy;"
             "print(sys.version.split()[0],pymodbus.__version__,pandas.__version__,sklearn.__version__,numpy.__version__)")
    py, pym, pd_, skl, npv = sh(["docker", "run", "--rm", image, "python", "-c", probe]).split()
    return {
        "image": image,
        "image_id": sh(["docker", "image", "inspect", image, "--format", "{{.Id}}"]),
        "docker_server": sh(["docker", "version", "--format", "{{.Server.Version}}"]),
        "python_in_image": py, "pymodbus": pym, "pandas": pd_, "scikit_learn": skl, "numpy": npv,
        "tcpdump": sh(["docker", "run", "--rm", image, "tcpdump", "--version"]).splitlines()[0],
        "tshark": sh(["docker", "run", "--rm", image, "tshark", "--version"]).splitlines()[0],
        "host_python": sys.version.split()[0],
        "git_commit": sh(["git", "-C", str(REPO), "rev-parse", "HEAD"]),
        "git_branch": sh(["git", "-C", str(REPO), "branch", "--show-current"]),
        "git_worktree_dirty": bool(sh(["git", "-C", str(REPO), "status", "--porcelain"])),
        "testbed_code_sha256": code,
    }


def host_vm_offsets(container: str, n: int = 3) -> list:
    """Coarse host-vs-VM wall-clock offset; uncertainty is the docker exec round trip."""
    out = []
    for _ in range(n):
        h0 = time.time_ns()
        vm = int(sh(["docker", "exec", container, "python", "-c", "import time;print(time.time_ns())"]))
        h1 = time.time_ns()
        out.append({"vm_minus_host_mid_ms": round((vm - (h0 + h1) / 2) / 1e6, 3), "round_trip_ms": round((h1 - h0) / 1e6, 3)})
    return out


def protect(path: Path):
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def run_one(cfg, coll_dir: Path, run_id: str, scenario: str, seed: int, versions: dict, site=None,
            frozen_plan: dict | None = None, worker: int = 0) -> dict:
    img = cfg["image"]
    run_dir = coll_dir / "runs" / run_id
    run_dir.mkdir(parents=True)
    mount = ["-v", f"{TB}:/tb:ro", "-v", f"{run_dir}:/out"]
    net = f"c2tb_{run_id}"
    roles = ("target", "capture", "background_hmi", "actor") + (("clock",) if cfg.get("clock_monitor") else ())
    names = {k: f"c2tb_{run_id}_{k}" for k in roles}
    if site is None and "site_seed" in cfg:
        site = {"site_id": "default", "site_seed": cfg["site_seed"]}
    rng = random.Random(seed)
    lo, hi = cfg["client_ip_pool"]
    # Each parallel worker uses its own non-overlapping subnet (Docker rejects overlapping bridge pools).
    subnet = cfg["subnet"].replace("10.52.0.", f"10.52.{worker}.")
    target_ip = cfg["target_ip"].replace("10.52.0.", f"10.52.{worker}.")
    base = target_ip.rsplit(".", 1)[0]
    ips = {"background_hmi": f"{base}.{rng.randint(lo, hi)}"}
    while True:
        ips["actor"] = f"{base}.{rng.randint(lo, hi)}"
        if ips["actor"] != ips["background_hmi"]:
            break
    manifest = {
        "collection_id": coll_dir.name, "run_id": run_id, "scenario_id": scenario,
        "family": "recon" if scenario.startswith("R") else "normal", "run_seed": seed,
        "config_id": cfg["config_id"], "run_duration_s": cfg["run_duration_s"],
        "target": {"ip": target_ip, "port": 502, "role": "modbus_tcp_server"}, "worker": worker,
        "clients": {k: {"ip": v} for k, v in ips.items()},
        "actor_role_by_family": "recon actor after legitimate lead-in" if scenario.startswith("R") else "normal actor",
        "network": {"name": net, "subnet": subnet, "internal": True},
        "capture": {"file": "capture.pcap", "interface": "target eth0 (target network namespace)",
                    "tool": "tcpdump -i eth0 -s 0 -U -n --time-stamp-precision nano", "link_type": None},
        "software_versions": versions,
        "collection_state": "started", "collection_error": None,
    }
    try:
        sh(["docker", "network", "create", "--internal", "--subnet", subnet, net])
        if frozen_plan is not None:  # pre-generated, hash-checked plan (final collection)
            src = TB / frozen_plan["path"]
            if sha256(src) != frozen_plan["sha256"]:
                raise RuntimeError(f"frozen plan hash mismatch: {src}")
            (run_dir / "plan.json").write_bytes(src.read_bytes())
            manifest["frozen_plan"] = frozen_plan
        else:
            sh(["docker", "run", "--rm", *mount, img, "python", "-m", "c2tb.make_plan", "--run-id", run_id,
            "--scenario", scenario, "--seed", str(seed), "--duration", str(cfg["run_duration_s"]),
                "--out", "/out/plan.json", "--design", cfg.get("scenario_design", "v1"),
                *(["--site-seed", str(site["site_seed"]), "--site-id", site["site_id"]] if site else [])])
        plan = json.loads((run_dir / "plan.json").read_text())
        manifest["server_seed"] = plan["server_seed"]
        manifest["scenario_design"] = plan["scenario_design"]
        manifest["map_size"] = plan["map_size"]
        manifest["site_read_granularity"] = plan.get("site")
        manifest["site_id"] = plan.get("site_id")
        for k in ("units", "horizon_s", "effective_duration_s", "end_policy"):
            if k in plan:
                manifest[k] = plan[k]
        manifest["background_parameters"] = plan["background"]
        manifest["actor_scenario_parameters"] = plan["actor_scenario_parameters"]
        manifest["recon_targets_selected"] = plan["recon_targets_selected"]
        manifest["planned_actions"] = {k: len(v["actions"]) for k, v in plan["clients"].items()}
        manifest["planned_recon_actions"] = sum(a["role"] == "recon" for a in plan["clients"]["actor"]["actions"])
        manifest["tid_start"] = {k: v["tid_start"] for k, v in plan["clients"].items()}
        sh(["docker", "run", "-d", "--name", names["target"], "--network", net, "--ip", target_ip,
            *mount, img, "python", "-m", "c2tb.server", "--seed", str(plan["server_seed"]),
            "--map-size", str(plan["map_size"]), "--units", ",".join(map(str, plan.get("units", [1, 2, 3])))])
        if "clock" in names:
            sh(["docker", "run", "-d", "--name", names["clock"], "--network", "none", *mount, img,
                "python", "-m", "c2tb.clockmon", "--out", "/out/clock.jsonl", "--period", "0.01"])
            manifest["clock_offsets_start"] = host_vm_offsets(names["target"])
        sh(["docker", "run", "-d", "--name", names["capture"], "--network", f"container:{names['target']}",
            "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", *mount, img,
            "tcpdump", "-i", "eth0", "-s", "0", "-U", "-n", "--time-stamp-precision", "nano",
            "-w", "/out/capture.pcap"])
        for _ in range(100):
            if "server_start" in sh(["docker", "logs", names["target"]], check=False) and \
                    (run_dir / "capture.pcap").exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("target or capture did not start")
        time.sleep(1.5)
        vm_now = int(sh(["docker", "exec", names["target"], "python", "-c", "import time;print(time.time_ns())"]))
        start_ns = vm_now + 3_000_000_000
        manifest["planned_start_epoch_ns"] = start_ns
        for c in ("background_hmi", "actor"):
            sh(["docker", "run", "-d", "--name", names[c], "--network", net, "--ip", ips[c], *mount, img,
                "python", "-m", "c2tb.client", "--plan", "/out/plan.json", "--client", c,
                "--ledger", f"/out/ledger_{c}.jsonl", "--server", target_ip,
                "--start-epoch-ns", str(start_ns)])
        for c in ("background_hmi", "actor"):
            code = sh(["docker", "wait", names[c]], timeout=plan.get("horizon_s", cfg["run_duration_s"]) + 120)
            manifest["clients"][c]["exit_code"] = int(code)
            (run_dir / f"client_{c}.log").write_text(sh(["docker", "logs", names[c]], check=False))
        time.sleep(1.0)
        sh(["docker", "kill", "--signal", "INT", names["capture"]])
        sh(["docker", "wait", names["capture"]], timeout=30)
        cap_log = subprocess.run(["docker", "logs", names["capture"]], capture_output=True, text=True)
        (run_dir / "tcpdump.log").write_text(cap_log.stdout + cap_log.stderr)
        if "clock" in names:
            manifest["clock_offsets_end"] = host_vm_offsets(names["target"])
            sh(["docker", "stop", "-t", "5", names["clock"]])
        (run_dir / "server.log").write_text(sh(["docker", "logs", names["target"]], check=False))
        manifest["end_wall_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        manifest["collection_state"] = "collected"
    except Exception as e:  # keep the run directory and record why
        manifest["collection_state"] = "collection_error"
        manifest["collection_error"] = repr(e)
    finally:
        for n in names.values():
            subprocess.run(["docker", "rm", "-f", n], capture_output=True)
        subprocess.run(["docker", "network", "rm", net], capture_output=True)
    files = {}
    for p in sorted(run_dir.iterdir()):
        files[p.name] = {"bytes": p.stat().st_size, "sha256": sha256(p)}
        if p.name == "capture.pcap" or p.name.startswith("ledger_") or p.name in ("plan.json", "clock.jsonl"):
            protect(p)
    manifest["raw_files"] = files
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=1))
    protect(run_dir / "run_manifest.json")
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--only", type=int, default=None, help="collect only the first N runs (smoke test)")
    ap.add_argument("--collection-id", default=None)
    ap.add_argument("--plans", default=None, help="frozen plan manifest (final collection); overrides the schedule")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--run-ids", default=None, help="comma list: collect only these frozen run IDs (replacement rule)")
    ap.add_argument("--id-suffix", default="", help="appended to run IDs, e.g. -retry1 (same frozen plan and seed)")
    a = ap.parse_args()
    cfg = json.loads((TB / a.config).read_text())
    coll_id = a.collection_id or f"{cfg['config_id']}_{dt.datetime.now().strftime('%Y%m%dT%H%M%S')}"
    coll_dir = TB / "data" / coll_id
    coll_dir.mkdir(parents=True, exist_ok=bool(a.id_suffix))  # retries add runs to an existing collection
    rng = random.Random(cfg["collection_seed"])
    sites = cfg.get("sites", [None]) if "scenarios" in cfg else []
    runs = [(s, rep, site) for s in cfg.get("scenarios", []) for site in sites
            for rep in range(cfg["replicates_per_scenario"])]
    rng.shuffle(runs)
    schedule = []
    for i, (s, rep, site) in enumerate(runs, 1):
        schedule.append({"run_id": f"{coll_id}-r{i:02d}", "scenario_id": s, "replicate": rep,
                         "seed": rng.getrandbits(31), **({"site": site} if site else {})})
    if a.plans:
        frozen = json.loads((TB / a.plans).read_text())
        schedule = frozen["schedule"]
    if a.run_ids:
        keep = set(a.run_ids.split(","))
        schedule = [r for r in schedule if r["run_id"] in keep]
    if a.id_suffix:
        schedule = [{**r, "run_id": r["run_id"] + a.id_suffix} for r in schedule]
    if a.only:
        schedule = schedule[:a.only]
    versions = software_versions(cfg["image"])
    coll = {"collection_id": coll_id, "config": cfg, "schedule": schedule, "software_versions": versions,
            "started_wall_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
    man_name = f"collection_manifest{a.id_suffix}.json"  # a retry never overwrites the original manifest
    (coll_dir / man_name).write_text(json.dumps(coll, indent=1))
    import queue
    import threading
    todo, results, lock = queue.Queue(), [], threading.Lock()
    for r in schedule:
        todo.put(r)

    def worker(w):
        while True:
            try:
                r = todo.get_nowait()
            except queue.Empty:
                return
            t0 = time.time()
            m = run_one(cfg, coll_dir, r["run_id"], r["scenario_id"], r["seed"], versions, r.get("site"),
                        r.get("frozen_plan"), w)
            with lock:
                results.append({"run_id": r["run_id"], "scenario_id": r["scenario_id"], "worker": w,
                                "collection_state": m["collection_state"], "error": m["collection_error"]})
                print(f"{r['run_id']} {r['scenario_id']:28s} w{w} {m['collection_state']} {time.time() - t0:.0f}s",
                      flush=True)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(a.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    coll["finished_wall_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    coll["results"] = results
    (coll_dir / man_name).write_text(json.dumps(coll, indent=1))


if __name__ == "__main__":
    main()
