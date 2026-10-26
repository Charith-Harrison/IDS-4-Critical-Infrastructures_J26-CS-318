"""Offline demo server for Component 2 (final controlled-testbed system).

Serves the built React frontend and a small API backed only by the demo bundle (frozen models, held-out test runs,
final reports).  No internet, Docker or PyTorch needed.  Start with start_c2_demo.ps1 or:
    python -m uvicorn server:app --app-dir C2_Reconnaissance_Detection/demo --port 8020
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from inference import BUNDLE as DEFAULT_BUNDLE
from inference import MODELS, FrozenPipeline, SchemaError

HERE = Path(__file__).resolve().parent
BUNDLE = Path(os.environ.get("C2_DEMO_BUNDLE", DEFAULT_BUNDLE))
DIST = HERE.parent / "frontend" / "dist"
MAX_UPLOAD_ROWS = 60000
TIE = 1e-9

app = FastAPI(title="C2 reconnaissance detection demo", version="2.0.0")


def j(rel):
    return json.loads((BUNDLE / rel).read_text())


@lru_cache(maxsize=1)
def pipeline():
    return FrozenPipeline(BUNDLE)


def bundle_check():
    man = j("bundle_manifest.json")
    bad = [f for f, h in man["files"].items()
           if not (BUNDLE / f).exists() or hashlib.sha256((BUNDLE / f).read_bytes()).hexdigest() != h]
    return {"files": len(man["files"]), "missing_or_changed": bad}


@app.get("/api/health")
def health():
    if not (BUNDLE / "bundle_manifest.json").exists():
        raise HTTPException(503, f"demo bundle not found at {BUNDLE}")
    p = pipeline()
    return {"status": "ok", "bundle": str(BUNDLE.name), "integrity": bundle_check(), "models": MODELS,
            "thresholds": p.thresholds}


def h1_row(rep, m):
    h = rep["H1_primary_full_context"]
    r = rep["rates_full_context"][m]
    out = {"recall": h["scenario_balanced_recall"][m],
           "fpr_revisiting": r["revisiting_normal"], "fpr_one_pass": r["one_pass_normal"],
           "fpr_background": r["background"], "auc_vs_revisiting": r["auc_recon_vs_revisiting_normal"],
           "auc_vs_one_pass": r["auc_recon_vs_one_pass_normal"]}
    if m in h["gain_over_A"]:
        out["gain_over_A"] = h["gain_over_A"][m]
    return out


@app.get("/api/summary")
def summary():
    ev = j("reports/validation_evidence.json")
    st = ev["collection_status"]
    ins, sc, val = j("reports/test_in_site_report.json"), j("reports/test_out_of_site_report.json"), \
        j("reports/validation_report.json")
    sel = j("models/selected.json")
    models = []
    for m, name, kind in [("A", "Current message", "Current request only"),
                          ("B2", "Order-free summary", "Last 20 requests, order ignored"),
                          ("B1", "Flattened-history RF", "Last 20 requests, flattened (proposal baseline)"),
                          ("B3", "History-statistics RF", "Pre-specified history statistics"),
                          ("L", "LSTM", "Last 20 requests, sequence model")]:
        models.append({"id": m, "name": name, "input": kind, "cv_auc": sel[m]["cv_auc"],
                       "validation": {"recall": val["models"][m]["full_context"]["recall_recon"],
                                      "fpr_revisiting": val["models"][m]["full_context"]["fpr_revisiting_normal"]},
                       "in_site": h1_row(ins, m), "site_c": h1_row(sc, m)})
    return {"title": "Reconnaissance Attack Detection Using Temporal Behavior Analysis",
            "component": "Component 2 / RP2", "runs_planned": st["planned_runs"], "runs_accepted": st["accepted_final"],
            "requests": st["requests_total_accepted_runs"], "recon_runs_in_site": ins["H1_primary_full_context"]["recon_runs"],
            "recon_runs_site_c": sc["H1_primary_full_context"]["recon_runs"], "context_length": 20,
            "thresholds": pipeline().thresholds, "models": models,
            "test_openings": {"in_site": j("reports/opened_test_in_site.json")["opened_utc"],
                              "site_c": j("reports/opened_test_out_of_site.json")["opened_utc"]},
            "per_scenario": {"in_site": ins["H1_primary_full_context"]["per_scenario_recall_descriptive"],
                             "site_c": sc["H1_primary_full_context"]["per_scenario_recall_descriptive"]}}


@app.get("/api/validation")
def validation():
    ev = j("reports/validation_evidence.json")
    return {"evidence": ev, "gates": j("reports/collection_gates.json"), "pilots": j("reports/pilots.json")}


@app.get("/api/cic")
def cic():
    return j("reports/cic_audit_facts.json")


@app.get("/api/runs")
def runs():
    return j("runs/index.json")


@lru_cache(maxsize=16)
def load_run(run_id: str):
    p = BUNDLE / "runs" / f"{run_id}.json"
    if not p.exists():
        raise HTTPException(404, f"unknown run {run_id}")
    d = json.loads(p.read_text())
    raw = pd.read_csv(BUNDLE / "runs" / f"{run_id}.csv")
    assert raw.adu_id.tolist() == d["rows"]["adu_id"]
    return d, raw


@app.get("/api/runs/{run_id}")
def run(run_id: str):
    d, raw = load_run(run_id)
    info = d["info"]
    rows = dict(d["rows"])
    for c in ["frame_number", "src_ip", "src_port", "dst_ip", "tid", "unit", "wire_fc", "address", "quantity",
              "adu_hex"]:
        rows[c] = raw[c].tolist()
    rows["client"] = ["actor" if ip == info["actor_ip"] else "hmi" for ip in raw.src_ip]
    return {"info": info, "rows": rows, "thresholds": pipeline().thresholds}


@app.get("/api/runs/{run_id}/input.csv")
def run_input(run_id: str):
    """The run's raw parsed request table exactly as fed to the pipeline (no ground-truth columns)."""
    p = BUNDLE / "runs" / f"{run_id}.csv"
    if not p.exists():
        raise HTTPException(404, f"unknown run {run_id}")
    return FileResponse(p, media_type="text/csv", filename=f"{run_id}_requests.csv")


@app.post("/api/runs/{run_id}/verify")
def verify(run_id: str):
    """Re-score the run's raw request table with the frozen pipeline and compare with the saved test predictions."""
    d, raw = load_run(run_id)
    p = pipeline()
    out = p.score(raw).set_index("adu_id").loc[d["rows"]["adu_id"]]
    res = {}
    for m in MODELS:
        saved = np.asarray(d["rows"]["saved_scores"][m])
        live = out[m].to_numpy()
        t = p.thresholds[m]
        disagree = (live > t) != (saved > t)
        tie = np.abs(saved - t) <= TIE
        res[m] = {"max_abs_score_diff": float(np.abs(live - saved).max()),
                  "alert_agreement": float(1 - disagree.mean()),
                  "alert_disagreements": int(disagree.sum()),
                  "disagreements_at_exact_threshold_tie": int((disagree & tie).sum())}
    b3 = max(float(np.abs(out[c].to_numpy() - np.asarray(v)).max()) for c, v in d["rows"]["saved_b3"].items())
    return {"run_id": run_id, "requests": len(raw), "models": res, "b3_feature_max_abs_diff": b3}


@app.post("/api/score")
async def score_upload(file: UploadFile = File(...)):
    data = await file.read()
    try:
        if file.filename.lower().endswith(".parquet"):
            df = pd.read_parquet(io.BytesIO(data))
        else:
            df = pd.read_csv(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"could not read file: {e}") from e
    if len(df) > MAX_UPLOAD_ROWS:
        raise HTTPException(400, f"at most {MAX_UPLOAD_ROWS} requests per upload")
    try:
        out = pipeline().score(df)
    except SchemaError as e:
        raise HTTPException(400, str(e)) from e
    cols = ["adu_id", "run_id", "src_ip", "dst_ip", "frame_number", "full_context"] + MODELS + \
           [f"alert_{m}" for m in MODELS]
    out["t"] = (out.ts_corr_ns - out.ts_corr_ns.min()) / 1e9
    return {"requests": len(out), "streams": int(out.groupby(["run_id", "src_ip", "dst_ip"]).ngroups),
            "alerts": {m: int(out[f"alert_{m}"].sum()) for m in MODELS},
            "rows": out[cols + ["t"]].head(2000).to_dict("list"), "truncated_to": min(len(out), 2000)}


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str):
        f = DIST / path
        return FileResponse(f if path and f.is_file() else DIST / "index.html")
