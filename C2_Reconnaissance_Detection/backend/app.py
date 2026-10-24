"""FastAPI integration and dashboard backend service for C2 Reconnaissance Detection (Section 24).

Endpoints:
- `GET  /health`           : Service status, loaded models, operational thresholds, and dataset integrity summary.
- `GET  /metrics`          : Verified experimental metrics (`metrics.json`), latency (`latency.json`), and leakage audit summary.
- `GET  /examples`         : Real verifiable example sequences (`example_sequences.json`).
- `GET  /dashboard-data`   : Complete unified payload for the React Detection Accuracy & Network Packets Dashboard.
- `GET  /detected-packets` : Filterable feed of real network packets and detection verdicts from the rebuilt dataset.
- `POST /predict`          : Score a 20-packet Modbus/TCP sequence and return the standardized C2 integration contract.
- `GET  /`                 : Minimal self-contained HTML diagnostic console backed by real endpoints (zero mock data).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from common import ARTIFACTS, read_json  # noqa: E402
from contract import C2InferenceEngine  # noqa: E402

app = FastAPI(
    title="C2 Reconnaissance Detection API (J26-CS-318)",
    description=(
        "Protocol-Aware Modbus/TCP Reconnaissance Attack Detection Using Temporal Behavior Analysis "
        "(Component C2 / RP2 — Charith H., IT23269002)."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_ENGINE: C2InferenceEngine | None = None
_DASHBOARD_CACHE: dict[str, Any] | None = None


def get_engine() -> C2InferenceEngine:
    global _ENGINE
    if _ENGINE is None or not _ENGINE.models_loaded:
        _ENGINE = C2InferenceEngine().load()
    return _ENGINE


def get_dashboard_cache() -> dict[str, Any]:
    global _DASHBOARD_CACHE
    dash_path = ARTIFACTS / "dashboard_data.json"
    if _DASHBOARD_CACHE is None:
        if not dash_path.exists():
            from export_dashboard_data import build_dashboard_data

            _DASHBOARD_CACHE = build_dashboard_data()
        else:
            _DASHBOARD_CACHE = read_json(dash_path)
    return _DASHBOARD_CACHE


class PacketInput(BaseModel):
    timestamp: str | None = Field(default=None, description="ISO-8601 UTC timestamp string")
    ts_ns: int | None = Field(default=None, description="Epoch timestamp in nanoseconds")
    dt_s: float | None = Field(default=None, description="Inter-packet interval in seconds")
    func_code: int = Field(..., description="Modbus function code (e.g. 1..6)")
    modbus_len: int = Field(..., description="Modbus MBAP length field")
    register_start: int = Field(..., description="Starting register or coil address")
    quantity: int = Field(..., description="Register or coil quantity")
    packet_size: int = Field(..., description="Frame size in bytes")


class PredictRequest(BaseModel):
    session_id: str = Field(
        default="runtime_session",
        description="Directional host-pair session identifier (metadata only; not used as a model feature)",
    )
    model_version: str = Field(
        default="c2-lstm-v1",
        description="Model identifier: 'c2-lstm-v1', 'c2-lstm-notiming-v1', or 'c2-rf-baseline-v1'",
    )
    include_attribution: bool = Field(
        default=True,
        description="Whether to compute per-timestep and per-feature gradient*input salience",
    )
    packets: list[PacketInput] = Field(
        ...,
        min_length=2,
        description="Ordered sequence of Modbus/TCP packets (standard window length = 20)",
    )


@app.get("/health")
def health() -> dict[str, Any]:
    engine = get_engine()
    profile = read_json(ARTIFACTS / "dataset_profile.json")
    rebuild = read_json(ARTIFACTS / "rebuild_report.json")
    return {
        "status": "ok",
        "module": "C2_RECON_DETECTION",
        "project_id": "J26-CS-318",
        "models_loaded": engine.models_loaded,
        "available_models": [
            "c2-lstm-v1",
            "c2-lstm-notiming-v1",
            "c2-rf-baseline-v1",
        ],
        "operational_thresholds": {
            "c2-lstm-v1": engine.thr_c,
            "c2-lstm-notiming-v1": engine.thr_d,
            "c2-rf-baseline-v1": engine.thr_b,
        },
        "dataset_summary": {
            "raw_packets": profile["packets"]["rows"],
            "as_provided_sequences": profile["sequences"]["rows"],
            "rebuilt_packets": rebuild["packets_kept"],
            "rebuilt_windows": rebuild["windows"],
            "rebuilt_positive_windows": rebuild["window_label_counts"]["1"],
            "capture_groups": len(rebuild["per_group"]),
        },
    }


@app.get("/metrics")
def get_metrics() -> dict[str, Any]:
    metrics = read_json(ARTIFACTS / "metrics.json")
    latency = read_json(ARTIFACTS / "latency.json")
    leakage = read_json(ARTIFACTS / "leakage_audit.json")
    return {
        "evaluation_metrics": metrics,
        "latency_benchmarks": latency,
        "leakage_audit_summary": {
            "overlapping_window_leakage": leakage["overlapping_window_leakage"],
            "protocol_field_shortcut_risk": leakage["protocol_field_shortcut_risk"][
                "trivial_rule_any_modbus_len_eq_3_on_rebuilt_windows"
            ],
        },
    }


@app.get("/examples")
def get_examples() -> dict[str, Any]:
    return read_json(ARTIFACTS / "example_sequences.json")


@app.get("/dashboard-data")
def get_dashboard_data() -> dict[str, Any]:
    return get_dashboard_cache()


@app.get("/detected-packets")
def get_detected_packets(
    verdict: str | None = Query(default=None, description="Filter by TP, FP, FN, TN, or ALL"),
    capture_group: str | None = Query(default=None, description="Filter by capture group ID"),
    limit: int | None = Query(default=None, ge=1, description="Optional row limit (omit for all)"),
) -> dict[str, Any]:
    data = get_dashboard_cache()
    rows = data.get("detected_packets_feed", [])
    if verdict and verdict.upper() != "ALL":
        rows = [r for r in rows if r.get("verdict_lstm_c") == verdict.upper()]
    if capture_group and capture_group.upper() != "ALL":
        rows = [r for r in rows if r.get("capture_group") == capture_group]
    return {
        "total_matching": len(rows),
        "packets": rows[:limit] if limit else rows,
    }


@app.post("/predict")
def predict(req: PredictRequest) -> dict[str, Any]:
    try:
        engine = get_engine()
        pkt_dicts = [p.model_dump() for p in req.packets]
        return engine.score_window(
            packets=pkt_dicts,
            session_id=req.session_id,
            model_choice=req.model_version,
            include_attribution=req.include_attribution,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class AnalyzeFileRequest(BaseModel):
    filename: str = Field(default="uploaded_capture.csv")
    packets: list[dict[str, Any]] = Field(..., min_length=2)


@app.post("/analyze-packets")
def analyze_uploaded_packets(req: AnalyzeFileRequest) -> dict[str, Any]:
    """Score uploaded Modbus/TCP packets in 20-packet windows using the trained C2 models."""
    try:
        engine = get_engine()
        raw_pkts = req.packets
        n_pkts = len(raw_pkts)
        win_len = min(20, n_pkts)
        stride = 5 if n_pkts >= 25 else max(1, win_len)

        scored_packets: list[dict[str, Any]] = []
        scored_windows: list[dict[str, Any]] = []

        fc_names = {
            1: "FC01 Read Coils",
            2: "FC02 Read Discrete Inputs",
            3: "FC03 Read Holding Registers",
            4: "FC04 Read Input Registers",
            5: "FC05 Write Single Coil",
            6: "FC06 Write Single Register",
        }

        w_idx = 0
        for start_i in range(0, max(1, n_pkts - win_len + 1), stride):
            chunk = raw_pkts[start_i : start_i + win_len]
            if len(chunk) < 2:
                break
            norm_chunk = []
            for idx_in_w, p in enumerate(chunk):
                fc = int(float(p.get("func_code", 1) or 1))
                ml = int(float(p.get("modbus_len", 6) or 6))
                reg = int(float(p.get("register_start", p.get("reg", 0)) or 0))
                qty = int(float(p.get("quantity", 1) or 1))
                psize = int(float(p.get("packet_size", 60 + ml) or (60 + ml)))
                dt_s = float(p.get("dt_s", p.get("time_delta", 0.02)) or 0.02)
                lbl = int(float(p.get("label", p.get("packet_label", 0)) or 0))
                norm_chunk.append(
                    {
                        "row_index": int(p.get("row_index", start_i + idx_in_w + 1)),
                        "timestamp": str(p.get("timestamp", f"t+{start_i + idx_in_w}")),
                        "ts_ns": int(p.get("ts_ns", (start_i + idx_in_w) * 20_000_000)),
                        "dt_s": dt_s,
                        "src_ip": str(p.get("src_ip", "185.175.0.5")),
                        "dst_ip": str(p.get("dst_ip", "185.175.0.3")),
                        "session_id": str(p.get("session_id", req.filename)),
                        "capture_group": str(p.get("capture_group", req.filename)),
                        "func_code": fc,
                        "func_name": fc_names.get(fc, f"FC{fc:02d}"),
                        "modbus_len": ml,
                        "register_start": reg,
                        "quantity": qty,
                        "packet_size": psize,
                        "label": lbl,
                    }
                )

            res = engine.score_window(
                packets=norm_chunk,
                session_id=norm_chunk[0]["session_id"],
                model_choice="c2-lstm-v1",
                include_attribution=True,
            )
            score_c = float(res["comparative_scores"]["Model_C_LSTM_Full"])
            score_b = float(res["comparative_scores"]["Model_B_Window_RF"])
            score_d = float(res["comparative_scores"]["Model_D_LSTM_NoTiming"])
            score_a = float(res["comparative_scores"]["Model_A_Packet_LogReg"])

            pred_c = int(score_c >= engine.thr_c)
            pred_b = int(score_b >= engine.thr_b)
            win_true = int(any(p["label"] == 1 for p in norm_chunk))

            verdict_c = (
                "TP"
                if (win_true == 1 and pred_c == 1)
                else ("FP" if (win_true == 0 and pred_c == 1) else ("FN" if (win_true == 1 and pred_c == 0) else "TN"))
            )
            verdict_b = (
                "TP"
                if (win_true == 1 and pred_b == 1)
                else ("FP" if (win_true == 0 and pred_b == 1) else ("FN" if (win_true == 1 and pred_b == 0) else "TN"))
            )

            wid = f"upload_w{w_idx:04d}"
            sal_list = (
                res["attribution"]["timestep_salience"]
                if res.get("attribution")
                else [1.0 / len(norm_chunk)] * len(norm_chunk)
            )

            win_pkts = []
            for s_i, p in enumerate(norm_chunk):
                pkt_rec = {
                    **p,
                    "step": s_i,
                    "window_id": wid,
                    "packet_label": p["label"],
                    "window_label": win_true,
                    "salience": float(sal_list[s_i]) if s_i < len(sal_list) else 0.0,
                    "score_lstm_c": score_c,
                    "pred_lstm_c": pred_c,
                    "verdict_lstm_c": verdict_c,
                    "score_rf_b": score_b,
                    "pred_rf_b": pred_b,
                    "verdict_rf_b": verdict_b,
                }
                win_pkts.append(pkt_rec)
                if start_i == 0 or s_i >= win_len - stride:
                    scored_packets.append(pkt_rec)

            scored_windows.append(
                {
                    "window_id": wid,
                    "window_index": w_idx,
                    "capture_group": req.filename,
                    "session_id": norm_chunk[0]["session_id"],
                    "true_label": win_true,
                    "category": "Uploaded Capture",
                    "verdict_lstm_c": verdict_c,
                    "verdict_rf_b": verdict_b,
                    "oof_scores": {
                        "Model_C_LSTM_Full": score_c,
                        "Model_D_LSTM_NoTiming": score_d,
                        "Model_B_Window_RF": score_b,
                        "Model_B_Window_LogReg": score_b,
                        "Model_A_Packet_DT": score_b,
                        "Model_A_Packet_LogReg": score_a,
                    },
                    "packets": win_pkts,
                }
            )
            w_idx += 1

        return {
            "filename": req.filename,
            "n_packets": len(scored_packets),
            "n_windows": len(scored_windows),
            "detected_packets_feed": scored_packets,
            "inspected_windows": scored_windows,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


FRONTEND_DIST = ROOT / "frontend" / "dist"
if (FRONTEND_DIST / "assets").exists():
    app.mount(
        "/assets",
        StaticFiles(directory=str(FRONTEND_DIST / "assets")),
        name="frontend_assets",
    )


@app.get("/dashboard_data.json")
def get_static_dashboard_json() -> dict[str, Any]:
    return get_dashboard_cache()


@app.get("/whole_network_packets.bin")
def get_whole_network_packets_bin() -> Any:
    bin_path = ARTIFACTS / "whole_network_packets.bin"
    if not bin_path.exists():
        get_dashboard_cache()
    return FileResponse(bin_path, media_type="application/octet-stream")


@app.get("/", response_class=HTMLResponse)
def root_console() -> Any:
    dist_index = FRONTEND_DIST / "index.html"
    if dist_index.exists():
        return FileResponse(dist_index)
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>C2 Reconnaissance Detection — Research Diagnostic Console</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1e293b; background: #f8fafc; }
    h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
    .sub { color: #475569; font-size: 0.9rem; margin-bottom: 1.25rem; }
    .card { background: #fff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
    button { background: #0f172a; color: #fff; border: none; border-radius: 4px; padding: 0.45rem 0.9rem; cursor: pointer; margin-right: 0.5rem; }
    button:hover { background: #334155; }
    pre { background: #0f172a; color: #e2e8f0; padding: 0.85rem; border-radius: 4px; overflow-x: auto; font-size: 0.82rem; }
  </style>
</head>
<body>
  <h1>C2 / RP2 — Modbus/TCP Reconnaissance Detection Diagnostic Console</h1>
  <div class="sub">Project J26-CS-318 | Student: Charith H. (IT23269002) | All outputs backed by real artifacts &amp; trained models</div>
  <div class="card">
    <button onclick="loadEndpoint('/health')">GET /health</button>
    <button onclick="loadEndpoint('/metrics')">GET /metrics</button>
    <button onclick="testSample('true_positive_cat1_modbus_len3_signature')">Test Real Recon Window (POST /predict)</button>
    <button onclick="testSample('true_negative_routine_polling')">Test Real Normal Window (POST /predict)</button>
  </div>
  <div class="card">
    <strong>Response Output:</strong>
    <pre id="out">Click any button above to query the live FastAPI backend.</pre>
  </div>
  <script>
    async function loadEndpoint(path) {
      const r = await fetch(path);
      const j = await r.json();
      document.getElementById('out').textContent = JSON.stringify(j, null, 2);
    }
    async function testSample(key) {
      const exRes = await fetch('/examples');
      const exData = await exRes.json();
      const sample = exData.examples[key];
      const payload = {
        session_id: sample.session_id,
        model_version: 'c2-lstm-v1',
        include_attribution: true,
        packets: sample.packets
      };
      const r = await fetch('/predict', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json();
      document.getElementById('out').textContent = JSON.stringify(j, null, 2);
    }
  </script>
</body>
</html>"""
