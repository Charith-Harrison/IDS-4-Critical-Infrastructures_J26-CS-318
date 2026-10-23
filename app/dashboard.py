"""Run with streamlit run app/dashboard.py from the project root."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from app import ui_utils
from app.pages import detection_events, event_investigation, model_performance, overview, system_health
from src.inference import predict_csv
from src.utils import ROOT, load_config


def main():
    st.set_page_config(page_title="J26-CS-318 | Modbus Detection", page_icon="🛡️", layout="wide")
    st.title("Command and Response Injection Detection")
    st.caption("J26-CS-318 · Context-Aware Modbus/TCP Command Analysis · Research prototype")
    cfg = load_config()
    ui_utils.banner(cfg["model_mode"])
    kind = st.sidebar.selectbox("Model", ["contextual", "baseline"])
    pages = {
        "Security Overview": overview,
        "Detection Events": detection_events,
        "Event Investigation": event_investigation,
        "Model Performance": model_performance,
        "System Health": system_health,
    }
    page = st.sidebar.radio("Page", list(pages))
    upload = st.sidebar.file_uploader("Analyze a CSV batch", type=["csv"])
    try:
        paths = [
            ROOT / f"models/{kind}/model.joblib",
            ROOT / "data/processed/events.parquet",
            ROOT / "config/config.yaml",
        ]
        signature = tuple(p.stat().st_mtime_ns for p in paths)
        artifact = ui_utils.cached_model(kind, signature)
        if upload is not None:
            if upload.size > 50 * 1024 * 1024:
                raise ValueError("CSV upload exceeds 50 MB")
            key = (kind, upload.name, upload.getvalue(), signature)
            if st.session_state.get("upload_key") != key:
                with st.spinner("Reconstructing context and predicting..."):
                    events, health = predict_csv(pd.read_csv(upload), artifact, source=upload.name)
                st.session_state["upload_result"] = (events, health)
                st.session_state["upload_key"] = key
            events, health = st.session_state["upload_result"]
            st.caption("Uploaded batch; context resets at each batch and session boundary.")
        else:
            with st.spinner("Loading validation demo..."):
                events, _ = ui_utils.demo_predictions(signature, kind)
            health = {"processed": len(events), "malformed": 0, "total": len(events), "source": "validation demo"}
            st.caption("Demo: first 3,000 validation events. No test rows are used for this live display.")
        pages[page].render(events, artifact, health)
    except (FileNotFoundError, ValueError, KeyError) as exc:
        st.error(str(exc))
        st.info(
            "Prepare and train the selected configuration using the documented scripts. No placeholder predictions are shown."
        )


if __name__ == "__main__":
    main()
