"""Searchable predictions and stable API export."""

import json

import streamlit as st

from app.ui_utils import render_table
from src.inference import prediction_records


def render(events, artifact, health):
    st.header("Detection Events")
    classes = artifact["metadata"]["classes"]
    selected = st.multiselect("Predicted classes", classes, default=classes)
    query = st.text_input("Search event ID or contextual evidence")
    threshold = st.slider("Minimum confidence", 0.0, 1.0, 0.0, 0.05)
    filtered = events[events.prediction.isin(selected) & events.confidence.ge(threshold)].copy()
    if query:
        filtered = filtered[
            filtered.event_id.str.contains(query, case=False, regex=False)
            | filtered.evidence.astype(str).str.contains(query, case=False, regex=False)
        ]
    st.caption(f"{len(filtered):,} matching events. Confidence is an uncalibrated Random Forest vote fraction.")
    columns = [
        "event_id",
        "timestamp",
        "prediction",
        "confidence",
        "modbus_func_code",
        "modbus_ref_num",
        "is_request",
        "pair_status",
        "evidence",
    ]
    render_table(filtered.reindex(columns=columns).head(5000))
    st.download_button(
        "Download predictions as JSON",
        json.dumps(prediction_records(filtered), indent=2),
        "detections.json",
        "application/json",
    )
    if events.prediction.isna().any():
        st.warning(f"{int(events.prediction.isna().sum())} invalid records were not classified. See System Health.")
