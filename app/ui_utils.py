# Share cached loading, class colours, and tables between the older dashboard pages.
"""Shared loading and mode-aware presentation helpers."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.inference import load_model, predict_events
from src.utils import BINARY_NOTE, ROOT, load_config, read_json

COLORS = {
    "Normal": "#15803d",
    "Command_Response_Injection": "#dc2626",
    "Command_Injection": "#dc2626",
    "Response_Injection": "#ea580c",
}


# Reuse the loaded saved model until its artifact signature changes.
@st.cache_resource
def cached_model(kind: str, signature: tuple):
    return load_model(kind, load_config())


# Cache the prepared event table for the older dashboard.
@st.cache_data
def cached_events(signature: tuple):
    return pd.read_parquet(ROOT / "data/processed/events.parquet")


# Predict a small validation subset with an already saved model.
@st.cache_data
def demo_predictions(signature: tuple, kind: str):
    events = cached_events(signature)
    # Use the validation partition for the UI, never an undeclared final test set.
    subset = (
        events[events.partition.eq("validation")]
        .sort_values(["group_id", "timestamp", "source_row"])
        .head(3000)
        .reset_index(drop=True)
    )
    artifact = cached_model(kind, signature)
    return predict_events(subset, artifact), subset


# Show the older model's configured binary or three-class scope.
def banner(mode: str):
    if mode == "temporary_binary":
        st.warning("PRELIMINARY BINARY DETECTION")
        st.caption(
            "Separate Command Injection and Response Injection classification pending verified three-class dataset."
        )
        st.info(BINARY_NOTE)
    else:
        st.info("Three-class research model — dataset label evidence is recorded in the model metadata.")


# Display the table with consistent colours for predicted classes.
def render_table(frame: pd.DataFrame):
    # Choose a text colour for a displayed class without changing its value.
    def color(value):
        return f'color: {COLORS.get(value, "#64748b")}; font-weight: 600'

    if "prediction" in frame:
        st.dataframe(frame.style.map(color, subset=["prediction"]), width="stretch", hide_index=True)
    else:
        st.dataframe(frame, width="stretch", hide_index=True)


# Read an optional report if it is present; otherwise return no report.
def optional_json(relative: str):
    path = ROOT / relative
    return read_json(path) if path.exists() else None
