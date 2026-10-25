# Summarize the batch currently loaded by the older dashboard.
"""Observed traffic and predicted alert summary for the loaded batch."""

import pandas as pd
import streamlit as st

from app.ui_utils import render_table


# Summarize the batch currently loaded by the older dashboard.
def render(events, artifact, health):
    st.header("Security Overview")
    valid = events[events.prediction.notna()]
    normal = int(valid.prediction.eq("Normal").sum())
    attacks = len(valid) - normal
    columns = st.columns(4)
    for col, name, value in zip(
        columns,
        ["Total events", "Normal predictions", "Detected injections", "Attack percentage"],
        [len(events), normal, attacks, f"{100 * attacks / max(len(valid), 1):.1f}%"],
    ):
        col.metric(name, value)
    st.caption("Counts describe predictions in the loaded batch; they are not independently verified incidents.")
    if len(valid):
        chart = valid.copy()
        chart["time"] = pd.to_datetime(chart.timestamp, unit="s", errors="coerce", utc=True).dt.floor("min")
        st.subheader("Traffic timeline (UTC)")
        timeline = chart.groupby(["time", "prediction"]).size().unstack(fill_value=0)
        if len(timeline):
            st.line_chart(timeline)
        left, right = st.columns(2)
        left.subheader("Function-code distribution")
        left.bar_chart(valid.modbus_func_code.value_counts().sort_index())
        operation = (
            valid.modbus_func_code.mod(128)
            .map({1: "Read", 2: "Read", 3: "Read", 4: "Read", 5: "Write", 6: "Write", 15: "Write", 16: "Write"})
            .fillna("Other")
        )
        right.subheader("Read/write distribution")
        right.bar_chart(operation.value_counts())
        st.subheader("Latest events")
        render_table(
            valid.sort_values("timestamp").tail(15)[
                ["event_id", "timestamp", "prediction", "confidence", "modbus_func_code"]
            ]
        )
