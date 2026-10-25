# Inspect a selected event using the older application's feature and explanation helpers.
"""Inspect an event with the same causal feature builder used for inference."""

import streamlit as st

from src.explainability import explain_event
from src.feature_engineering import build_features


# Inspect a selected event using the older application's feature and explanation helpers.
def render(events, artifact, health):
    st.header("Event Investigation")
    valid = events[events.prediction.notna()].copy()
    if valid.empty:
        st.info("No valid detections are available.")
        return
    event_id = st.selectbox("Select event", valid.event_id.tolist())
    row = valid[valid.event_id.eq(event_id)].iloc[0]
    history = valid[valid.context_id.eq(row.context_id)].sort_values(["timestamp", "source_row"])
    # Include all same-session history supplied for this batch; features are still past-only.
    features = build_features(history, artifact["metadata"]["configuration"], artifact["metadata"]["model_kind"])
    explanation = explain_event(features.loc[row.name], artifact)
    st.metric("Prediction", row.prediction, f"{row.confidence:.1%} confidence")
    st.json(
        {
            c: row[c]
            for c in [
                "event_id",
                "timestamp",
                "modbus_func_code",
                "modbus_ref_num",
                "is_request",
                "pair_status",
                "model_mode",
                "model_version",
            ]
        }
    )
    st.subheader("Observed evidence")
    for item in explanation["evidence"]:
        st.write("• " + item)
    st.caption(explanation["explanation_note"])
    st.dataframe(explanation["important_features"], hide_index=True)
    st.subheader("Previous events in this context")
    position = history.index.get_loc(row.name)
    st.dataframe(
        history.iloc[max(0, position - 10) : position][
            ["event_id", "timestamp", "modbus_func_code", "modbus_ref_num", "prediction"]
        ],
        hide_index=True,
    )
    st.subheader("Feature values")
    st.dataframe(features.loc[row.name].rename("value").to_frame())
