# Show processing failures and model provenance in the older dashboard.
"""Artifact provenance and visible processing failures."""

import streamlit as st

from app.ui_utils import optional_json


# Show processing failures and model provenance in the older dashboard.
def render(events, artifact, health):
    st.header("System Health")
    metadata = artifact["metadata"]
    st.json(
        {
            "model_loaded": True,
            "preprocessing_loaded": "imputer" in artifact["pipeline"].named_steps,
            "dataset_loaded": True,
            "model_version": metadata["model_version"],
            "feature_version": metadata["feature_version"],
            "model_mode": metadata["model_mode"],
            **health,
        }
    )
    manifest = optional_json("data/manifests/preprocessing.json")
    if manifest:
        st.subheader("Dataset preprocessing")
        st.json(
            {
                key: manifest[key]
                for key in [
                    "source_rows",
                    "retained_rows",
                    "removed_rows",
                    "removal_reasons",
                    "group_methods",
                    "pair_status",
                ]
            }
        )
    failed = events[events.prediction.isna()]
    if len(failed):
        st.subheader("Records not classified")
        st.dataframe(failed[["event_id", "invalid_reason", "processing_status"]], hide_index=True)
    with st.expander("Model provenance and configuration"):
        st.json(metadata)
