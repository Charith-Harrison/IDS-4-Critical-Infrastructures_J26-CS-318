# Display saved model measurements in the older dashboard.
"""Display measured results without training or evaluating from the dashboard."""

import pandas as pd
import streamlit as st

from app.ui_utils import optional_json
from src.utils import ROOT


# Display saved model measurements in the older dashboard.
def render(events, artifact, health):
    st.header("Model Performance")
    metadata = artifact["metadata"]
    st.write("Current mode:", metadata["model_mode"])
    st.write("Classes:", ", ".join(metadata["classes"]))
    report = optional_json("results/metrics/comparison.json")
    if report:
        st.info(report["interpretation"])
        metrics = [
            "accuracy",
            "macro_precision",
            "macro_recall",
            "macro_f1",
            "weighted_f1",
            "attack_recall",
            "false_positive_rate",
            "roc_auc",
            "pr_auc",
            "batch_inference_ms_per_event",
            "single_event_model_latency_ms_median",
            "feature_count",
        ]
        st.dataframe(
            pd.DataFrame({kind: {key: values.get(key) for key in metrics} for kind, values in report["models"].items()})
        )
        for kind, values in report["models"].items():
            st.subheader(f"{kind.title()} confusion matrix — actual rows, predicted columns")
            st.dataframe(pd.DataFrame(values["confusion_matrix"], index=values["classes"], columns=values["classes"]))
        st.caption(
            "Latency is model-only. PR-AUC uses average precision. This holdout is preliminary and has prior legacy exposure."
        )
    else:
        st.info("No saved holdout evaluation. Run python scripts/evaluate_models.py after training.")
    st.subheader("Training class counts")
    st.bar_chart(pd.Series(metadata["class_distribution"]))
    st.subheader("Global feature importance")
    importance = pd.read_csv(ROOT / f'models/{metadata["model_kind"]}/feature_importance.csv')
    st.bar_chart(importance.head(15).set_index("feature"))
    st.caption("Impurity-based importance can favor high-cardinality variables. It is not causal attribution.")
