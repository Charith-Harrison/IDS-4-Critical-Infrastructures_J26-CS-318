# ruff: noqa: E402
# Progress dashboard for the Modbus/TCP command/response injection component.
# All numbers shown here are read from generated result files or computed by
# the shared src/ modules; no preprocessing logic is duplicated in this file.
from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st
from matplotlib import pyplot as plt

# Make `src` importable when launched with `streamlit run app/dashboard.py`.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.loader import DataValidationError, validate_upload
from src.inference import dashboard_data as dd
from src.inference.predict import (
    FeatureSchemaError,
    ModelLoadError,
    attach_oof,
    detect_dataframe,
    detect_validation_records,
    load_artifacts,
    single_event_inference,
    to_csv_bytes,
    to_standard_json,
)
from src.utils.config import (
    BINARY_LIMITATION,
    MAX_UPLOAD_MB,
    PROGRESS_DIR,
    RESULTS_DIR,
)

PAGES = [
    "Overview",
    "Data Quality",
    "Preprocessing & Features",
    "Protocol Traffic",
    "Request-Response Events",
    "Attack Detection",
    "Validation Detection Results",
    "Event Investigation",
    "Preliminary Model Performance",
]
CV_NOTE = "Preliminary cross-validation results — final test evaluation pending."
VAL_NOTE = "Preliminary validation results — final held-out test evaluation pending."
AUTH_NOTE = "Use only authorized public research data or authorized laboratory traffic."

# Plain hand-written CSS: light background, dark-grey text, one muted teal accent.
CSS = """
<style>
html, body, [class*="css"] { font-family: -apple-system, "Segoe UI", Arial, sans-serif; color: #333; }
.stApp { background: #fafafa; }
section[data-testid="stSidebar"] { background: #f0f0f0; }
h1, h2, h3 { color: #2f3b3d; font-weight: 600; }
h1 { font-size: 1.5rem; border-bottom: 2px solid #3d7a80; padding-bottom: 4px; }
h2 { font-size: 1.15rem; margin-top: 1.2rem; } h3 { font-size: 1rem; }
.block-container { padding-top: 1.5rem; max-width: 1200px; }
.note { border-left: 3px solid #3d7a80; background: #eef3f3; padding: 6px 10px; margin: 6px 0; font-size: 0.9rem; }
.stButton > button { font-size: 0.85rem; padding: 2px 12px; border-radius: 3px; border: 1px solid #3d7a80; color: #2f5f64; background: #fff; }
.stButton > button:hover { background: #3d7a80; color: #fff; }
</style>
"""


def note(text: str) -> None:
    """Render a plain left-bordered note."""
    st.markdown(f'<div class="note">{text}</div>', unsafe_allow_html=True)


def safe(fn, *args, **kwargs):
    """Run a loader and show a clear error instead of a fake fallback."""
    try:
        return fn(*args, **kwargs)
    except (dd.MissingResultError, ModelLoadError, FeatureSchemaError, DataValidationError) as exc:
        st.error(str(exc))
    except Exception as exc:  # unexpected failure: show it, never invent output
        st.error(f"Unexpected error: {exc}")
    return None


@st.cache_data(show_spinner=False)
def cached(name: str, *args):
    """Cache read-only result loaders."""
    return getattr(dd, name)(*args)


@st.cache_resource(show_spinner=False)
def artifacts(model: str):
    """Load a saved model once per session."""
    return load_artifacts(model)


def table(df: pd.DataFrame, height: int | None = None) -> None:
    """Show a simple table."""
    kwargs = {"height": height} if height else {}
    st.dataframe(df, width="stretch", hide_index=True, **kwargs)


# ---------------------------------------------------------------- pages
def page_overview() -> None:
    st.title("Command and Response Injection Detection in Modbus/TCP")
    st.caption("IT4010 — J26-CS-318 — Context-aware command analysis (progress stage)")
    note(BINARY_LIMITATION)
    note(VAL_NOTE)
    cap = safe(cached, "capture_report")
    stats = safe(cached, "dev_pairing_stats")
    if cap is None or stats is None:
        return
    c = st.columns(4)
    c[0].metric("Development captures", len(cap))
    c[1].metric("Development packets", int(cap["records"].sum()))
    c[2].metric("Requests", stats["requests"])
    c[3].metric("Matched pairs", stats["matched_pairs"])
    st.subheader("Implemented in this stage")
    table(
        pd.DataFrame(
            {
                "Component": [
                    "Dataset audit and capture reconstruction",
                    "Duplicate investigation",
                    "Evidence-based label mapping",
                    "Request-response reconstruction",
                    "Isolated, protocol-aware and contextual features",
                    "Capture-grouped 80/20 split (test untouched)",
                    "Grouped CV with fold-specific statistics",
                    "Baseline and context-aware Random Forest",
                    "Preliminary Normal / Command Injection detection",
                ]
            }
        )
    )
    st.caption("Counts above cover the 80% development partition only.")


def page_quality() -> None:
    st.title("Data Quality")
    st.markdown("### Source files")
    audit = safe(cached, "audit_summary")
    if audit:
        rows = []
        for a in audit.values():
            rows.append(
                {
                    "file": a["filename"],
                    "path": a["relative_path"],
                    "rows": a["rows"],
                    "columns": len(a["columns"]),
                    "size_bytes": a["size_bytes"],
                    "exact_duplicate_rows": a["exact_duplicate_rows"],
                    "missing_values": sum(a["missing_counts"].values()),
                    "timestamp_min": a["timestamp_min"],
                    "timestamp_max": a["timestamp_max"],
                    "original_labels": str(a["original_labels"]),
                    "sha256": a["sha256"],
                }
            )
        table(pd.DataFrame(rows))
    st.markdown("### Captures (development partition)")
    cap = safe(cached, "capture_report")
    if cap is not None:
        table(cap.drop(columns=["src_dst_pairs"], errors="ignore"))
    st.markdown("### Label evidence")
    ev = safe(cached, "csv_result", "label_evidence.csv", dd.AUDIT_DIR, False)
    if ev is not None:
        table(
            ev[
                [
                    "label_status",
                    "original_sub_types",
                    "direction",
                    "function_code",
                    "records",
                    "proposed_class",
                    "mapping_decision",
                    "label_provenance",
                ]
            ]
        )
        st.caption("Reconstructed labels are researcher-defined and not independently verified ground truth.")
    st.markdown("### Duplicate investigation")
    dup = safe(dd.json_result, "duplicate_investigation.json", dd.AUDIT_DIR)
    if dup:
        st.json(dup, expanded=False)
    st.markdown("### Circular-labelling diagnostic")
    circ = safe(dd.json_result, "circularity_diagnostics.json", PROGRESS_DIR)
    if circ:
        note(
            "A rule that merely restates the label construction scores "
            f"macro F1 = {circ['rule_unseen_write_equals_label_rule']['macro_f1']:.4f} on development "
            "data, so high model scores partly reflect the labelling rule."
        )


def page_preprocessing() -> None:
    st.title("Modbus/TCP Preprocessing and Contextual Feature Generation")
    st.caption("Function 1 — real preprocessing and feature generation on development records.")
    caps = safe(cached, "dev_captures")
    if not caps:
        return
    cid = st.selectbox("Development capture", caps)
    n = st.slider("Packets to process", 200, 5000, 1000, 100)
    if st.button("Generate features"):
        pk = safe(cached, "dev_packets")
        if pk is None:
            return
        t0 = time.perf_counter()
        sub = pk[pk["capture_id"] == cid].sort_values(["timestamp", "frame_number"]).head(n).reset_index(drop=True)
        art = safe(artifacts, "contextual")
        if art is None:
            return
        from src.inference.predict import featurize_packets

        ev, ps, feats = featurize_packets(sub, art["stats"])
        st.session_state["feat"] = (cid, feats, ps, (time.perf_counter() - t0) * 1000)
    if "feat" in st.session_state:
        cid, feats, ps, ms = st.session_state["feat"]
        st.caption(f"Capture {cid}: {len(feats)} request events processed in {ms:.0f} ms.")
        art = safe(artifacts, "contextual")
        cols = ["event_id", "modbus_func_code", "function_name", "modbus_ref_num", "pair_status"] + art["features"]
        table(feats[[c for c in dict.fromkeys(cols) if c in feats.columns]].head(300), 380)
        st.markdown("### Feature derivations")
        inv = safe(cached, "feature_inventory")
        if inv is not None:
            table(inv[["name", "category", "group", "exact_derivation", "current_or_past_only", "leakage_risk"]], 320)
        st.download_button(
            "Download preprocessed features (CSV)", to_csv_bytes(feats), "preprocessed_features.csv", "text/csv"
        )
    st.markdown("### Unavailable features")
    un = safe(pd.read_csv, RESULTS_DIR / "feature_audit" / "unavailable_features.csv")
    if un is not None:
        table(un)


def page_traffic() -> None:
    st.title("Protocol Traffic")
    pk = safe(cached, "dev_packets")
    if pk is None:
        return
    st.caption("Development partition only.")
    st.markdown("### Function codes")
    fc = (
        pk.groupby(["modbus_func_code", "function_name"]).size().reset_index(name="packets")
        if "function_name" in pk
        else pk["modbus_func_code"].value_counts().rename_axis("function_code").reset_index(name="packets")
    )
    table(fc)
    st.markdown("### Most-accessed registers (requests)")
    req = pk[pk["is_request"] == 1]
    table(
        req.groupby(["modbus_func_code", "modbus_ref_num"])
        .size()
        .reset_index(name="requests")
        .sort_values("requests", ascending=False)
        .head(25)
    )
    st.markdown("### Source → destination")
    table(pk.groupby(["src_ip", "dst_ip"]).size().reset_index(name="packets").sort_values("packets", ascending=False))


def page_pairs() -> None:
    st.title("Request-Response Events")
    ps = safe(cached, "dev_pairing_stats")
    if ps is None:
        return
    st.caption(ps.get("pairing_level", ""))
    table(pd.DataFrame([{"metric": k, "value": v} for k, v in ps.items() if k != "pairing_level"]))
    caps = set(dd.dev_captures())
    st.markdown("### Unmatched requests (development captures)")
    um = safe(pd.read_csv, PROGRESS_DIR / "unmatched_requests.csv")
    if um is not None:
        um = um[um["capture_id"].isin(caps)]
        st.caption(f"{len(um)} rows; atk-0 contains no response packets, so its requests appear here.")
        table(um.head(500), 300)
    st.markdown("### Orphan responses")
    orp = safe(pd.read_csv, PROGRESS_DIR / "orphan_responses.csv")
    if orp is not None:
        if "capture_id" in orp:
            orp = orp[orp["capture_id"].isin(caps)]
        table(orp.head(500), 300)


def show_summary(s: dict) -> None:
    """Summary values taken from the current detection run."""
    keys = [
        ("input_records", "Input records"),
        ("valid_records", "Valid records"),
        ("invalid_records", "Invalid records"),
        ("successfully_classified", "Classified events"),
        ("normal_predictions", "Normal predictions"),
        ("command_injection_predictions", "Command Injection predictions"),
        ("failed_predictions", "Failed predictions"),
    ]
    cols = st.columns(len(keys))
    for c, (k, label) in zip(cols, keys):
        c.metric(label, s[k])
    c2 = st.columns(3)
    c2[0].metric("Average confidence", "n/a" if s["average_confidence"] is None else f"{s['average_confidence']:.4f}")
    c2[1].metric(
        "Avg inference time (ms/event)",
        "n/a" if s["average_inference_time_ms"] is None else f"{s['average_inference_time_ms']:.4f}",
    )
    c2[2].metric("Total processing time (ms)", f"{s['total_processing_time_ms']:.0f}")


def page_detection() -> None:
    st.title("Attack Detection")
    st.caption("Function 3 — preliminary Normal / Command Injection detection with the saved contextual Random Forest.")
    note(BINARY_LIMITATION)
    note(AUTH_NOTE)
    mode = st.radio("Input", ["Validation records (development captures)", "Authorized CSV upload"], horizontal=True)
    if mode.startswith("Validation"):
        caps = safe(cached, "dev_captures")
        if not caps:
            return
        cid = st.selectbox("Development capture", caps)
        n = st.slider("Request events", 500, 5000, 2000, 500)
        if st.button("Validate Data"):
            st.session_state["ready"] = ("val", cid, n)
            st.success("Validation records found in the development partition.")
    else:
        up = st.file_uploader(f"CSV file (max {MAX_UPLOAD_MB} MB)", type=["csv"])
        if st.button("Validate Data"):
            if up is None:
                st.error("Choose a CSV file first.")
            else:
                try:
                    df = validate_upload(up.name, up.getvalue())
                    st.session_state["ready"] = ("csv", up.name, df)
                    st.success(f"Schema valid: {len(df)} rows.")
                except DataValidationError as exc:
                    st.session_state.pop("ready", None)
                    st.error(str(exc))
    c1, c2 = st.columns([1, 1])
    run = c1.button("Run Attack Detection", disabled="ready" not in st.session_state)
    if c2.button("Reset"):
        for k in ("ready", "det"):
            st.session_state.pop(k, None)
        st.rerun()
    if run and "ready" in st.session_state:
        art = safe(artifacts, "contextual")
        if art is None:
            return
        kind = st.session_state["ready"][0]
        try:
            if kind == "val":
                out = detect_validation_records(art, st.session_state["ready"][1], st.session_state["ready"][2])
                out["results"] = attach_oof(out["results"])
            else:
                out = detect_dataframe(st.session_state["ready"][2], art, st.session_state["ready"][1])
            st.session_state["det"] = (kind, out)
        except Exception as exc:
            st.error(f"Detection failed: {exc}")
    if "det" in st.session_state:
        kind, out = st.session_state["det"]
        show_summary(out["summary"])
        res = out["results"]
        if kind == "val":
            note(
                "Records come from development captures that the saved final model was trained on, so the "
                "final-model columns are in-sample. The oof_* columns are the saved out-of-fold predictions."
            )
        if not out["summary"]["labels_available"]:
            st.caption("Actual Class: Unavailable (no verified labels in this input; accuracy is not calculated).")
        show = [
            "event_id",
            "timestamp",
            "function_code",
            "function_name",
            "register",
            "operation",
            "pair_status",
            "actual_class",
            "predicted_class",
            "normal_probability",
            "command_injection_probability",
            "confidence",
            "main_observation",
            "inference_time_ms",
            "processing_status",
        ]
        if "oof_predicted_class" in res:
            show += ["oof_fold", "oof_predicted_class", "oof_command_injection_probability"]
        table(res[show], 420)
        if len(out["invalid"]):
            st.markdown("### Invalid records")
            table(out["invalid"].head(200), 200)
        if len(out["unclassifiable"]):
            st.markdown("### Unclassifiable events")
            table(out["unclassifiable"])
        st.markdown("### Exports")
        e = st.columns(4)
        e[0].download_button(
            "Preprocessed traffic (CSV)", to_csv_bytes(out["packets"]), "preprocessed_traffic.csv", "text/csv"
        )
        e[1].download_button("Detection results (CSV)", to_csv_bytes(res), "detection_results.csv", "text/csv")
        e[2].download_button("Invalid records (CSV)", to_csv_bytes(out["invalid"]), "invalid_records.csv", "text/csv")
        e[3].download_button(
            "Standardized output (JSON)", to_standard_json(res), "detection_output.json", "application/json"
        )
        st.caption("Preliminary progress-stage detection output — final integration schema pending.")


def page_validation() -> None:
    st.title("Validation Detection Results")
    note(VAL_NOTE)
    st.markdown("### Function 2 — saved-model loading and validation prediction")
    st.caption("Out-of-fold predictions saved during grouped cross-validation (development partition only).")
    oof = safe(cached, "oof_predictions")
    if oof is None:
        return
    model = st.selectbox("Model", sorted(oof["model_name"].unique()), index=1)
    sub = oof[oof["model_name"] == model]
    st.markdown("### Actual vs predicted (out-of-fold)")
    table(pd.crosstab(sub["actual_class"], sub["predicted_class"]).reset_index())
    fold = st.selectbox("Fold", sorted(sub["fold"].unique()))
    table(sub[sub["fold"] == fold].head(1000), 360)
    st.markdown("### Single-event prediction with the saved final model")
    art = safe(artifacts, "contextual")
    caps = safe(cached, "dev_captures")
    if art is None or not caps:
        return
    cid = st.selectbox("Development capture", caps, key="sv_cap")
    if st.button("Load model and predict one event"):
        out = detect_validation_records(art, cid, 500)
        feats = out["features"]
        eid = feats["event_id"].iloc[len(feats) // 2]
        one = single_event_inference(feats, eid, art)
        st.json(one)
        st.caption("In-sample for the final model; see out-of-fold table above for validation output.")


def page_investigation() -> None:
    st.title("Event Investigation")
    if "det" not in st.session_state:
        st.info("Run Attack Detection first; events from the latest run appear here.")
        return
    _, out = st.session_state["det"]
    res = out["results"]
    done = res[res["processing_status"] == "complete"]
    if done.empty:
        st.info("No classified events in the latest run.")
        return
    eid = st.selectbox("Event", done["event_id"].tolist())
    r = res[res["event_id"] == eid].iloc[0]
    f = out["features"][out["features"]["event_id"] == eid].iloc[0]

    def val(x):
        return "Unavailable" if pd.isna(x) else x

    st.markdown("### Protocol fields")
    table(
        pd.DataFrame(
            {
                "field": ["function", "register", "operation", "timestamp"],
                "value": [f"{r.function_code} {r.function_name}", val(r.register), r.operation, r.timestamp],
            }
        )
    )
    st.markdown("### Request-response")
    table(
        pd.DataFrame(
            {
                "field": ["pair_status", "response_delay (s)", "response_exception", "response_length_valid"],
                "value": [
                    r.pair_status,
                    val(r.response_delay),
                    val(f.get("response_exception")),
                    val(f.get("response_length_valid")),
                ],
            }
        )
    )
    st.markdown("### Context, timing, access and value evidence")
    ctx = [
        "prev_fc",
        "prev_is_write",
        "prev_ref",
        "read_to_write",
        "write_to_write",
        "writes_prev_k",
        "reads_prev_k",
        "iat",
        "iat_mean_prev_k",
        "time_since_last_write",
        "access_combo_unseen",
        "access_write_unseen",
        "prev_value_same_ref",
        "value_delta",
        "value_outside_normal_range",
    ]
    table(pd.DataFrame({"feature": ctx, "value": [val(f.get(c)) for c in ctx]}))
    st.markdown("### Prediction")
    table(
        pd.DataFrame(
            {
                "item": [
                    "Predicted class",
                    "Normal probability",
                    "Command Injection probability",
                    "Confidence",
                    "Actual class",
                    "Model version",
                    "Inference time (ms)",
                ],
                "value": [
                    r.predicted_class,
                    r.normal_probability,
                    r.command_injection_probability,
                    r.confidence,
                    r.actual_class,
                    r.model_version,
                    r.inference_time_ms,
                ],
            }
        ).astype(str)
    )
    st.markdown("### Supporting contextual observations")
    obs = [o for o in r.supporting_observations.split("; ") if o]
    for o in obs or ["No observations triggered."]:
        st.write("- " + o)


def page_performance() -> None:
    st.title("Preliminary Model Performance")
    note(CV_NOTE)
    m = safe(dd.json_result, "cv_metrics.json")
    oof = safe(cached, "oof_predictions")
    if not m or oof is None:
        return
    st.caption(m["cv_design"])
    summaries = safe(dd.summarize_oof_predictions, oof)
    if summaries is None:
        return

    st.markdown("### Out-of-fold metrics")
    note(
        "All classification metrics and curves below use pooled out-of-fold predictions from the development "
        "partition. Accuracy is included here because it is derived directly from those saved predictions."
    )
    metric_rows = [{"model": name, **summary["metrics"]} for name, summary in summaries.items()]
    metrics = pd.DataFrame(metric_rows).set_index("model")
    table(metrics.reset_index())

    core_metrics = ["accuracy", "balanced_accuracy", "macro_precision", "macro_recall", "macro_f1"]
    attack_metrics = [
        "command_injection_precision",
        "command_injection_recall",
        "command_injection_f1",
        "false_positive_rate",
        "false_negative_rate",
        "roc_auc",
        "pr_auc",
    ]
    for heading, metric_names in (
        ("Overall classification metrics", core_metrics),
        ("Command Injection detection and error rates", attack_metrics),
    ):
        st.markdown(f"### {heading}")
        fig, ax = plt.subplots(figsize=(12, 4))
        metrics[metric_names].T.plot(kind="bar", ax=ax, ylim=(0, 1.04), rot=20)
        ax.set_ylabel("Score")
        ax.set_xlabel("")
        ax.legend(title="Model")
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)

    st.markdown("### Out-of-fold confusion matrices")
    confusion_fig, axes = plt.subplots(1, len(summaries), figsize=(5 * len(summaries), 4))
    if len(summaries) == 1:
        axes = [axes]
    for ax, (name, summary) in zip(axes, summaries.items()):
        matrix = summary["confusion_matrix"]
        image = ax.imshow(matrix, cmap="Blues")
        ax.set_title(name)
        ax.set_xlabel("Predicted class")
        ax.set_ylabel("Actual class")
        ax.set_xticks([0, 1], labels=["Normal", "Command\nInjection"])
        ax.set_yticks([0, 1], labels=["Normal", "Command\nInjection"])
        threshold = matrix.max() / 2
        for row in range(2):
            for column in range(2):
                ax.text(
                    column,
                    row,
                    f"{matrix[row, column]:,}",
                    ha="center",
                    va="center",
                    color="white" if matrix[row, column] > threshold else "black",
                )
        confusion_fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    confusion_fig.tight_layout()
    st.pyplot(confusion_fig)
    plt.close(confusion_fig)

    st.markdown("### Ranking curves")
    curve_fig, curve_axes = plt.subplots(1, 2, figsize=(12, 4))
    for name, summary in summaries.items():
        roc = summary["roc_curve"]
        curve_axes[0].plot(
            roc["false_positive_rate"],
            roc["true_positive_rate"],
            label=f"{name} (AUC {summary['metrics']['roc_auc']:.4f})",
        )
        pr = summary["precision_recall_curve"]
        curve_axes[1].plot(
            pr["recall"],
            pr["precision"],
            label=f"{name} (AP {summary['metrics']['pr_auc']:.4f})",
        )
    curve_axes[0].plot([0, 1], [0, 1], linestyle="--", color="grey", label="Chance")
    curve_axes[0].set(title="ROC curve", xlabel="False-positive rate", ylabel="True-positive rate")
    curve_axes[1].set(title="Precision-recall curve", xlabel="Recall", ylabel="Precision")
    for ax in curve_axes:
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.04)
        ax.grid(alpha=0.25)
        ax.legend()
    curve_fig.tight_layout()
    st.pyplot(curve_fig)
    plt.close(curve_fig)

    st.markdown("### Fold-to-fold macro F1")
    fold_rows = [
        {"fold": point["fold"], "model": name, "macro_f1": point["macro_f1"]}
        for name, summary in summaries.items()
        for point in summary["fold_macro_f1"]
    ]
    fold_frame = pd.DataFrame(fold_rows)
    fold_fig, fold_ax = plt.subplots(figsize=(8, 4))
    for name, frame in fold_frame.groupby("model", sort=True):
        fold_ax.plot(frame["fold"], frame["macro_f1"], marker="o", label=name)
    fold_ax.set_xlabel("Validation fold")
    fold_ax.set_ylabel("Macro F1")
    fold_ax.set_ylim(0, 1.04)
    fold_ax.grid(alpha=0.25)
    fold_ax.legend(title="Model")
    fold_fig.tight_layout()
    st.pyplot(fold_fig)
    plt.close(fold_fig)

    sel = m["selected"]
    st.markdown("### Per-class precision / recall / F1 (pooled out-of-fold)")
    pc = [
        {"model": n, "class": c, **{k: x for k, x in d.items()}}
        for n, v in sel.items()
        for c, d in v["pooled_oof"]["per_class"].items()
    ]
    table(pd.DataFrame(pc))
    st.markdown("### Fold composition and model complexity")
    table(
        pd.DataFrame(
            [{"model": n, **{f"fold {i}": x for i, x in enumerate(v["fold_macro_f1"])}} for n, v in sel.items()]
        )
    )
    table(
        pd.DataFrame(
            [
                {"fold": f["fold"], "validation captures": ", ".join(f["val_captures"]), **f["val_class_counts"]}
                for f in m["folds"]
            ]
        )
    )
    note(
        "Folds with a macro F1 of 0.5 contain only Normal validation records (the development partition has only "
        "three attack captures), so that value reflects fold composition, not model failure."
    )
    note(
        "Near-perfect scores partly restate the labelling rule (function code and register novelty). "
        "See the circular-labelling diagnostic on the Data Quality page."
    )
    st.markdown("### Selected hyperparameters")
    st.json({n: v["params"] for n, v in sel.items()}, expanded=False)
    st.markdown("### Training time and validation inference latency")
    runtime = pd.DataFrame(
        [{"model": n, "training_seconds": d["training_seconds"], **d["latency"]} for n, d in m["models"].items()]
    ).set_index("model")
    table(runtime.reset_index())
    st.bar_chart(runtime[["single_median_ms", "single_p95_ms", "batch_per_event_ms"]])


def main() -> None:
    st.set_page_config(page_title="Modbus injection detection — progress", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown("**Progress Demonstration — Approximately 70% Implementation**")
        # Page selector; the label is hidden so no visible heading is shown.
        page = st.radio("pages", PAGES, label_visibility="collapsed")
    st.caption("Progress Demonstration — Approximately 70% Implementation")
    {
        "Overview": page_overview,
        "Data Quality": page_quality,
        "Preprocessing & Features": page_preprocessing,
        "Protocol Traffic": page_traffic,
        "Request-Response Events": page_pairs,
        "Attack Detection": page_detection,
        "Validation Detection Results": page_validation,
        "Event Investigation": page_investigation,
        "Preliminary Model Performance": page_performance,
    }[page]()


main()
