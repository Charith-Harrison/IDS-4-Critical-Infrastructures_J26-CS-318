"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: app/routes.py

Purpose:
    Defines Flask routes and API endpoints for the research prototype dashboard.
    Implements dataset upload, data audit with ReportLab PDF export, configurable
    data cleaning and preprocessing, transaction reconstruction inspection,
    time-window feature extraction, dual feature tables for normal and replay traffic,
    genuine Excel (.xlsx) exports via openpyxl, XGBoost boosting round progress tracking,
    feature importance visualization, ROC curve and probability distribution charts,
    and interactive test prediction inspection with 4-way filtering.

Pipeline Navigation:
    0. File Upload (/upload)
    A. Stage A – Data Audit (/audit)
    B. Stage B – Features & Split (/features)
    C. Stage C – Train Model (/training)
    D. Stage D – Preliminary Evaluation (/evaluation)
"""

import json
import os
import math
import uuid
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from flask import Blueprint, render_template, request, jsonify, send_file, current_app, redirect, url_for
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from werkzeug.utils import secure_filename

from src.data_loader import (
    load_datasets,
    load_active_dataset_config,
    save_active_dataset_config,
    reset_active_dataset_config,
    validate_dataset_file,
    resolve_file_path,
    MAX_UPLOAD_SIZE_BYTES
)
from src.data_validation import audit_dataset_integrity
from src.data_cleaning import clean_datasets
from src.transaction_context import reconstruct_transactions
from src.split_data import create_train_test_split
from src.feature_engineering import (
    extract_features,
    MODEL_FEATURE_COLUMNS,
    FEATURE_DICTIONARY,
    EXCLUDED_INPUT_COLUMNS
)
from src.train_model import train_xgboost_model
from src.predictor import ReplayPredictor
from src.evaluate_model import evaluate_test_partition
from src.pdf_generator import build_audit_pdf
from src.excel_exporter import export_dataframe_to_excel_buffer

main_bp = Blueprint("main", __name__)


def get_paths() -> Dict[str, str]:
    """
    Resolves absolute filesystem paths for all project artifacts and active datasets.
    """
    root = current_app.config["PROJECT_ROOT"]
    cfg = current_app.config["APP_CONFIG"]
    art = cfg.get("artifacts", {})

    active_cfg = load_active_dataset_config(root)
    normal_rel = active_cfg.get("normal_path", "normal_traffic_baseline.csv")
    replay_rel = active_cfg.get("replay_path", "replay_attacks.csv")

    try:
        norm_abs = resolve_file_path(normal_rel, root)
    except Exception:
        norm_abs = os.path.join(root, normal_rel)

    try:
        rep_abs = resolve_file_path(replay_rel, root)
    except Exception:
        rep_abs = os.path.join(root, replay_rel)

    return {
        "root": root,
        "normal_csv": norm_abs,
        "replay_csv": rep_abs,
        "cleaned_normal_csv": os.path.join(root, "artifacts", "cleaned", "cleaned_normal.csv"),
        "cleaned_replay_csv": os.path.join(root, "artifacts", "cleaned", "cleaned_replay.csv"),
        "cleaning_summary": os.path.join(root, "artifacts", "audits", "cleaning_summary.json"),
        "reconstructed_tx_csv": os.path.join(root, "artifacts", "audits", "reconstructed_transactions.csv"),
        "session_metadata": os.path.join(root, "artifacts", "session", "session_metadata.json"),
        "audit_report": os.path.join(root, art.get("audit_report", "artifacts/audits/data_audit_report.json")),
        "audit_pdf": os.path.join(root, art.get("audit_pdf", "artifacts/audits/RP4_Data_Audit_Report.pdf")),
        "split_manifest": os.path.join(root, art.get("split_manifest", "artifacts/splits/split_manifest.csv")),
        "features_csv": os.path.join(root, art.get("features_csv", "artifacts/results/extracted_features.csv")),
        "normal_features_csv": os.path.join(root, art.get("normal_features_csv", "artifacts/results/normal_protocol_features.csv")),
        "replay_features_csv": os.path.join(root, art.get("replay_features_csv", "artifacts/results/replay_protocol_features.csv")),
        "feature_dictionary": os.path.join(root, art.get("feature_dictionary", "artifacts/results/feature_dictionary.json")),
        "model_path": os.path.join(root, art.get("model_path", "artifacts/models/xgboost_model.json")),
        "pipeline_path": os.path.join(root, art.get("pipeline_path", "artifacts/models/pipeline_artifacts.joblib")),
        "training_history": os.path.join(root, art.get("training_history", "artifacts/models/xgboost_training_history.json")),
        "feature_importance": os.path.join(root, art.get("feature_importance", "artifacts/models/feature_importance.json")),
        "predictions_csv": os.path.join(root, art.get("predictions_csv", "artifacts/predictions/test_predictions.csv")),
        "metrics_json": os.path.join(root, art.get("metrics_json", "artifacts/metrics/evaluation_metrics.json"))
    }


def get_active_clean_paths() -> Tuple[str, str]:
    """
    Returns paths to cleaned datasets if cleaning has been executed,
    otherwise falls back to raw active dataset paths.
    """
    paths = get_paths()
    norm_path = paths["cleaned_normal_csv"] if os.path.exists(paths["cleaned_normal_csv"]) else paths["normal_csv"]
    rep_path = paths["cleaned_replay_csv"] if os.path.exists(paths["cleaned_replay_csv"]) else paths["replay_csv"]
    return norm_path, rep_path


def check_pipeline_status() -> Dict[str, bool]:
    """
    Verifies prerequisite artifact generation to enforce strict sequential pipeline execution.
    """
    paths = get_paths()
    return {
        "upload_ready": os.path.exists(paths["normal_csv"]) and os.path.exists(paths["replay_csv"]),
        "audit_ready": os.path.exists(paths["audit_report"]),
        "features_ready": os.path.exists(paths["features_csv"]) and os.path.exists(paths["split_manifest"]),
        "model_ready": os.path.exists(paths["model_path"]) and os.path.exists(paths["pipeline_path"]),
        "evaluation_ready": os.path.exists(paths["metrics_json"]) and os.path.exists(paths["predictions_csv"])
    }


def invalidate_downstream_artifacts(from_stage: str = "features") -> None:
    """
    Invalidates outdated pipeline artifacts when upstream configurations or datasets change.
    """
    paths = get_paths()
    stages = ["upload", "audit", "cleaning", "features", "training", "evaluation"]
    if from_stage not in stages:
        return

    idx = stages.index(from_stage)

    if idx <= 0:  # Upload changed: remove session and cleaned
        for k in ["session_metadata", "cleaned_normal_csv", "cleaned_replay_csv"]:
            if os.path.exists(paths[k]):
                try:
                    os.remove(paths[k])
                except Exception:
                    pass

    if idx <= 1:  # Audit changed: remove audit artifacts and cleaned files
        for k in ["audit_report", "audit_pdf", "cleaning_summary", "reconstructed_tx_csv"]:
            if os.path.exists(paths[k]):
                try:
                    os.remove(paths[k])
                except Exception:
                    pass

    if idx <= 2:  # Cleaning changed: features and downstream are invalidated
        pass

    if idx <= 3:  # Features changed: remove feature and split artifacts
        for k in ["features_csv", "normal_features_csv", "replay_features_csv", "split_manifest"]:
            if os.path.exists(paths[k]):
                try:
                    os.remove(paths[k])
                except Exception:
                    pass

    if idx <= 4:  # Training changed: remove model, history, and importance artifacts
        for k in ["model_path", "pipeline_path", "training_history", "feature_importance"]:
            if os.path.exists(paths[k]):
                try:
                    os.remove(paths[k])
                except Exception:
                    pass

    if idx <= 5:  # Evaluation changed: remove evaluation outputs
        for k in ["predictions_csv", "metrics_json"]:
            if os.path.exists(paths[k]):
                try:
                    os.remove(paths[k])
                except Exception:
                    pass


# ==============================================================================
# SECTION 1: FILE UPLOAD (INITIAL DASHBOARD PAGE)
# ==============================================================================

@main_bp.route("/")
def index():
    """Default landing route redirects to the initial File Upload page."""
    return redirect(url_for("main.upload_page"))


@main_bp.route("/upload")
def upload_page():
    """Renders the initial dataset upload dashboard page."""
    root = current_app.config["PROJECT_ROOT"]
    paths = get_paths()
    active_cfg = load_active_dataset_config(root)
    status = check_pipeline_status()

    session_data = None
    if os.path.exists(paths["session_metadata"]):
        try:
            with open(paths["session_metadata"], "r", encoding="utf-8") as f:
                session_data = json.load(f)
        except Exception:
            session_data = None

    return render_template(
        "upload.html",
        active_tab="upload",
        status=status,
        active_datasets=active_cfg,
        session_data=session_data,
        max_size_mb=int(MAX_UPLOAD_SIZE_BYTES / (1024 * 1024))
    )


@main_bp.route("/api/upload_dataset", methods=["POST"])
def upload_dataset_api():
    """
    Accepts, validates, and stores uploaded normal or replay datasets (.csv or .pcap).
    Enforces the 200 MB maximum size limit and validates file signatures.
    """
    root = current_app.config["PROJECT_ROOT"]
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file payload found in the request."}), 400

    uploaded_file = request.files["file"]
    category = request.form.get("category", "normal_traffic")
    if category not in ("normal_traffic", "replay_traffic"):
        return jsonify({"success": False, "error": "Invalid dataset category specified."}), 400

    if not uploaded_file.filename:
        return jsonify({"success": False, "error": "Uploaded file has an empty filename."}), 400

    filename = secure_filename(uploaded_file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".csv", ".pcap", ".pcapng"):
        return jsonify({"success": False, "error": f"Unsupported extension '{ext}'. Only .csv, .pcap, and .pcapng are allowed."}), 400

    # Save to dedicated uploads directory
    target_dir = os.path.join(root, "uploads", "normal" if category == "normal_traffic" else "replay")
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)

    try:
        uploaded_file.save(target_path)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save file to disk: {str(e)}"}), 500

    # Validate file integrity and size
    is_valid, val_msg, val_meta = validate_dataset_file(target_path)
    if not is_valid:
        try:
            os.remove(target_path)
        except Exception:
            pass
        return jsonify({"success": False, "error": val_msg}), 400

    # Update active dataset configuration
    active_cfg = load_active_dataset_config(root)
    file_size = os.path.getsize(target_path)
    rel_path = os.path.relpath(target_path, root)

    if category == "normal_traffic":
        active_cfg["normal_path"] = rel_path
        active_cfg["normal_filename"] = filename
        active_cfg["normal_type"] = val_meta.get("format", ext.lstrip("."))
        active_cfg["normal_size"] = file_size
    else:
        active_cfg["replay_path"] = rel_path
        active_cfg["replay_filename"] = filename
        active_cfg["replay_type"] = val_meta.get("format", ext.lstrip("."))
        active_cfg["replay_size"] = file_size

    active_cfg["is_custom_uploaded"] = True
    save_active_dataset_config(root, active_cfg)

    # Invalidate downstream artifacts to enforce re-audit and re-extraction
    invalidate_downstream_artifacts(from_stage="upload")

    return jsonify({
        "success": True,
        "message": f"Successfully uploaded and validated {filename}.",
        "filename": filename,
        "file_size": file_size,
        "size_formatted": f"{file_size / (1024*1024):.2f} MB",
        "category": category,
        "format": val_meta.get("format", ext.lstrip("."))
    })


@main_bp.route("/api/upload_and_process", methods=["POST"])
def upload_and_process_api():
    """
    Validates uploaded or active Normal and Replay datasets, parses their contents,
    verifies Modbus/TCP protocol fields and timestamps, generates a unique processing
    session ID, and enables Stage A (Data Audit).
    """
    root = current_app.config["PROJECT_ROOT"]
    paths = get_paths()
    active_cfg = load_active_dataset_config(root)

    # Handle direct multipart file uploads if sent with the request
    for cat_key, form_name in [("normal_traffic", "normal_file"), ("replay_traffic", "replay_file")]:
        if form_name in request.files:
            up_file = request.files[form_name]
            if up_file and up_file.filename:
                fname = secure_filename(up_file.filename)
                ext = os.path.splitext(fname)[1].lower()
                if ext not in (".csv", ".pcap", ".pcapng"):
                    return jsonify({"success": False, "error": f"Invalid extension '{ext}' for {fname}."}), 400
                tdir = os.path.join(root, "uploads", "normal" if cat_key == "normal_traffic" else "replay")
                os.makedirs(tdir, exist_ok=True)
                tpath = os.path.join(tdir, fname)
                up_file.save(tpath)
                is_val, vmsg, vmeta = validate_dataset_file(tpath)
                if not is_val:
                    return jsonify({"success": False, "error": vmsg}), 400
                fsize = os.path.getsize(tpath)
                rel_p = os.path.relpath(tpath, root)
                if cat_key == "normal_traffic":
                    active_cfg["normal_path"] = rel_p
                    active_cfg["normal_filename"] = fname
                    active_cfg["normal_type"] = vmeta.get("format", ext.lstrip("."))
                    active_cfg["normal_size"] = fsize
                else:
                    active_cfg["replay_path"] = rel_p
                    active_cfg["replay_filename"] = fname
                    active_cfg["replay_type"] = vmeta.get("format", ext.lstrip("."))
                    active_cfg["replay_size"] = fsize
                active_cfg["is_custom_uploaded"] = True
                save_active_dataset_config(root, active_cfg)

    paths = get_paths()

    # Verify both files exist
    if not os.path.exists(paths["normal_csv"]):
        return jsonify({"success": False, "error": f"Normal traffic dataset file not found: {paths['normal_csv']}"}), 400
    if not os.path.exists(paths["replay_csv"]):
        return jsonify({"success": False, "error": f"Replay attack traffic dataset file not found: {paths['replay_csv']}"}), 400

    try:
        # Parse and inspect dataset contents
        df_norm, df_rep, _ = load_datasets(
            normal_csv_path=paths["normal_csv"],
            replay_csv_path=paths["replay_csv"],
            base_dir=root
        )

        # Check required Modbus/TCP protocol fields
        expected_fields = [
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "mbtcp_trans_id", "mbtcp_unit_id", "modbus_func_code", "is_request"
        ]
        norm_fields = [f for f in expected_fields if f in df_norm.columns]
        rep_fields = [f for f in expected_fields if f in df_rep.columns]
        detected_fields = sorted(list(set(norm_fields).intersection(set(rep_fields))))

        # Timestamp validity
        ts_valid_norm = "timestamp" in df_norm.columns and pd.to_numeric(df_norm["timestamp"], errors="coerce").notnull().all()
        ts_valid_rep = "timestamp" in df_rep.columns and pd.to_numeric(df_rep["timestamp"], errors="coerce").notnull().all()
        timestamps_valid = bool(ts_valid_norm and ts_valid_rep)

        # Generate unique session ID
        session_id = f"RP4-SESSION-{uuid.uuid4().hex[:8].upper()}"

        session_meta = {
            "session_id": session_id,
            "created_at": datetime.now().isoformat(),
            "normal_file": active_cfg.get("normal_filename", os.path.basename(paths["normal_csv"])),
            "normal_rows": len(df_norm),
            "normal_size": os.path.getsize(paths["normal_csv"]),
            "replay_file": active_cfg.get("replay_filename", os.path.basename(paths["replay_csv"])),
            "replay_rows": len(df_rep),
            "replay_size": os.path.getsize(paths["replay_csv"]),
            "timestamps_valid": timestamps_valid,
            "protocol_fields_detected": detected_fields,
            "stage_a_ready": True
        }

        # Invalidate downstream audit and model artifacts
        invalidate_downstream_artifacts(from_stage="audit")

        # Persist session metadata
        os.makedirs(os.path.dirname(paths["session_metadata"]), exist_ok=True)
        with open(paths["session_metadata"], "w", encoding="utf-8") as f:
            json.dump(session_meta, f, indent=2)

        return jsonify({
            "success": True,
            "message": "Datasets successfully validated, parsed, and registered for Stage A.",
            "session": session_meta
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to process datasets: {str(e)}"}), 500


@main_bp.route("/api/session_status", methods=["GET"])
def get_session_status_api():
    """Returns active session status and dataset metadata."""
    paths = get_paths()
    session_data = None
    if os.path.exists(paths["session_metadata"]):
        try:
            with open(paths["session_metadata"], "r", encoding="utf-8") as f:
                session_data = json.load(f)
        except Exception:
            session_data = None
    return jsonify({
        "success": True,
        "session": session_data,
        "pipeline_status": check_pipeline_status()
    })


@main_bp.route("/api/remove_dataset", methods=["POST"])
def remove_dataset_api():
    """
    Removes an uploaded dataset for a specific category and reverts to benchmark default.
    """
    root = current_app.config["PROJECT_ROOT"]
    data = request.get_json(silent=True) or {}
    category = data.get("category", "all")

    active_cfg = load_active_dataset_config(root)
    default_cfg = reset_active_dataset_config(root)

    if category == "normal_traffic":
        active_cfg["normal_path"] = default_cfg["normal_path"]
        active_cfg["normal_filename"] = default_cfg["normal_filename"]
        active_cfg["normal_type"] = default_cfg["normal_type"]
        active_cfg["normal_size"] = default_cfg["normal_size"]
        save_active_dataset_config(root, active_cfg)
    elif category == "replay_traffic":
        active_cfg["replay_path"] = default_cfg["replay_path"]
        active_cfg["replay_filename"] = default_cfg["replay_filename"]
        active_cfg["replay_type"] = default_cfg["replay_type"]
        active_cfg["replay_size"] = default_cfg["replay_size"]
        save_active_dataset_config(root, active_cfg)
    else:
        active_cfg = reset_active_dataset_config(root)

    invalidate_downstream_artifacts(from_stage="upload")

    return jsonify({
        "success": True,
        "message": "Dataset reset to default benchmark file.",
        "active_datasets": active_cfg
    })


@main_bp.route("/api/active_datasets", methods=["GET"])
def get_active_datasets_api():
    """Returns metadata for currently active datasets."""
    root = current_app.config["PROJECT_ROOT"]
    active_cfg = load_active_dataset_config(root)
    return jsonify({"success": True, "data": active_cfg})


# ==============================================================================
# SECTION 2: STAGE A – DATA AUDIT, CLEANING & TRANSACTION RECONSTRUCTION
# ==============================================================================

@main_bp.route("/audit")
def audit_page():
    """Renders the Stage A Data Audit page."""
    paths = get_paths()
    status = check_pipeline_status()

    audit_data = None
    if os.path.exists(paths["audit_report"]):
        try:
            with open(paths["audit_report"], "r", encoding="utf-8") as f:
                audit_data = json.load(f)
        except Exception:
            audit_data = None

    cleaning_summary = None
    if os.path.exists(paths["cleaning_summary"]):
        try:
            with open(paths["cleaning_summary"], "r", encoding="utf-8") as f:
                cleaning_summary = json.load(f)
        except Exception:
            cleaning_summary = None

    has_reconstructed_tx = os.path.exists(paths["reconstructed_tx_csv"])

    return render_template(
        "audit.html",
        active_tab="audit",
        status=status,
        audit_data=audit_data,
        cleaning_summary=cleaning_summary,
        has_reconstructed_tx=has_reconstructed_tx
    )


@main_bp.route("/api/run_audit", methods=["POST"])
def run_audit_api():
    """
    Executes row-level schema inspection, label auditing, and transaction pairing coverage.
    Automatically generates both the structured JSON report and the publication-quality PDF.
    """
    paths = get_paths()
    cfg = current_app.config["APP_CONFIG"]
    try:
        norm_path, rep_path = get_active_clean_paths()

        # Load active normal and replay datasets
        df_norm, df_rep, load_summary = load_datasets(
            normal_csv_path=norm_path,
            replay_csv_path=rep_path,
            normal_max_rows=cfg.get("data", {}).get("normal_max_rows", None),
            inter_capture_gap_seconds=cfg.get("transaction_context", {}).get("inter_capture_gap_seconds", 100.0),
            base_dir=paths["root"]
        )

        # Audit schema and label integrity
        audit_report = audit_dataset_integrity(df_norm, df_rep, audit_report_path=paths["audit_report"])

        # Reconstruct transactions for coverage audit
        timeout_sec = cfg.get("transaction_context", {}).get("response_timeout_seconds", 1.0)
        tx_df, orphan_df, coverage = reconstruct_transactions(df_norm, df_rep, response_timeout=timeout_sec)
        audit_report["reconstruction_coverage"] = coverage

        # Save reconstructed transactions CSV for preview inspection table
        os.makedirs(os.path.dirname(paths["reconstructed_tx_csv"]), exist_ok=True)
        tx_df.to_csv(paths["reconstructed_tx_csv"], index=False)

        # Attach cleaning summary if existing
        if os.path.exists(paths["cleaning_summary"]):
            try:
                with open(paths["cleaning_summary"], "r", encoding="utf-8") as f:
                    audit_report["cleaning_summary"] = json.load(f)
            except Exception:
                pass

        # Save complete JSON audit report
        with open(paths["audit_report"], "w", encoding="utf-8") as f:
            json.dump(audit_report, f, indent=2)

        # Generate publication-quality ReportLab PDF audit report
        build_audit_pdf(audit_report, paths["audit_pdf"])

        return jsonify({
            "success": True,
            "message": "Data audit and PDF report generated successfully.",
            "data": audit_report
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route("/api/apply_cleaning", methods=["POST"])
def apply_cleaning_api():
    """
    Applies configurable data cleaning rules (duplicate removal, missing value handling,
    timestamp validation, chronological ordering, and invalid frame exclusion).
    Re-runs transaction reconstruction and data audit, updating metrics immediately.
    """
    paths = get_paths()
    cfg = current_app.config["APP_CONFIG"]
    data = request.get_json(silent=True) or {}

    options = {
        "remove_duplicates": bool(data.get("remove_duplicates", True)),
        "handle_missing": bool(data.get("handle_missing", True)),
        "validate_timestamps": bool(data.get("validate_timestamps", True)),
        "sort_chronological": bool(data.get("sort_chronological", True)),
        "inspect_inconsistent_labels": bool(data.get("inspect_inconsistent_labels", True)),
        "exclude_invalid": bool(data.get("exclude_invalid", True))
    }

    try:
        # Load raw active datasets
        df_norm, df_rep, _ = load_datasets(
            normal_csv_path=paths["normal_csv"],
            replay_csv_path=paths["replay_csv"],
            normal_max_rows=cfg.get("data", {}).get("normal_max_rows", None),
            inter_capture_gap_seconds=cfg.get("transaction_context", {}).get("inter_capture_gap_seconds", 100.0),
            base_dir=paths["root"]
        )

        # Clean datasets
        norm_clean, rep_clean, clean_summary = clean_datasets(df_norm, df_rep, options=options)

        # Save cleaned CSV files
        os.makedirs(os.path.dirname(paths["cleaned_normal_csv"]), exist_ok=True)
        norm_clean.to_csv(paths["cleaned_normal_csv"], index=False)
        rep_clean.to_csv(paths["cleaned_replay_csv"], index=False)

        # Save cleaning summary
        os.makedirs(os.path.dirname(paths["cleaning_summary"]), exist_ok=True)
        with open(paths["cleaning_summary"], "w", encoding="utf-8") as f:
            json.dump(clean_summary, f, indent=2)

        # Re-audit cleaned datasets
        audit_report = audit_dataset_integrity(norm_clean, rep_clean, audit_report_path=paths["audit_report"])

        # Reconstruct transactions
        timeout_sec = cfg.get("transaction_context", {}).get("response_timeout_seconds", 1.0)
        tx_df, orphan_df, coverage = reconstruct_transactions(norm_clean, rep_clean, response_timeout=timeout_sec)
        audit_report["reconstruction_coverage"] = coverage
        audit_report["cleaning_summary"] = clean_summary

        # Save reconstructed transactions
        os.makedirs(os.path.dirname(paths["reconstructed_tx_csv"]), exist_ok=True)
        tx_df.to_csv(paths["reconstructed_tx_csv"], index=False)

        # Save JSON audit report & PDF
        with open(paths["audit_report"], "w", encoding="utf-8") as f:
            json.dump(audit_report, f, indent=2)
        build_audit_pdf(audit_report, paths["audit_pdf"])

        # Invalidate downstream features and models
        invalidate_downstream_artifacts(from_stage="features")

        return jsonify({
            "success": True,
            "message": "Data cleaning and preprocessing applied successfully.",
            "cleaning_summary": clean_summary,
            "audit_report": audit_report
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Cleaning failed: {str(e)}"}), 500


@main_bp.route("/api/reconstructed_transactions", methods=["GET"])
def get_reconstructed_transactions_api():
    """
    Returns server-side paginated, searchable, and filtered reconstructed transactions.
    """
    paths = get_paths()
    if not os.path.exists(paths["reconstructed_tx_csv"]):
        # Attempt on-the-fly reconstruction if raw data exists
        if os.path.exists(paths["normal_csv"]) and os.path.exists(paths["replay_csv"]):
            try:
                norm_p, rep_p = get_active_clean_paths()
                df_norm, df_rep, _ = load_datasets(normal_csv_path=norm_p, replay_csv_path=rep_p, base_dir=paths["root"])
                cfg = current_app.config["APP_CONFIG"]
                timeout_sec = cfg.get("transaction_context", {}).get("response_timeout_seconds", 1.0)
                tx_df, _, _ = reconstruct_transactions(df_norm, df_rep, response_timeout=timeout_sec)
                os.makedirs(os.path.dirname(paths["reconstructed_tx_csv"]), exist_ok=True)
                tx_df.to_csv(paths["reconstructed_tx_csv"], index=False)
            except Exception as e:
                return jsonify({"success": False, "error": f"Failed to reconstruct transactions: {str(e)}", "data": [], "total": 0}), 500
        else:
            return jsonify({"success": False, "error": "Reconstructed transactions not generated yet.", "data": [], "total": 0}), 404

    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(5, int(request.args.get("limit", 20))))
    search_query = request.args.get("search", "").strip().lower()
    status_filter = request.args.get("status_filter", "all").strip().lower()
    sort_by = request.args.get("sort_by", "transaction_id")
    sort_order = request.args.get("sort_order", "asc").lower()

    try:
        df = pd.read_csv(paths["reconstructed_tx_csv"])
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to read transactions CSV: {str(e)}"}), 500

    if status_filter != "all" and "match_status" in df.columns:
        if status_filter == "matched":
            df = df[df["match_status"] == "matched"]
        elif status_filter == "timeout":
            df = df[df["match_status"].str.contains("timeout", na=False)]
        elif status_filter == "ambiguous":
            df = df[df["match_status"].str.contains("ambiguous", na=False)]

    if search_query:
        mask = (
            df["transaction_id"].astype(str).str.lower().str.contains(search_query) |
            df["client_ip"].astype(str).str.lower().str.contains(search_query) |
            df["server_ip"].astype(str).str.lower().str.contains(search_query) |
            df["modbus_func_code"].astype(str).str.contains(search_query)
        )
        df = df[mask]

    total_records = len(df)
    if sort_by in df.columns:
        ascending = (sort_order == "asc")
        df = df.sort_values(by=sort_by, ascending=ascending)

    total_pages = max(1, math.ceil(total_records / limit))
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_df = df.iloc[start_idx:end_idx]

    display_records = []
    for _, row in page_df.iterrows():
        resp_time = row.get("response_time")
        latency_ms = round(float(resp_time) * 1000.0, 2) if (pd.notnull(resp_time) and float(resp_time) >= 0) else None
        display_records.append({
            "transaction_id": str(row.get("transaction_id", "")),
            "timestamp": round(float(row.get("request_timestamp", 0)), 4) if pd.notnull(row.get("request_timestamp")) else None,
            "client_ip": str(row.get("client_ip", "")),
            "server_ip": str(row.get("server_ip", "")),
            "modbus_func_code": int(row.get("modbus_func_code", 0)) if pd.notnull(row.get("modbus_func_code")) else None,
            "match_status": str(row.get("match_status", "matched")),
            "latency_ms": latency_ms,
            "label_conflict": "Yes" if bool(row.get("label_conflict", False)) else "No",
            "dataset_category": str(row.get("dataset_category", "normal_traffic"))
        })

    return jsonify({
        "success": True,
        "page": page,
        "limit": limit,
        "total": total_records,
        "total_pages": total_pages,
        "data": display_records
    })


# ==============================================================================
# SECTION 3: STAGE B – FEATURES, SPLIT & TIME-WINDOW CONFIGURATION
# ==============================================================================

@main_bp.route("/features")
def features_page():
    """Renders the Stage B Features and Dataset Split page."""
    paths = get_paths()
    status = check_pipeline_status()
    cfg = current_app.config["APP_CONFIG"]

    split_summary = None
    normal_count = 0
    replay_count = 0

    if not status["audit_ready"]:
        return render_template(
            "features.html",
            active_tab="features",
            status=status,
            error_message="Stage A (Data Audit) must be executed before viewing or configuring features."
        )

    if os.path.exists(paths["split_manifest"]):
        try:
            m_df = pd.read_csv(paths["split_manifest"])
            train_sub = m_df[m_df["partition"] == "train"]
            test_sub = m_df[m_df["partition"] == "test"]
            gap_sub = m_df[m_df["partition"] == "gap_excluded"]
            split_summary = {
                "train_total": len(train_sub),
                "train_normal": int((train_sub["transaction_is_attack"] == 0).sum()),
                "train_replay": int((train_sub["transaction_is_attack"] == 1).sum()),
                "test_total": len(test_sub),
                "test_normal": int((test_sub["transaction_is_attack"] == 0).sum()),
                "test_replay": int((test_sub["transaction_is_attack"] == 1).sum()),
                "gap_excluded": len(gap_sub)
            }
        except Exception:
            split_summary = None

    if os.path.exists(paths["normal_features_csv"]):
        try:
            normal_count = len(pd.read_csv(paths["normal_features_csv"], usecols=["transaction_id"]))
        except Exception:
            normal_count = 0

    if os.path.exists(paths["replay_features_csv"]):
        try:
            replay_count = len(pd.read_csv(paths["replay_features_csv"], usecols=["transaction_id"]))
        except Exception:
            replay_count = 0

    time_window_default = cfg.get("feature_engineering", {}).get("trailing_time_window_seconds", 60.0)

    return render_template(
        "features.html",
        active_tab="features",
        status=status,
        split_summary=split_summary,
        time_window_seconds=time_window_default,
        normal_feature_rows=normal_count,
        replay_feature_rows=replay_count,
        total_feature_cols=len(MODEL_FEATURE_COLUMNS)
    )


@main_bp.route("/api/run_features", methods=["POST"])
def run_features_api():
    """
    Generates the 70/30 chronological split and extracts protocol-aware features.
    Accepts an optional configurable time window in seconds.
    """
    paths = get_paths()
    status = check_pipeline_status()
    cfg = current_app.config["APP_CONFIG"]

    if not status["audit_ready"]:
        return jsonify({"success": False, "error": "Please complete Stage A (Data Audit) first."}), 400

    data = request.get_json(silent=True) or {}
    time_window_sec = float(data.get("time_window_seconds", cfg.get("feature_engineering", {}).get("trailing_time_window_seconds", 60.0)))

    if time_window_sec <= 0:
        return jsonify({"success": False, "error": "Time window size must be a strictly positive number of seconds."}), 400

    # Persist updated time-window in runtime config
    cfg.setdefault("feature_engineering", {})["trailing_time_window_seconds"] = time_window_sec

    try:
        norm_path, rep_path = get_active_clean_paths()

        # Load active or cleaned datasets
        df_norm, df_rep, _ = load_datasets(
            normal_csv_path=norm_path,
            replay_csv_path=rep_path,
            normal_max_rows=cfg.get("data", {}).get("normal_max_rows", None),
            inter_capture_gap_seconds=cfg.get("transaction_context", {}).get("inter_capture_gap_seconds", 100.0),
            base_dir=paths["root"]
        )

        timeout_sec = cfg.get("transaction_context", {}).get("response_timeout_seconds", 1.0)
        tx_df, _, _ = reconstruct_transactions(df_norm, df_rep, response_timeout=timeout_sec)

        split_cfg = cfg.get("split", {})
        tx_split, manifest_summary = create_train_test_split(
            tx_df=tx_df,
            train_ratio=split_cfg.get("train_ratio", 0.70),
            separation_gap_seconds=split_cfg.get("separation_gap_seconds", 300.0),
            random_seed=split_cfg.get("random_seed", 42),
            manifest_path=paths["split_manifest"]
        )

        feat_cfg = cfg.get("feature_engineering", {})
        feat_df, feat_summary = extract_features(
            tx_df=tx_split,
            history_window_size=feat_cfg.get("history_window_size", 100),
            trailing_time_window_seconds=time_window_sec,
            max_unseen_time_sentinel=feat_cfg.get("max_unseen_time_sentinel", 3600.0),
            features_csv_path=paths["features_csv"],
            dictionary_json_path=paths["feature_dictionary"]
        )

        # Invalidate downstream model training and evaluation results
        invalidate_downstream_artifacts(from_stage="training")

        norm_count = int((feat_df["dataset_category"] == "normal_traffic").sum())
        rep_count = int((feat_df["dataset_category"] == "replay_traffic").sum())

        return jsonify({
            "success": True,
            "message": f"Features extracted successfully with a {time_window_sec}s trailing window.",
            "manifest_summary": manifest_summary,
            "feature_summary": feat_summary,
            "time_window_seconds": time_window_sec,
            "normal_features_count": norm_count,
            "replay_features_count": rep_count
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route("/api/features_data", methods=["GET"])
def get_features_data_api():
    """
    Returns server-side paginated, searchable, and sortable protocol-aware features
    for the two separate traffic sources (Normal vs Replay).
    """
    paths = get_paths()
    source = request.args.get("source", "normal").lower()
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(5, int(request.args.get("limit", 20))))
    search_query = request.args.get("search", "").strip().lower()
    sort_by = request.args.get("sort_by", "transaction_id")
    sort_order = request.args.get("sort_order", "asc").lower()

    target_csv = paths["normal_features_csv"] if source == "normal" else paths["replay_features_csv"]
    if not os.path.exists(target_csv):
        return jsonify({"success": False, "error": "Features not extracted yet.", "data": [], "total": 0}), 404

    try:
        df = pd.read_csv(target_csv)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to read features CSV: {str(e)}"}), 500

    # Filter by search term across key columns
    if search_query:
        mask = (
            df["transaction_id"].astype(str).str.lower().str.contains(search_query) |
            df["client_ip"].astype(str).str.lower().str.contains(search_query) |
            df["server_ip"].astype(str).str.lower().str.contains(search_query) |
            df["modbus_func_code"].astype(str).str.contains(search_query)
        )
        df = df[mask]

    total_records = len(df)

    # Column sorting
    if sort_by in df.columns:
        ascending = (sort_order == "asc")
        df = df.sort_values(by=sort_by, ascending=ascending)

    total_pages = max(1, math.ceil(total_records / limit))
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_df = df.iloc[start_idx:end_idx]

    # Convert numeric floats to readable decimals
    display_records = []
    for _, row in page_df.iterrows():
        rec = row.to_dict()
        for k, v in rec.items():
            if isinstance(v, float) and np.isnan(v):
                rec[k] = None
            elif isinstance(v, float):
                rec[k] = round(v, 4)
        display_records.append(rec)

    return jsonify({
        "success": True,
        "source": source,
        "page": page,
        "limit": limit,
        "total": total_records,
        "total_pages": total_pages,
        "features_count": len(MODEL_FEATURE_COLUMNS),
        "data": display_records
    })


# ==============================================================================
# SECTION 4: STAGE C – MODEL TRAINING, PROGRESS & FEATURE IMPORTANCE
# ==============================================================================

@main_bp.route("/training")
def training_page():
    """Renders the Stage C Model Training page."""
    paths = get_paths()
    status = check_pipeline_status()
    cfg = current_app.config["APP_CONFIG"]

    if not status["features_ready"]:
        return render_template(
            "training.html",
            active_tab="training",
            status=status,
            error_message="Stage B (Features & Split) must be generated before model training."
        )

    saved_model_info = None
    training_history = None
    feature_importance = None

    if os.path.exists(paths["pipeline_path"]):
        try:
            bundle = joblib.load(paths["pipeline_path"])
            saved_model_info = {
                "model_name": "XGBClassifier",
                "status": "Serialized & Ready",
                "trained_at": bundle.get("training_timestamp", "Unknown"),
                "sample_count": (bundle.get("train_class_counts", {}).get("normal_0", 0) + bundle.get("train_class_counts", {}).get("replay_1", 0)),
                "feature_count": len(bundle.get("feature_order", [])),
                "duration_seconds": bundle.get("training_duration_seconds", 0.0),
                "boosting_rounds": bundle.get("hyperparameters", {}).get("n_estimators", 100),
                "version": xgb.__version__,
                "scale_pos_weight": round(bundle.get("scale_pos_weight", 1.0), 4),
                "probability_threshold": bundle.get("probability_threshold", 0.5),
                "train_class_counts": bundle.get("train_class_counts", {}),
                "hyperparameters": bundle.get("hyperparameters", {})
            }
            training_history = bundle.get("training_history")
            feature_importance = bundle.get("feature_importance")
        except Exception:
            saved_model_info = None

    if not training_history and os.path.exists(paths["training_history"]):
        try:
            with open(paths["training_history"], "r", encoding="utf-8") as f:
                training_history = json.load(f)
        except Exception:
            training_history = None

    if not feature_importance and os.path.exists(paths["feature_importance"]):
        try:
            with open(paths["feature_importance"], "r", encoding="utf-8") as f:
                feature_importance = json.load(f)
        except Exception:
            feature_importance = None

    return render_template(
        "training.html",
        active_tab="training",
        status=status,
        default_params=cfg.get("model", {}),
        saved_model_info=saved_model_info,
        training_history=training_history,
        feature_importance=feature_importance
    )


@main_bp.route("/api/train_model", methods=["POST"])
def train_model_api():
    """
    Trains the XGBoost binary classifier on the 70% training partition.
    Logs binary log loss per boosting round and returns structured training history
    and feature importance rankings.
    """
    paths = get_paths()
    status = check_pipeline_status()
    cfg = current_app.config["APP_CONFIG"]

    if not status["features_ready"]:
        return jsonify({"success": False, "error": "Features CSV and split manifest must exist before training."}), 400

    try:
        feat_df = pd.read_csv(paths["features_csv"])
        classifier, train_meta = train_xgboost_model(
            feat_df=feat_df,
            model_params=cfg.get("model", {}),
            model_path=paths["model_path"],
            pipeline_path=paths["pipeline_path"],
            history_path=paths["training_history"]
        )

        # Invalidate downstream evaluation
        invalidate_downstream_artifacts(from_stage="evaluation")

        return jsonify({
            "success": True,
            "message": "XGBoost model successfully trained and serialized.",
            "metadata": train_meta,
            "training_history": train_meta.get("training_history"),
            "feature_importance": train_meta.get("feature_importance")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route("/api/load_saved_model", methods=["POST"])
def load_saved_model_api():
    """
    Loads saved model artifacts and restores the recorded boosting loss progression
    and feature importance analysis.
    """
    paths = get_paths()
    if not os.path.exists(paths["model_path"]) or not os.path.exists(paths["pipeline_path"]):
        return jsonify({"success": False, "error": "No saved model files found on disk."}), 404

    try:
        predictor = ReplayPredictor(model_path=paths["model_path"], pipeline_path=paths["pipeline_path"])
        bundle = predictor.pipeline_bundle

        history_data = bundle.get("training_history")
        if not history_data and os.path.exists(paths["training_history"]):
            try:
                with open(paths["training_history"], "r", encoding="utf-8") as f:
                    history_data = json.load(f)
            except Exception:
                history_data = None

        feat_imp = bundle.get("feature_importance")
        if not feat_imp and os.path.exists(paths["feature_importance"]):
            try:
                with open(paths["feature_importance"], "r", encoding="utf-8") as f:
                    feat_imp = json.load(f)
            except Exception:
                feat_imp = None

        sample_cnt = bundle.get("train_class_counts", {}).get("normal_0", 0) + bundle.get("train_class_counts", {}).get("replay_1", 0)

        return jsonify({
            "success": True,
            "message": "Saved model artifacts verified and loaded successfully.",
            "model_name": "XGBClassifier",
            "status": "Serialized & Ready",
            "trained_at": bundle.get("training_timestamp"),
            "sample_count": sample_cnt,
            "feature_count": len(bundle.get("feature_order", [])),
            "duration_seconds": bundle.get("training_duration_seconds", 0.0),
            "boosting_rounds": bundle.get("hyperparameters", {}).get("n_estimators", 100),
            "version": xgb.__version__,
            "scale_pos_weight": round(bundle.get("scale_pos_weight", 1.0), 4),
            "training_history": history_data,
            "feature_importance": feat_imp
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==============================================================================
# SECTION 5: STAGE D – PRELIMINARY EVALUATION & PREDICTION RESULTS
# ==============================================================================

@main_bp.route("/evaluation")
def evaluation_page():
    """Renders the Stage D Preliminary Evaluation page."""
    paths = get_paths()
    status = check_pipeline_status()

    if not status["model_ready"]:
        return render_template(
            "evaluation.html",
            active_tab="evaluation",
            status=status,
            error_message="Stage C (Train Model) must be executed before viewing evaluation metrics."
        )

    eval_data = None
    if os.path.exists(paths["metrics_json"]):
        try:
            with open(paths["metrics_json"], "r", encoding="utf-8") as f:
                eval_data = json.load(f)
        except Exception:
            eval_data = None

    return render_template(
        "evaluation.html",
        active_tab="evaluation",
        status=status,
        eval_data=eval_data
    )


@main_bp.route("/api/run_evaluation", methods=["POST"])
def run_evaluation_api():
    """
    Evaluates the Rule Baseline and XGBoost model on the held-out 30% test partition.
    Generates test_predictions.csv and evaluation_metrics.json.
    """
    paths = get_paths()
    status = check_pipeline_status()
    cfg = current_app.config["APP_CONFIG"]

    if not status["model_ready"]:
        return jsonify({"success": False, "error": "A trained model is required before evaluation."}), 400

    try:
        feat_df = pd.read_csv(paths["features_csv"])
        eval_results = evaluate_test_partition(
            feat_df=feat_df,
            model_path=paths["model_path"],
            pipeline_path=paths["pipeline_path"],
            rule_baseline_config=cfg.get("rule_baseline", {}),
            predictions_csv_path=paths["predictions_csv"],
            metrics_json_path=paths["metrics_json"]
        )

        return jsonify({
            "success": True,
            "message": "Preliminary evaluation completed successfully.",
            "data": eval_results
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route("/api/predictions_data", methods=["GET"])
def get_predictions_data_api():
    """
    Returns server-side paginated, searchable, and filtered test transaction predictions.
    Supports filtering by predicted label, actual label, prediction status, and source dataset.
    """
    paths = get_paths()
    if not os.path.exists(paths["predictions_csv"]):
        return jsonify({"success": False, "error": "Predictions not generated yet.", "data": [], "total": 0}), 404

    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(5, int(request.args.get("limit", 20))))
    search_query = request.args.get("search", "").strip().lower()
    sort_by = request.args.get("sort_by", "transaction_id")
    sort_order = request.args.get("sort_order", "asc").lower()

    pred_filter = request.args.get("pred_filter", "all").lower()
    actual_filter = request.args.get("actual_filter", "all").lower()
    status_filter = request.args.get("status_filter", "all").strip()
    dataset_filter = request.args.get("dataset_filter", "all").lower()

    try:
        df = pd.read_csv(paths["predictions_csv"])
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to read predictions CSV: {str(e)}"}), 500

    # Total counts before filtering
    total_unfiltered = len(df)
    total_normal_pred = int((df["xgb_pred"] == 0).sum()) if "xgb_pred" in df.columns else 0
    total_replay_pred = int((df["xgb_pred"] == 1).sum()) if "xgb_pred" in df.columns else 0

    # Apply filters
    if pred_filter in ("0", "normal"):
        df = df[df["xgb_pred"] == 0]
    elif pred_filter in ("1", "replay"):
        df = df[df["xgb_pred"] == 1]

    if actual_filter in ("0", "normal"):
        df = df[df["target_is_attack"] == 0]
    elif actual_filter in ("1", "replay"):
        df = df[df["target_is_attack"] == 1]
    elif actual_filter == "unknown":
        df = df[~df["target_is_attack"].isin([0, 1])]

    if status_filter != "all" and "prediction_status" in df.columns:
        sf_lower = status_filter.lower()
        if "true negative" in sf_lower or sf_lower == "tn":
            df = df[df["prediction_status"].str.lower().str.contains("true negative")]
        elif "true positive" in sf_lower or sf_lower == "tp":
            df = df[df["prediction_status"].str.lower().str.contains("true positive")]
        elif "false positive" in sf_lower or sf_lower == "fp":
            df = df[df["prediction_status"].str.lower().str.contains("false positive")]
        elif "false negative" in sf_lower or sf_lower == "fn":
            df = df[df["prediction_status"].str.lower().str.contains("false negative")]
        elif "not evaluated" in sf_lower:
            df = df[df["prediction_status"].str.lower().str.contains("not evaluated")]
        else:
            df = df[df["prediction_status"].str.lower() == sf_lower]

    if dataset_filter in ("normal", "normal traffic") and "source_dataset" in df.columns:
        df = df[df["source_dataset"].str.lower().str.contains("normal")]
    elif dataset_filter in ("replay", "replay attack traffic") and "source_dataset" in df.columns:
        df = df[df["source_dataset"].str.lower().str.contains("replay")]

    # Free-text search
    if search_query:
        mask = (
            df["transaction_id"].astype(str).str.lower().str.contains(search_query) |
            df["client_ip"].astype(str).str.lower().str.contains(search_query) |
            df["server_ip"].astype(str).str.lower().str.contains(search_query) |
            df["modbus_func_code"].astype(str).str.contains(search_query)
        )
        df = df[mask]

    total_filtered = len(df)

    # Sorting
    if sort_by in df.columns:
        ascending = (sort_order == "asc")
        df = df.sort_values(by=sort_by, ascending=ascending)

    total_pages = max(1, math.ceil(total_filtered / limit))
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_df = df.iloc[start_idx:end_idx]

    display_records = []
    for _, row in page_df.iterrows():
        rec = row.to_dict()
        for k, v in rec.items():
            if isinstance(v, float) and np.isnan(v):
                rec[k] = None
        display_records.append(rec)

    return jsonify({
        "success": True,
        "page": page,
        "limit": limit,
        "total_filtered": total_filtered,
        "total_unfiltered": total_unfiltered,
        "total_normal_pred": total_normal_pred,
        "total_replay_pred": total_replay_pred,
        "total_pages": total_pages,
        "data": display_records
    })


# ==============================================================================
# SECTION 6: ARTIFACT DOWNLOAD HANDLERS (EXCEL VIA OPENPYXL & PDF VIA REPORTLAB)
# ==============================================================================

@main_bp.route("/download/<file_type>")
def download_artifact(file_type: str):
    """
    Serves generated research artifacts with appropriate MIME types and filenames.
    Feature extracts and transaction predictions are exported as genuine .xlsx workbooks
    built using openpyxl. PDF reports are delivered as binary application/pdf streams.
    """
    paths = get_paths()

    # 1. Genuine Excel Export: Normal Traffic Features
    if file_type == "normal_features":
        if not os.path.exists(paths["normal_features_csv"]):
            return "Normal traffic features have not been extracted yet.", 404
        try:
            df = pd.read_csv(paths["normal_features_csv"])
            buf = export_dataframe_to_excel_buffer(df, sheet_name="Normal_Traffic_Features")
            return send_file(
                buf,
                as_attachment=True,
                download_name="normal_protocol_features.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except Exception as e:
            return f"Failed to export Excel workbook: {str(e)}", 500

    # 2. Genuine Excel Export: Replay Attack Traffic Features
    if file_type == "replay_features":
        if not os.path.exists(paths["replay_features_csv"]):
            return "Replay attack features have not been extracted yet.", 404
        try:
            df = pd.read_csv(paths["replay_features_csv"])
            buf = export_dataframe_to_excel_buffer(df, sheet_name="Replay_Traffic_Features")
            return send_file(
                buf,
                as_attachment=True,
                download_name="replay_protocol_features.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except Exception as e:
            return f"Failed to export Excel workbook: {str(e)}", 500

    # 3. Genuine Excel Export: Transaction Predictions
    if file_type == "predictions":
        if not os.path.exists(paths["predictions_csv"]):
            return "Predictions have not been generated yet.", 404
        try:
            df = pd.read_csv(paths["predictions_csv"])
            buf = export_dataframe_to_excel_buffer(df, sheet_name="Transaction_Predictions")
            return send_file(
                buf,
                as_attachment=True,
                download_name="RP4_Transaction_Predictions.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except Exception as e:
            return f"Failed to export Excel workbook: {str(e)}", 500

    # 4. Publication-Quality PDF: Data Audit Report
    if file_type in ("audit", "audit_pdf"):
        if not os.path.exists(paths["audit_pdf"]):
            if os.path.exists(paths["audit_report"]):
                try:
                    with open(paths["audit_report"], "r", encoding="utf-8") as f:
                        data = json.load(f)
                    build_audit_pdf(data, paths["audit_pdf"])
                except Exception as e:
                    return f"Failed to generate PDF audit report: {str(e)}", 500
            else:
                return "Data audit report has not been generated yet.", 404
        return send_file(
            paths["audit_pdf"],
            as_attachment=True,
            download_name="RP4_Data_Audit_Report.pdf",
            mimetype="application/pdf"
        )

    # 5. Other static artifacts (manifest, metrics, raw features CSV)
    static_mapping = {
        "audit_json": (paths["audit_report"], "data_audit_report.json", "application/json"),
        "features": (paths["features_csv"], "extracted_features.csv", "text/csv"),
        "manifest": (paths["split_manifest"], "split_manifest.csv", "text/csv"),
        "metrics": (paths["metrics_json"], "evaluation_metrics.json", "application/json")
    }

    if file_type not in static_mapping:
        return "Unknown artifact file type requested.", 404

    file_path, download_name, mime = static_mapping[file_type]
    if not os.path.exists(file_path):
        return f"Artifact {download_name} has not been generated yet.", 404

    return send_file(file_path, as_attachment=True, download_name=download_name, mimetype=mime)
