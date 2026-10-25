"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Stage 1 End-to-End Pipeline Runner (CLI)

Usage:
    py -3.13 run_pipeline.py
    py -3.13 run_pipeline.py --config config/default.yaml
    py -3.13 run_pipeline.py --normal-rows 50000
"""

import argparse
import os
import sys
import yaml

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data_loader import load_datasets
from src.data_validation import audit_dataset_integrity
from src.transaction_context import reconstruct_transactions
from src.split_data import create_train_test_split
from src.feature_engineering import extract_features
from src.train_model import train_xgboost_model
from src.evaluate_model import evaluate_test_partition


def load_config(config_path: str = "config/default.yaml") -> dict:
    if not os.path.isabs(config_path):
        config_path = os.path.join(PROJECT_ROOT, config_path)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_pipeline(config: dict, normal_max_rows: int = None) -> dict:
    raise RuntimeError(
        "Historical pipeline disabled after the Component 4 audit: its inferred capture "
        "split and outcome-dependent features do not establish independent evaluation. "
        "Use python -m component4_replay.src.prepare --out <NEW_DIRECTORY>; "
        "see component4_replay/README.md. Existing artifacts are preserved."
    )
    print("=" * 75)
    print("Protocol-Aware Replay Attack Detection for Modbus/TCP")
    print("Stage 1 University Research Prototype Pipeline")
    print("=" * 75)

    data_cfg = config.get("data", {})
    norm_path = data_cfg.get("normal_csv", "data/raw/normal_traffic_baseline.csv")
    rep_path = data_cfg.get("replay_csv", "data/raw/replay_attacks.csv")
    rows_limit = normal_max_rows if normal_max_rows is not None else data_cfg.get("normal_max_rows", None)

    art_cfg = config.get("artifacts", {})
    audit_path = os.path.join(PROJECT_ROOT, art_cfg.get("audit_report", "artifacts/audits/data_audit_report.json"))
    manifest_path = os.path.join(PROJECT_ROOT, art_cfg.get("split_manifest", "artifacts/splits/split_manifest.csv"))
    features_csv_path = os.path.join(PROJECT_ROOT, art_cfg.get("features_csv", "artifacts/results/extracted_features.csv"))
    dictionary_json_path = os.path.join(PROJECT_ROOT, art_cfg.get("feature_dictionary", "artifacts/results/feature_dictionary.json"))
    model_path = os.path.join(PROJECT_ROOT, art_cfg.get("model_path", "artifacts/models/xgboost_model.json"))
    pipeline_path = os.path.join(PROJECT_ROOT, art_cfg.get("pipeline_path", "artifacts/models/pipeline_artifacts.joblib"))
    predictions_csv_path = os.path.join(PROJECT_ROOT, art_cfg.get("predictions_csv", "artifacts/predictions/test_predictions.csv"))
    metrics_json_path = os.path.join(PROJECT_ROOT, art_cfg.get("metrics_json", "artifacts/metrics/evaluation_metrics.json"))

    # Step 1: Ingestion
    print("\n[Step 1/7] Ingesting Datasets & Metadata...")
    df_norm, df_rep, load_summary = load_datasets(
        normal_csv_path=norm_path,
        replay_csv_path=rep_path,
        normal_max_rows=rows_limit,
        inter_capture_gap_seconds=config.get("transaction_context", {}).get("inter_capture_gap_seconds", 100.0),
        base_dir=PROJECT_ROOT
    )
    print(f"  * Normal rows loaded: {load_summary['normal_rows_loaded']:,}")
    print(f"  * Replay rows loaded: {load_summary['replay_rows_loaded']:,}")
    print(f"  * Capture groups: Normal={load_summary['normal_captures_count']}, Replay={load_summary['replay_captures_count']}")

    # Step 2: Data & Label Audit
    print("\n[Step 2/7] Executing Data Integrity & Label Audit...")
    audit_report = audit_dataset_integrity(df_norm, df_rep, audit_report_path=audit_path)
    print(f"  * Normal class distribution: {audit_report['label_audit']['normal_class_distribution']}")
    print(f"  * Replay class distribution: {audit_report['label_audit']['replay_class_distribution']}")
    print(f"  * Replay contains normal rows: {audit_report['label_audit']['replay_contains_normal_rows']}")
    print(f"  * Missing values: Normal={audit_report['missing_values']['normal_missing_total']}, Replay={audit_report['missing_values']['replay_missing_total']}")
    print(f"  * Audit report saved: {audit_path}")

    # Step 3: Transaction Context Reconstruction
    print("\n[Step 3/7] Reconstructing Modbus Transaction Context...")
    timeout_sec = config.get("transaction_context", {}).get("response_timeout_seconds", 1.0)
    tx_df, orphan_df, coverage = reconstruct_transactions(df_norm, df_rep, response_timeout=timeout_sec)
    print(f"  * Total transactions: {coverage['total_requests_processed']:,}")
    print(f"  * Matched: {coverage['matched_transactions']:,} ({coverage['pairing_success_rate'] * 100:.1f}%)")
    print(f"  * Timeouts / Missing responses: {coverage['timeout_missing_responses']:,} ({coverage['timeout_rate'] * 100:.1f}%)")
    print(f"  * Orphan responses: {coverage['orphan_responses']:,}")
    print(f"  * Label conflicts flagged: {coverage['label_conflicts_flagged']:,}")

    # Step 4: Data Partitioning & Leakage Control
    print("\n[Step 4/7] Partitioning Transactions (70/30 Split)...")
    split_cfg = config.get("split", {})
    tx_split, manifest_summary = create_train_test_split(
        tx_df=tx_df,
        train_ratio=split_cfg.get("train_ratio", 0.70),
        separation_gap_seconds=split_cfg.get("separation_gap_seconds", 300.0),
        random_seed=split_cfg.get("random_seed", 42),
        manifest_path=manifest_path
    )
    print(f"  * Training transactions: {manifest_summary['train_transactions']:,} (Normal: {manifest_summary['train_class_counts']['normal_0']:,}, Replay: {manifest_summary['train_class_counts']['replay_1']:,})")
    print(f"  * Test transactions: {manifest_summary['test_transactions']:,} (Normal: {manifest_summary['test_class_counts']['normal_0']:,}, Replay: {manifest_summary['test_class_counts']['replay_1']:,})")
    print(f"  * Embargo gap excluded: {manifest_summary['gap_excluded_transactions']:,} transactions")
    print(f"  * Split manifest saved: {manifest_path}")

    # Step 5: Protocol-Aware Feature Extraction
    print("\n[Step 5/7] Extracting Protocol-Aware Features...")
    feat_cfg = config.get("feature_engineering", {})
    feat_df, feat_summary = extract_features(
        tx_df=tx_split,
        history_window_size=feat_cfg.get("history_window_size", 100),
        trailing_time_window_seconds=feat_cfg.get("trailing_time_window_seconds", 5.0),
        max_unseen_time_sentinel=feat_cfg.get("max_unseen_time_sentinel", 3600.0),
        features_csv_path=features_csv_path,
        dictionary_json_path=dictionary_json_path
    )
    print(f"  * Model input features ({feat_summary['model_input_feature_count']}): {', '.join(feat_summary['feature_names'][:6])}...")
    print(f"  * Excluded metadata fields: {feat_summary['excluded_metadata_columns']} columns (IPs, ports, timestamps, frame #s, labels)")
    print(f"  * Features CSV saved: {features_csv_path}")

    # Step 6: Initial Model Training
    print("\n[Step 6/7] Training Initial Supervised XGBoost Classifier...")
    model_params = config.get("model", {})
    classifier, train_meta = train_xgboost_model(
        feat_df=feat_df,
        model_params=model_params,
        model_path=model_path,
        pipeline_path=pipeline_path
    )
    print(f"  * Trained on {train_meta['training_samples']:,} samples with scale_pos_weight={train_meta['scale_pos_weight_applied']}")
    print(f"  * Saved model: {model_path}")
    print(f"  * Saved pipeline bundle: {pipeline_path}")

    # Step 7: Preliminary Evaluation
    print("\n[Step 7/7] Evaluating Baseline vs. XGBoost on Held-Out Test Set...")
    eval_results = evaluate_test_partition(
        feat_df=feat_df,
        model_path=model_path,
        pipeline_path=pipeline_path,
        rule_baseline_config=config.get("rule_baseline", {}),
        predictions_csv_path=predictions_csv_path,
        metrics_json_path=metrics_json_path
    )

    base_m = eval_results["rule_baseline_metrics"]
    xgb_m = eval_results["xgboost_metrics"]

    print("\n" + "=" * 75)
    print("PRELIMINARY STAGE 1 EVALUATION RESULTS")
    print("=" * 75)
    print(f"{'Metric':<25} {'Rule Baseline':<20} {'XGBoost':<20}")
    print("-" * 65)
    print(f"{'Accuracy':<25} {base_m['accuracy']:<20.4f} {xgb_m['accuracy']:<20.4f}")
    print(f"{'Precision':<25} {base_m['precision']:<20.4f} {xgb_m['precision']:<20.4f}")
    print(f"{'Recall':<25} {base_m['recall']:<20.4f} {xgb_m['recall']:<20.4f}")
    print(f"{'F1-Score':<25} {base_m['f1_score']:<20.4f} {xgb_m['f1_score']:<20.4f}")
    print(f"{'False Positive Rate':<25} {base_m['false_positive_rate']:<20.4f} {xgb_m['false_positive_rate']:<20.4f}")
    print(f"{'ROC-AUC':<25} {str(base_m['roc_auc']):<20} {str(xgb_m['roc_auc']):<20}")
    print("-" * 65)
    print(f"Test Class Support: Normal = {eval_results['partition_counts']['test']['normal']:,}, Replay = {eval_results['partition_counts']['test']['replay']:,}")
    print(f"Average Detection Delay: {eval_results['timing_breakdown']['total_operational_detection_delay_ms']:.2f} ms")
    print(f"  - Model Inference: {eval_results['timing_breakdown']['model_inference_time_per_tx_ms']:.4f} ms")
    print(f"  - Network Latency / Timeout: {eval_results['timing_breakdown']['avg_network_resolution_delay_ms']:.2f} ms")
    print("=" * 75)
    print(f"Metrics saved to: {metrics_json_path}")
    print(f"Predictions saved to: {predictions_csv_path}")

    return {
        "load_summary": load_summary,
        "audit_report": audit_report,
        "coverage": coverage,
        "manifest_summary": manifest_summary,
        "train_meta": train_meta,
        "eval_results": eval_results
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Stage 1 Replay Attack Detection Pipeline")
    parser.add_argument("--config", default="config/default.yaml", help="Path to config file")
    parser.add_argument("--normal-rows", type=int, default=None, help="Max normal rows to load (default: all)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    run_pipeline(cfg, normal_max_rows=args.normal_rows)
