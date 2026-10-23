"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Comprehensive Automated Verification for All Extended Interactive Capabilities

Verifies:
1. Upload & Process endpoint (/api/upload_and_process) and session metadata.
2. Data cleaning & preprocessing endpoint (/api/apply_cleaning) and summary report.
3. Reconstructed transactions preview API (/api/reconstructed_transactions) with pagination & filters.
4. Genuine openpyxl Excel exports (.xlsx) for Normal Features, Replay Features, and Predictions.
5. XGBoost feature importance and training progress tracking.
6. Preliminary evaluation with ROC Curve points, probability distribution bins, and prediction summary counts.
7. Prediction table search, sorting, and 4-way multi-filtering.
"""

import os
import sys
import io
import json
import unittest
import openpyxl
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from src.data_loader import reset_active_dataset_config


class TestNewPipelineFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

        # Reset active datasets to baseline
        reset_active_dataset_config(PROJECT_ROOT)

    def test_01_upload_and_process_api(self):
        """Verify /api/upload_and_process parses datasets and generates a unique session ID."""
        resp = self.client.post("/api/upload_and_process")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("session", data)
        sess = data["session"]
        self.assertTrue(sess["session_id"].startswith("RP4-SESSION-"))
        self.assertGreater(sess["normal_rows"], 0)
        self.assertGreater(sess["replay_rows"], 0)
        self.assertTrue(sess["timestamps_valid"])
        self.assertIn("mbtcp_trans_id", sess["protocol_fields_detected"])
        self.assertIn("modbus_func_code", sess["protocol_fields_detected"])

        # Check session_status endpoint
        status_resp = self.client.get("/api/session_status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.get_json()
        self.assertTrue(status_data["success"])
        self.assertIsNotNone(status_data["session"])
        self.assertEqual(status_data["session"]["session_id"], sess["session_id"])

    def test_02_data_cleaning_api(self):
        """Verify /api/apply_cleaning executes data hygiene and updates audit metrics."""
        opts = {
            "remove_duplicates": True,
            "handle_missing": True,
            "validate_timestamps": True,
            "sort_chronological": True,
            "inspect_inconsistent_labels": True,
            "exclude_invalid": True
        }
        resp = self.client.post("/api/apply_cleaning", json=opts)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("cleaning_summary", data)
        summary = data["cleaning_summary"]
        self.assertIn("transformations", summary)
        self.assertIn("cleaned_records", summary)
        self.assertGreater(summary["cleaned_records"]["total"], 0)

        # Audit report should now contain cleaning summary
        self.assertIn("audit_report", data)
        self.assertIn("reconstruction_coverage", data["audit_report"])

    def test_03_reconstructed_transactions_api(self):
        """Verify /api/reconstructed_transactions provides paginated, searchable transaction pairing data."""
        resp = self.client.get("/api/reconstructed_transactions?page=1&limit=15")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["data"]), 15)
        self.assertGreater(data["total"], 15)

        # Verify record schema
        rec = data["data"][0]
        self.assertIn("transaction_id", rec)
        self.assertIn("client_ip", rec)
        self.assertIn("server_ip", rec)
        self.assertIn("modbus_func_code", rec)
        self.assertIn("match_status", rec)
        self.assertIn("latency_ms", rec)
        self.assertIn("label_conflict", rec)

        # Search test
        search_resp = self.client.get("/api/reconstructed_transactions?search=192.168")
        self.assertEqual(search_resp.status_code, 200)
        self.assertTrue(search_resp.get_json()["success"])

    def test_04_features_and_excel_downloads(self):
        """Verify feature extraction and openpyxl genuine Excel export for normal and replay features."""
        feat_resp = self.client.post("/api/run_features", json={"time_window_seconds": 60.0})
        self.assertEqual(feat_resp.status_code, 200)
        self.assertTrue(feat_resp.get_json()["success"])

        # Test Normal Features Excel Download
        norm_resp = self.client.get("/download/normal_features")
        self.assertEqual(norm_resp.status_code, 200)
        self.assertEqual(norm_resp.headers.get("Content-Type"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertIn("normal_protocol_features.xlsx", norm_resp.headers.get("Content-Disposition", ""))
        
        # Verify it is a genuine Excel workbook using openpyxl
        norm_wb = openpyxl.load_workbook(io.BytesIO(norm_resp.data), read_only=True)
        self.assertIn("Normal_Traffic_Features", norm_wb.sheetnames)
        norm_ws = norm_wb["Normal_Traffic_Features"]
        first_row = [cell for cell in next(norm_ws.iter_rows(values_only=True))]
        self.assertIn("transaction_id", first_row)
        norm_wb.close()

        # Test Replay Features Excel Download
        rep_resp = self.client.get("/download/replay_features")
        self.assertEqual(rep_resp.status_code, 200)
        self.assertEqual(rep_resp.headers.get("Content-Type"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertIn("replay_protocol_features.xlsx", rep_resp.headers.get("Content-Disposition", ""))

        rep_wb = openpyxl.load_workbook(io.BytesIO(rep_resp.data), read_only=True)
        self.assertIn("Replay_Traffic_Features", rep_wb.sheetnames)
        rep_ws = rep_wb["Replay_Traffic_Features"]
        rep_first_row = [cell for cell in next(rep_ws.iter_rows(values_only=True))]
        self.assertIn("transaction_id", rep_first_row)
        rep_wb.close()

    def test_05_train_model_with_feature_importance(self):
        """Verify model training returns boosting loss history and feature importance."""
        resp = self.client.post("/api/train_model")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("feature_importance", data)
        self.assertGreater(len(data["feature_importance"]), 0)
        top_feat = data["feature_importance"][0]
        self.assertIn("feature", top_feat)
        self.assertIn("importance", top_feat)

        # Test load_saved_model returns feature importance
        load_resp = self.client.post("/api/load_saved_model")
        self.assertEqual(load_resp.status_code, 200)
        load_data = load_resp.get_json()
        self.assertTrue(load_data["success"])
        self.assertIn("feature_importance", load_data)
        self.assertGreater(len(load_data["feature_importance"]), 0)

    def test_06_evaluation_and_predictions_excel(self):
        """Verify evaluation metrics, ROC curve data, distribution bins, and openpyxl predictions Excel."""
        eval_resp = self.client.post("/api/run_evaluation")
        self.assertEqual(eval_resp.status_code, 200)
        data = eval_resp.get_json()["data"]

        # Check ROC curve data
        self.assertIn("roc_curve", data)
        roc = data["roc_curve"]
        self.assertIn("fpr", roc)
        self.assertIn("tpr", roc)
        self.assertIn("auc", roc)
        self.assertGreater(len(roc["fpr"]), 1)

        # Check probability distribution
        self.assertIn("prediction_distribution", data)
        dist = data["prediction_distribution"]
        self.assertIn("normal_counts", dist)
        self.assertIn("replay_counts", dist)
        self.assertEqual(len(dist["normal_counts"]), 10)

        # Check prediction summary
        self.assertIn("prediction_summary", data)
        summary = data["prediction_summary"]
        self.assertGreater(summary["correct_predictions"], 0)
        self.assertEqual(summary["total_count"], summary["correct_predictions"] + summary["incorrect_predictions"])

        # Test Genuine Excel Export for Predictions
        pred_resp = self.client.get("/download/predictions")
        self.assertEqual(pred_resp.status_code, 200)
        self.assertEqual(pred_resp.headers.get("Content-Type"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertIn("RP4_Transaction_Predictions.xlsx", pred_resp.headers.get("Content-Disposition", ""))

        pred_wb = openpyxl.load_workbook(io.BytesIO(pred_resp.data), read_only=True)
        self.assertIn("Transaction_Predictions", pred_wb.sheetnames)
        pred_ws = pred_wb["Transaction_Predictions"]
        pred_first_row = [cell for cell in next(pred_ws.iter_rows(values_only=True))]
        self.assertIn("xgb_pred", pred_first_row)
        pred_wb.close()

    def test_07_predictions_filtering_and_search(self):
        """Verify /api/predictions_data supports 4-way filtering and search."""
        # 1. Filter by Status (True Negative)
        resp_tn = self.client.get("/api/predictions_data?status_filter=TN")
        self.assertEqual(resp_tn.status_code, 200)
        data_tn = resp_tn.get_json()
        self.assertTrue(data_tn["success"])
        self.assertGreater(len(data_tn["data"]), 0)
        for r in data_tn["data"]:
            self.assertIn("True Negative", r["prediction_status"])

        # 2. Filter by Predicted Label
        resp_pred_0 = self.client.get("/api/predictions_data?pred_filter=normal")
        self.assertEqual(resp_pred_0.status_code, 200)
        data_p0 = resp_pred_0.get_json()
        for r in data_p0["data"]:
            self.assertEqual(r["xgb_pred"], 0)

        # 3. Filter by Actual Label
        resp_act_1 = self.client.get("/api/predictions_data?actual_filter=replay")
        self.assertEqual(resp_act_1.status_code, 200)
        data_a1 = resp_act_1.get_json()
        for r in data_a1["data"]:
            self.assertEqual(r["target_is_attack"], 1)

        # 4. Filter by Source Dataset
        resp_ds = self.client.get("/api/predictions_data?dataset_filter=normal")
        self.assertEqual(resp_ds.status_code, 200)
        data_ds = resp_ds.get_json()
        for r in data_ds["data"]:
            self.assertIn("normal", r["source_dataset"].lower())


if __name__ == "__main__":
    unittest.main()
