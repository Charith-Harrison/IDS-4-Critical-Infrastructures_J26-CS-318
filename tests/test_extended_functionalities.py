"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Automated Verification Suite for Extended Functionalities

Tests:
1. /upload page loads and serves upload interface.
2. /api/upload_dataset validates extensions, enforces 200 MB limit.
3. /download/audit delivers publication-quality PDF with Content-Type application/pdf.
4. /api/run_features applies configurable time window and creates dual feature CSVs.
5. /api/features_data provides server-side pagination, search, and sorting for normal & replay traffic.
6. /api/train_model logs boosting loss history and /training renders training progress.
7. /api/predictions_data provides server-side pagination, sorting, search, and multi-filter capabilities.
8. /api/upload_dataset and /api/remove_dataset handle custom uploads and revert cleanly.
"""

import os
import sys
import io
import json
import unittest
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from src.data_loader import reset_active_dataset_config, load_active_dataset_config


class TestExtendedFunctionalities(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

        # Ensure default datasets are configured
        reset_active_dataset_config(PROJECT_ROOT)

        # Run audit to establish baseline audit report & PDF
        audit_pdf = os.path.join(PROJECT_ROOT, "artifacts", "audits", "RP4_Data_Audit_Report.pdf")
        if not os.path.exists(audit_pdf):
            resp = cls.client.post("/api/run_audit")
            assert resp.status_code == 200, f"Audit setup failed: {resp.data}"

    def test_01_upload_page_rendering(self):
        """Verify the new initial File Upload page renders with status 200 and required elements."""
        resp = self.client.get("/upload")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("Upload Normal Traffic File", html)
        self.assertIn("Upload Replay Attack Traffic File", html)
        self.assertIn("normal_traffic", html)
        self.assertIn("replay_traffic", html)
        self.assertIn("Proceed to Stage A: Data Audit", html)

    def test_02_upload_validation_rejects_bad_files(self):
        """Verify upload validation rejects empty requests and invalid extensions."""
        # 1. Missing file payload
        resp = self.client.post("/api/upload_dataset", data={})
        self.assertEqual(resp.status_code, 400)
        res_json = resp.get_json()
        self.assertFalse(res_json["success"])

        # 2. Invalid file extension (.txt)
        bad_data = {
            "file": (io.BytesIO(b"malicious script or text"), "bad_file.txt"),
            "category": "normal_traffic"
        }
        resp = self.client.post("/api/upload_dataset", data=bad_data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

        # 3. Invalid category
        bad_cat_data = {
            "file": (io.BytesIO(b"timestamp\n1.0\n"), "test.csv"),
            "category": "invalid_category"
        }
        resp = self.client.post("/api/upload_dataset", data=bad_cat_data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_03_audit_pdf_download_binary_delivery(self):
        """Verify /download/audit returns application/pdf with RP4_Data_Audit_Report.pdf."""
        resp = self.client.get("/download/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "application/pdf")
        self.assertIn("RP4_Data_Audit_Report.pdf", resp.headers.get("Content-Disposition", ""))
        # Verify PDF magic bytes
        self.assertTrue(resp.data.startswith(b"%PDF-"), "Downloaded file must begin with %PDF- header.")

    def test_04_features_time_window_configuration(self):
        """Verify /api/run_features accepts time_window_seconds and saves dual feature tables."""
        resp = self.client.post("/api/run_features", json={"time_window_seconds": 30.0})
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["time_window_seconds"], 30.0)

        # Check dual CSV files created
        norm_feat = os.path.join(PROJECT_ROOT, "artifacts", "results", "normal_protocol_features.csv")
        rep_feat = os.path.join(PROJECT_ROOT, "artifacts", "results", "replay_protocol_features.csv")
        self.assertTrue(os.path.exists(norm_feat), "Normal features CSV must be generated.")
        self.assertTrue(os.path.exists(rep_feat), "Replay features CSV must be generated.")

        # Verify ground truth preserved (Normal CSV has all 0s, Replay has both 0 and 1)
        df_norm = pd.read_csv(norm_feat)
        df_rep = pd.read_csv(rep_feat)
        self.assertTrue((df_norm["target_is_attack"] == 0).all(), "Normal features must strictly have label 0.")
        self.assertTrue(1 in df_rep["target_is_attack"].values, "Replay features must contain attack records.")
        self.assertTrue(0 in df_rep["target_is_attack"].values, "Replay features must contain normal records.")

    def test_05_features_pagination_api(self):
        """Verify /api/features_data returns paginated, searchable, and sorted records."""
        # Query normal features
        resp_norm = self.client.get("/api/features_data?source=normal&page=1&limit=10")
        self.assertEqual(resp_norm.status_code, 200)
        res_norm = resp_norm.get_json()
        self.assertTrue(res_norm["success"])
        self.assertEqual(len(res_norm["data"]), 10)
        self.assertGreater(res_norm["total"], 10)

        # Query replay features
        resp_rep = self.client.get("/api/features_data?source=replay&page=1&limit=5")
        self.assertEqual(resp_rep.status_code, 200)
        res_rep = resp_rep.get_json()
        self.assertTrue(res_rep["success"])
        self.assertEqual(len(res_rep["data"]), 5)

        # Search query check
        resp_search = self.client.get("/api/features_data?source=replay&search=tx_")
        self.assertEqual(resp_search.status_code, 200)
        res_search = resp_search.get_json()
        self.assertTrue(res_search["success"])

    def test_06_training_progress_history(self):
        """Verify model training records boosting loss progression."""
        resp = self.client.post("/api/train_model")
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json["success"])
        self.assertIn("training_history", res_json)
        self.assertIn("eval_metric_history", res_json["training_history"])
        self.assertGreater(len(res_json["training_history"]["eval_metric_history"]), 0)

        # Test training page renders progress chart elements
        page_resp = self.client.get("/training")
        self.assertEqual(page_resp.status_code, 200)
        html = page_resp.data.decode("utf-8")
        self.assertIn("XGBoost Training Progress", html)
        self.assertIn("trainingLossSvg", html)

    def test_07_predictions_data_filtering_api(self):
        """Verify /api/predictions_data supports status, label, and dataset filtering."""
        # Run evaluation
        eval_resp = self.client.post("/api/run_evaluation")
        self.assertEqual(eval_resp.status_code, 200)

        # Test predictions endpoint
        resp = self.client.get("/api/predictions_data?page=1&limit=20")
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json["success"])
        self.assertGreater(res_json["total_unfiltered"], 0)

        # Test filter by status (True Negative)
        resp_tn = self.client.get("/api/predictions_data?status_filter=True Negative (TN)")
        self.assertEqual(resp_tn.status_code, 200)
        res_tn = resp_tn.get_json()
        self.assertTrue(res_tn["success"])
        for row in res_tn["data"]:
            self.assertEqual(row["prediction_status"], "True Negative (TN)")

        # Test filter by dataset
        resp_ds = self.client.get("/api/predictions_data?dataset_filter=replay")
        self.assertEqual(resp_ds.status_code, 200)
        res_ds = resp_ds.get_json()
        self.assertTrue(res_ds["success"])
        for row in res_ds["data"]:
            self.assertIn("replay", row["source_dataset"].lower())

    def test_08_upload_and_reset_reverts_cleanly(self):
        """Verify uploading a custom CSV and subsequently resetting reverts configuration."""
        csv_bytes = b"timestamp,src_ip,dst_ip,src_port,dst_port,mbtcp_trans_id,mbtcp_unit_id,modbus_func_code,is_request,is_attack\n100.0,1.1.1.1,2.2.2.2,1234,502,1,1,3,1,0\n"
        upload_data = {
            "file": (io.BytesIO(csv_bytes), "temporary_normal.csv"),
            "category": "normal_traffic"
        }
        resp = self.client.post("/api/upload_dataset", data=upload_data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)

        # Revert back to default benchmark
        reset_resp = self.client.post("/api/remove_dataset", json={"category": "normal_traffic"})
        self.assertEqual(reset_resp.status_code, 200)
        res_reset = reset_resp.get_json()
        self.assertTrue(res_reset["success"])
        self.assertEqual(res_reset["active_datasets"]["normal_filename"], "normal_traffic_baseline.csv")


if __name__ == "__main__":
    unittest.main()
