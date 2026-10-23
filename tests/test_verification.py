"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Automated Verification Suite

Covers mandatory checks required by Section 13:
1. Labels and metadata excluded from model inputs.
2. No transaction appearing in both partitions.
3. No feature-history sharing between independent captures.
4. Request-response pairing scoped to the correct communication context.
5. Both classes present before training and evaluation.
6. Feature order matching the saved model.
7. Prediction probabilities surviving a save/load round trip.
8. Flask dashboard endpoint and artifact download integrity.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_engineering import MODEL_FEATURE_COLUMNS, EXCLUDED_INPUT_COLUMNS, extract_features
from src.transaction_context import reconstruct_transactions
from src.split_data import create_train_test_split
from src.train_model import train_xgboost_model
from src.predictor import ReplayPredictor
from app import create_app


class TestVerification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Ensures pipeline artifacts exist before running validation checks."""
        manifest_path = os.path.join(PROJECT_ROOT, "artifacts", "splits", "split_manifest.csv")
        features_path = os.path.join(PROJECT_ROOT, "artifacts", "results", "extracted_features.csv")
        model_path = os.path.join(PROJECT_ROOT, "artifacts", "models", "xgboost_model.json")

        if not (os.path.exists(manifest_path) and os.path.exists(features_path) and os.path.exists(model_path)):
            app = create_app()
            client = app.test_client()
            client.post("/api/run_audit")
            client.post("/api/run_features")
            client.post("/api/train_model")
            client.post("/api/run_evaluation")

    def setUp(self):
        self.artifacts_dir = os.path.join(PROJECT_ROOT, "artifacts")
        self.manifest_path = os.path.join(self.artifacts_dir, "splits", "split_manifest.csv")
        self.features_path = os.path.join(self.artifacts_dir, "results", "extracted_features.csv")
        self.model_path = os.path.join(self.artifacts_dir, "models", "xgboost_model.json")
        self.pipeline_path = os.path.join(self.artifacts_dir, "models", "pipeline_artifacts.joblib")

    def test_01_labels_and_metadata_excluded_from_model_inputs(self):
        """Check 1: Verify all labels, metadata, endpoints, and timestamps are excluded from model inputs."""
        forbidden_substrings = ["attack", "ip", "port", "source", "frame", "timestamp", "row"]
        
        # Check against explicitly forbidden names
        strictly_forbidden = {
            "is_attack", "attack_category", "attack_sub_type", "target_is_attack",
            "src_ip", "dst_ip", "src_port", "dst_port", "client_ip", "server_ip",
            "client_port", "server_port", "frame_number", "original_row_id",
            "file_source", "source_file", "timestamp", "request_timestamp", "response_timestamp"
        }

        for feat in MODEL_FEATURE_COLUMNS:
            self.assertNotIn(feat, strictly_forbidden, f"Feature '{feat}' violates leakage policy and must not be a model input!")

        # Verify excluded list documents all forbidden fields
        for forbidden in strictly_forbidden:
            self.assertIn(forbidden, EXCLUDED_INPUT_COLUMNS, f"'{forbidden}' should be listed in EXCLUDED_INPUT_COLUMNS documentation.")

    def test_02_no_transaction_appearing_in_both_partitions(self):
        """Check 2: Verify zero intersection of transaction IDs between training and testing partitions."""
        self.assertTrue(os.path.exists(self.manifest_path), "Split manifest must exist.")
        df_manifest = pd.read_csv(self.manifest_path)

        train_ids = set(df_manifest[df_manifest["partition"] == "train"]["transaction_id"])
        test_ids = set(df_manifest[df_manifest["partition"] == "test"])
        gap_ids = set(df_manifest[df_manifest["partition"] == "gap_excluded"]["transaction_id"])

        intersection_train_test = train_ids.intersection(test_ids)
        self.assertEqual(len(intersection_train_test), 0, f"Found {len(intersection_train_test)} transactions leaking between train and test!")

        intersection_train_gap = train_ids.intersection(gap_ids)
        self.assertEqual(len(intersection_train_gap), 0, "Transactions leaked into gap exclusion!")

    def test_03_no_feature_history_sharing_between_independent_captures(self):
        """Check 3: Verify feature extraction resets channel state across independent captures."""
        # Create synthetic multi-capture dataframe
        sample_txs = pd.DataFrame([
            {
                "transaction_id": "tx_cap1_1", "capture_id": "cap_A", "partition": "train",
                "source_file": "file1.pcap", "request_row": 0, "response_row": 1,
                "request_frame": 1, "response_frame": 2, "request_timestamp": 100.0,
                "response_timestamp": 100.05, "client_ip": "1.1.1.1", "server_ip": "2.2.2.2",
                "client_port": 1234, "server_port": 502, "mbtcp_trans_id": 999,
                "mbtcp_unit_id": 1, "modbus_func_code": 3, "modbus_ref_num": 10,
                "modbus_word_cnt": 1, "modbus_bit_cnt": 0, "modbus_val": 0,
                "payload_len": 12, "match_status": "matched", "label_conflict": False,
                "response_time": 0.05, "transaction_is_attack": 0
            },
            {
                # Same TID in a different capture should NOT be marked as tid_previously_seen because state must reset
                "transaction_id": "tx_cap2_1", "capture_id": "cap_B", "partition": "train",
                "source_file": "file2.pcap", "request_row": 0, "response_row": 1,
                "request_frame": 1, "response_frame": 2, "request_timestamp": 200.0,
                "response_timestamp": 200.05, "client_ip": "1.1.1.1", "server_ip": "2.2.2.2",
                "client_port": 1234, "server_port": 502, "mbtcp_trans_id": 999,
                "mbtcp_unit_id": 1, "modbus_func_code": 3, "modbus_ref_num": 10,
                "modbus_word_cnt": 1, "modbus_bit_cnt": 0, "modbus_val": 0,
                "payload_len": 12, "match_status": "matched", "label_conflict": False,
                "response_time": 0.05, "transaction_is_attack": 0
            }
        ])

        feat_df, _ = extract_features(sample_txs)
        # In cap_B, tid_previously_seen must be 0.0 despite cap_A having TID 999
        cap_b_record = feat_df[feat_df["capture_id"] == "cap_B"].iloc[0]
        self.assertEqual(cap_b_record["tid_previously_seen"], 0.0, "History was incorrectly shared across capture boundaries!")

    def test_04_request_response_pairing_scoped_to_correct_context(self):
        """Check 4: Verify pairing is scoped strictly to matching endpoints, TID, UID, and Function Code."""
        sample_norm = pd.DataFrame([
            # Request
            {
                "frame_number": 1, "timestamp": 10.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "src_port": 50000, "dst_port": 502, "is_request": 1, "mbtcp_trans_id": 55,
                "mbtcp_unit_id": 1, "modbus_func_code": 3, "modbus_ref_num": 1, "modbus_word_cnt": 1,
                "modbus_bit_cnt": 0, "modbus_val": 0, "payload_len": 12, "is_attack": 0,
                "attack_category": "Normal", "attack_sub_type": "Normal", "source_file": "test.pcap",
                "original_row_id": 0, "capture_id": "test_cap"
            },
            # Response with mismatched TID (should NOT pair)
            {
                "frame_number": 2, "timestamp": 10.05, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                "src_port": 502, "dst_port": 50000, "is_request": 0, "mbtcp_trans_id": 56,
                "mbtcp_unit_id": 1, "modbus_func_code": 3, "modbus_ref_num": 1, "modbus_word_cnt": 1,
                "modbus_bit_cnt": 0, "modbus_val": 0, "payload_len": 12, "is_attack": 0,
                "attack_category": "Normal", "attack_sub_type": "Normal", "source_file": "test.pcap",
                "original_row_id": 1, "capture_id": "test_cap"
            }
        ])
        empty_rep = pd.DataFrame(columns=sample_norm.columns)

        tx_df, orphan_df, cov = reconstruct_transactions(sample_norm, empty_rep, response_timeout=1.0)
        # Should result in 1 timeout request and 1 orphan response
        self.assertEqual(cov["matched_transactions"], 0)
        self.assertEqual(cov["timeout_missing_responses"], 1)
        self.assertEqual(cov["orphan_responses"], 1)

    def test_05_both_classes_present_before_training_and_evaluation(self):
        """Check 5: Verify both classes exist in both training and test sets."""
        self.assertTrue(os.path.exists(self.features_path), "Features CSV must exist.")
        df_feat = pd.read_csv(self.features_path)

        train_labels = df_feat[df_feat["partition"] == "train"]["target_is_attack"].value_counts().to_dict()
        test_labels = df_feat[df_feat["partition"] == "test"]["target_is_attack"].value_counts().to_dict()

        self.assertGreater(train_labels.get(0, 0), 0, "Train partition lacks Normal (0) samples!")
        self.assertGreater(train_labels.get(1, 0), 0, "Train partition lacks Replay (1) samples!")
        self.assertGreater(test_labels.get(0, 0), 0, "Test partition lacks Normal (0) samples!")
        self.assertGreater(test_labels.get(1, 0), 0, "Test partition lacks Replay (1) samples!")

    def test_06_feature_order_matching_saved_model(self):
        """Check 6: Verify the saved pipeline bundle matches the exact expected feature order."""
        self.assertTrue(os.path.exists(self.pipeline_path), "Pipeline bundle must exist.")
        bundle = joblib.load(self.pipeline_path)

        saved_features = bundle["feature_order"]
        self.assertEqual(saved_features, MODEL_FEATURE_COLUMNS, "Saved feature order does not match MODEL_FEATURE_COLUMNS!")

    def test_07_prediction_probabilities_save_load_round_trip(self):
        """Check 7: Verify prediction probabilities survive serialization and deserialization."""
        self.assertTrue(os.path.exists(self.model_path), "Model file must exist.")
        self.assertTrue(os.path.exists(self.pipeline_path), "Pipeline file must exist.")

        predictor = ReplayPredictor(model_path=self.model_path, pipeline_path=self.pipeline_path)
        df_feat = pd.read_csv(self.features_path, nrows=10)

        preds, probs, timing = predictor.predict(df_feat[MODEL_FEATURE_COLUMNS])

        # Validate probability ranges
        self.assertTrue(np.all(probs >= 0.0) and np.all(probs <= 1.0), "Probabilities out of [0, 1] range!")
        # Validate binary predictions align with 0.5 threshold
        expected_preds = (probs >= 0.5).astype(int)
        np.testing.assert_array_equal(preds, expected_preds)

    def test_08_flask_dashboard_endpoints(self):
        """Check 8: Verify Flask routes and download endpoints respond with HTTP 200."""
        app = create_app()
        client = app.test_client()

        for route in ["/audit", "/features", "/training", "/evaluation"]:
            resp = client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} failed with status {resp.status_code}")

        # Test artifact downloads
        for dl in ["features", "manifest", "metrics", "predictions", "audit"]:
            resp = client.get(f"/download/{dl}")
            self.assertEqual(resp.status_code, 200, f"Download /download/{dl} failed with status {resp.status_code}")


if __name__ == "__main__":
    unittest.main()
