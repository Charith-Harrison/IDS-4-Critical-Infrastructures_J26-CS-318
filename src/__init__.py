"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Research package initialization.
"""

from src.data_loader import load_datasets
from src.data_validation import audit_dataset_integrity
from src.transaction_context import reconstruct_transactions
from src.split_data import create_train_test_split
from src.feature_engineering import extract_features, MODEL_FEATURE_COLUMNS, FEATURE_DICTIONARY
from src.baseline import ProtocolRuleBaseline
from src.train_model import train_xgboost_model
from src.predictor import ReplayPredictor
from src.evaluate_model import evaluate_test_partition

__all__ = [
    "load_datasets",
    "audit_dataset_integrity",
    "reconstruct_transactions",
    "create_train_test_split",
    "extract_features",
    "MODEL_FEATURE_COLUMNS",
    "FEATURE_DICTIONARY",
    "ProtocolRuleBaseline",
    "train_xgboost_model",
    "ReplayPredictor",
    "evaluate_test_partition"
]
