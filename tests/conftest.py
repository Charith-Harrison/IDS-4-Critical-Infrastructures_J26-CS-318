# Create small synthetic fixtures for software tests, not research measurements.
"""Small synthetic protocol fixtures for software checks, never reported as research data."""

import copy

import numpy as np
import pandas as pd
import pytest

from src.event_builder import build_events
from src.preprocessing import preprocess_frame
from src.utils import load_config


# Create an isolated test configuration instead of changing the real project settings.
@pytest.fixture
def cfg():
    config = copy.deepcopy(load_config())
    config["training"]["n_estimators"] = 8
    config["training"]["n_jobs"] = 1
    config["training"]["candidates"] = [
        {"max_depth": 4, "min_samples_leaf": 1, "max_features": "sqrt", "class_weight": "balanced"}
    ]
    config["features"]["windows"] = [3, 5, 10]
    return config


# Build a small synthetic CSV-style fixture for software tests.
@pytest.fixture
def raw():
    n = 48
    return pd.DataFrame(
        {
            "frame_number": np.arange(n),
            "timestamp": 1700000000 + np.arange(n) * 0.1,
            "src_ip": ["client" if i % 2 == 0 else "server" for i in range(n)],
            "dst_ip": ["server" if i % 2 == 0 else "client" for i in range(n)],
            "src_port": [1200 if i % 2 == 0 else 502 for i in range(n)],
            "dst_port": [502 if i % 2 == 0 else 1200 for i in range(n)],
            "mbtcp_trans_id": np.arange(n) // 2,
            "mbtcp_unit_id": 1,
            "modbus_func_code": [3 if i < 24 else 5 for i in range(n)],
            "modbus_ref_num": np.arange(n) % 4,
            "modbus_val": np.arange(n) % 7,
            "modbus_word_cnt": 1,
            "modbus_bit_cnt": 0,
            "modbus_byte_cnt": 0,
            "is_request": [int(i % 2 == 0) for i in range(n)],
            "is_exception": 0,
            "attack_category": ["Normal" if i < 24 else "Command_Response_Injection" for i in range(n)],
            "file_source": "software-test-capture",
        }
    )


# Prepare the synthetic fixture as events for downstream software checks.
@pytest.fixture
def events(raw, cfg):
    return build_events(preprocess_frame(raw, cfg, "fixture.csv"), cfg)
