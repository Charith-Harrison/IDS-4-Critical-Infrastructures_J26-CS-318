"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/feature_engineering.py

Purpose:
    Extracts protocol-aware, sequence, and transaction-consistency features from
    reconstructed Modbus/TCP transactions.
    Enforces strict partition and capture isolation: feature-history state is
    reset between independent captures and evaluation partitions.

Viva Explanation:
    - Replay attacks violate transaction sequence consistency. When an attacker replays
      previously captured Modbus packets, the Transaction ID (TID) jumps, repeats out-of-order,
      or appears with an irregular inter-arrival cadence.
    - We extract features scoped to each communication channel (client_ip, server_ip, unit_id):
        1. Sequence features: TID delta, bounded TID recurrence (tid_previously_seen).
        2. Timing features: Request inter-arrival time (IAT), response latency.
        3. Observed-command fingerprint: (unit_id, func_code, ref_num, word_cnt, bit_cnt, val).
           NOTE: This is NOT a raw-payload hash (raw bytes are not in the CSV). It is a
           structured protocol-level command fingerprint.
        4. Repetition & Frequency: Duplicate command count and frequency within a trailing window.
        5. Transaction outcome: Match status, timeout / missing-response status, latency missingness.
    - Excluded from model inputs:
        All raw IP addresses, TCP ports, frame numbers, absolute timestamps, filenames,
        and attack labels are strictly excluded to prevent shortcut learning.
"""

from collections import deque
import json
import os
from typing import Tuple, Dict, Any, List, Optional
import pandas as pd
import numpy as np


# The verified list of features used as inputs to the models
MODEL_FEATURE_COLUMNS = [
    "trans_id_delta",
    "trans_id_raw_diff",
    "tid_previously_seen",
    "request_iat",
    "time_since_identical_cmd",
    "is_repeated_command",
    "repeated_cmd_count_window",
    "duplicate_cmd_freq",
    "outstanding_requests",
    "modbus_func_code",
    "mbtcp_unit_id",
    "modbus_ref_num",
    "modbus_word_cnt",
    "modbus_bit_cnt",
    "modbus_val",
    "payload_len",
    "is_matched",
    "is_timeout",
    "is_ambiguous",
    "response_latency",
    "has_response_latency"
]

EXCLUDED_INPUT_COLUMNS = [
    "is_attack",
    "attack_category",
    "attack_sub_type",
    "target_is_attack",
    "source_file",
    "dataset_category",
    "file_source",
    "capture_id",
    "partition",
    "split_method",
    "transaction_id",
    "request_row",
    "response_row",
    "request_frame",
    "response_frame",
    "request_timestamp",
    "response_timestamp",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "frame_number",
    "original_row_id",
    "client_ip",
    "server_ip",
    "client_port",
    "server_port",
    "label_conflict"
]

FEATURE_DICTIONARY = {
    "trans_id_delta": {
        "type": "float",
        "description": "Modulo-65536 difference between current request TID and previous request TID in this communication channel. Normal Modbus sequentially increments by 1.",
        "supported_by": "MBAP Header mbtcp_trans_id",
        "relevance": "Replays often exhibit abrupt TID jumps or backwards wraps compared to the active session."
    },
    "trans_id_raw_diff": {
        "type": "float",
        "description": "Unbounded numerical difference (curr_tid - prev_tid) in communication channel.",
        "supported_by": "MBAP Header mbtcp_trans_id",
        "relevance": "Captures raw positive or negative jumps when replayed bursts disrupt monotonic sequence."
    },
    "tid_previously_seen": {
        "type": "binary (0.0 or 1.0)",
        "description": "1.0 if current TID was observed in the preceding bounded history window (default 100 transactions) in this channel, else 0.0.",
        "supported_by": "Channel TID history deque",
        "relevance": "Direct indicator of TID reuse within a short operational timeframe."
    },
    "request_iat": {
        "type": "float (seconds)",
        "description": "Inter-arrival time between this request and the preceding request in this communication channel.",
        "supported_by": "Packet capture timestamps",
        "relevance": "Attacker burst injection or replay timing deviations disrupt normal periodic polling rates."
    },
    "time_since_identical_cmd": {
        "type": "float (seconds)",
        "description": "Elapsed seconds since the exact same observed-command fingerprint was sent in this channel (capped at 3600.0s sentinel if not yet observed).",
        "supported_by": "Observed-command fingerprint history",
        "relevance": "Measures polling periodicity and highlights burst repetition of replayed commands."
    },
    "is_repeated_command": {
        "type": "binary (0.0 or 1.0)",
        "description": "1.0 if this observed-command fingerprint was previously observed in the channel history, else 0.0.",
        "supported_by": "Observed-command fingerprint cache",
        "relevance": "Contextual indicator that a command has prior presence in the capture."
    },
    "repeated_cmd_count_window": {
        "type": "float",
        "description": "Count of identical observed-command fingerprints occurring in the trailing time window (default 5.0 seconds).",
        "supported_by": "Trailing time-window queue",
        "relevance": "Captures anomalous clustering of repeated commands indicative of rapid replay."
    },
    "duplicate_cmd_freq": {
        "type": "float (events/sec)",
        "description": "Rate of duplicate commands per second within the trailing time window.",
        "supported_by": "Trailing time-window queue",
        "relevance": "Normalizes command repetition across time."
    },
    "outstanding_requests": {
        "type": "float",
        "description": "Number of currently active, pending requests in the channel awaiting response when this request was sent.",
        "supported_by": "Transaction context tracker",
        "relevance": "Replay floods often generate backlog without corresponding responses."
    },
    "modbus_func_code": {
        "type": "float (integer code)",
        "description": "Modbus Function Code (e.g., 1=Read Coils, 3=Read Holding Registers, 4=Read Input Registers).",
        "supported_by": "Modbus PDU Header",
        "relevance": "Specifies command type and operation semantics."
    },
    "mbtcp_unit_id": {
        "type": "float",
        "description": "Modbus Unit ID / Slave address in MBAP header.",
        "supported_by": "MBAP Header",
        "relevance": "Target device sub-address."
    },
    "modbus_ref_num": {
        "type": "float",
        "description": "Starting register reference / memory address queried by the command.",
        "supported_by": "Modbus PDU request payload",
        "relevance": "Industrial register target."
    },
    "modbus_word_cnt": {
        "type": "float",
        "description": "Number of 16-bit words requested.",
        "supported_by": "Modbus PDU request payload",
        "relevance": "Quantity of registers requested."
    },
    "modbus_bit_cnt": {
        "type": "float",
        "description": "Number of discrete bits requested.",
        "supported_by": "Modbus PDU request payload",
        "relevance": "Quantity of coil/discrete inputs requested."
    },
    "modbus_val": {
        "type": "float",
        "description": "Modbus write value or single parameter.",
        "supported_by": "Modbus PDU request payload",
        "relevance": "Command parameter value."
    },
    "payload_len": {
        "type": "float (bytes)",
        "description": "Total Modbus TCP application payload length in bytes.",
        "supported_by": "TCP frame headers",
        "relevance": "PDU size consistency."
    },
    "is_matched": {
        "type": "binary (0.0 or 1.0)",
        "description": "1.0 if a matching server response was received within timeout, 0.0 otherwise.",
        "supported_by": "Transaction reconstruction pairing",
        "relevance": "Validates whether the transaction was acknowledged by an active server."
    },
    "is_timeout": {
        "type": "binary (0.0 or 1.0)",
        "description": "1.0 if the transaction timed out with missing response, 0.0 otherwise.",
        "supported_by": "Transaction reconstruction pairing",
        "relevance": "Replays injected into closed or invalid sessions often produce no server response."
    },
    "is_ambiguous": {
        "type": "binary (0.0 or 1.0)",
        "description": "1.0 if multiple identical outstanding requests matched the response, 0.0 otherwise.",
        "supported_by": "Transaction reconstruction pairing",
        "relevance": "Identifies transaction collision caused by replayed duplicate TIDs."
    },
    "response_latency": {
        "type": "float (seconds)",
        "description": "Round-trip time (response_time - request_time) for matched transactions, or imputed timeout sentinel if missing.",
        "supported_by": "Reconstructed transaction timestamps",
        "relevance": "Legitimate Modbus responses exhibit consistent low server latency."
    },
    "has_response_latency": {
        "type": "binary (0.0 or 1.0)",
        "description": "Missingness indicator: 1.0 if response_latency is genuinely observed, 0.0 if imputed due to timeout.",
        "supported_by": "Missing value indicator for latency",
        "relevance": "Allows the tree model to distinguish genuine low-latency responses from imputed timeouts."
    }
}


def extract_features(
    tx_df: pd.DataFrame,
    history_window_size: int = 100,
    trailing_time_window_seconds: float = 5.0,
    max_unseen_time_sentinel: float = 3600.0,
    features_csv_path: Optional[str] = None,
    dictionary_json_path: Optional[str] = None
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Extracts protocol-aware consistency features with strict isolation per partition
    and per capture group.

    Parameters:
        tx_df: Reconstructed transactions DataFrame with 'partition' column
        history_window_size: Maximum previous TIDs remembered in channel history
        trailing_time_window_seconds: Trailing window duration for command frequencies
        max_unseen_time_sentinel: Sentinel value for elapsed time when command is first observed
        features_csv_path: Optional destination to save full feature CSV
        dictionary_json_path: Optional destination to save feature dictionary JSON

    Returns:
        Tuple of (feat_df, feature_summary)
    """
    feature_records: List[Dict[str, Any]] = []

    # Process per partition and per capture to prevent any state leakage across boundaries
    for (part, cap_id), grp in tx_df.groupby(["partition", "capture_id"], sort=False):
        grp = grp.sort_values(by="request_timestamp").reset_index(drop=True)

        # Communication channel state: (client_ip, server_ip, mbtcp_unit_id)
        channel_states: Dict[tuple, Dict[str, Any]] = {}

        for _, row in grp.iterrows():
            ch_key = (row["client_ip"], row["server_ip"], row["mbtcp_unit_id"])
            if ch_key not in channel_states:
                channel_states[ch_key] = {
                    "prev_trans_id": None,
                    "tid_history": deque(maxlen=history_window_size),
                    "prev_req_time": None,
                    "cmd_history": deque(), # (timestamp, cmd_fingerprint)
                    "last_seen_cmd_time": {}, # cmd_fingerprint -> timestamp
                    "outstanding_count": 0
                }
            st = channel_states[ch_key]

            curr_tid = int(row["mbtcp_trans_id"])
            curr_time = float(row["request_timestamp"])

            # Observed-command fingerprint constructed from verified protocol fields:
            # (unit_id, func_code, ref_num, word_cnt, bit_cnt, val)
            cmd_fp = (
                int(row["mbtcp_unit_id"]),
                int(row["modbus_func_code"]),
                float(row["modbus_ref_num"]),
                float(row["modbus_word_cnt"]),
                float(row["modbus_bit_cnt"]),
                float(row["modbus_val"])
            )

            # 1. Transaction-ID delta within communication context
            if st["prev_trans_id"] is not None:
                trans_id_delta = float((curr_tid - st["prev_trans_id"]) % 65536)
                trans_id_raw_diff = float(curr_tid - st["prev_trans_id"])
            else:
                trans_id_delta = 1.0 # Default normal increment for first transaction
                trans_id_raw_diff = 1.0

            # 2. TID previously observed in bounded history window
            tid_previously_seen = 1.0 if curr_tid in st["tid_history"] else 0.0

            # 3. Request inter-arrival time
            if st["prev_req_time"] is not None:
                iat = max(0.0, curr_time - st["prev_req_time"])
            else:
                iat = 0.0

            # 4. Time since identical observed command
            if cmd_fp in st["last_seen_cmd_time"]:
                time_since_identical_cmd = max(0.0, curr_time - st["last_seen_cmd_time"][cmd_fp])
                is_repeated_command = 1.0
            else:
                time_since_identical_cmd = max_unseen_time_sentinel
                is_repeated_command = 0.0

            # Clean up trailing time-window
            while st["cmd_history"] and (curr_time - st["cmd_history"][0][0]) > trailing_time_window_seconds:
                st["cmd_history"].popleft()

            # Count identical commands in trailing time window
            repeated_cmd_count_window = float(sum(1 for (t, fp) in st["cmd_history"] if fp == cmd_fp))
            duplicate_cmd_freq = repeated_cmd_count_window / max(0.001, trailing_time_window_seconds)

            # 5. Outstanding request count before this request
            outstanding_count = float(st["outstanding_count"])

            # 6. Response latency and match status indicators
            is_matched = 1.0 if row["match_status"] == "matched" else 0.0
            is_timeout = 1.0 if row["match_status"] == "timeout_missing_response" else 0.0
            is_ambiguous = 1.0 if row["match_status"] == "ambiguous_match" else 0.0

            if pd.notnull(row["response_time"]):
                response_latency = float(row["response_time"])
                has_response_latency = 1.0
            else:
                response_latency = 1.0 # Imputed with timeout duration
                has_response_latency = 0.0

            # Update channel state
            st["prev_trans_id"] = curr_tid
            st["tid_history"].append(curr_tid)
            st["prev_req_time"] = curr_time
            st["last_seen_cmd_time"][cmd_fp] = curr_time
            st["cmd_history"].append((curr_time, cmd_fp))

            if row["match_status"] == "timeout_missing_response":
                st["outstanding_count"] += 1
            else:
                st["outstanding_count"] = max(0, st["outstanding_count"] - 1)

            record = {
                # Metadata (strictly excluded from model inputs)
                "transaction_id": row["transaction_id"],
                "partition": part,
                "capture_id": cap_id,
                "source_file": row["source_file"],
                "dataset_category": str(row.get("dataset_category", "normal_traffic" if "normal" in str(row["source_file"]).lower() else "replay_traffic")),
                "request_row": row["request_row"],
                "response_row": row["response_row"],
                "request_frame": row["request_frame"],
                "response_frame": row["response_frame"],
                "request_timestamp": row["request_timestamp"],
                "response_timestamp": row["response_timestamp"],
                "client_ip": row["client_ip"],
                "server_ip": row["server_ip"],
                "client_port": row["client_port"],
                "server_port": row["server_port"],
                "label_conflict": row["label_conflict"],
                "target_is_attack": int(row["transaction_is_attack"]),

                # Model input features
                "trans_id_delta": trans_id_delta,
                "trans_id_raw_diff": trans_id_raw_diff,
                "tid_previously_seen": tid_previously_seen,
                "request_iat": iat,
                "time_since_identical_cmd": time_since_identical_cmd,
                "is_repeated_command": is_repeated_command,
                "repeated_cmd_count_window": repeated_cmd_count_window,
                "duplicate_cmd_freq": duplicate_cmd_freq,
                "outstanding_requests": outstanding_count,
                "modbus_func_code": float(row["modbus_func_code"]),
                "mbtcp_unit_id": float(row["mbtcp_unit_id"]),
                "modbus_ref_num": float(row["modbus_ref_num"]),
                "modbus_word_cnt": float(row["modbus_word_cnt"]),
                "modbus_bit_cnt": float(row["modbus_bit_cnt"]),
                "modbus_val": float(row["modbus_val"]),
                "payload_len": float(row["payload_len"]),
                "is_matched": is_matched,
                "is_timeout": is_timeout,
                "is_ambiguous": is_ambiguous,
                "response_latency": response_latency,
                "has_response_latency": has_response_latency
            }
            feature_records.append(record)

    feat_df = pd.DataFrame(feature_records)

    # Save feature CSVs if requested
    if features_csv_path:
        out_dir = os.path.dirname(features_csv_path)
        os.makedirs(out_dir, exist_ok=True)
        feat_df.to_csv(features_csv_path, index=False)

        # Export separate Normal and Replay feature CSV datasets
        normal_feat_path = os.path.join(out_dir, "normal_protocol_features.csv")
        replay_feat_path = os.path.join(out_dir, "replay_protocol_features.csv")

        df_norm_feat = feat_df[feat_df["dataset_category"] == "normal_traffic"]
        df_rep_feat = feat_df[feat_df["dataset_category"] == "replay_traffic"]

        df_norm_feat.to_csv(normal_feat_path, index=False)
        df_rep_feat.to_csv(replay_feat_path, index=False)

    # Save feature dictionary JSON if requested
    if dictionary_json_path:
        os.makedirs(os.path.dirname(dictionary_json_path), exist_ok=True)
        with open(dictionary_json_path, "w", encoding="utf-8") as f:
            json.dump({
                "model_features": FEATURE_DICTIONARY,
                "excluded_features": EXCLUDED_INPUT_COLUMNS
            }, f, indent=2)

    summary = {
        "total_feature_rows": int(len(feat_df)),
        "model_input_feature_count": len(MODEL_FEATURE_COLUMNS),
        "excluded_metadata_columns": len(EXCLUDED_INPUT_COLUMNS),
        "feature_names": MODEL_FEATURE_COLUMNS,
        "sample_feature_values": feat_df[MODEL_FEATURE_COLUMNS].head(3).to_dict(orient="records")
    }

    # TODO(Stage 2): Conventional-feature XGBoost comparison (raw statistical packet rate vs proposed method).
    # TODO(Stage 2): Feature-group ablation (evaluate sequence vs timing vs outcome features).
    # TODO(Stage 2): SHAP analysis and feature attribution across Modbus attack sub-types.

    return feat_df, summary
