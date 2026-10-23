"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/transaction_context.py

Purpose:
    Reconstructs Modbus/TCP transactions by pairing requests and responses using
    capture scope, IP/port endpoints, transaction ID, unit ID, function code,
    and timestamp ordering within a configurable timeout.

Viva Explanation:
    - Modbus/TCP is a request-response protocol. A complete transaction consists of
      a client query and a server response sharing the same Transaction ID (TID)
      and Unit ID.
    - We NEVER pair by TID alone! Because TID is only 16 bits (0-65535) and resets,
      we scope pairing to:
        (capture_id, client_ip, server_ip, client_port, server_port, TID, Unit ID, Function Code).
    - We explicitly handle real-world network phenomena:
        * Missing responses: Replayed or dropped requests timeout without a server reply.
        * Multiple outstanding requests / Repeated TIDs: Tracked as ambiguous matches.
        * Orphan responses: Responses that arrive with no preceding request.
    - We preserve source row and frame identifiers for every request and response.
    - Label handling: If request and response packet labels disagree (e.g. injected replay
      request is labeled 'Replay' while the server's reply is labeled 'Normal'), we flag
      'label_conflict = True' without silently resolving or modifying the annotations.
"""

from typing import Tuple, Dict, Any, List
import pandas as pd
import numpy as np


def reconstruct_transactions(
    df_normal: pd.DataFrame,
    df_replay: pd.DataFrame,
    response_timeout: float = 1.0
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Reconstructs request-response transactions across both normal and replay datasets.

    Parameters:
        df_normal: Normal traffic DataFrame
        df_replay: Replay attack DataFrame
        response_timeout: Maximum elapsed seconds allowed between request and response

    Returns:
        Tuple of:
            tx_df: DataFrame of reconstructed transactions (both matched and timed out)
            orphan_df: DataFrame of orphan responses
            coverage_summary: Dictionary of pairing coverage metrics
    """
    combined = pd.concat([df_normal, df_replay], ignore_index=True)

    transactions: List[Dict[str, Any]] = []
    orphan_responses: List[Dict[str, Any]] = []

    # Process within each capture independently to guarantee no cross-capture pairing
    for cap_id, cap_df in combined.groupby("capture_id", sort=False):
        cap_df = cap_df.sort_values(by="timestamp").reset_index(drop=True)

        # Outstanding requests queue:
        # Key: (client_ip, server_ip, client_port, server_port, trans_id, unit_id, func_code)
        outstanding: Dict[tuple, List[Dict[str, Any]]] = {}

        for _, row in cap_df.iterrows():
            is_req = int(row["is_request"])

            if is_req == 1:
                # REQUEST FRAME: Direction Client -> Server
                c_ip, s_ip = str(row["src_ip"]), str(row["dst_ip"])
                c_port, s_port = int(row["src_port"]), int(row["dst_port"])
                tid = int(row["mbtcp_trans_id"])
                uid = int(row["mbtcp_unit_id"])
                fc = int(row["modbus_func_code"])

                key = (c_ip, s_ip, c_port, s_port, tid, uid, fc)

                tx = {
                    "transaction_id": f"{cap_id}_req_{row['original_row_id']}_{row['frame_number']}",
                    "capture_id": str(cap_id),
                    "source_file": str(row["source_file"]),
                    "dataset_category": str(row.get("dataset_category", "normal_traffic" if "normal" in str(row["source_file"]).lower() else "replay_traffic")),
                    "request_row": int(row["original_row_id"]),
                    "request_frame": int(row["frame_number"]),
                    "request_timestamp": float(row["timestamp"]),
                    "client_ip": c_ip,
                    "server_ip": s_ip,
                    "client_port": c_port,
                    "server_port": s_port,
                    "mbtcp_trans_id": tid,
                    "mbtcp_unit_id": uid,
                    "modbus_func_code": fc,
                    "modbus_ref_num": float(row["modbus_ref_num"]),
                    "modbus_word_cnt": float(row["modbus_word_cnt"]),
                    "modbus_bit_cnt": float(row["modbus_bit_cnt"]),
                    "modbus_val": float(row["modbus_val"]),
                    "payload_len": float(row["payload_len"]),
                    "request_is_attack": int(row["is_attack"]),
                    "request_attack_category": str(row["attack_category"]),
                    "request_attack_sub_type": str(row["attack_sub_type"]),
                    "response_row": None,
                    "response_frame": None,
                    "response_timestamp": None,
                    "response_is_attack": None,
                    "response_time": None,
                    "match_status": "pending",
                    "label_conflict": False,
                    "is_ambiguous": False
                }

                if key not in outstanding:
                    outstanding[key] = []
                outstanding[key].append(tx)

            else:
                # RESPONSE FRAME: Direction Server -> Client
                s_ip, c_ip = str(row["src_ip"]), str(row["dst_ip"])
                s_port, c_port = int(row["src_port"]), int(row["dst_port"])
                tid = int(row["mbtcp_trans_id"])
                uid = int(row["mbtcp_unit_id"])
                fc = int(row["modbus_func_code"])

                key = (c_ip, s_ip, c_port, s_port, tid, uid, fc)

                matched_tx = None
                if key in outstanding and len(outstanding[key]) > 0:
                    # Candidates within valid positive timeout window
                    candidates = [
                        t for t in outstanding[key]
                        if 0 <= (row["timestamp"] - t["request_timestamp"]) <= response_timeout
                    ]

                    if len(candidates) == 1:
                        matched_tx = candidates[0]
                        outstanding[key].remove(matched_tx)
                        matched_tx["match_status"] = "matched"
                    elif len(candidates) > 1:
                        # Ambiguous match: multiple identical outstanding requests
                        matched_tx = candidates[0] # Match earliest outstanding
                        outstanding[key].remove(matched_tx)
                        matched_tx["match_status"] = "ambiguous_match"
                        matched_tx["is_ambiguous"] = True

                if matched_tx is not None:
                    matched_tx["response_row"] = int(row["original_row_id"])
                    matched_tx["response_frame"] = int(row["frame_number"])
                    matched_tx["response_timestamp"] = float(row["timestamp"])
                    matched_tx["response_is_attack"] = int(row["is_attack"])
                    matched_tx["response_time"] = float(row["timestamp"] - matched_tx["request_timestamp"])
                    matched_tx["label_conflict"] = bool(matched_tx["request_is_attack"] != matched_tx["response_is_attack"])
                    transactions.append(matched_tx)
                else:
                    # Orphan response: no preceding matching request found in this capture
                    orphan_responses.append({
                        "capture_id": str(cap_id),
                        "source_file": str(row["source_file"]),
                        "response_row": int(row["original_row_id"]),
                        "response_frame": int(row["frame_number"]),
                        "response_timestamp": float(row["timestamp"]),
                        "server_ip": s_ip,
                        "client_ip": c_ip,
                        "server_port": s_port,
                        "client_port": c_port,
                        "mbtcp_trans_id": tid,
                        "mbtcp_unit_id": uid,
                        "modbus_func_code": fc,
                        "response_is_attack": int(row["is_attack"]),
                        "match_status": "orphan_response"
                    })

        # Any remaining outstanding requests exceeded timeout without a matching response
        for key, tx_list in outstanding.items():
            for tx in tx_list:
                tx["match_status"] = "timeout_missing_response"
                tx["response_time"] = np.nan
                tx["label_conflict"] = False
                transactions.append(tx)

    tx_df = pd.DataFrame(transactions)
    orphan_df = pd.DataFrame(orphan_responses)

    # Primary ground truth assignment:
    # A transaction's intent is defined by the initiating request.
    # When an injected replay request is answered by a victim server, the server's response
    # was annotated as 'Normal' in CIC Modbus 2023, while the transaction was initiated maliciously.
    # We assign 'transaction_is_attack = request_is_attack' and preserve 'label_conflict' as metadata.
    tx_df["transaction_is_attack"] = tx_df["request_is_attack"]

    total_reqs = len(tx_df)
    matched_count = int((tx_df["match_status"] == "matched").sum())
    ambiguous_count = int((tx_df["match_status"] == "ambiguous_match").sum())
    timeout_count = int((tx_df["match_status"] == "timeout_missing_response").sum())
    orphan_count = int(len(orphan_df))
    conflict_count = int(tx_df["label_conflict"].sum())

    coverage_summary = {
        "total_requests_processed": total_reqs,
        "matched_transactions": matched_count,
        "ambiguous_matches": ambiguous_count,
        "timeout_missing_responses": timeout_count,
        "orphan_responses": orphan_count,
        "pairing_success_rate": round(matched_count / max(1, total_reqs), 4),
        "timeout_rate": round(timeout_count / max(1, total_reqs), 4),
        "label_conflicts_flagged": conflict_count,
        "label_conflict_explanation": (
            f"Flagged {conflict_count} transactions where request is_attack != response is_attack. "
            "In CIC Modbus 2023 replay episodes, victim servers execute replayed queries legitimately, "
            "causing the response packet to be labeled Normal while the initiating request is labeled Replay. "
            "The transaction label preserves the request's attack annotation while retaining conflict metadata."
        )
    }

    # TODO(Stage 2): Full TCP stream reassembly using TCP sequence and acknowledgment numbers if PCAP bytes available.
    # TODO(Stage 2): Exact raw-payload matching and deep payload byte inspection.

    return tx_df, orphan_df, coverage_summary
