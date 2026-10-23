"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/pcap_loader.py

Purpose:
    Provides robust parsing and ingestion of raw PCAP/PCAPNG network packet captures.
    Extracts Modbus Application Protocol (MBAP) headers and Modbus Protocol Data Units (PDU)
    directly from raw Ethernet/IP/TCP frames on port 502.

Academic Context:
    - In industrial automation, Modbus/TCP runs over standard TCP port 502.
    - Each Modbus/TCP frame begins with a 7-byte MBAP header:
        * Transaction ID (2 bytes, big-endian)
        * Protocol ID (2 bytes, 0x0000 for standard Modbus)
        * Length (2 bytes, big-endian byte count of remaining fields)
        * Unit ID (1 byte, destination device address)
    - Following the MBAP header is the Modbus PDU:
        * Function Code (1 byte)
        * Function-specific data (register references, counts, coils, values)
    - If an uploaded PCAP does not carry external ground-truth attack annotations,
      records are marked with is_attack = -1 (Unknown) rather than inventing labels.
"""

import os
import struct
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np


# PCAP and PCAPNG file signature magic numbers
PCAP_MAGIC_NUMBERS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (same endian)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (swapped endian)
    b"\x4d\x3c\x2b\x1a",  # Nanosecond pcap (same endian)
    b"\x1a\x2b\x3c\x4d",  # Nanosecond pcap (swapped endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG block type 0x0A0D0D0A
]


def is_valid_pcap_signature(file_path: str) -> bool:
    """
    Validates whether a file begins with a known PCAP or PCAPNG magic byte signature.

    Parameters:
        file_path: Path to the target file.

    Returns:
        True if the file signature matches PCAP or PCAPNG, False otherwise.
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) < 4:
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            return any(header.startswith(magic) for magic in PCAP_MAGIC_NUMBERS)
    except Exception:
        return False


def parse_modbus_pdu(payload: bytes, is_request: int) -> Tuple[int, float, float, float, float]:
    """
    Parses a Modbus Protocol Data Unit (PDU) payload to extract function code
    and parameter fields (reference register, word count, bit count, and write value).

    Parameters:
        payload: Byte sequence of the Modbus PDU (starting with the function code).
        is_request: 1 for client request query, 0 for server response.

    Returns:
        Tuple of (func_code, ref_num, word_cnt, bit_cnt, val)
    """
    if len(payload) < 1:
        return 0, 0.0, 0.0, 0.0, 0.0

    func_code = int(payload[0])
    ref_num = 0.0
    word_cnt = 0.0
    bit_cnt = 0.0
    val = 0.0

    # Function codes:
    # FC 1 (Read Coils), FC 2 (Read Discrete Inputs)
    # FC 3 (Read Holding Registers), FC 4 (Read Input Registers)
    # FC 5 (Write Single Coil), FC 6 (Write Single Register)
    # FC 15 (Write Multiple Coils), FC 16 (Write Multiple Registers)
    try:
        if is_request == 1:
            if func_code in (1, 2) and len(payload) >= 5:
                ref_num = float(struct.unpack(">H", payload[1:3])[0])
                bit_cnt = float(struct.unpack(">H", payload[3:5])[0])
            elif func_code in (3, 4) and len(payload) >= 5:
                ref_num = float(struct.unpack(">H", payload[1:3])[0])
                word_cnt = float(struct.unpack(">H", payload[3:5])[0])
            elif func_code in (5, 6) and len(payload) >= 5:
                ref_num = float(struct.unpack(">H", payload[1:3])[0])
                val = float(struct.unpack(">H", payload[3:5])[0])
            elif func_code in (15, 16) and len(payload) >= 5:
                ref_num = float(struct.unpack(">H", payload[1:3])[0])
                if func_code == 15:
                    bit_cnt = float(struct.unpack(">H", payload[3:5])[0])
                else:
                    word_cnt = float(struct.unpack(">H", payload[3:5])[0])
        else:
            # Server response parsing
            if func_code in (1, 2, 3, 4) and len(payload) >= 2:
                byte_cnt = int(payload[1])
                word_cnt = float(byte_cnt // 2)
            elif func_code in (5, 6) and len(payload) >= 5:
                ref_num = float(struct.unpack(">H", payload[1:3])[0])
                val = float(struct.unpack(">H", payload[3:5])[0])
    except Exception:
        # Fall back to zero defaults for non-standard or malformed PDUs
        pass

    return func_code, ref_num, word_cnt, bit_cnt, val


def load_pcap_to_dataframe(
    pcap_path: str,
    dataset_category: str = "normal_traffic",
    max_packets: Optional[int] = None
) -> pd.DataFrame:
    """
    Streams and parses a PCAP or PCAPNG capture file into a structured pandas DataFrame
    matching the CIC Modbus protocol schema.

    Parameters:
        pcap_path: Absolute or relative path to the PCAP file.
        dataset_category: 'normal_traffic' or 'replay_traffic'.
        max_packets: Optional limit on the number of packets to process.

    Returns:
        DataFrame containing parsed Modbus/TCP packet records with complete provenance.
    """
    # Import scapy lazily to optimize initial startup time
    from scapy.all import PcapReader, IP, TCP, Raw

    records: List[Dict[str, Any]] = []
    source_filename = os.path.basename(pcap_path)

    frame_idx = 0
    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            frame_idx += 1
            if max_packets and frame_idx > max_packets:
                break

            # Filter exclusively for IPv4 TCP packets on Modbus port 502
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue

            tcp_layer = pkt[TCP]
            sport = int(tcp_layer.sport)
            dport = int(tcp_layer.dport)

            if sport != 502 and dport != 502:
                continue

            # Check for TCP payload containing the MBAP header
            raw_payload = bytes(tcp_layer.payload) if pkt.haslayer(Raw) else bytes()
            if len(raw_payload) < 7:
                # Modbus MBAP requires at least 7 bytes
                continue

            # Parse MBAP Header
            try:
                trans_id, proto_id, mbap_len, unit_id = struct.unpack(">HHHB", raw_payload[:7])
            except Exception:
                continue

            # Standard Modbus protocol ID must be 0
            if proto_id != 0:
                continue

            # Direction: dport 502 indicates client request query; sport 502 indicates server response
            is_req = 1 if dport == 502 else 0

            # Modbus PDU payload (payload following 7-byte MBAP header)
            pdu_bytes = raw_payload[7:]
            func_code, ref_num, word_cnt, bit_cnt, val = parse_modbus_pdu(pdu_bytes, is_req)

            # Epoch timestamp from packet metadata
            pkt_time = float(pkt.time)

            record = {
                "timestamp": pkt_time,
                "frame_number": int(frame_idx),
                "src_ip": str(pkt[IP].src),
                "dst_ip": str(pkt[IP].dst),
                "src_port": sport,
                "dst_port": dport,
                "mbtcp_trans_id": int(trans_id),
                "mbtcp_unit_id": int(unit_id),
                "modbus_func_code": int(func_code),
                "modbus_ref_num": float(ref_num),
                "modbus_word_cnt": float(word_cnt),
                "modbus_bit_cnt": float(bit_cnt),
                "modbus_val": float(val),
                "payload_len": float(len(raw_payload)),
                "is_request": int(is_req),
                "source_file": source_filename,
                "original_row_id": int(frame_idx - 1),
                "dataset_category": dataset_category,
                # Ground-truth defaults for unannotated PCAP traffic
                "is_attack": 0 if dataset_category == "normal_traffic" else -1,
                "attack_category": "Normal" if dataset_category == "normal_traffic" else "Unknown",
                "attack_sub_type": "None" if dataset_category == "normal_traffic" else "Unknown",
            }
            records.append(record)

    if not records:
        # Return empty structured DataFrame if no Modbus packets found
        columns = [
            "timestamp", "frame_number", "src_ip", "dst_ip", "src_port", "dst_port",
            "mbtcp_trans_id", "mbtcp_unit_id", "modbus_func_code", "modbus_ref_num",
            "modbus_word_cnt", "modbus_bit_cnt", "modbus_val", "payload_len", "is_request",
            "source_file", "original_row_id", "dataset_category", "is_attack",
            "attack_category", "attack_sub_type"
        ]
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(records)
    # Sort chronologically by packet timestamp
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["capture_id"] = f"{dataset_category}_{source_filename}"
    return df
