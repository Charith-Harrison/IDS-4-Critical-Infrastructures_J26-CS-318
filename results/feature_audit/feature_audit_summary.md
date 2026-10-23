# Feature audit summary

Features by category (A direct, B derived, C training-derived): {'B': 41, 'A': 15, 'C': 4}.
Dropped as constant on development data: frame_len, payload_len, mbtcp_len, unit_id, tcp_syn, tcp_ack, tcp_fin, tcp_rst, tcp_psh, is_known_fc, proto_id_valid, length_consistent, len_discrepancy, has_stacked_frames.

Metadata/grouping fields (D): capture_id, event_id, source_row, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, mbtcp_trans_id, file_source

Label/target fields (E): is_attack, attack_sub_type, attack_category, class_id, label_status

## Unavailable (F)
- **source_role_map**: No device-role/authorisation map exists; only client/server direction is derivable.
- **authorised_register_map**: No authorisation map supplied; 'unseen in normal training traffic' is used instead.
- **recent_missing_responses_window**: Whether an earlier request gets a response is only known later; using it would leak future information.
- **recent_exceptions_window**: Same reason: earlier responses may arrive after the current request.
- **response_delay_context_window**: Same reason (depends on later response arrival).
- **response_injection_pair_forgery_evidence**: No forged-response labels or evidence exist in the data.
- **value_echo_for_reads**: Read requests carry no value to echo.

## Invalid or unsupported (G)
- **inter_arrival_time (dataset column)**: Derivation not verifiable (capture-wide?); recomputed past-only per stream instead.
- **packet_rate_1s (dataset column)**: Derivation not verifiable and may include the current/following packets; recomputed past-only.
- **response_time (dataset column)**: Response-side measurement of unknown construction; recomputed from pairing.
- **trans_id_diff (dataset column)**: Depends on transaction-id sequence across the capture; replay-related and ID values are metadata.
- **transaction_id_match**: Constant 1 by construction of the pairing key (transaction id is part of the key).
- **raw src_ip / dst_ip / ports / transaction id as inputs**: Identify capture hosts (e.g. the attacking host) rather than behaviour: label leakage.
- **frame_number / absolute timestamp**: Capture position leaks the scenario.
- **file_source / capture_id / attack_* / is_attack**: Label or scenario identifiers.

## Leakage notes
- Labels are constructed from function code and register novelty; features built from the same fields can re-learn the labelling rule (see results/progress_70/circularity_diagnostics.json).
- PAIR features use the current event's own response, so they assume a completed request/response.
- Capture atk-0 contains no response packets, so `response_missing` is partly a capture-vantage artefact.