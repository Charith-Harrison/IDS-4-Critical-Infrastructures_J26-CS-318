# Data dictionary

## Raw columns (both CSVs, 35 shared columns; baseline adds `file_source`)

`frame_number`, `timestamp`, `frame_len`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `payload_len`, `is_request`, `tcp_flags_*` (syn, ack, fin, rst, psh), `mbtcp_trans_id`, `mbtcp_proto_id`, `mbtcp_len`, `mbtcp_unit_id`, `modbus_func_code`, `is_exception`, `modbus_exception_code`, `modbus_ref_num`, `modbus_word_cnt`, `modbus_bit_cnt`, `modbus_byte_cnt`, `modbus_val`, `len_discrepancy`, `has_stacked_frames`, `inter_arrival_time`, `packet_rate_1s`, `response_time`, `trans_id_diff`, `attack_sub_type`, `is_attack`, `attack_category`.

Exact types, missing counts and checksums: `results/data_audit/dataset_audit.json` and `column_schema.csv`.

`inter_arrival_time`, `packet_rate_1s`, `response_time` and `trans_id_diff` are not used: their derivation across capture boundaries could not be verified, so equivalents are recomputed per capture.

## Added metadata (never model inputs)

`source_row` (original row id), `source_name`, `capture_id` (`base-<file_source>` genuine, or `atk-N` reconstructed from frame-number/timestamp resets), `boundary_reason`, `event_id` (`capture_id:source_row`), `function_name`, `is_write`.

## Label fields

`class_id` 0 = Normal, 1 = Command Injection, empty = excluded/ambiguous. `label_status` records why (`dataset_normal`, `reconstructed_command_injection`, `ambiguous_write_matches_normal_profile`, `unsupported_length_manipulation`, `attack_labelled_response_packet`, `no_label_available`). Label construction is documented in `results/data_audit/label_evidence.csv`.

## Features

Every feature (source columns, derivation, past-only status, leakage risk, validity decision): `results/feature_audit/feature_inventory.csv`.
Groups: BASELINE (current event only, 7 features), PROTOCOL, PAIR, SEQUENCE, ACCESS, VALUE, RATE (contextual model: 46 features). Constant features on the development data are dropped and listed in `models/contextual/training_manifest.json`.

## Output fields

`event_id, timestamp, function_code, function_name, register, operation, pair_status, response_delay, actual_class, predicted_class, normal_probability, command_injection_probability, confidence, supporting_observations, model_version, feature_schema_version, inference_time_ms, processing_status`. `actual_class` is `Unavailable` for unlabelled input.
