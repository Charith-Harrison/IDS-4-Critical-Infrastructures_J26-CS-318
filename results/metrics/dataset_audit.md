# Dataset inspection



Original CSVs are read only.



## data/raw/normal_traffic_baseline.csv

Rows: 150,000; columns: 36; duplicates: 0.

Labels: {'attack_sub_type': {'Normal': 150000}, 'is_attack': {'0': 150000}, 'attack_category': {'Normal': 150000}}

Constant fields: tcp_flags_syn, tcp_flags_ack, tcp_flags_fin, tcp_flags_rst, tcp_flags_psh, mbtcp_proto_id, mbtcp_unit_id, is_exception, modbus_exception_code, len_discrepancy, has_stacked_frames, attack_sub_type, is_attack, attack_category



## data/raw/command_response_injection_attacks.csv

Rows: 192,920; columns: 35; duplicates: 0.

Labels: {'attack_sub_type': {'Normal': 97960, 'Coil_Brute_Force': 94940, 'Length_Manipulation': 20}, 'is_attack': {'0': 97960, '1': 94960}, 'attack_category': {'Normal': 97960, 'Command_Response_Injection': 94960}}

Constant fields: tcp_flags_syn, tcp_flags_ack, tcp_flags_fin, tcp_flags_rst, tcp_flags_psh, mbtcp_proto_id, mbtcp_unit_id, has_stacked_frames



## Interpretation

Supplied binary labels are not independently packet-verified.

No command/response target separation is inferred from direction.

Reset-inferred groups are not verified capture identifiers.

Exporter-provided timing and value semantics require original PCAP confirmation.

High risk: attack-category and subtype fields reveal targets and are forbidden as features.

High risk: capture identity and traffic function mix may confound validation; grouped splitting cannot establish external validity.