# Dataset audit

All counts below were recomputed from CSV bytes, not copied from saved summaries. Complete column names/dtypes, null counts per column, class percentages, duplicate counts, timestamp quantiles/decimal precision, frame reset row indices, TID/latency/diff distributions, endpoint pairs, functions, directions, registers/counts, payload-related fields and provenance availability are in `evidence/audit_v1/audit.json` under `datasets`. High-cardinality port distributions show distinct count plus top 30 rather than tens of thousands of table cells. Timestamp digits were checked using CSV text, independently of float conversion. Historical derived-table names do not establish provenance.

| Dataset | Rows | Columns | Classes (0 normal / 1 replay) | Null cells | Exact duplicate rows | Minimum epoch | Maximum epoch |
| --- | --- | --- | --- | --- | --- | --- | --- |
| artifacts/audits/reconstructed_transactions.csv | 80753 | 31 | {"0": 78679, "1": 2074} | 10665 | 0 | 1674360030.295526 | 1679546582.992352 |
| artifacts/predictions/test_predictions.csv | 25923 | 22 | {"0": 25330, "1": 593} | 0 | 0 | 1674360030.295526 | 1679546582.992352 |
| artifacts/results/extracted_features.csv | 80753 | 38 | {"0": 78679, "1": 2074} | 6399 | 0 | 1674360030.295526 | 1679546582.992352 |
| artifacts/results/normal_protocol_features.csv | 75002 | 38 | {"0": 75002} | 150 | 0 | 1674360030.295526 | 1674526444.074282 |
| artifacts/results/replay_protocol_features.csv | 5751 | 38 | {"0": 3677, "1": 2074} | 6249 | 0 | 1675223325.48644 | 1679546582.992352 |
| artifacts/splits/split_manifest.csv | 80753 | 9 | {"0": 78679, "1": 2074} | 2133 | 0 | 1674360030.295526 | 1679546582.992352 |
| data/raw/normal_traffic_baseline.csv | 150000 | 36 | {"0": 150000} | 0 | 0 | 1674360030.274995 | 1674526444.074282 |
| data/raw/replay_attacks.csv | 9494 | 35 | {"0": 7247, "1": 2247} | 0 | 0 | 1675223325.48644 | 1679546582.992797 |
| normal_traffic_baseline.csv | 150000 | 36 | {"0": 150000} | 0 | 0 | 1674360030.274995 | 1674526444.074282 |
| replay_attacks.csv | 9494 | 35 | {"0": 7247, "1": 2247} | 0 | 0 | 1675223325.48644 | 1679546582.992797 |
| uploads/normal/normal_traffic_baseline.csv | 150000 | 36 | {"0": 150000} | 0 | 0 | 1674360030.274995 | 1674526444.074282 |
| uploads/normal/sample_test_normal.csv | 1 | 10 | {"0": 1} | 0 | 0 | 100.0 | 100.0 |
| uploads/normal/temporary_normal.csv | 1 | 10 | {"0": 1} | 0 | 0 | 100.0 | 100.0 |
| uploads/replay/replay_attacks.csv | 9494 | 35 | {"0": 7247, "1": 2247} | 0 | 0 | 1675223325.48644 | 1679546582.992797 |

## normal_traffic_baseline.csv

Classes: `{"0": 150000}`; percentages: `{"0": 100.0}`. Nulls: `{"frame_number": 0, "timestamp": 0, "frame_len": 0, "src_ip": 0, "dst_ip": 0, "src_port": 0, "dst_port": 0, "payload_len": 0, "is_request": 0, "tcp_flags_syn": 0, "tcp_flags_ack": 0, "tcp_flags_fin": 0, "tcp_flags_rst": 0, "tcp_flags_psh": 0, "mbtcp_trans_id": 0, "mbtcp_proto_id": 0, "mbtcp_len": 0, "mbtcp_unit_id": 0, "modbus_func_code": 0, "is_exception": 0, "modbus_exception_code": 0, "modbus_ref_num": 0, "modbus_word_cnt": 0, "modbus_bit_cnt": 0, "modbus_byte_cnt": 0, "modbus_val": 0, "len_discrepancy": 0, "has_stacked_frames": 0, "inter_arrival_time": 0, "packet_rate_1s": 0, "response_time": 0, "trans_id_diff": 0, "attack_sub_type": 0, "is_attack": 0, "attack_category": 0, "file_source": 0}`. Timestamp: `{"null": 0, "unique": 149983, "negative": 0, "zero": 0, "quantiles": {"0.0": 1674360030.274995, "0.01": 1674360713.1198652, "0.5": 1674481414.9144154, "0.95": 1674524536.8060732, "0.99": 1674526061.9463625, "1.0": 1674526444.074282}, "backward_steps": 2, "equal_adjacent": 4, "decimal_digits": {"6": 150000}}`. Frame reset CSV row indices (zero-based): `[25000, 50000, 75000, 100000, 125000]`.

| Field | Recomputed distribution/summary |
| --- | --- |
| mbtcp_trans_id | {"null": 0, "unique": 38130, "negative": 0, "zero": 0, "quantiles": {"0.0": 1.0, "0.01": 84.0, "0.5": 17164.0, "0.95": 60159.0, "0.99": 61161.0, "1.0": 61669.0}} |
| endpoint_pairs | {"185.175.0.3 -> 185.175.0.5": 26595, "185.175.0.5 -> 185.175.0.3": 26594, "185.175.0.3 -> 185.175.0.4": 26477, "185.175.0.4 -> 185.175.0.3": 26475, "185.175.0.3 -> 185.175.0.8": 21930, "185.175.0.8 -> 185.175.0.3": 21929} |
| src_port_counts | {"distinct": 14117, "top_30": {"502": 74998, "41408": 8, "41412": 8, "41414": 8, "41416": 8, "41418": 8, "41422": 8, "41430": 8, "41432": 8, "41436": 8, "41442": 8, "41444": 8, "41446": 8, "41448": 8, "41450": 8, "41452": 8, "41454": 8, "41458": 8, "41468": 8, "41470": 8, "41476": 8, "41480": 8, "41484": 8, "41488": 8, "41490": 8, "41494": 8, "41496": 8, "41498": 8, "41500": 8, "41502": 8}} |
| dst_port_counts | {"distinct": 14117, "top_30": {"502": 75002, "41408": 8, "41412": 8, "41414": 8, "41416": 8, "41418": 8, "41422": 8, "41430": 8, "41432": 8, "41436": 8, "41442": 8, "41444": 8, "41446": 8, "41448": 8, "41450": 8, "41452": 8, "41454": 8, "41458": 8, "41468": 8, "41470": 8, "41476": 8, "41480": 8, "41484": 8, "41488": 8, "41490": 8, "41494": 8, "41496": 8, "41498": 8, "41500": 8, "41502": 8}} |
| modbus_func_code_counts | {"1": 59558, "3": 30254, "4": 29784, "2": 29774, "6": 484, "5": 146} |
| is_request_counts | {"1": 75002, "0": 74998} |
| modbus_ref_num_counts | {"0": 74683, "8": 29413, "5": 10615, "14": 9626, "13": 9625, "35": 5363, "25": 5339, "15": 5336} |
| modbus_word_cnt_counts | {"0": 119981, "1": 30019} |
| modbus_bit_cnt_counts | {"0": 105332, "1": 44668} |
| modbus_byte_cnt_counts | {"0": 75317, "1": 44664, "2": 30019} |
| modbus_val_counts | {"0": 75167, "1": 74833} |
| frame_len_counts | {"78": 75317, "76": 44664, "77": 30019} |
| payload_len_counts | {"12": 75317, "10": 44664, "11": 30019} |
| mbtcp_len_counts | {"6": 75317, "4": 44664, "5": 30019} |
| is_exception_counts | {"0": 150000} |
| response_time | {"null": 0, "unique": 4860, "negative": 0, "zero": 75007, "quantiles": {"0.0": 0.0, "0.01": 0.0, "0.5": 0.0, "0.95": 0.001991, "0.99": 0.004216030000000028, "1.0": 41.071027}} |
| trans_id_diff | {"null": 0, "unique": 215, "negative": 7854, "zero": 73257, "quantiles": {"0.0": -27518.0, "0.01": -104.0, "0.5": 0.0, "0.95": 1.0, "0.99": 101.0, "1.0": 11143.0}} |
| payload_columns | ["payload_len", "modbus_byte_cnt", "modbus_val", "has_stacked_frames", "inter_arrival_time"] |
| read_response_values | {"rows": 74683, "values": {"0": 74683}} |

Observed discontinuity segments (gap >100s, backwards timestamp/frame, or source change; **not verified captures**):

| Segment | Rows | Positive rows | Start epoch | End epoch | First frame | Last frame |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 25000 | 0 | 1674481924.004201 | 1674486194.498424 | 3 | 133331 |
| 2 | 25000 | 0 | 1674520590.864227 | 1674526444.074282 | 8 | 131762 |
| 3 | 9372 | 0 | 1674360636.658912 | 1674365484.387946 | 283 | 52893 |
| 4 | 15628 | 0 | 1674423639.660549 | 1674431602.346113 | 53278 | 140087 |
| 5 | 25000 | 0 | 1674468178.561445 | 1674480905.82463 | 2 | 125023 |
| 6 | 10585 | 0 | 1674360030.274995 | 1674365489.464286 | 2 | 59586 |
| 7 | 14415 | 0 | 1674423643.943761 | 1674430797.41358 | 59833 | 140753 |
| 8 | 9442 | 0 | 1674507125.777466 | 1674508725.771959 | 3 | 50662 |
| 9 | 1251 | 0 | 1674509152.664583 | 1674509381.546108 | 51402 | 58238 |
| 10 | 14307 | 0 | 1674510122.314705 | 1674512552.536585 | 58405 | 134620 |

## replay_attacks.csv

Classes: `{"0": 7247, "1": 2247}`; percentages: `{"0": 76.33242047609016, "1": 23.667579523909836}`. Nulls: `{"frame_number": 0, "timestamp": 0, "frame_len": 0, "src_ip": 0, "dst_ip": 0, "src_port": 0, "dst_port": 0, "payload_len": 0, "is_request": 0, "tcp_flags_syn": 0, "tcp_flags_ack": 0, "tcp_flags_fin": 0, "tcp_flags_rst": 0, "tcp_flags_psh": 0, "mbtcp_trans_id": 0, "mbtcp_proto_id": 0, "mbtcp_len": 0, "mbtcp_unit_id": 0, "modbus_func_code": 0, "is_exception": 0, "modbus_exception_code": 0, "modbus_ref_num": 0, "modbus_word_cnt": 0, "modbus_bit_cnt": 0, "modbus_byte_cnt": 0, "modbus_val": 0, "len_discrepancy": 0, "has_stacked_frames": 0, "inter_arrival_time": 0, "packet_rate_1s": 0, "response_time": 0, "trans_id_diff": 0, "attack_sub_type": 0, "is_attack": 0, "attack_category": 0}`. Timestamp: `{"null": 0, "unique": 9494, "negative": 0, "zero": 0, "quantiles": {"0.0": 1675223325.48644, "0.01": 1675223406.6942787, "0.5": 1675225783.272701, "0.95": 1678880041.3502188, "0.99": 1678881089.0182858, "1.0": 1679546582.992797}, "backward_steps": 1, "equal_adjacent": 0, "decimal_digits": {"6": 9494}}`. Frame reset CSV row indices (zero-based): `[4, 5000, 9424]`.

| Field | Recomputed distribution/summary |
| --- | --- |
| mbtcp_trans_id | {"null": 0, "unique": 5777, "negative": 0, "zero": 10, "quantiles": {"0.0": 0.0, "0.01": 42.0, "0.5": 2365.5, "0.95": 47585.5, "0.99": 51824.7, "1.0": 52640.0}} |
| endpoint_pairs | {"185.175.0.3 -> 185.175.0.4": 4618, "185.175.0.4 -> 185.175.0.3": 3689, "185.175.0.3 -> 185.175.0.5": 1035, "185.175.0.3 -> 185.175.0.8": 59, "185.175.0.5 -> 185.175.0.3": 19, "185.175.0.2 -> 185.175.0.8": 13, "185.175.0.5 -> 185.175.0.2": 12, "185.175.0.8 -> 185.175.0.2": 12, "185.175.0.2 -> 185.175.0.5": 11, "185.175.0.2 -> 185.175.0.4": 11, "185.175.0.4 -> 185.175.0.2": 11, "185.175.0.7 -> 185.175.0.4": 4} |
| src_port_counts | {"distinct": 4906, "top_30": {"502": 3743, "53984": 4, "55298": 4, "55908": 4, "57490": 4, "33732": 4, "45288": 4, "53456": 3, "53812": 3, "53842": 3, "53846": 3, "53848": 3, "53870": 3, "53894": 3, "54116": 3, "54148": 3, "54208": 3, "54320": 3, "54778": 3, "54856": 3, "54898": 3, "54914": 3, "54996": 3, "55078": 3, "55156": 3, "55224": 3, "55362": 3, "55490": 3, "55496": 3, "55634": 3}} |
| dst_port_counts | {"distinct": 3489, "top_30": {"502": 5751, "53456": 3, "53812": 3, "53870": 3, "54208": 3, "55156": 3, "55224": 3, "55298": 3, "55496": 3, "55722": 3, "55812": 3, "57424": 3, "53482": 2, "53534": 2, "53642": 2, "53746": 2, "53768": 2, "53778": 2, "53834": 2, "53842": 2, "53846": 2, "53848": 2, "53886": 2, "53894": 2, "53900": 2, "53914": 2, "53932": 2, "53984": 2, "54004": 2, "54036": 2}} |
| modbus_func_code_counts | {"3": 4976, "1": 2255, "4": 1149, "2": 1114} |
| is_request_counts | {"1": 5751, "0": 3743} |
| modbus_ref_num_counts | {"0": 3743, "8": 3618, "35": 880, "14": 545, "13": 538, "5": 85, "25": 47, "15": 29, "1": 9} |
| modbus_word_cnt_counts | {"0": 5483, "1": 4010, "2": 1} |
| modbus_bit_cnt_counts | {"0": 7754, "1": 1731, "20": 9} |
| modbus_byte_cnt_counts | {"0": 5751, "2": 2114, "1": 1628, "3": 1} |
| modbus_val_counts | {"1": 5741, "0": 3752, "2": 1} |
| frame_len_counts | {"78": 5752, "77": 2114, "76": 1628} |
| payload_len_counts | {"12": 5752, "11": 2114, "10": 1628} |
| mbtcp_len_counts | {"6": 5752, "5": 2114, "4": 1628} |
| is_exception_counts | {"0": 9494} |
| response_time | {"null": 0, "unique": 2770, "negative": 0, "zero": 5751, "quantiles": {"0.0": 0.0, "0.01": 0.0, "0.5": 0.0, "0.95": 0.09664910000000006, "0.99": 0.21029969999999956, "1.0": 0.720804}} |
| trans_id_diff | {"null": 0, "unique": 2249, "negative": 2244, "zero": 3586, "quantiles": {"0.0": -46155.0, "0.01": -31129.28, "0.5": 0.0, "0.95": 29262.4, "0.99": 30824.559999999998, "1.0": 31238.0}} |
| payload_columns | ["payload_len", "modbus_byte_cnt", "modbus_val", "has_stacked_frames", "inter_arrival_time"] |
| read_response_values | {"rows": 3743, "values": {"0": 3743}} |

Observed discontinuity segments (gap >100s, backwards timestamp/frame, or source change; **not verified captures**):

| Segment | Rows | Positive rows | Start epoch | End epoch | First frame | Last frame |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 4 | 0 | 1675256622.70579 | 1675256777.70174 | 480 | 516 |
| 2 | 4996 | 0 | 1675223325.48644 | 1675225910.727015 | 5 | 27948 |
| 3 | 4424 | 2212 | 1678870414.805525 | 1678881156.665522 | 64 | 299126 |
| 4 | 12 | 6 | 1679539957.149365 | 1679540021.814174 | 46246 | 48358 |
| 5 | 12 | 6 | 1679541220.689726 | 1679541287.183009 | 92851 | 95778 |
| 6 | 12 | 6 | 1679542184.25562 | 1679542246.564995 | 128418 | 131283 |
| 7 | 12 | 6 | 1679543865.509983 | 1679543930.728626 | 190413 | 192508 |
| 8 | 10 | 5 | 1679544767.24382 | 1679544838.60795 | 222981 | 225222 |
| 9 | 4 | 2 | 1679546362.648966 | 1679546362.67068 | 282441 | 282455 |
| 10 | 8 | 4 | 1679546532.984944 | 1679546582.992797 | 288934 | 290532 |

## Interpretation and row unit

The raw-reference CSV has one extracted Modbus-bearing **packet/message observation** per row, with request and response directions separate. Frame numbers identify captured frames, and `has_stacked_frames` is a field; without the original exporter/bytes we cannot prove that each retained row is exactly one complete ADU. There is no TCP reassembly or true flow aggregation in these CSVs. Do not call these transaction rows.

The existing saved `reconstructed_transactions.csv` and feature tables instead contain **80,753 request-led observations**, including unmatched requests, not necessarily 80,753 complete pairs. Request labels give 78,679 normal and 2,074 replay requests (2.5683% replay; about 37.94 normal requests per positive). Raw combined packet/message labels give 157,247 normal and 2,247 replay rows (1.4088% replay). The derivative alone is 23.6676% replay; full normal plus positives is 1.4759% replay. Response-only attacks are not additional request targets: 173 positive response observations remain separately annotated. Pairing does not make these independent examples.

Normal `file_source` gives six PCAP filenames, each with exactly 25,000 rows; this regular truncation and nonzero first frame indicate a selected derivative, not full captures. Four additional long-gap cuts make ten observed normal segments. Replay has no `file_source` column at all and ten observed segments. No CSV carries verified campaign/run IDs, `tcp.stream`, sequence/acknowledgment numbers or payload bytes/hashes. Six observed normal source names plus ten unknown replay segments are not sixteen independent campaigns.

Of 2,247 replay-labelled rows, 2,212 (98.4424%) occur in one long observed replay segment. The remaining 35 occur in seven short segments. Two early segments contain no positives. Current-message positive signatures number only 14; positive request command signatures number only 10. Independent attack campaign count is **unknown**, not 2,247, not 2,074, and not ten. Whole-campaign class imbalance cannot be quantified until campaign identity is established. No oversampling was used or is justified by these counts alone.

Read-response `modbus_val` is zero in all 3,743 derivative read responses. The historical parser explicitly leaves read-response `val` at its initialized zero and only decodes byte count; a synthetic nonzero-value PDU check verifies this parser behavior. The exact producer of these historical CSVs is absent, so this is evidence of non-information, not proof that the true returned values were all zero. The baseline also contains placeholder-like request values. Never interpret this scalar as full process payload content.

The timestamp/endpoint/port/TID/function/register mirror probe found no matching cross-source observations within 10ms in these selected normal rows (`mirror_probe.json`). This does not prove independent recordings: truncated, disjoint-interface or time-shifted views remain possible without run metadata/TCP sequence numbers. No historical row or hard normal case was removed.
