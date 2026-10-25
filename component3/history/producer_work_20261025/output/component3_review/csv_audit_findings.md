# Read-only audit of supplied Modbus derivatives

Source files were read completely with bundled Python/pandas. The source files were not changed. These findings concern the supplied derivatives only; the unavailable 14 GB source dataset has not been inspected. Physical CSV line numbers below count the header as line 1.

## Verified inventory

| Item | normal_traffic_baseline.csv | command_response_injection_attacks.csv |
|---|---:|---:|
| Rows | 150,000 | 215,830 |
| Columns | 36 | 35 |
| Rows labelled normal | 150,000 | 110,415 |
| Rows labelled attack | 0 | 105,415 |
| Request rows | 75,002 | 147,435 |
| Response rows | 74,998 | 68,395 |
| Null cells according to CSV/pandas | 0 | 0 |
| Exact duplicate rows within file | 0 | 0 |
| Integer-second timestamps | 0 | 215,830 |

The sole header difference is **`file_source` is missing from the attack derivative**. No other existing header is missing relative to the baseline. Both derivatives omit additional information needed for dependable context analysis; adding one empty `file_source` column would not repair those losses.

## Highest-priority fault: contradictory labels on the same observations

The files overlap after accounting for the derivative's timestamp rounding. Matching frame number, endpoint tuple, direction, transaction ID, function code, MBAP fields, lengths, address/count/value fields and rounded timestamp identifies **96 shared observations**. Every match also has exactly equal `inter_arrival_time`, `packet_rate_1s`, `response_time` and `trans_id_diff`. **48 have contradictory `is_attack` labels**. All 96 match the baseline's `veth5bbeaa2-normal-13.pcap` rows. These 96 observations are the final 96 rows of the attack derivative.

Concrete example:

| Field | Baseline line 2880 | Derivative line 215736 |
|---|---|---|
| frame_number | 14924 | 14924 |
| timestamp | 1674482417.866921 | 1674482418 |
| source | 185.175.0.3:35564 | 185.175.0.3:35564 |
| destination | 185.175.0.5:502 | 185.175.0.5:502 |
| transaction ID | 57951 | 57951 |
| function code | 5 | 5 |
| inter_arrival_time | 0.000978 | 0.000978 |
| label | Normal / 0 | Coil_Brute_Force / 1 |

The matching response at baseline line 2881 / derivative line 215737 also changes from normal to attack; both contain response_time 0.000131. The available files do not establish which annotation policy is authoritative. The conflict must be resolved using source provenance and independent ground truth before training/evaluation. A function-code-based labelling heuristic is strongly suggested by the distribution below, but the original extraction code was not supplied, so that mechanism is an inference.

An exact all-column duplicate comparison reports zero overlap because the timestamp and labels differ. Deduplication must account for precision changes and provenance rather than relying on exact row equality.

## Values required for semantic response analysis are not established

`modbus_val` cannot currently be trusted as a decoded process value:

- All **74,687 baseline read requests** (FC1–4) have `modbus_val` equal to the requested bit/word quantity. Read requests carry a requested quantity, not the returned register/coil value.
- All **74,683 baseline read responses** have `modbus_val=0`, including all **15,127 FC3 responses**.
- All **55,745 derivative read responses** likewise have `modbus_val=0`, including all **11,136 FC3 responses**.
- Of 54,694 derivative read requests, 54,678 have `modbus_val` equal to quantity. The 16 exceptions are additional evidence that field semantics need checking against packet bytes rather than assuming a universal interpretation.

For example, baseline line 2 is FC3 read address35/quantity1/`modbus_val=1`; line 3 is the corresponding FC3 response with byte_count2/`modbus_val=0`/address0. The response address0 is an exporter placeholder for a field the response does not carry; recover the requested address from the matched request. Do not conclude the physical process returned zero solely from the scalar column. Real returned values might happen to be zero, but the export does not provide enough evidence to validate that.

The files lack raw TCP/PDU payload bytes and value arrays. Actual register/coil values and arbitrary response tampering cannot be reconstructed from this scalar representation without the source capture or another authoritative export.

## Label/function shortcut and absent response-attack evidence

Derivative labels:

| Label | Rows | Direction/function detail |
|---|---:|---|
| Normal | 110,415 | Only FC1–4; no normal FC5/FC6 rows |
| Coil_Brute_Force | 105,391 | 105,181 FC5; 210 FC6 |
| Length_Manipulation | 24 | Six requests each for FC1, FC2, FC3, FC4 |

Every derivative FC5/FC6 row is labelled attack. All 24 length-manipulation rows have `len_discrepancy=5`; all other rows have zero discrepancy. A trivial descriptive rule, `FC in {5,6} OR len_discrepancy != 0`, exactly reproduces the derivative's binary labels. On both supplied CSVs combined it yields TP105,415/FN0/FP630/TN259,785: recall100%, precision99.406%, accuracy99.828%, F1 99.702%. **These numbers expose an easy label shortcut; they are not evidence of a useful context-aware detector.** The 630 false positives are normal FC5/FC6 observations in the baseline, including some observations relabelled attack in the derivative.

No supplied label explicitly establishes forged-response attacks. The 12,650 rows labelled attack that have `is_request=0` may be ordinary replies to injected writes or exception replies. They do not prove response injection. FC6 is a register write, so calling all these observations `Coil_Brute_Force` also needs an explicit taxonomy. Need source event labels plus evidence of actual injection, not just a write operation or a response flag.

## Timestamp, ordering and provenance problems

Baseline timestamps retain fractions; the derivative stores every timestamp as integer seconds. The overlap example demonstrates rounding, not simply truncation, in at least those matching rows. The derivative retains fractional `inter_arrival_time` and `response_time` despite losing timestamp fractions, so accurate latency/reordering cannot be recomputed. It has 203,960 equal adjacent timestamps and only 11,069 distinct timestamp values.

The baseline is six consecutive chunks of exactly 25,000 rows each:

1. veth5bbeaa2-normal-13.pcap (line 2)
2. veth5bbeaa2-normal-14.pcap (line 25002)
3. veth4edc015-normal-4.pcap (line 50002)
4. vethd9e14c0-normal-4.pcap (line 75002)
5. veth8bc3408-normal-4.pcap (line 100002)
6. network-wide-normal-14.pcap (line 125002)

This demonstrates fixed row quotas; the selection algorithm (head, random, reservoir, etc.) is unknown. File order is not globally chronological: baseline has two timestamp decreases; derivative has three. Baseline `frame_number` repeats 53,156 times beyond first occurrence; derivative repeats 41,490 times. A frame number alone is not a unique key. A global timestamp sort would mix capture vantage points/independent runs and cannot replace provenance.

`inter_arrival_time` equals the immediately preceding file/capture row delta on **149,992/149,999** baseline transitions (1 μs tolerance). `trans_id_diff` equals the global preceding row's ID difference on **149,994/149,999** transitions; the five disagreements occur at source boundaries. These are capture-stream predecessor features, not proved per-device command features. Baseline line 4's interarrival .020575 measures time since the preceding response, whereas time since the preceding request is .021050. Such a network-load feature can be legitimate if documented, but cannot stand in for per-unit command history.

Baseline response_time is zero on all 75,002 requests and five responses. Derivative response_time is zero on all 147,435 requests and 6,412 responses, with positive response times on the other 61,983 responses (max .905616s). **It is not all zero.** Unavailable/not-applicable timing should be nullable with an explicit match status, rather than indistinguishable from a true zero latency.

## What transaction matching can and cannot recover

Candidate key: capture ID when present + direction-normalized client/server IP/port four-tuple + unit ID + transaction ID. This is a diagnostic key, not a complete TCP session or Modbus transaction identifier.

| Diagnostic | Baseline | Derivative |
|---|---:|---:|
| Groups with exactly one request and one response | 74,993 | 52,960 |
| Rows in those groups | 149,986 | 105,920 |
| Groups with multiple requests or multiple responses | 0 | 10,175 |
| Groups with request(s) and no response | 9 | 76,509 |
| Groups with response(s) and no request | 5 | 1,692 |

The last three categories are not disjoint (an unmatched group can contain multiple requests). Baseline candidate pairs all have matching function codes and nonnegative time order; recorded latency matches timestamp delta within1 μs on all 74,993. In the derivative, candidate matches are harder to validate because captures are unknown, four-tuples/IDs can be reused and subsecond timestamps are lost. Sixteen unique candidate pairs have differing packet-level attack labels; this is a question for annotation semantics, not automatically an error, since an injected request may receive a legitimate reply.

Missing `tcp.stream`, connection generation, TCP sequence/acknowledgement fields and raw payload prevents reliable retransmission handling, stream reassembly and boundary disambiguation. Derivative has no capture scope at all. Never force ambiguous matches or treat unmatched responses as attacks without ruling out capture loss, truncation and parser filtering.

## Consequences for rebuilding and evaluation

- Inspect the actual 14 GB source format, file inventory and available labels before choosing extraction code. It might be PCAP, a CSV, or an archive; these derivatives do not establish that.
- Re-extract capture/run/event provenance, exact epoch timestamp text or integer nanoseconds, stream/session identity, per-PDU identity, raw bytes/decoded arrays, request-response match status and independent labels. Keep all relevant normal context, legitimate writes, responses, exceptions and malformed Modbus candidates.
- Read-only extraction must not overwrite sources. Stream large inputs, checkpoint, keep a manifest, log every skipped/quarantined item with a reason, and preserve unknown labels as unknown.
- Reconstruct and validate complete transaction/context units before splitting. Split independent runs/events/captures or chronological blocks, keep duplicate observations from multiple vantage points together, and apply boundary purges for overlapping context windows.
- Fit normal profiles/scalers/encoders only on training data. Never put `is_attack`, `attack_category`, `attack_sub_type`, file names, capture/event IDs or label-derived fields into the predictive input. Retain provenance separately for auditing and split control.
- Both malformed-length detection and semantic response validation need actual stream/PDU parsing. TCP segmentation or multiple ADUs in one TCP segment must not be labelled a length attack from packet-length arithmetic alone.
- Validate benign writes, valid exceptions, delayed/lost/retransmitted packets and changes in operating mode. If genuine response-injection labels or actual process values are absent, document that coverage gap rather than claiming it has been repaired by a split.

## Reproducibility

`csv_audit.py` computes complete schemas, distributions, per-field summaries and candidate pairs; `csv_audit_deep.py` computes field semantics/timing diagnostics and the descriptive shortcut; `csv_audit_overlap.py` checks timestamp-normalized shared observations and contradictory labels. Outputs are `csv_audit.json`, `csv_audit_deep.json`, and `csv_audit_overlap.json`. The first audit includes SHA256 digests of both original files. No model was trained and no source data was edited.
