# Analyze CSV traffic

Uploading a CSV does not train the model. CSV and PCAP both call the same `infer_observations` function, `Detector`, saved imputer and saved Random Forest. The official locked results remain unchanged.

## Use it

1. Open **Demo → Analyze traffic**.
2. Choose **CSV**.
3. Download the template if needed.
4. Select an observation CSV. The page checks its schema.
5. Confirm that the observations use the declared single-writer/trusted-anchor testbed policy.
6. Click **Run detection on CSV**. Streams are ordered and validated before classification.
7. Filter the predictions and select one to inspect its current bytes and earlier anchors.
8. If ground truth is present, open **Evaluate predictions** and calculate the uploaded-label metrics.
9. Download the prediction report.

For a real round-trip example, select **Recorded PCAP**, run MX025, and download **observations (CSV input)**. Select CSV and analyze that file. The replay-decisions CSV is an output report and is deliberately rejected as input.

## Supported input

Preferred and currently supported mode: **ordered Modbus observations**. UTF-8 CSV with one complete Modbus/TCP ADU per row. This reuses the existing observation field names and raw-byte decoder; fields such as function, TID, unit and value are not guessed from unrelated flow columns.

| Required column | Type and meaning |
|---|---|
| run_id | Nonempty string identifying a recording/run. Each run owns separate history. |
| event_id | Nonempty occurrence ID, unique within the run. Equal message bytes are allowed at separate positions. |
| connection_id | Nonempty TCP connection-generation/session ID within that run. Never recycle it across reconnects. |
| observed_at_ns | Exact nonnegative integer Unix timestamp in nanoseconds; no float/scientific notation. |
| direction | `client_to_server` or `server_to_client`. |
| stream_offset | Nonnegative byte offset, beginning at 0 separately for each direction of the connection. Offsets must remain contiguous. |
| adu_hex | One complete 8–260-byte Modbus/TCP ADU, including MBAP, encoded as hex without separators. |
| map_id | `M0`, `M1` or `M2`, from the existing supplied public map/policy. |

Optional columns:

- `source_ip,destination_ip,source_port,destination_port`: all four together, or omit all four. Ports 1–65535; valid IPs; consistent reversed endpoints for replies. Primary B/D models do not require wire-header predictors.
- `tid,unit,function_code,pdu_hex,role`: redundant public fields, checked against the ADU/direction. `role` must be `request` or `response`.
- `observation_schema`: if present, every value must equal `c3-modbus-observations-v1`.
- At most one ground-truth column: `label`, `class`, `ground_truth`, `target` or `target_label`. It is held separately from detector inputs. Values for optional scoring are exactly `normal`, `command_injection`, `response_injection`, or blank for unlabelled rows. Invalid labels do not prevent prediction; they prevent scoring until corrected.

Unknown/private extra columns are rejected. Generic Wireshark/Zeek/CICFlowMeter flow CSVs, prediction reports and model-feature tables are not accepted automatically. Limits: 20 MiB and 100,000 observations. The four template rows are synthetic schema examples, not measured research data.

## Context and ordering

A separate detector is used for each **(run_id, connection_id)**. Each connection uses one public map and the existing unit 1/single-object FC1/3/5/6, one-outstanding-request policy. No private episode reset is introduced. TID reuse is handled by the pending request and connection generation, not TID uniqueness.

Already ordered streams retain file order, including tied timestamps that are otherwise consistent. Out-of-order streams are reordered only when timestamps are unique. Tied timestamps in a shuffled stream are ambiguous and that stream is rejected. Direction-specific byte offsets, pairing, echo checks and endpoints are checked after ordering. Gaps, inconsistent pairing, unsupported input or impossible order reject the stream; other valid streams may still be analyzed. Rejected rows remain visible and downloadable with no invented prediction.

The PCAP route obtains order from captured TCP byte/frame evidence. CSV cannot recover that evidence from an unreliable clock. A timestamp repair that contradicts stream offsets/pairing is rejected, not accepted as a new history.

Earlier mode reads and setpoint ACKs are reconstructed through the same causal state code as PCAP. Full normal context is processed before selecting targets. No future reply can affect its preceding command decision. Missing or stale context follows the existing six-intervening-ADU policy: contextual inference abstains before imputation. Other messages are out of scope rather than successful normal classifications.

## Provenance and evaluation

The UI checks membership against the original index/roster/receipt metadata. A full ordered direction+ADU trace, with the matching public map, can match a sealed original recording even if the uploaded run name was changed. A known ID without a full trace match is marked **unverified or partial**; a name alone is not proof of held-out content. Without local collection metadata, the saved locked membership file supplies ID-only matches.

- **TRAINING RUN:** implementation replay only. Training data — do not use this as independent performance evidence.
- **VALIDATION RUN:** development data; not independent test evidence.
- **HELD-OUT TEST RUN:** a previously observed test recording/ID. Upload metrics are exploratory; official saved results remain authoritative.
- **EXTERNAL / UNKNOWN:** no match; independence and label authenticity are not established. Renaming a subset may prevent full-trace recognition, so “unknown” never means “proven unseen”.

Ground truth is joined after prediction. Optional metrics use only labelled rows with actual supported predictions; labelled abstentions, out-of-scope and rejected counts are disclosed separately. Per-class precision/recall/F1, support, fixed-three-class macro F1, confusion matrix and supported-normal FPR are shown. Unsupported classes and undefined rates remain explicit. Uploaded labels are user-supplied, not automatically authenticated by a matching run name.

The downloaded prediction report contains source row/event, timestamp, run/connection, decoded function/address, prediction/confidence, eligibility/context/status and optional ground truth/correctness. It excludes private simulator state and is not a model-ready input file.

## Limits and advanced features

The frozen feature names/order exist, but a precomputed feature CSV cannot by itself verify causal history, pairing or public task eligibility. **Advanced model-feature ingestion is therefore not implemented.** Use raw observation CSVs through the context builder.

CSV assertions about connection identity, timestamps, public maps and genuine anchors are not equivalent to verified PCAP byte lineage. The route applies the same declared laboratory assumptions, not industrial authorization or physical-process validation. No transform is fitted, no threshold is tuned and no original experiment file is overwritten.
