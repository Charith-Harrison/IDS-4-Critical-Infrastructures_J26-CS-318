# Extraction data dictionary

Generated from the actual Arrow schemas by `write_data_dictionary.py`. No research rows or predictors are transformed by this documentation command.

All fields retain their declared Arrow types, with nullable fields remaining null when absent, inapplicable or unknown. Zero is preserved when observed. Binary payloads and integer epoch-microsecond times are lossless for the actual classic-PCAP Ethernet microsecond sources. Register values are unsigned 16-bit words stored in int32 arrays; no scaling, encoding, imputation, engineering-unit interpretation or learned profiles are applied.

`events.parquet` is one ADU or explicitly retained nonframed/incomplete byte run per row. It is not a model matrix. Other tables are audit/evidence/lineage metadata and must remain separate from later predictor selection. Decoder emission order can differ from chronological completion order because buffered streams flush later; membership manifests explicitly sort completion time.

Object-space semantics are a deterministic protocol lookup in `modbus.OBJECT_SPACE`: FC1/5/15 coil, FC2 discrete_input, FC3/6/16/22/23 holding_register, FC4 input_register. No guessed object-space or process-policy feature is generated. Addresses are zero-based wire references, not display notations such as 40001. A read-response address is absent on wire and is associated only in the pair audit.

Future current-ADU predictors require the researcher's reviewed causal allowlist. Source IDs, raw identities, labels, evidence methods, split membership, final connection outcomes and offline pair metadata are not automatically eligible. Request-derived response addresses and expected reply sizes are contextual; they do not belong to an isolated-current-response baseline.

## events.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `event_uid` | `string` | Canonical view:eN event identity; one-based N. Attribution/join metadata, never a predictor. |
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `view_id` | `string` | One selected observation interface/chain alias. Provenance metadata, never a predictor. |
| `event_seq` | `int64` | One-based decoder emission sequence within the view. It is not necessarily timestamp order. |
| `record_kind` | `string` | adu, nonframed or incomplete. Non-ADU candidate bytes remain visible. |
| `conn_uid` | `string` | View-scoped endpoint-tuple connection generation. Pairing/provenance identity. |
| `client_ip` | `string` | Observed client endpoint, inferred from configured server port/direction. Attribution, not an authorization label. |
| `client_port` | `int32` | Observed TCP client port, unit TCP port number. Attribution/pairing identity. |
| `server_ip` | `string` | Observed server endpoint, inferred from configured Modbus port. Attribution, not an authorization label. |
| `server_port` | `int32` | Observed TCP server port, normally configured 502. Attribution/pairing identity. |
| `direction` | `string` | c2s or s2c from server-port role. Role is independent of maliciousness. |
| `protocol_role` | `string` | request or response inferred from direction; does not determine target class. |
| `dir_record_index` | `int32` | Zero-based emitted-record index within this connection and direction. |
| `stream_off_start` | `int64` | Inclusive reconstructed direction-stream byte offset; provenance. |
| `stream_off_end` | `int64` | Exclusive reconstructed direction-stream byte offset; end-start equals adu_len. |
| `ts_first_us` | `int64` | Integer Unix epoch microseconds of the segment carrying the record's first stream byte. |
| `ts_complete_us` | `int64` | Integer Unix epoch microseconds of the latest contributing segment arrival; causal completion time. |
| `first_chunk` | `int16` | Original numeric capture-chunk suffix containing the first stream bytes; provenance. |
| `first_frame` | `int64` | One-based original PCAP-local frame number at the first stream bytes; needs source path/chunk. |
| `last_chunk` | `int16` | Original numeric capture-chunk suffix containing the last stream bytes; provenance. |
| `last_frame` | `int64` | One-based original PCAP-local frame number at the last stream bytes; needs source path/chunk. |
| `n_segments` | `int16` | Number of contributing delivered TCP segments, including segmented ADUs. |
| `frame_refs` | `string` | Convenience chunk:frame string, bounded by max_frame_refs. segment_refs is the structured lineage. |
| `segment_refs` | `list<item: struct<chunk: int16, frame: int64, pcap_offset: int64, stream_start: int64, stream_end: int64, event_byte_start: int32, event_byte_end: int32, timestamp_us: int64>>` | Contributing segment structs: chunk/frame, PCAP record-header byte offset, stream interval, record-relative byte interval and original epoch-us segment timestamp. |
| `starts_at_segment_start` | `bool` | Whether the record begins at its first contributing TCP segment's start; framing audit. |
| `ends_at_segment_end` | `bool` | Whether the record ends at its last contributing TCP segment's end; framing audit. |
| `reasm_ooo` | `bool` | A contributing segment was delivered from the out-of-order buffer; extraction status. |
| `reasm_overlap` | `bool` | A contributing payload had overlap with already delivered stream bytes; extraction status. |
| `reasm_after_gap` | `bool` | Record begins after a declared observed stream/capture gap; context-boundary metadata. |
| `conn_midstream` | `bool` | A complete initial handshake/stream start was not observed; extraction uncertainty. |
| `adu_bytes` | `binary` | Lossless emitted MBAP+PDU bytes, or the retained nonframed/incomplete byte run. Never imputed. |
| `adu_len` | `int32` | Number of bytes actually retained in adu_bytes; not an unobserved intended length. |
| `adu_sha256` | `string` | SHA256 of retained bytes for integrity. Equal payload hashes alone do not prove duplicate observations. |
| `pdu_bytes` | `binary` | Lossless bytes after the seven-byte MBAP header for an ADU; null for non-ADU runs. |
| `mbap_trans_id` | `int32` | Wire unsigned 16-bit transaction identifier. Connection/generation scoped; not a global event ID. |
| `mbap_proto_id` | `int32` | Wire unsigned 16-bit protocol identifier, normally zero for Modbus. Malformed bytes are preserved. |
| `mbap_length` | `int32` | Wire unsigned 16-bit MBAP length: following unit byte plus PDU, not total frame/TCP length. |
| `unit_id` | `int16` | Wire unsigned 8-bit unit identifier; no device authorization inference. |
| `func_raw` | `int16` | Original unsigned function byte including exception bit 7. |
| `func_code` | `int16` | Function number func_raw & 0x7f. Decode category; preserve func_raw separately. |
| `func_name` | `string` | Deterministic protocol name from function number; unassigned/user-defined remains explicit. |
| `is_exception` | `bool` | Whether original function byte carries bit 7. A valid exception is not automatically an attack. |
| `exception_code` | `int16` | Wire exception byte when present; otherwise null. |
| `pdu_len` | `int32` | Actual retained PDU byte count for an ADU. |
| `address` | `int32` | Function-specific unsigned zero-based wire start/reference address. Zero is valid; read responses have no wire address. |
| `quantity` | `int32` | Function-specific requested or acknowledged object count. Not a returned process value. |
| `write_address` | `int32` | FC23 write starting address when present, separate from its read address. |
| `write_quantity` | `int32` | FC23 write register count when present, separate from its read quantity. |
| `byte_count` | `int32` | Function-specific wire data-byte count where carried by the PDU. May disagree with actual bytes in malformed data. |
| `single_value` | `int32` | Unsigned single-write wire value/echo for FC5/6. Genuine zero is preserved. |
| `reg_values` | `list<item: int32>` | Complete decoded unsigned 16-bit register-word array. No engineering-unit, signedness, scaling or multiword-order interpretation. |
| `bit_bytes` | `binary` | Lossless packed bit-data bytes. Bit order/padding must be interpreted with associated requested quantity later. |
| `sub_function` | `int32` | Wire diagnostic subfunction where supported, e.g. FC8; null when absent/unsupported. |
| `and_mask` | `int32` | FC22 unsigned 16-bit AND mask on wire; zero is valid. |
| `or_mask` | `int32` | FC22 unsigned 16-bit OR mask on wire; zero is valid. |
| `mei_type` | `int16` | Wire encapsulated-interface type for applicable FC43 structures; deeper unsupported content remains raw. |
| `expected_pdu_len` | `int32` | Protocol-structural expected PDU bytes from current function/declared fields. Parse audit, not a fitted profile. |
| `shape_ok` | `bool` | Current-PDU structural length/shape validation result; null when undetermined/unsupported. |
| `shape_reason` | `string` | Protocol-specific structural/unsupported reason. Separate from target labels. |
| `parse_status` | `string` | ok, exception, malformed, unsupported, nonframed or incomplete; processing status, not class. |
| `parse_reason` | `string` | Detailed framing/decoding explanation; retained malformed bytes remain authoritative. |

## connections.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `conn_uid` | `string` | View-scoped endpoint-tuple connection generation. Pairing/provenance identity. |
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `view_id` | `string` | One selected observation interface/chain alias. Provenance metadata, never a predictor. |
| `conn_seq` | `int64` | One-based connection-generation sequence within the selected view. |
| `client_ip` | `string` | Observed client endpoint, inferred from configured server port/direction. Attribution, not an authorization label. |
| `client_port` | `int32` | Observed TCP client port, unit TCP port number. Attribution/pairing identity. |
| `server_ip` | `string` | Observed server endpoint, inferred from configured Modbus port. Attribution, not an authorization label. |
| `server_port` | `int32` | Observed TCP server port, normally configured 502. Attribution/pairing identity. |
| `syn_seen` | `bool` | Whether an observed opening client SYN establishes this connection generation. |
| `midstream` | `bool` | Connection starts without complete initial TCP evidence; uncertainty metadata. |
| `first_ts_us` | `int64` | First observed connection frame time in integer Unix epoch microseconds. |
| `last_ts_us` | `int64` | Last observed connection frame time in integer Unix epoch microseconds. |
| `first_chunk` | `int16` | Original numeric capture-chunk suffix containing the first stream bytes; provenance. |
| `last_chunk` | `int16` | Original numeric capture-chunk suffix containing the last stream bytes; provenance. |
| `spans_chunks` | `bool` | Connection generation has observed traffic across rotating chunks; continuity audit. |
| `fin_c2s` | `bool` | Client-side FIN observed. Does not alone prove both directions' completeness. |
| `fin_s2c` | `bool` | Server-side FIN observed. Does not alone prove both directions' completeness. |
| `rst` | `bool` | TCP reset observed for this connection generation. |
| `end_reason` | `string` | Closed, idle/capacity eviction, superseding SYN or chain end; extraction-policy outcome. |
| `frames` | `int64` | Observed frames assigned to the connection; not a generated rolling predictor. |
| `c2s_bytes` | `int64` | Delivered client-to-server stream bytes accounted into emitted records. |
| `s2c_bytes` | `int64` | Delivered server-to-client stream bytes accounted into emitted records. |
| `c2s_records` | `int32` | Emitted candidate/ADU records in client-to-server direction. |
| `s2c_records` | `int32` | Emitted candidate/ADU records in server-to-client direction. |
| `retrans_segments` | `int32` | Extraction count of retransmission/overlap observations. See suppressed-observation bytes and comparison status. |
| `retrans_conflicts` | `int32` | Observed overlapping bytes differed from retained bytes within comparison coverage; ambiguity remains visible. |
| `ooo_segments` | `int32` | Extraction count of out-of-order segments. |
| `gaps` | `int32` | Declared missing stream/capture-byte gaps, including explicit bounded-buffer outcomes. |
| `gap_bytes` | `int64` | Declared absent stream bytes; no synthetic bytes were inserted. |
| `truncated_segments` | `int32` | Segments with snaplen/capture truncation evidence. |
| `post_close_payload_segments` | `int32` | Payload observed after connection-close evidence but within retention policy. |
| `unverified_retrans_segments` | `int32` | Overlap outside the bounded byte-comparison tail. These bytes remain in the sidecar; equality is not asserted. |

## suppressed_observations.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `conn_uid` | `string` | View-scoped endpoint-tuple connection generation. Pairing/provenance identity. |
| `direction` | `string` | c2s or s2c from server-port role. Role is independent of maliciousness. |
| `chunk` | `int16` | Original source capture numeric suffix, linked through the extraction checkpoint. |
| `frame` | `int64` | One-based original PCAP-local frame number. |
| `pcap_offset` | `int64` | Byte offset of original PCAP record header; source attribution. |
| `timestamp_us` | `int64` | Original observed Unix epoch microseconds, or explicitly parsed candidate log time as identified by its table. |
| `stream_offset` | `int64` | Suppressed observation's direction-stream start byte position. |
| `payload` | `binary` | Lossless suppressed retransmission/overlap bytes. Kept separately from canonical delivered stream. |
| `reason` | `string` | Audit/annotation explanation, never a target shortcut predictor. |
| `comparison` | `string` | identical_bytes, conflicting_bytes or outside-comparison-tail uncertainty; no equality assumed when unverified. |

## pairs.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `view_id` | `string` | One selected observation interface/chain alias. Provenance metadata, never a predictor. |
| `conn_uid` | `string` | View-scoped endpoint-tuple connection generation. Pairing/provenance identity. |
| `request_uid` | `string` | Observed request endpoint of the relation; null for orphan/ambiguous response-only relations. |
| `response_uid` | `string` | Observed response endpoint of the relation; null for pending/unpairable request-only relations. |
| `candidate_request_uids` | `list<item: string>` | Observed possible request identities for unresolved/reused-ID/late candidates. Not forced into a match. |
| `transaction_generation` | `int32` | Observed request occurrence number for this TID within the connection; null without resolved request. |
| `status` | `string` | Pair/match/evidence state, table-specific; not an attack target or predictor. |
| `reasons` | `list<item: string>` | Pair consistency, capacity or incomplete-capture explanations; offline metadata. |
| `request_complete_us` | `int64` | Matched/known request completion in integer epoch microseconds; null without request. |
| `response_complete_us` | `int64` | Observed response completion in integer epoch microseconds; null without response. |
| `elapsed_us_audit_only` | `int64` | Response completion minus request completion, in microseconds. Offline relation; unavailable at request-time prediction. |
| `request_address_audit_only` | `int32` | Wire address recovered from the related request; contextual metadata, not current-response wire address. |
| `request_quantity_audit_only` | `int32` | Related request's quantity; contextual metadata. |
| `expected_response_bytes_audit_only` | `int32` | Expected response DATA byte count from request quantity: ceil(bits/8) or two bytes per register. Not total ADU/PDU length. |
| `request_first_chunk` | `int16` | Request's first contributing source chunk, or null without request; pair-boundary audit. |
| `request_last_chunk` | `int16` | Request's last contributing source chunk, or null without request; pair-boundary audit. |
| `response_first_chunk` | `int16` | Response's first contributing source chunk, or null without response; pair-boundary audit. |
| `response_last_chunk` | `int16` | Response's last contributing source chunk, or null without response; pair-boundary audit. |

## annotations.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `event_uid` | `string` | Canonical view:eN event identity; one-based N. Attribution/join metadata, never a predictor. |
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `view_id` | `string` | One selected observation interface/chain alias. Provenance metadata, never a predictor. |
| `component_label` | `string` | Accepted evidence-supported normal/command_injection/response_injection target, otherwise null. Never predictor input. |
| `annotation_state` | `string` | Supported, unknown/ambiguous, unlabelled, associated-only or out-of-scope annotation state. Separate from parse/pair status. |
| `label_method` | `string` | Versioned evidence/normal-provenance method used for annotation. Never predictor input. |
| `label_evidence_refs` | `list<item: string>` | Original source/log evidence references for an accepted annotation. Never predictor input. |
| `original_attack_names` | `list<item: string>` | Preserved original CIC mechanism names, not automatically collapsed into desired targets. |
| `matched_log_signature_ids` | `list<item: string>` | Accepted original-log signature references; evidence only. |
| `candidate_log_signature_ids` | `list<item: string>` | Candidate/ambiguous original-log associations; evidence only. |
| `associated_attack_request_uid` | `string` | Relationship to an injected request, not a response-injection label. |
| `associated_response_attack_uid` | `string` | Relationship to an independently supported injected response, not a request-injection label. |
| `reason` | `string` | Audit/annotation explanation, never a target shortcut predictor. |

## log_matches.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `event_uid` | `string` | Canonical view:eN event identity; one-based N. Attribution/join metadata, never a predictor. |
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `view_id` | `string` | One selected observation interface/chain alias. Provenance metadata, never a predictor. |
| `log_signature_id` | `string` | Stable deduplicated evidence-signature identity; not an independent recording or predictor. |
| `log_event_id` | `string` | Original retained log-row identity associated with a candidate packet. |
| `attack_original` | `string` | Literal original log attack description; preserved as evidence, not a predictor. |
| `family` | `string` | Deterministic original-description mechanism grouping; does not itself establish a core injection target. |
| `candidate_clock_offset_us` | `int64` | Explicit clock-alignment hypothesis in microseconds, tested rather than blindly applied. |
| `residual_us` | `int64` | Observed event completion minus hypothesized aligned log timestamp, in microseconds. |
| `behavior_supported` | `bool` | Candidate event behavior satisfies the frozen mechanism check; still requires uniqueness, clock and pair evidence. |
| `status` | `string` | Pair/match/evidence state, table-specific; not an attack target or predictor. |

## log_signatures.parquet

| Field | Arrow type | Source, units, applicability and interpretation |
|---|---|---|
| `log_signature_id` | `string` | Stable deduplicated evidence-signature identity; not an independent recording or predictor. |
| `recording_id` | `string` | Conservative whole-campaign parent group. Partition/group metadata, never a predictor. |
| `source_event_id` | `string` | Retained source log-row identity representing this evidence signature. |
| `source_path` | `string` | Original permitted CIC relative log path. Provenance only. |
| `source_sheet` | `string` | Original XLSX sheet, null for CSV source. Duplicate versions are not independent episodes. |
| `source_row` | `int64` | Original row/line position in source; attribution only. |
| `timestamp_us_candidate_utc` | `int64` | Naive original log time interpreted under explicit candidate UTC hypothesis; original strings/Excel serials remain in logs.parquet. |
| `target_ip` | `string` | Literal original log target IP, when provided. Missing does not become guessed endpoint. |
| `transaction_id` | `int64` | Original log integer TID. Only a verified 0..65535 wire candidate is eligible; sentinel values are never modulo-wrapped. |
| `attack_original` | `string` | Literal original log attack description; preserved as evidence, not a predictor. |
| `family` | `string` | Deterministic original-description mechanism grouping; does not itself establish a core injection target. |
| `coil_address` | `int64` | Explicit coil address parsed from the original attack description, when available. |
| `repeated_source_row_count` | `int64` | Number of exactly equivalent original evidence signatures collapsed for matching; not duplicated wire events. |
| `status` | `string` | Pair/match/evidence state, table-specific; not an attack target or predictor. |

## Pair outcomes and boundaries

Pairs are scoped to one recording, view and TCP connection generation. `matched`, `matched_exception` and `matched_inconsistent` retain observed request/response lineage and mismatch reasons. Reused-TID ambiguity, unit/function mismatch, orphan response, late/duplicate candidate, pending capacity eviction, pending at connection/capture end and unpairable record outcomes remain explicit. No unobserved timeout is invented: the audit applies a bounded pending count without temporal expiry, and reports matched-delay threshold sensitivity separately. A late/duplicate candidate is not proved replay or injection.

`expected_response_bytes_audit_only` counts data bytes, not MBAP, unit, function, count byte or entire ADU. Read-response wire address stays null. Chunk fields allow request/response dependencies across valid rotation boundaries to be counted without splitting them into separate partitions.

## Source/log and membership manifests

`inventory.json` preserves relative source paths, bytes, format, SHA256 and complete capture-header/time metadata. `group_sources.json` maps every permitted capture to conservative parent campaign/view/chunk membership, including the specially reassigned small March23 substation capture. `logs.parquet` retains original log row text/values, source sheet/row, timestamp strings/Excel serials, explicit candidate epoch conversion, valid-wire-TID status, completion/version eligibility and original attack description. A completion sentinel outside uint16 is never a wire ID. Duplicate CSV/XLSX versions remain evidenced rather than counted as independent events.

Candidate membership files contain event_uid, recording_id, view_id, event_seq, ts_complete_us and partition. These are exact attribution/split records, not predictor matrices. `candidate_*` names explicitly avoid declaring an unsupported class-complete independent experiment ready for scoring. The split manifest holds one whole-group assignment and source/event/annotation hashes; duplicate and pair-containment reports state audit scope and unresolved limits.

## Missingness and unsupported cases

A null wire address on a read response is inapplicable; a truncated byte sequence is missing; an undocumented engineering unit is unknown; an observed zero is a real value. These cases must not be merged into a numerical zero. Unsupported function structures remain raw and explicitly unsupported. Current parser support is IPv4/TCP in classic Ethernet PCAP with microsecond timestamps, matching the actual inputs. PCAPNG, nanosecond PCAP, IPv6 and fragmented IP require an added validated parser profile and are not claimed supported. Malformed and partial bytes are not repaired into invented messages.
