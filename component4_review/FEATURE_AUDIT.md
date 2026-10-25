# Feature semantics and causal availability

The proposal requires transaction relationships, not malformed-packet detection. Inputs must describe evidence available at the stated decision time. Labels, source names, frame IDs, absolute timestamps, IPs and ports remain audit metadata. They are never new model features. Current structural fields can still encode scenario fingerprints; dropping explicit source columns alone does not eliminate that risk.

| Feature/evidence | Historical implementation | Corrected implementation | Earliest availability / support |
| --- | --- | --- | --- |
| Raw `trans_id_diff` | Upstream global diff in normal data; replay upstream ordering incomplete | Preserved only in historical inputs; not an allowed new feature | Current row contains upstream history of uncertain scope; unsafe |
| TID signed/modulo delta | Request endpoint+unit history, excluding ports; first increment forced to 1 | `session_tid_diff` / `session_tid_delta_mod65536` within observed four-tuple lifetime; NaN first | Current request arrival, CONDITIONAL on proxy identity |
| Endpoint TID changes | Called communication-channel sequence | Separate `endpoint_*` fields cross ports explicitly | Current request arrival; endpoint continuity hypothesis, not TCP-session evidence |
| TID recurrence | Last 100 endpoint requests | Separate session/endpoint recurrence, last 100 requests within 60 seconds | Current request arrival; normal reuse/wrap/retries remain possible |
| Request IAT | Earlier endpoint request, all history | Bounded `session_request_iat` and `endpoint_request_iat`; missing history explicit | Current request arrival; may mainly identify scenario polling cadence |
| Duplicate command | Unit, function, reference, word count, bit count and scalar value | Same partial observed-command fingerprint; missing fields disable equality | On later request arrival; PARTIAL payload support |
| Time since identical command | Unbounded last-seen dictionary despite bounded-count history | Bounded preceding endpoint requests; NaN if unseen/expired | Later request arrival only; no first-occurrence hindsight |
| Duplicate count/frequency | Trailing queue plus derived rate | Bounded trailing observed-command count; no redundant rate feature | Current request arrival; normal repetitive polling retained |
| Outstanding requests | Increment when the previous request's eventual outcome is missing; decrement otherwise; no real expiry | Removed from new inputs | Historical feature is not a pending-request count and can use future outcomes |
| Current response latency | Reconstructed reply delay; otherwise fixed 1.0 sentinel | Audit metadata only, NaN when unobserved | On unique reply, not at request arrival |
| Matched/timeout/ambiguity | Terminal reconstruction status used as inputs | Audit metadata only; ambiguous responses unpaired | Reply or search deadline; missing reply is not confirmed timeout |
| Label conflict | Preserved metadata; request label used as target | Both labels and explicit `request_label_target` preserved | Annotation metadata only; NEVER an input |
| Current Modbus/TCP fields | Seven command/unit/length inputs | Explicit 21-field CURRENT allowlist (includes raw TID, lengths, flags, exception/structure fields) | Current complete request observation |
| Payload bytes / exact full-ADU equality | Not stored | Not fabricated; unsupported | Requires retained complete ADU bytes/hash and stream reassembly |
| Read response process value | Scalar often zero; checked-in parser ignores returned registers | Never represented as a recovered response process value | Unsupported from these CSVs |
| TCP stream/session/campaign identity | Capture heuristics and four-tuple pairing presented too strongly | Observed segment/lifetime proxy, source filename status and unknown campaign explicitly separate | CONDITIONAL; true stream/run evidence missing |

Modbus requires matching outstanding request/response identifiers on the relevant TCP connection. A monotonically incrementing counter is one implementation option, not a universal validity rule; the implementation guide also permits using TIDs as context indices. Concurrent requests are allowed. A negative delta, reset, TID reuse after completion or modulo wrap is not proof of replay. [Modbus Organization implementation guide, sections 4.4.1.2-3](https://www.modbus.org/file/secure/messagingimplementationguide.pdf).

The new request-arrival schema is `c4-request-arrival-v1`. CURRENT has 21 fields and CONTEXT has 13; source code is the feature-order authority. XGBoost uses native missing values; no global median/scaler is fitted. `session_history_available` and `endpoint_history_available` distinguish missing first history from a measured zero delta. History is ordered stably by timestamp and original CSV row, reset by partition and observed segment, bounded by 100 requests and 60 seconds. Equal-timestamp ordering cannot reveal an unknown wire order; pairing marks request/reply ties for scrutiny. First-history missingness itself can expose sampling differences and must be examined on independent data.

Most four-tuple proxies carry one request, leaving actual within-proxy TID changes unavailable. Endpoint timing dominates the causal diagnostic model. Calling that evidence “session sequence consistency” would overstate what is measured. See `RESULTS.md` for timing and TID ablations.

The old PCAP loader does not reassemble split ADUs, iterate stacked ADUs, retain raw payload hashes or preserve TCP sequence state. It treats one TCP payload as one PDU, can initialize absent/malformed fields to zero, and sets unknown labels to -1. It remains historical code, not a repaired full stream parser. The new path accepts strict CSVs and explicitly rejects raw PCAP ingestion rather than presenting that loader as correct reassembly. A later raw-data exporter must preserve bytes, stream identities and extraction version; this audit did not rebuild the public archive.
