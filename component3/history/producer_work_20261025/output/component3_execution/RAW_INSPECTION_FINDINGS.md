# Read-only inspection of the downloaded CIC Modbus dataset

Date: 24 October 2026

Source root: `G:\modbus cic 2023\Modbus Dataset`

## Scope

The user requested inspection here and reserved extraction/splitting for the other researcher's machine. This review inspected the file tree, all original CSV log records, the retained XLSX log's underlying cell values, bounded PCAP header/tail samples, four specific benign packet frames, and one bounded log-linked packet window in one attack PCAP. No training dataset, split, model preprocessing, feature windows or trained model was created. No source file on G: was written or changed. No MSU/external dataset was used.

The helper packet inspector is a narrow evidence tool, not a production parser: it decodes complete ADUs contained in sampled TCP payloads and does not reassemble TCP. It must not be reused as a complete extraction implementation.

## 1. Verified inventory

| Item | Observed |
|---|---:|
| Total files | 207 |
| Total bytes | 15,761,969,012 |
| Size | 15.762 GB / 14.679 GiB |
| Classic PCAP files | 170 |
| Original CSV logs | 34 |
| XLSX log workbook | 1 |
| README / setup diagram | 1 each |

All inspected capture global headers report little-endian classic PCAP, Ethernet link type 1 and microsecond timestamp precision. First record headers and bounded suffixes were inspected for all 170 captures. This does not validate every intervening packet or prove that the distribution is complete relative to the publisher's original archive.

See `INVENTORY.md` and `source_inventory.json` for exact relative paths, sizes, candidate series and bounded timestamp evidence. No full-source SHA-256 pass was run during this inspection.

## 2. A source packet proves an old value-export error

Source relative path:

`benign/scada-hmi/scada-hmi-network-capture/veth5bbeaa2-normal-13.pcap`

Frame 3 is a function-3 read request, transaction 57464, start address 35, quantity 1. Frame 5 is its reply on the reversed endpoints and same transaction.

The reply TCP payload is:

```text
e078 0000 0005 01 03 02 0009
```

Its PDU is `03 02 00 09`: function 3, two data bytes, raw register word **9**. The matching old baseline CSV row stores `modbus_val=0`.

This confirms a wrong returned-value export for this actual matched sample. It does not establish how every other value in the distribution was decoded. The earlier all-zero response-column pattern is therefore a demonstrated extraction problem, not a sufficient representation of real process values.

Frames 14924 and 14926 in the same documented benign capture also contain the previously disputed FC5 write/acknowledgement: transaction 57951, address 15, wire word `ff00`. Their exact timestamps and endpoints match the earlier exported-record comparison. This strengthens the source linkage behind the conflicting labels; independent benign/attack provenance still governs final annotation decisions.

See `benign_packet_sample.json` for exact bytes, timestamps, endpoints and TCP sequence/acknowledgement fields.

## 3. One concrete log-linked response-side manipulation example

Original log:

`attack/compromised-ied/attack logs/03-23-2023/03-23-2023-1.csv`, physical CSV line 35.

```text
Timestamp:     2023-03-23 16:26:51.793
TargetIP:      185.175.0.2
Attack:        False Data Injection Attack
TransactionID: 7485
```

Source capture:

`attack/compromised-ied/trust-scada-hmi/trust-scada-network-captures/veth3efd353-1.pcap`

| Observation | Request | Response |
|---|---|---|
| Frame | 833140 | 833142 |
| Timestamp, interpreting log clock as UTC for this trial | 16:26:51.792015 UTC | 16:26:51.798726 UTC |
| Sender | HMI `185.175.0.2:53144` | IED `185.175.0.5:502` |
| Destination | IED `185.175.0.5:502` | HMI `185.175.0.2:53144` |
| Transaction | 7485 | 7485 |
| PDU bytes | `01 000f 0001` | `01 ab cd` |

The request reads one coil at address 15. The response retains FC1 and transaction identity, but its byte count is `ab` hexadecimal = **171**, with only **one actual data byte** (`cd`) following. The reply is structurally inconsistent. TCP sequence/acknowledgement information and the closely aligned tool log support the relationship.

This is concrete evidence of a log-linked manipulated reply candidate in the actual source, substantially stronger than inferring response injection from a direction flag alone. Validate the same source bytes on the other machine before promoting it into a final evidence label. A complete production parser must still handle the rest of the traffic and capture state.

Important research limitation: this case is malformed. A simple protocol-consistency rule can identify its structural fault. It does not prove that the dataset supplies enough independent, syntactically valid, stealthy response manipulations for a context-aware classifier, nor that contextual ML improves on such a rule. The response is one example, not a class-wide label assignment.

The zero-offset UTC interpretation matched this event within milliseconds. This is not evidence that every log/scenario has the same clock alignment. Do not apply an automatic three-hour shift to epoch timestamps.

See `response_candidate_sample.json` for the full bounded inspection evidence. The scan inspected record headers from one approximately 100 MB file, decoded payloads only in a +/-2-second window, and retained just the matching transaction samples as inspection evidence.

## 4. Original log schemas are not uniform

The 34 CSVs contain **1,420,042 tool-event rows**. These are not counts of independently labelled malicious packets.

- Twenty-eight CSVs have the advertised `Timestamp,TargetIP,Attack,TransactionID` schema.
- Six external-attacker CSVs have only `Timestamp,Attack`; target and transaction identity are unavailable there.
- Log folder dates frequently differ from the dates in event timestamps. Do not join or split by folder name alone.
- Some completion markers have TransactionID **1048575**, outside the 16-bit wire range. Treat these as tool/episode metadata, not a literal packet transaction ID. Do not wrap them modulo 65536 to force a match.
- There are many repeated event signatures. A same-millisecond repeated tool loop may be legitimate repeated logging; do not automatically erase it as a duplicate packet.
- Some logs describe dates outside the supplied capture time coverage. An unmatched log entry is not necessarily a parser failure, and unrelated packets must not be forced into its label.

The audit found **54 literal `False Data Injection Attack` entries** across seven compromised-IED log days, targeting HMI `.2` with valid 16-bit transaction IDs. These are the initial candidate list to verify individually, not 54 independently confirmed capture episodes.

## 5. The retained XLSX recovers truncated timestamp information

The March 21 CSV `03-21-2023-1-original.csv` contains short values such as `07:40.5`, losing visible date/hour precision. The neighbouring `03-21-2023-1-formatted.xlsx` retains full numeric Excel serial dates/times in its underlying cells.

The workbook has three target-specific sheets:

| Sheet | Target | Data rows |
|---|---|---:|
| To IED4C | `.8` | 8,306 |
| To IED1A | `.4` | 8,306 |
| To IED1B | `.5` | 99,472 |

For example, the numeric value `45006.130330057873` represents **2023-03-21 03:07:40.517** under the workbook's date system. Preserve the raw serial, date-system flag, conversion precision and unresolved timezone.

The short CSV overlaps the IED4C sheet: target/attack/TID fields match its 8,306 rows in order. Do not append both as separate independent events. Other sheets contain additional target-specific log evidence; do not discard them by reading only the first sheet. Raw serials should take precedence over copying the displayed `mm:ss.0` rendering.

See `LOG_EVIDENCE.md` and `log_inventory.json` for workbook XML evidence and the CSV comparison caveats.

## 6. Numeric capture order would produce a wrong chronology

Within:

`attack/compromised-scada/substation-wide-capture`

`substation-0.pcap` is a small 20,006-byte file dated **March 23, 02:12:00.885275-02:15:43.529226 UTC**. Files 1-17 cover **March 15-22**. Concatenating file 0 followed by file 1 jumps backwards approximately **7.72 days**.

File 0 also overlaps the compromised-IED recording period. Its run/scenario identity is unresolved; an overwritten/rotated capture is one possible explanation, not a confirmed cause. Treat it as a provenance problem. Simply re-sorting all files by time also does not prove TCP/run continuity or independence.

The other 145 inspected numeric neighbouring boundaries have nonnegative endpoint gaps no larger than approximately 4.973 seconds. This supports possible rotation continuity for those series, but does not establish independent experiment identity. Keep device/bridge observations and capture chunks scoped by actual recording evidence.

Benign series start at suffixes such as 4, 13 and 14. No internal numeric suffix gaps were found. Nonzero starts are source-boundary caveats; this inspection does not prove a corrupt/incomplete download.

## What to tell her Codex

1. Reproduce these small inspection examples on her own source copy. Compare relative paths, sizes and packet/log bytes before adopting findings as evidence.
2. Parse original logs according to their actual schema. Read the XLSX raw numeric times, reconcile its CSV overlap, and preserve clock uncertainty.
3. Resolve the out-of-order `substation-0.pcap` and cross-view/run identity before any independent split.
4. Preserve real returned value arrays and raw ADUs; do not inherit old `modbus_val` or old attack flags.
5. Verify the 54 response-side candidates individually; separate malformed protocol attacks from valid-looking value manipulation and keep a simple rules baseline in the later research design.
6. Keep the existing CIC-only, extraction/splitting-only scope. Preprocessing remains the researcher's later work. This inspection does not certify a final split or promise three-class feasibility.

These are actionable inspection findings for her machine, not a completed extraction or split.
