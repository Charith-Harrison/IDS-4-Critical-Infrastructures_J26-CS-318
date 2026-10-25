# Original CIC evidence and bounded recovery

## Source location and preservation

The original collection is available read-only at `G:\modbus cic 2023\Modbus Dataset`. The repository's historical absolute paths on other computers were not evidence of absence once this collection was located. The source manifest records source-file hashes. This review never writes to that root. Previously supplied datasets, reports and scripts remain unchanged.

The local `README.md` identifies CIC Modbus Dataset 2023, a simulated substation testbed, NIC captures and a Docker bridge capture, and external-attacker, compromised-IED and compromised-HMI scenarios. It explicitly describes sequentially numbered 100 MB PCAP chunks as portions of overall traffic. A chunk is therefore not an independently initialized experiment. Device roles in that source are `.7` attacker, `.3` normal HMI, `.2` secure HMI, `.4/.5/.8` IEDs.

The README's general log dictionary lists Timestamp, TargetIP, Attack and TransactionID. Actual external-attacker CSVs have only Timestamp and Attack. Missing target/TID values were not invented. The README names reconnaissance but does not establish that the supplied traffic performs sequential starting-address sweeps. Actual request bytes and original logs determine that question.

## Original logs read independently

`scripts/recover_raw_requests.py` scanned every supplied CSV and the formatted XLSX log. There are 1,420,042 CSV rows plus 116,084 XLSX rows. These include 1,453 reconnaissance-text rows, and 643 distinct parseable non-completion start signatures after exact-signature deduplication. Those are source records/tool invocations, not 643 independent campaigns. The formatted workbook and CSV may repeat underlying records. Every candidate retains original references rather than counting such duplication as new evidence.

Eight reconnaissance rows contain time-only values such as `07:40.5`; they cannot be assigned an epoch and were excluded from epoch-based joins. Some external log dates precede the supplied February capture. Some log filenames are not the same date as every timestamp contained in the file. Filenames and calendar dates do not prove run boundaries.

SCADA recon start rows frequently record TID `0`. Completion rows can record `1048575`, which is outside the 16-bit Modbus wire TID range. That literal is retained as tool metadata and is never wrapped, truncated, or silently treated as a wire transaction ID.

See `evidence/original_recon_log_rows.csv` and `evidence/original_log_inventory.json`.

## Canonical capture selection

The bounded request recovery read the complete external-attacker capture, all 18 SCADA bridge files, and the non-overlapping early portion of HMI `veth291ab9a-0.pcap` before the bridge's earliest timestamp. The HMI prefix adds coverage rather than duplicate observations of the same period. One IED interface view was additionally read only to reconcile old positive packet rows.

The original collection's other interfaces are inventoried, and all original log families were searched. No reconnaissance-text events were found in the compromised-IED log family. Mirrored interfaces and rotated chunks never become independent positive groups. The local benign HMI-chain census is documented separately by the root audit.

`substation-0.pcap` is a small March 23 capture, whereas the larger `substation-1` through `17` files span earlier March dates. Numeric filename ordering is not chronology. The causal history resets on negative time movement or a gap over 60 seconds, and final candidate ordering uses source timestamps. This isolated file is not joined across the backwards timestamp boundary.

## Extraction contract and limitations

The read-only PCAP reader is `C3/component3_preparation/c3prep/pcapio.py`, imported with bytecode writing disabled. The audit independently decodes complete Modbus ADUs inside individual captured TCP payloads, preserving frame number, PCAP record offset, ADU byte offset, endpoints, ports, TCP sequence, MBAP fields and exact hex bytes. Multiple complete ADUs in a single payload are preserved individually.

This is not a full TCP-reassembly extraction. The primary 20-file pass accounts for 20,662,398 captured frames, 3,683,267 complete single-segment ADUs, and 454 incomplete single-segment ADU cases. Those counts include the extra reconciliation view and are observation counts, not deduplicated experiments. Split or unframed data is not guessed. Candidate recovery is a bounded lower-bound recovery, not a completeness certificate for all messages in the original collection.

Request/response association uses reversed TCP endpoints, TID, unit and base function, with nonnegative response delay no greater than 5 seconds. The extractor's retained request is the latest matching predecessor. Reused TIDs, partial capture beginnings and missing full TCP-generation/pending-transaction proof prevent a universal claim of unique one-to-one transaction correspondence. All response associations remain audit metadata. An observed SYN count is not proof that every connection began inside the capture.

## Label-evidence contract

Naive log timestamps are treated as candidate UTC values for a bounded target/range/time join within ±25 ms. Signed offsets are retained. Global logger synchronization, logging-call placement and drift are not established. A nearby log by itself is not an exact label.

All candidate matches require the same source recording family and, where supplied, target IP and requested range. Original function is not explicitly recorded by these recon log rows. A unique eligible start yields `supported_contextual`, never `supported_exact`. Multiple distinct eligible start signatures yield `ambiguous`; `evidence_supported_recon_request=False` prevents their automatic inclusion as training positives. All equally eligible references remain visible.

The final candidate table contains 468 actual read requests: 148 `supported_contextual` and 320 `ambiguous`. They belong to two provisional recording families, comprising 436 SCADA requests and 32 external-attacker requests. The 148 contextual requests reference 91 distinct original log rows, not 148 independent experiments. There are zero `supported_exact` claims. Independent campaign count remains unknown.

All 468 request ADUs and all 269 associated response ADUs passed independent source-offset byte verification in `evidence/quality_raw_evidence_checks.json`. A CSV numeric-type inference error in response hex was corrected by rereading the exact source frames; no bytes were reconstructed by guessed padding. Hex columns must always be read as strings. `evidence/response_byte_reconciliation.json` documents this repair.

## What was recovered

Most SCADA recon requests read a large range beginning at address 1, using FC1/FC2 quantity 2000 and FC3/FC4 quantity 125. Across all 468 candidates, 459 start at address 1, four at address 0, three at address 2 and two at address 5. All have MBAP length 6 and captured packet size 78. Their quantity values are greater than one. The source supports range-read/function-probing behavior; it does not establish a sustained sequential starting-address sweep across these requests.

For example, `substation-1.pcap` frame 365018 at `2023-03-15T12:40:46.470397Z` is an actual `.3 → .4` FC3 request, address 1, quantity 125, TID 0, ADU `00000000000601030001007d`. The unique contextual start is original March-15 log row 66246, 397 µs earlier. FC4 frame 365024 also references that log start, illustrating why request count and log-event count must remain separate.

The external capture frame 6 at `2023-02-01T03:51:37.648697Z` contains FC1, address 0, quantity 65535, ADU `00000000000601010000ffff`, near original external log row 2 (`Recon. Range: 65535`). That quantity exceeds valid FC1 request bounds. This is useful evidence of probing, but it is a conspicuous current-message anomaly and does not establish the need for temporal learning.

## Reproduction

Run the scripts from the repository root using the recorded bundled Python runtime. All outputs are confined to this review.

1. Convert/inspect the old workbooks with the independent sequence-audit extraction.
2. Run `scripts/raw_label_audit.py` for the derivative-stage snapshot.
3. Run `scripts/recover_raw_requests.py` and then the same script with `--hmi-prefix`.
4. Run `scripts/finalize_raw_evidence.py` to merge canonical evidence, preserve ambiguity and enrich legacy provenance.
5. Run `scripts/verify_response_bytes.py` to verify exact response bytes against source frames.
6. Run `scripts/inspect_competing_read_mechanism.py` to annotate competing original query-flooding context for the residual quantity-20 legacy positives.

The derivative-stage snapshots explicitly identify themselves as superseded for raw-source availability. Final source conclusions come from the raw recovery, original-log reconciliation and final per-positive provenance table.
