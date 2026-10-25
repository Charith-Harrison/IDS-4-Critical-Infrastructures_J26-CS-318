# Reconnaissance label provenance

## The central finding

The dominant old positive cohort is not established reconnaissance. All 8,400 `func_code=5, modbus_len=3` positives are actual slave-to-master Modbus exception replies: wire function `0x85`, exception code `0x03` (Illegal Data Value). They are not truncated normal FC5 replies. Their associated requests are FC5 writes with invalid coil-value encodings, and the closest original log context is brute-force/specific-coil activity. Calling them reconnaissance actions, or automatically calling them consequences of reconnaissance, is unsupported.

This is semantic label contamination as well as a static shortcut. It is more serious than an argument about whether length is an easy feature.

## Populations and preservation

The original processed packet workbook has 879,225 rows and 8,699 supplied positives. The audit preserves every supplied label and every source file. It does not automatically relabel, remove responses, delete length/size/function fields, or fit a final model.

Exact original-capture evidence was recovered for 8,687 positive packet rows. The 12 time-only external-snippet positives have no recovered CIC source identity. There are 8,731 raw message observations for the matched 8,687 packet rows: two packet rows each correspond to 23 identical ADUs coalesced in a single captured frame, at distinct TCP byte offsets. These are message expansions, not 44 mirrored duplicates. The old packet representation had lost unique message identity for those rows.

`label_provenance.csv` contains all 8,699 positive rows, source-workbook row identity, actual raw reference/bytes where available, supplied label, audit state, log evidence and limitations. The final audit-state counts are:

| Audit state | Old positive rows | Meaning |
|---|---:|---|
| `attack_associated_response` | 8,400 | FC5 exception replies associated with invalid writes and original brute-force/specific-coil context; not proven recon |
| `supported_contextual` | 66 | Raw read-request correspondence with one eligible contextual recon-start signature |
| `ambiguous` | 106 | Nonunique source-message/event attribution or response semantics insufficient for a recon label |
| `unsupported_heuristic` | 127 | Supplied positive lacks defensible recon evidence under the bounded reconstruction |

These states are audit judgments, not replacements for the old binary label. Exact packet-byte provenance is not the same thing as exact semantic attack ground truth.

## FC5 length-three cohort: exact bytes and triggering behavior

For original processed row 192326, `attack/compromised-scada/substation-wide-capture/substation-1.pcap` frame 95348 contains:

```text
0005 0000 0003 01 85 03
TID  PID  LEN  UID FC EXCEPTION
```

The associated predecessor frame 95181 contains:

```text
0005 0000 0006 01 05 0001 ffff
TID  PID  LEN  UID FC ADDR VALUE
```

This is an FC5 write to coil address 1 with value `0xffff`, followed by exception function `0x85` and code 3. The closest original log row is `attack/compromised-scada/attack logs/03-15-2023/03-15-2023-1.csv#row=49716`, `Brute force or specific coil. Address: 1`, with request-minus-log offset 203 µs.

All 8,400 matching requests use a value outside the valid FC5 coil encodings `0x0000` and `0xff00`. The observed request ADUs are dominated by `00050000000601050001ffff` (8,005 rows), then `000600000006010500010008` (375 rows), with a few writes to addresses 8, 13 and 14. Address 1 accounts for 8,380 of 8,400 associated requests.

All 8,400 have an eligible preceding reversed-endpoint/TID/unit/function request. Associated response delays range from 161 to 108,407 µs, median 2,012.5 µs. All nearest brute-force/specific-coil source-log offsets are at most 1,020 µs in absolute value. The latest-predecessor matcher is not a complete pending-transaction/generation uniqueness proof; requests in a burst may reuse TIDs. The mechanism conclusion relies on actual invalid-write/exception bytes and original non-recon log context, not on claiming every burst transaction pairing is uniquely solved.

The old `func_code=5` field omits the on-wire exception high bit. Raw source decoding restores `wire_function_code=133`. The upstream extraction/label-generation script is absent, so the audit cannot prove whether that normalization came from a dissector field, custom code, or another preprocessing step. It also cannot prove the original label algorithm merely from its perfect agreement with the shortcut.

All 13 other length-three positives are real read exception replies with wire functions `0x81`–`0x84`, exception code 2. Their existence identifies a response consequence. It does not by itself establish which reconnaissance request or original log event caused each response. They remain ambiguous unless additional source correspondence resolves that question.

Full message observations and representative exact-byte cases are in `evidence/raw_positive_packet_matches.csv` and `evidence/len3_source_byte_examples.json`.

## The mapped-event workbook is not trustworthy ground truth

All 158 mapped packet tuples occur in the old packet workbook and are supplied positives. Their eight distinct derivative log signatures exist in the actual original logs. However:

- 131 of 158 packet rows have neither endpoint equal to the original log TargetIP.
- Only 27 of 158 rows include the logged target.
- 73 mapped rows associate with one original source row, 65 with two, and 20 with three repeated source rows.
- The packet-minus-log offsets assuming candidate UTC range from about −209.98 to +141.49 minutes. A fixed timezone shift cannot explain these varying offsets.
- Completion TID `1048575` is not a valid wire TID and cannot provide transaction-level matching.

For example, the original `Recon. Range: 2000` row at `2023-03-15 19:49:09.043` targets `.8`; the mapped workbook associates it with packets involving `.4` and `.5` as well. The original `Recon. Complete` timestamp `17:27:36.753` targets `.4`, yet mapped packets also involve `.5` and `.8`.

Matching a derivative timestamp/src/dst tuple proves only agreement between derivatives. It does not validate the underlying original-log mapping. The mapping algorithm was not recovered. See `evidence/original_log_map_reconciliation.csv`, `event_map_reconciliation.csv` and `event_map_clock_offsets.csv`.

## Nonroutine read shape does not establish reconnaissance either

The 116 old positive nonroutine-read rows are not a homogeneous recon class. Thirty-six quantity-20 read rows lie within −823 to +721 µs of original external `Query flooding. Complete` context. That is a competing original attack mechanism, not a recon label. Two of those packet rows contain the 23-ADU coalescing ambiguity described above. `evidence/unsupported_read_nearest_original_events.csv` preserves the source references and signed offsets. Proximity to a completion record is contextual evidence and does not automatically assign the full traffic interval to an attack.

## Actual recon request recovery

The source reconstruction recovered 468 actual master/attacker-to-IED read requests, with all addresses, quantities, unit IDs, functions, TIDs, timestamps, ports, source frames and exact bytes retained. Of these, 148 have one eligible contextual original start signature and 320 have multiple eligible signatures. The latter remain `ambiguous` and are not promoted to supported training positives. No `supported_exact` semantic labels are claimed.

The requests reveal bulk range reads and function probing, predominantly fixed starting address 1 and quantities 2000/125. Their packet size and MBAP length are shared with ordinary reads, but their quantities are not shared with the full benign HMI-chain read census, whose 2,042,925 read requests all request quantity 1. This already supplies a current-request discriminator even after removing response length-three artifacts.

Real temporal sequences exist in source evidence, particularly short FC1→FC2→FC3→FC4 probe patterns. This does not establish that temporal context is necessary, that the proposed sequential-starting-address behavior is represented, or that a final LSTM has learned anything. The root temporal diagnostics analyze unambiguous contextual and ambiguous cohorts separately. Independent campaign-level train/validation/test feasibility remains unsupported without further run provenance.

## Interpretation of the previous audit

The earlier report's inference that FC5 exception replies are reconnaissance effects is not supported by the recovered source. The raw data instead points to invalid coil-write/brute-force activity. Its claims that the packet signature categories are proven original label-generation rules also exceed the recovered implementation evidence. The original upstream label script is unavailable; this review reports observed cohorts and verified source context.

Raw-source recovery changes the scientific question from “should we remove easy length features?” to “which original events actually instantiate the proposed recon target, and can temporal value be tested against shape-matched legitimate requests?” Source bytes, label semantics, experiment independence and matched normal overlap must be resolved before final preprocessing or model fitting.
