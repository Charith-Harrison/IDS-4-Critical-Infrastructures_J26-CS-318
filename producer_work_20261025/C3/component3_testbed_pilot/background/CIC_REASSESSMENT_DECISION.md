# Component 3 evidence and coverage decision — reassessment v1

**Keep the frozen baseline. Independent-campaign three-class generalization remains UNSUPPORTED.** The review's cohort, parser-shape, timing-window and excluded-endpoint counts reproduce locally. No labels, checkpoints, configuration, split memberships or model datasets were changed. Original source root is the verified local `data/raw/Modbus Dataset`, not the reviewer's G: path.

## Established

The baseline retains **1,404,306 normal / 100 command / 54 response** accepted ADUs; each class bears one campaign. All 154 accepted injections were checked again against original PCAP bytes and original CSV/XLSX rows. Commands have 98 malformed and 2 parser-ok PDUs; responses have 53 malformed and 1 parser-ok. Command outcomes are 82 observed exception replies with code 3 and 18 missing replies. Both parser-ok commands lack an observed reply. This establishes logged attempts and observed outcomes, not successful process manipulation. Missing replies prove neither success nor failure.

Selected SCADA IED1a has 99,290 FC5 requests, including 46,297 parser-ok requests; 96,200 FC5 requests literally use TID 5. They are not automatically attacks. Holding candidate edges, zero offset and stream-risk filters fixed:

| Residual window(us) | Unique diagnostic candidates | Parser-ok | Malformed | Frozen100 retained | New diagnostic candidates |
|---|---:|---:|---:|---:|---:|
| 0 | 82 | 34 | 48 | 0 | 82 |
| 1,000 | 400 | 63 | 337 | 97 | 303 |
| 5,000 | 187 | 10 | 177 | 100 | 87 |
| 25,000 | 100 | 2 | 98 | 100 | 0 |

No candidate was promoted. All 63 parser-ok candidates at 1 ms share `050001ff00` and have no observed matched reply in this audit. Exact-time and 1 ms candidate sets have zero overlap: broader windows introduce competitors, while different candidates with nonzero residuals enter. **Do not choose 1 ms to increase targets.**

Original CSVs serialize naive decimal times at up to milliseconds; workbook serials retain full dates, hours and fractions. All 170 PCAPs store microseconds. These are storage resolutions, not accuracy guarantees. The join uses ADU completion time; raw first/completion/frame times and log serials are preserved. Accepted command residuals are 32–1,560 us (median 540); FDI residuals are 267–5,717 us (median 969.5). Zero offset has observed family/campaign support versus ±3 hours. Selected matches cannot identify global offset, jitter, drift or logger call order. No original attacker source/configuration was found in the supplied CIC inventory. The precision/accuracy distinction is consistent with [Wireshark's timestamp documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimestamps.html).

## Recoverable coverage, with justified additional work

There are 153,560 brute-force log signatures outside the selected endpoint: 123,325 for `.5` and 30,235 for `.8`. These are not packet or attack counts. Bounded samples found compatible raw requests to `.4/.5/.8` across 20 log windows, including FC5 writes to `.5` with standard output values and PDU shapes. All remain diagnostic observations. No additional labels were accepted.

A concrete replacement canonical chain is **17 SCADA/HMI captures / 1,664,745,012 bytes**, alongside **19 benign/HMI captures / 1,858,748,158 bytes** for controls. The pilot inspected 22,895 unique frames, plus bounded cross-view comparisons, without full extraction. It confirmed 1,050 SCADA observation copies and 18 benign write copies. Same-view chronology and sampled boundary sequences support investigating the chains; full TCP loss and continuity remain unverified. Broader benign samples contain reads to all three targets but sampled FC5 controls remain `.5`, addresses 15/25; comparable attack-address controls remain a gap. Exact sources, hashes, bounds, resource estimates and stop gates are in `output/expanded_scope_plan.json`.

## Two evaluation claims

**A. Independent campaigns: UNSUPPORTED.** Extra rows/days/views cannot repair one campaign per class. Current candidate training lacks responses; validation has no accepted targets; test has responses only.

**B. Within-testbed chronology: CONDITIONAL and a different academic objective.** Global calendar blocks lack class completeness. Fixed duration-third probes separately within each campaign give the following aggregate counts before any purge; they combine different calendar periods and reuse campaigns. They are not train/validation/test assignments:

| Corresponding phase | Normal | Command | Response | Parser-ok command | Parser-ok response |
|---|---:|---:|---:|---:|---:|
| early | 465,934 | 57 | 13 | 2 | 0 |
| middle | 468,838 | 34 | 18 | 0 | 0 |
| late | 469,534 | 9 | 23 | 0 | 1 |

The two IED probe boundaries cross 66 and 11 connection generations respectively. No matched pair or original candidate tool interval crosses these probes, but burst semantics and missing/later replies remain uncertain. Boundaries need verified quiet points or entire-connection/dependency exclusions and declared causal lookback/label horizons. No purge, warm-up, window or replacement split was generated.

## Cannot be inferred and best next action

The accepted cohort's endpoint-pair sets are disjoint. All 54 forged replies contain ABCD and only 3 patterns; 151/154 accepted attacks are malformed. Endpoint/address/time recognition, specification checks and a static marker can explain much of this narrow cohort. Recovering commands alone cannot establish response diversity, physical plausibility, authorization, context necessity or deployment/generalization performance. Units, register maps, signedness, process impact and permission rules remain unknown.

**Single best next action: agree a narrower CIC-only within-testbed evidence/protocol study objective with the academic supervisor before authorizing expanded extraction or modelling.** If independent-campaign three-class generalization remains mandatory, retain UNSUPPORTED. The proposed policy revision is explicitly not adopted; it requires independent timing/identity justification and an event-level before/after decision ledger.

All new work is isolated here. Machine-readable lineage, count denominators, unresolved assumptions and stop conditions accompany this report. No context/lag/rate features, sequence windows, X/y matrices, imputation, scaling, encoding, feature selection, resampling, normal profiles or model training/evaluation were performed.
