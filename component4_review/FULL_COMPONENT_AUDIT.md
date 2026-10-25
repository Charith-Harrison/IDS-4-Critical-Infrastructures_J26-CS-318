# Component 4 - Full Component Audit

Replay Attack Detection Using Transaction Consistency Analysis  
Ilankoon I. M. D. S. - IT23284616  
Audit date: 2026-10-25, Asia/Colombo

**Conclusion:** There is a reproducible Modbus replay prototype and useful historical evidence, but the current extracts do not establish independent evaluation or the proposal's transaction-consistency novelty. The old scores reproduce; their scientific interpretation is invalid as proof of that contribution. A corrected, tested preparation/training/inference path is now implemented. Missing source provenance, payloads and independent campaigns were not invented, and no final model was trained on unsupported groups.

## 1. What Shashi proposed

The individual proposal's abstract and methodology (PDF pages 3 and 14-18), functional requirements (page 21), and team TAF's RP4 row (page 10) describe replay of **individually valid** Modbus communication. The unit is a reconstructed Modbus transaction or short transaction context; the classifier is binary XGBoost. Transaction IDs, timing, duplicate/repeated payload behavior, session sequence and function/register context should distinguish malicious reuse from legitimate repetitive polling. The critical experiment holds classifier/data/evaluation design consistent while comparing conventional/current-message features against transaction consistency, with rule baselines, ablation, FPR and detection latency.

The TAF explicitly includes capturing and labelling testbed replay. The proposal permits CIC as a main public benchmark supplemented by controlled traffic if its transaction evidence is inadequate. PP1 criteria call for a working proof of concept, sound practices and explicit risk mitigation; they do not justify unsupported performance claims. These documents and the old report are reference evidence, not instructions overriding this audit. See [requirements matrix](REQUIREMENTS_MATRIX.md).

## 2. What actually existed

Initial branch: `shashi-branch`, HEAD `25657a3`, clean working tree. This checkout contains the replay component's Flask dashboard and Python modules, rather than all four components in one active tree. The Shashi backup/origin trees have the same 61-file layout. Other components were visible only in separate local Git branch trees and were not modified or checked out.

Contrary to the concern that the **model** necessarily uses packet rows, the checked-in implementation already reconstructs request-response associations. It then builds 21 features, performs a hardcoded normal-capture/replay-block train/test split, trains XGBoost and compares it with a protocol rule. Its raw CSV rows remain packet/message observations; its saved training rows are request-led reconstructed observations, including unmatched requests. There is no current-message XGBoost comparison in the original source (it is marked TODO), no validation set and no true campaign independence proof.

There is no Component 4 notebook, historical prompt, original shared extractor, separate Component 4 spec or old limitations/decision log in this branch/its Shashi backup. The existing two-page PDF's “100% integrity”, certified training readiness and guaranteed temporal isolation are overclaims. Absence of nulls does not establish semantic correctness or provenance. [Source inventory](SOURCE_INVENTORY.md) records every initial file, byte size, SHA256, role, usage and duplicate status, plus the external PDFs.

## 3. Datasets and verified counts

| Dataset/unit | Normal | Replay | Total | Interpretation |
| --- | --- | --- | --- | --- |
| Normal baseline CSV | 150,000 | 0 | 150,000 | Six named sources, 25,000 retained rows each |
| Replay derivative CSV | 7,247 | 2,247 | 9,494 | No source-PCAP column |
| Combined message observations | 157,247 | 2,247 | 159,494 | 1.4088% positive; correlated observations |
| Full normal baseline plus derivative positives | 150,000 | 2,247 | 152,247 | Requested negative-TID stress diagnostic |
| Combined request-label targets | 78,679 | 2,074 | 80,753 | 2.5683% positive, about 37.94:1 normal:replay |

Root, `data/raw/`, and upload copies of each main CSV have identical SHA256s. `data/raw/` is the explicit canonical reference for the new path; nothing was deleted/moved. Two one-row upload files are test residues, not independent datasets. `normal_traffic_baseline(1).csv` is absent. All relevant 14 CSV paths, including features, predictions, split manifest and reconstructed observations, were profiled; identical copies share an independently computed hash/profile. See [dataset audit](DATASET_AUDIT.md) and its JSON evidence for schemas, percentages, nulls, duplicates, decimal precision, ranges/resets, distributions and provenance.

## 4. What one row represents

The 35/36-column input tables contain extracted Modbus-bearing **frame/message observations**, with requests and responses separate. Without the original exporter and bytes, one cannot prove every row is exactly one reassembled ADU rather than the first decoded PDU in a TCP payload. They are not reconstructed transactions, flows or independent attacks.

The 80,753 derived modelling rows are **request observations with an optional observed reply association**. Of these, 78,620 have a unique observed match under the one-second search bound; 2,133 have no match. Do not call all of them completed request-response transactions. No distinction between capture duplication, TCP retransmission, application retry and malicious replay is recoverable from scalar fingerprints alone.

## 5. Request-response reconstruction

The original code uses capture scope, reversed client/server endpoints and ports, TID, unit, function and timestamp bounds, tracks multiple outstanding candidates and retains request/response row IDs. That is valuable code/logic to preserve. It is not full TCP stream reassembly. Original weaknesses include arbitrary FIFO choice when identical outstanding candidates collide, exception-function mismatch, no full TCP connection lifetime, unbounded stale requests, and treating every missing response as a real timeout.

The new implementation preserves segment/input/row provenance and canonical bidirectional four-tuple/lifetime proxies; normalizes exception function codes; expires candidate matches; supports concurrent different TIDs; refuses to assign ambiguous replies to a fabricated pair; and retains unpaired replies rather than discarding them. Observed SYN/FIN/RST flags delimit proxy lifetimes when present. Late, duplicate and orphan reply causes cannot be distinguished conclusively without TCP history and remain explicitly unresolved. Tie timestamps and right-censoring are metadata.

Corrected full-data preparation reproduces **78,620 pairs, 2,133 response-not-observed requests and 121 unpaired replies**, with six right-censored requests and no observed identical-key pairing ambiguity. There are 1,047 label-disagreeing pairs. Both request and reply labels are retained; `request_label_target` explicitly means the initiating request's existing annotation, **not** a new verified transaction truth. The former explanation that every conflict is a benign server executing a replay is not established by these files.

## 6. Transaction-ID feature validity

The historical stored `trans_id_diff` is unsuitable as a session-consistency feature. Every one of 149,990 comparable within-observed-segment baseline rows agrees with a global previous-message difference. Interleaved normal servers create large negative jumps. The replay derivative only partly agrees because some stored deltas imply preceding TIDs absent from the retained CSV neighbors; its exact original producer/order is unavailable.

The supplied stream-interleaving concern is reproduced exactly: derivative rows 5000-5003 alternate server .4 TIDs 15044/15045 and server .5 TIDs 42101/42106, while storing -27056/+27057/-27060/+27061. Endpoint-local request differences are +1/+5, and true four-tuple history is largely absent because ports change. See [TID audit](TID_AUDIT.md) for all candidate comparisons and examples.

The original trained model does not directly consume stored `trans_id_diff`; it recomputes endpoint/unit request history, omitting ports and forcing a first increment of 1. That is better than a global diff, but cannot be called TCP-session history. New signed/modulo features separate within-proxy and cross-port endpoint history, retain first-history NaNs and explicitly represent wrap. Modbus permits multiple TID allocation schemes, so monotonic +1 is a traffic-pattern assumption rather than a universal protocol rule. [Modbus implementation guide, section 4.4.1](https://www.modbus.org/file/secure/messagingimplementationguide.pdf).

## 7. Duplicate/payload support

Observed-command repetition is **PARTIAL**: unit, function, register/counts and scalar value can form a limited request fingerprint. No full payload bytes/hash is stored. Exact raw request/response equality is **UNSUPPORTED**, and repeated read-response process values cannot be recovered.

All 3,743 derivative read-response rows have `modbus_val=0`. The checked-in parser ignores nonzero returned register bytes when assigning this scalar; a tiny synthetic response containing register value 0x1234 still returns scalar zero. This verifies the parser limitation without PCAP processing. It does not recover the historical exporter or prove the true returned values were zero. Missing fields are not fabricated as zeros in the new pipeline. See [feature audit](FEATURE_AUDIT.md).

## 8. Replay-label structural plausibility

All positive rows have protocol ID 0, no exception, zero length discrepancy and no stacked-frame flag; their read function/length shapes also occur normally. This is structurally plausible for replay and inconsistent with treating the task as malformed-packet detection. **Structural plausibility is not ground-truth verification**: no original attack logs/source-PCAP mapping or full byte lineage accompanies the derivative. Timestamps, labels, unit/register fields and plausible structure alone do not prove malicious retransmission.

## 9. Current-message overlap and the research premise

All **2,247 / 2,247 positives** have an exactly equivalent normal observed-message signature across direction, protocol/unit/function, register/count/scalar fields, MBAP/TCP/frame lengths and exception indicators. There are just 14 distinct positive signatures and 10 positive request command signatures. Adding absolute TID still leaves 438 / 2,247 (19.49%) matching normal signatures.

This supports the motivation to inspect context: malformed fields or an unseen command are not sufficient explanations here. It does **not** prove full payload equality, difficulty for every current-message classifier, independent replay diversity or a useful sequence detector. Normal overlap is expected when valid polling commands recur. The absolute TID ranges and timing can still encode scenarios.

## 10. Shortcuts and attack independence

| Negative stored TID rule | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Replay derivative alone | 2,213 | 31 | 7,216 | 34 | 0.986185 | 0.984869 | 0.985527 | 0.004278 | 0.993154 |
| Replay positives + full normal | 2,213 | 7,854 | 142,146 | 34 | 0.219827 | 0.984869 | 0.359428 | 0.052360 | 0.948189 |

The same positive support produces a large precision collapse when difficult normals are included. This is a shortcut diagnostic, not the final detector. Other fixed repeated-TID, jump, signature, direction, function, size and timing rules, plus in-sample endpoint/field artifact probes, are reported in the TID audit/JSON. No hard normal cases were removed.

Of 2,247 positive **message** rows, 2,074 are requests and 173 are replies. Positive requests are distinct observed proxy/TID/unit/function keys, but not established independent attacks. Of those requests, 1,141 have an observed reply and 933 do not. Among positive reply rows, 102 attach to positive requests, 8 to normal-labelled requests, and 63 are unpaired. These categories must not be double-counted as campaigns.

Ten inferred replay segments contain eight positive-bearing segments; 2,212 / 2,247 positive message rows (98.44%), and 2,057 / 2,074 positive requests (99.18%), are in one long segment. Seven short positive segments carry only 35 positive message rows. Six named normal source files and 80,639 four-tuple/lifetime proxies do not establish independent runs. The number of independent replay campaigns is **unknown**. No group-level class balance or confidence interval can be honestly computed without that grouping.

## 11. Leakage and split feasibility

The saved manifest shares `replay_capture_2` between train and test; normal source files are separated and a 300-second replay embargo is used. This reduces direct temporal adjacency but not campaign/recording dependence. The source also contains label-based row moves to force class representation and a fallback that discards an otherwise-empty embargo. Those fallback risks are real code, but are not demonstrated to have fired in the saved run. No random row split, SMOTE, pre-split fitted scaler/imputer, target-column input or pre-split feature selection was found in the visible training path. The old median imputer and class weight correctly use training data only.

The old outstanding-request feature is invalid: its request-time iteration increments from eventual missing-response status and decrements from eventual matches, without tracking actual response events or expiry. It can know a prior request will miss its deadline before that deadline and accumulates historical omissions rather than actual pending work. Response latency/terminal status are available only after reply/deadline and cannot support a request-arrival claim. See [leakage audit](LEAKAGE_AUDIT.md) for severity and exact source evidence.

Verified campaign groups are unavailable; capture identity is missing for replay, and even normal filenames need run/chunk/interface mapping. Treating the entire unproven replay derivative conservatively as related evidence leaves no independent positives for three partitions. Arbitrary segments cannot repair this. Independent train/validation/final-test feasibility is **UNSUPPORTED** from this checkout. The new split helper requires explicit independence evidence and refuses to manufacture balance. See [evaluation design](EVALUATION_DESIGN.md).

## 12. Existing results and ablation

Saved-model inference and the original training helper reproduce exactly: **TP 573, FP 42, TN 25,288, FN 20; F1 0.948675; FPR 0.001658; ROC-AUC 0.999501; average precision 0.983806**. Original training support is 53,342 normal/1,435 replay; test support is 25,330 normal/593 replay; 53 requests are gap-excluded. Hyperparameters, feature order, training-only imputation/weighting and seed are recoverable. Full [results](RESULTS.md) distinguish exact reproduction, probability-rounding differences and four-extra-FP variation in explicitly single-thread diagnostic refits.

Historical gain importance is dominated by response latency (60.043%), flawed outstanding count (17.889%) and timeout (8.213%). One-per-field fixed-seed permutation also makes the bad counter prominent. Importance does not establish transaction-consistency novelty.

After the audit, limited **diagnostic** A/B/C refits reused exactly the same historical targets/split, with new causal features and reset histories, and no tuning or final-model persistence. Current-request XGBoost B gives F1 **0.232040**, causal context C **0.930421**. However, **current fields plus timing already give 0.929669**. C without TID context gives 0.926672; C without timing falls to 0.452860. The gain is primarily timing/polling behavior inside one shared scenario. The recent TID+command recurrence rule detects zero positives under the fixed bounded window. This does not establish a distinctive payload/sequence consistency contribution or independent generalization. No claim of XGBoost superiority over other classifiers is warranted.

## 13. Detection latency and decision point

The new model's earliest causal decision point is observation of the complete current request plus preceding bounded history. It does not see the current response, timeout or later repeat. A duplicate feature can only flag the later recurrence at its arrival. No outcome input is made available early by filling a default value.

Response latency requires an observed reply; missing-response inference additionally requires elapsed search bound and complete capture coverage. Historical mean 24.81ms “operational delay” and 0.0004ms per-row model timing are offline batch summaries with a hardcoded timeout sentinel, not an actual live end-to-end latency experiment. New inference explicitly reports batch/amortized compute time and leaves operational end-to-end latency unmeasured. Parsing, reassembly, feature updating, buffering and scheduling must be measured separately on a logged replay schedule.

## 14. Implemented fixes and reorganization

- Added `component4_replay/` with simple strict loading, conservative reconstruction, bounded causal features, manifest validation, shared metrics, fixed-config A/B/C XGBoost training and compatible batch inference. No unnecessary framework, SHAP or oversampling added.
- Preserved CSV row identity/hash and source filenames where present. Unknown PCAP/campaign identity stays missing. Separated observed segments from verified captures/runs and endpoint history from session proxies.
- Removed outcome-dependent counters/current outcomes from new request-arrival model inputs; retained outcomes, label conflicts and unpaired replies as audit metadata. Missing optional values/history stay missing.
- Introduced new-directory-only output writes, checksummed input/output/model linkage, producing-code hashes, deterministic gzip, fixed seed/thread settings, runtime lock and explicit feature schema/decision point.
- Required explicit train/validation/test independence assignments with evidence; rejected missing classes/shared groups/known source overlap/identical events crossing partitions instead of reallocating labels.
- Kept all historical data/results/models and old source in place. Guarded old CLI and made the original dashboard a labelled read-only historical viewer so fixed-name artifact writes/deletions cannot erase evidence.
- Added student instructions and scientific reports. New `audit_v2` preparation is canonical; initial developmental `audit_v1` is preserved, not silently replaced. A working synthetic train/infer artifact round trip and scientific invariants pass **24 regression tests**. Legacy integration tests that overwrite historical artifacts were deliberately not run. Full-data preparation and exact legacy reproduction were executed; no new final current-data classifier was trained.

See [student README](../component4_replay/README.md) and [validation record](VALIDATION.md). Other components, Git branches and original datasets/results were preserved.

## 15. Unresolved evidence

Replay source filename/recording lineage, original shared CSV exporter and extraction selection, raw payload bytes, TCP stream/sequence continuity, attack-log mapping, full response visibility, true episode/campaign independence, and live detection-delay evidence remain unresolved. Code cannot reconstruct missing evidence honestly. New preparation is still offline batch processing; its bounded history is not a production streaming sensor. The explicit manifest checks enforce mechanics but cannot automatically verify the truth of a human-supplied run log.

## 16. Is CIC sufficient without a new testbed?

**These CSV extracts are insufficient for the final research claim. CIC as a whole is CONDITIONAL, not condemned or certified by this limited audit.** The public description confirms PCAPs, timestamped attack logs, multiple interface/bridge views and sequential chunks, which might support a targeted provenance/transaction check if the original producer/source mapping is recovered. It does not establish independent campaigns in the current derivative. [CIC dataset description](https://www.unb.ca/cic/datasets/modbus-2023.html).

No full archive extraction was necessary or launched. Existing source/CSV evidence plus a tiny synthetic parser check resolved the implementation ambiguities within scope. A limited future check could map the identified long-segment boundary examples to one known recording/log; it would not by itself create independent campaigns. The planned isolated testbed supplement is the clearest way to obtain controlled valid replays, realistic normal repetition and independent logged runs for the research question and TAF commitment.

## Final Verdict

**Dataset provenance:** FAIL  
**Replay-label plausibility:** CONDITIONAL  
**Transaction reconstruction:** CONDITIONAL  
**Transaction-ID feature semantics:** CONDITIONAL  
**Duplicate/payload feature support:** CONDITIONAL  
**Session/capture grouping:** FAIL  
**Leakage control:** CONDITIONAL  
**Existing model results:** INVALID  
**Transaction-consistency novelty:** NOT ESTABLISHED  
**Independent evaluation feasibility:** UNSUPPORTED  
**CIC suitability for Component 4:** CONDITIONAL  
**Controlled-testbed supplement required:** YES

“INVALID” concerns use of the historical scores as scientific evidence of independent replay detection/novelty; their arithmetic, saved inference and original-helper fit are reproducible. “CONDITIONAL” feature/reconstruction/control verdicts reflect implemented corrections together with unresolved stream/provenance evidence. They do not certify the legacy features or a final independent model.

### Single best next action

Record a small isolated Modbus/TCP testbed dataset in at least three independently restarted, fully logged runs, each containing repetitive normal polling and valid-request replay at varied delays, preserving complete ADUs and run/stream labels.
