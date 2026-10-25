# Component 3 preparation: independent review and next steps

Reviewed 24 October 2026. Supplied project: `D:\VSCode\GitHub\4th Year Cyber\C3\component3_preparation`. Original captures inspected at `G:\modbus cic 2023\Modbus Dataset`.

## Decision

**Keep the extraction work. Do not use the current candidate memberships as a supervised three-class train/validation/test split. Investigate evidence matching and endpoint coverage before deciding the research component is unworkable.**

The supplied feasibility report is appropriately conservative. It does not claim to have produced a valid independent three-class experiment. Its current accepted cohort genuinely contains mostly malformed attack messages. However, “only two parser-ok command attacks accepted by this policy” is different from “the CIC source contains only two well-formed malicious commands.” This review found concrete reasons to investigate that distinction.

The extraction and annotation stage has value as a reproducible evidence foundation. It has not yet demonstrated that contextual machine learning is needed, that injections changed the physical process, or that a classifier generalizes to an independent campaign. Those are separate claims requiring separate evidence.

This review used CIC only. It performed no model preprocessing, training, new accepted labelling, repartitioning or full extraction rerun. The downloaded preparation folder and raw captures were left unchanged. Review scripts and results are in this review directory and its parent.

## What was independently checked

| Check | Result | What it establishes |
|---|---|---|
| Existing offline tests rerun | 30 passed | The supplied parser, pairing, evidence and integrity tests pass in this environment; not proof of exhaustive correctness |
| Downloaded source files against recorded environment hashes | All 14 recorded code hashes match | These downloaded modules match the modules named in the supplied environment report |
| Actual Parquet annotations and target PDUs read | Reported accepted counts and shape composition reproduced | Findings are present in data, not just prose |
| All 100 accepted command examples checked against original PCAP frames with an independent decoder | No byte/value/shape disagreement | Invalid coil values are present in original packets; the 98 malformed accepted commands are not explained by the old CSV export error |
| All 154 accepted injection ADUs checked against original frame payloads using saved lineage | 154 matched, no mismatch | Accepted event bytes agree with the local original captures for these examples |
| Matching-window and endpoint-scope diagnostics independently recomputed | Results below | Identifies policy/coverage constraints without changing labels |

This was not an independent reconstruction of all 3.7 million ADUs. It does not validate every unlabelled event, every TCP edge case, or every source checksum. Original-byte agreement also does not itself prove maliciousness; accepted labels still depend on the original log interpretation and matching policy.

Evidence files: [cohort audit](cohort_audit.json), [scope and pair audit](scope_and_pairs_audit.json), [raw command/code checks](independent_review_checks.json), [all accepted byte checks](accepted_original_bytes_check.json). Reproduction scripts: `audit_cohort.py`, `audit_scope_and_pairs.py`, `validate_accepted_bytes.py`, and `../review_component3_bundle.py`.

## 1. The current split cannot support the intended experiment

These are accepted labelled ADUs, excluding unknown/unlabelled observations:

| Candidate partition | Normal | Command injection | Response injection |
|---|---:|---:|---:|
| Train | 1,404,306 | 100 | 0 |
| Validation | 0 | 0 | 0 |
| Test | 0 | 0 | 54 |

There is no response-injection training class, no accepted validation targets, and no normal or command test examples. This cannot train, tune and assess the proposed supervised three-class model. The membership files are useful audit artefacts, not scoring-ready data. The requested 70/15/15 ratio has not become a valid experimental split.

The code labels this situation `CANDIDATE_ONLY_UNSUPPORTED_INDEPENDENT_THREE_CLASS_EXPERIMENT`. That is the correct result under its present whole-campaign independence requirement. Each accepted class appears in only one conservative campaign group. More rows, repeated days, oversampling or mirrored PCAP copies cannot create additional independent campaigns.

Relevant source: `c3prep/audit.py` assignments near line 13 and class-completeness assessment near line 273; actual membership: `output/split_manifest.json`.

## 2. The malformed attack examples are real, but they are a narrow cohort

| Accepted class | Malformed PDU | Parser-ok PDU | Total |
|---|---:|---:|---:|
| Command injection | 98 | 2 | 100 |
| Response injection | 53 | 1 | 54 |

The 100 accepted command PDUs comprise six byte patterns. The common ones are `05000dffff`, `05000effff`, and `0500080001`. For FC5, the on-wire output values permitted by the Modbus specification are `0x0000` and `0xFF00`; `0xFFFF`, `0x0001` and `0x0008` are invalid. See section 6.5 of the [Modbus Organization application protocol specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf). This agrees with the independent raw-packet checks and the request decoder in `c3prep/modbus.py` near lines 102–108.

The two parser-ok accepted commands have the same PDU, `050001ff00`. All 54 accepted responses contain the `ABCD` marker and comprise only three patterns: `01abcd` (52), `02abcd` (1), `0302abcd` (1). The first two are malformed byte-count responses. The last is structurally accepted as an FC3 response returning raw register word 43981.

This is a serious shortcut risk. A detector may recognize malformed shapes, fixed payload markers, addresses, device identities or capture periods instead of useful command context. A high score would not establish detection of stealthy, valid-looking injections. A parser-ok result also does not establish authorized operation, plausible physical values, or meaningful process impact.

The labelling code does **not** require malformed PDUs as a condition for accepting command/response labels. Therefore, the concentration of malformed targets is not simply an explicit “malformed means attack” rule. Selection and ambiguity still affect which examples qualify.

## 3. The main command salvage lead: matching policy

The selected compromised-SCADA view contains **99,290 FC5 requests**, including **46,297 parser-ok requests** and 52,993 malformed requests. These parser-ok requests are observations, not 46,297 established attacks.

The frozen label policy uses a 25 ms matching window with campaign, target, literal transaction ID, logged coil behavior, connection-risk exclusions, calibrated clock offset and uniqueness requirements. A log must have a unique supported packet candidate, and the packet must have a unique supported log. Dense repeated requests make this deliberately restrictive.

Holding the existing candidate edges, offset and risk filters fixed, this review recomputed two-sided uniqueness at different windows:

| Absolute residual window | Unique command candidates | Parser-ok | Malformed |
|---|---:|---:|---:|
| 0 microseconds | 82 | 34 | 48 |
| 1 ms | 400 | 63 | 337 |
| 5 ms | 187 | 10 | 177 |
| 25 ms: current policy | 100 | 2 | 98 |

These are **diagnostic candidates, not newly accepted labels**. More candidates at a narrower window are possible because a wider window introduces competing matches and removes uniqueness. All 63 parser-ok candidates at 1 ms share `050001ff00`; increased count would still leave limited payload diversity.

Do not choose 1 ms because it produces more attacks. First establish timestamp precision, capture timestamp semantics, offset/jitter stability, TID semantics and burst behavior from independent evidence. A narrowly timed coincidence can still be a wrong match. Any justified revision must be documented, versioned and compared with the frozen policy, including newly rejected matches and ambiguity changes.

Observed wire TID 5 is reused extremely heavily in this view. A log field containing “5” cannot be assumed to mean a range without evidence; equally, an equality match on such a common ID has little identifying power by itself. Original attacker tool source, if present in CIC material, or independently verified packet/log behavior is needed to resolve semantics.

Relevant source: `c3prep/labels.py` line 21, matching near line 108, candidate sensitivity near line 243, acceptance near lines 282–295.

## 4. The second salvage lead: selected endpoint coverage

The completed extraction covers 21 selected PCAP chunks, about 1.816 GB, across four canonical views. It is not extraction of every CIC endpoint. Choosing one observation view helps avoid duplicates, but the chosen compromised-SCADA view is IED1a and does not cover all logged targets.

The scope audit found **153,560 brute-force/specific-coil log signatures outside the selected endpoint scope**: 123,325 targeting `185.175.0.5` and 30,235 targeting `185.175.0.8`. Additional signatures fall outside selected capture intervals. These are log signatures, not proven packet counts, attacks or independent repetitions.

A broader canonical SCADA/HMI capture chain is a concrete inspection candidate. Establish actual observed target/time coverage, capture loss, TCP continuity and overlaps before selecting it. Prefer a complete suitable canonical chain; do not blindly concatenate device, bridge and HMI views of the same traffic. Any additional views remain in the same parent campaign, and equivalent observations require explicit provenance and deduplication rules. Identical application payload at a different genuine stream position is not automatically a duplicate.

Benign controls also need endpoint/function/address coverage. The selected normal view is IED1b while selected commands are from IED1a. Observed benign FC5 request patterns here are `05000fff00` and `050019ff00`; accepted parser-ok attack commands use another address. This creates a device/address shortcut risk. Expanding only attack endpoints without comparable evidence-supported normal controls would worsen that problem.

Relevant source: `c3prep/run_extraction.py` selected views near line 17; `EXTRACTION_SCOPE_AND_GROUPING.md` and `output/selected_source_manifest.json`.

## 5. Injection attempt is different from successful process manipulation

Of the 100 accepted command relations, 82 are recorded as `matched_exception` and 18 as `pending_at_connection_end`. Both parser-ok accepted commands lack an observed matched reply. These examples support the documented injection-attempt evidence; they do not demonstrate a successful malicious state change. A missing reply also does not prove failure.

Of the 54 accepted response relations, 53 are `matched_inconsistent` and one is `matched`. Most can therefore be challenged by protocol or request-relative consistency before invoking learned physical context. A legitimate acknowledgement associated with an injected command remains an acknowledgement; it must not automatically become a forged-response target.

The available raw words are useful, but units, signedness, register meaning, authorization policy and expected physical evolution remain inadequately established. Avoid turning addresses or empirical normal ranges into authoritative safety/permission rules.

## 6. Defensible research routes and dead ends

### Route A: retain independent-campaign generalization

Keep the current conservative grouping. Audit broader coverage and matching evidence, but recognize that more accepted packets in these same campaigns do not fix class-bearing campaign scarcity. If no additional independent CIC runs can be established, report that the requested three-class independent evaluation is unsupported. The honest result can include a protocol/evidence study, limitations and a functioning prototype, without unsupported generalization claims.

### Route B: explicitly narrow the evaluation claim

Subject to agreement on the academic objective, investigate a **within-testbed temporal evaluation**. This is a different question from generalizing to independent campaigns. It requires recovered evidence, supported normal controls, chronological episode/time-block definitions, request/response and connection containment, mirrored-view containment and boundary purging. Repeated days alone do not establish independence. Avoid splitting a continuous attack burst across partitions.

Before adopting this route, produce a class-by-block feasibility table and explain what temporal separation can and cannot prevent. If repeated payload/tool/device patterns dominate, even a clean temporal score may reflect recognition of the same setup. Do not present that as unseen attack-family or deployment generalization.

### Later comparison, if a valid task becomes feasible

The researcher should perform the separate preprocessing stage herself and retain a clear script/notebook for the viva. A meaningful context comparison would need simple protocol-shape and static-signature baselines, a current-message baseline and a causal context model under the same justified evaluation. Assess the incremental benefit of context and disclose malformed versus structurally accepted examples separately. These are future evaluation requirements; no such model comparison was run here.

Only information available at the decision time may enter detection features. Future replies cannot enter a request-time classifier; later replies can support a separately defined delayed decision. Log-match residuals, accepted evidence flags, source folders, filenames, campaign/partition IDs and labels are audit metadata, not legitimate predictors. Historical state must not cross the experimental boundary without a documented deployment-realistic warm-up policy. Fit any learned transformations on training data only.

### Dead ends to avoid

- Random row splitting, shuffled rare episodes, or duplicate views used to manufacture independent class support.
- Labelling all writes, all attack-folder packets, all exceptions or all unmatched responses as injection.
- Treating unlabelled packets in an attack capture as normal.
- Choosing clock tolerance, endpoint scope or episode boundaries to maximize label counts or scores.
- Using SMOTE, duplication or class weighting to claim new attack diversity or independent repetitions.
- Calling a fixed `ABCD` signature or malformed-PDU detector evidence that context-aware ML was necessary.
- Copying labels/values from the old derivative CSVs, or filling their missing provenance with invented values.
- Introducing MSU or another dataset as a fallback.

## Recommended next action

Give her existing coding-agent session `FOLLOWUP_FOR_HER_CODEX.txt` alongside this review and the small JSON evidence files. Keep the current preparation folder as the baseline. The next job is a bounded CIC-only evidence-and-coverage reassessment, followed by a feasibility decision. It is not training, automatic relabelling or another random split.

**The preparation is not wasted. The broad proposed experiment remains unproven. There are concrete command-evidence and coverage leads to investigate, while the response examples and independent campaign support remain major limitations.**
