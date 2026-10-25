# What to do after the Component 3 reassessment

## Decision

The reassessment completed its diagnostic job. **It did not recover a training-ready dataset.** Accepted counts remain 1,404,306 normal, 100 command injection and 54 response injection. No new labels or replacement split were produced, and no sound justification for changing timing tolerance was found.

Keep the preparation and reassessment. The next step is to settle the academic objective, then pursue only the work that can answer that objective. More model code or repeated timing-window searches will not resolve the evidence limitations.

## What this independent review checked

- All eight supplied reassessment tests pass in the review environment. Several tests check recorded diagnostics rather than independently rechecking all original packets; passing them does not establish full data correctness.
- All 28 recorded code/configuration/stage-output hash checks match the downloaded package.
- The early/middle/late accepted class counts were independently recomputed from the baseline Parquet annotations and events and agree with the report.
- No full extraction, new labels, replacement split, preprocessing or training was run during this review. The supplied folders were not edited.

The earlier independent preparation review already checked all 154 accepted injection messages against local original PCAP bytes. This step did not independently repeat the new broader-view raw pilot. Its coverage findings remain bounded observations, not full-chain validation.

## What changed and what did not

The useful new finding is a specific broader extraction option: 17 compromised-SCADA/HMI capture files and 19 benign/HMI files, totalling 3,523,493,170 bytes. The bounded pilot found broader target coverage and observation copies. These chains have not undergone full TCP reconstruction or new label acceptance.

This option could improve command coverage and normal endpoint controls. It does not guarantee comparable benign controls at attack addresses, more well-supported command labels, diverse forged responses, additional independent campaigns, or successful process manipulation.

The 63 parser-ok command candidates under a 1 ms window remain candidates. The reassessment found no independent clock/identity evidence justifying that policy change. Both those candidates and the existing accepted parser-ok commands lack observed matched replies in the selected-view audit. That does not prove success or failure.

## Why the phase table is not a ready-made split

The diagnostic thirds within each campaign contain these accepted attacks before any boundary exclusions:

| Phase | Command injection | Response injection | Parser-ok commands | Parser-ok responses |
|---|---:|---:|---:|---:|
| Early | 57 | 13 | 2 | 0 |
| Middle | 34 | 18 | 0 | 0 |
| Late | 9 | 23 | 0 | 1 |

All classes being present is necessary for this type of evaluation, but it does not make the design valid. Corresponding phases mix January normal traffic with different March attack periods and reuse each campaign. They are not one globally forward-in-time deployment test. Some connections cross proposed boundaries; burst and later-response dependencies still need resolution. The late phase has just nine command targets before purging, all malformed.

A model can technically be fitted to small samples. The defensible claim would remain narrow. This table cannot establish independent-campaign generalization or meaningful training and testing on varied valid-looking response attacks. In particular, the early response cohort contains only malformed messages.

## The two decisions to put to the supervisor

**If independent-campaign three-class ML evaluation is mandatory:** the available evidence does not currently support it. Retain that conclusion. Broader views of the same campaigns cannot fix the requirement. The supervisor needs to resolve the requirement/data mismatch; do not manufacture a successful split. MSU and other datasets remain excluded under the current instruction.

**If a narrower CIC within-testbed study is acceptable:** agree on a documented scope such as evaluating what request-response consistency and causal command history add beyond current-message protocol/signature checks in this particular testbed. The outcome may be that simple checks explain the accepted attacks and historical context adds little. That is a possible research result, not grounds to alter labels or seek favourable scores. A Random Forest comparison may remain an exploratory method if a suitable cohort and split can be justified; the reassessment has not established that yet.

Do not promise that a protocol-only implementation automatically satisfies the original assessed ML component. The supervisor should confirm how a narrower claim or negative finding will be assessed.

## Message she can send herself

> I completed a CIC-only extraction audit and a separate evidence/coverage reassessment. The current accepted cohort has 100 command-injection and 54 response-injection messages, each from one campaign. Of these, 151 are malformed; all accepted forged replies contain the same ABCD marker. The existing candidate split is unsuitable for supervised three-class evaluation. A broader HMI capture option exists, but it cannot create independent campaigns and may not solve response diversity. Can we agree on a narrower within-testbed study comparing current-message checks with request-response/history context, with explicit limitations and the possibility that context gives no improvement? If the original independent evaluation is mandatory, the present CIC evidence does not support that requirement.

## Technical next step if that narrower objective is accepted

Continue in her existing repository with the following instruction. This is conditional guidance, not an instruction to run expanded extraction in the present review.

> The agreed academic objective is a limited CIC-only within-testbed comparison of current-message detection with causal request-response/history context. It does not claim independent-campaign, unseen-device or general deployment performance. Continue from component3_reassessment/v1_20261024 and implement its proposed canonical HMI expansion in a new version, preserving component3_preparation and the reassessment byte-for-byte. Use the exact source manifests for the 17 compromised-SCADA/HMI and 19 benign/HMI files, not a folder glob. Resolve actual repository/raw paths from local configuration. Validate a representative stream-reassembly pilot and resource/continuity gates before full selected-chain extraction. Preserve raw bytes, timestamps, values and source/stream lineage; never append overlapping endpoint copies as extra observations. Recompute log candidates and risk checks under the frozen evidence policy; do not transfer old event labels or switch tolerance for higher counts. Keep ambiguous observations unknown and attempts separate from outcomes. Retain the existing IED response evidence separately within its same parent campaign and report its limited diversity. Produce a version comparison, mechanism/endpoint/function/address/PDU/parse/pair coverage, and a proposed evaluation design with class support after connection/pair/burst boundary handling. Use actual observed controls, not unlabelled attack-period traffic renamed normal. If controls, evidence or valid evaluation remain insufficient, report the failure explicitly. Stop before adopting final partitions, engineering model features, preprocessing, resampling or training. No MSU or other dataset is permitted. She will implement and explain later preprocessing herself.

She should paste that only once the stated narrower objective actually reflects the agreed research scope. If the supervisor instead retains the original independent-campaign requirement, this expansion is not a solution to that requirement.

## Files to use

Start with her existing `component3_reassessment/v1_20261024/DECISION_REPORT.md`. The concrete expansion manifest is `output/expanded_scope_plan.json`; the phase probes and boundary warnings are in `output/temporal_feasibility.json`; the unadopted timing policy is documented in `PROPOSED_POLICY.md`.

This independent check is recorded in `independent_checks.json` beside this note; its read-only reproduction script is `../review_reassessment.py`. Current recommendation: discuss the objective using the decision report now, rather than treating another split or a trained model as evidence that the problem is solved.
