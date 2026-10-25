# Research alignment and proposed methodology amendment

This note is ready for an academic discussion. It records proposed wording and known evidence; it does not record approval that has not occurred.

## Keep the component question

The TAF's Component 3 requirements on pages 9–10 are command sequence and request–response analysis, legitimate protocol semantics, judging validity in surrounding context and comparison with a per-packet baseline. A controlled protocol-valid injection study can address that question without changing ownership into DoS, reconnaissance or replay detection.

The individual proposal's page 21 specifies normal, command and response classes and comparison of isolated-event and context-aware Random Forests. Pages 28–30 cover grouped evaluation, ablation, uncertainty and threats to validity; pages 31–35 cover event lineage and the shared result schema. Those remain appropriate later targets, not completed work.

The proposal's page 22 names CIC as the primary source and a controlled testbed as optional gap-filling. Promoting the testbed to the main experiment is a methodology change. References to MSU/external datasets are not an instruction to introduce them; they remain excluded from this work.

Sources are the supplied PDFs and their cached page text in `component3_preparation/output/reference_review/`. Historical prompts and narrated model results are reference evidence, not proof of current labels or research success.

## Evidence supporting a change

| Stage | Supported conclusion | Limit |
|---|---|---|
| Legacy export/app rebuild | Working software and preliminary binary models; baseline/contextual accuracy both approximately 99.61% | Context improvement was not demonstrated; inherited targets, inferred attack groups and prior test exposure limit interpretation |
| Original CIC extraction | 3,768,287 decoded/candidate records; accepted 1,404,306 normal, 100 command and 54 response records | One class-bearing campaign per class; 151/154 accepted targets malformed; response markers/static patterns dominate |
| Independent review/reassessment | Timing-window sensitivity and endpoint coverage gaps reproduced; all 154 accepted attack bytes/log links checked | Narrowing time windows is not a justification for new labels; more rows/views do not create independent campaigns |
| Local software testbed pilot | Actual TCP capture, 216 verified messages, 208/4/4 labels, normal controls matching all eight target role/PDUs | One scripted connection/process, 12 related episodes; no final dataset, learned model result or plant generalization |

The 48 conflicting exported observations found in the historical reference CSV audit concern those reference exports, not an assertion that 48 new raw-CIC or testbed labels conflict. The two historical attack CSV versions have different row counts. Keep that diagnostic history distinct from the evidence-supported replacement sources.

## Proposed amendment text

> The original CIC material remains a preserved, separate case study of protocol extraction and evidence limitations. The primary controlled experiment will use newly measured Modbus/TCP traffic from an isolated software PLC/HMI testbed with declared process rules, protocol-valid command and response interventions, matched normal controls and exact capture-level ground truth. Evaluation will concern held-out executions and selected conditions within this testbed. It will compare protocol checks, simple causal contextual rules, an isolated-event Random Forest and the same learner with causal context. The study may find no added value from ML. It will not claim generalization to independent industrial plants, broad unseen attack families or real physical-process effects.

CIC and lab rows will not be silently pooled, and no additional external dataset is proposed.

## Decisions to record

1. Accept or reject the testbed-primary methodology change and bounded within-testbed claim.
2. Confirm that direct compromised-client commands and compromised-server reply interventions match the intended threat model; this is not a MITM or authentication-bypass demonstration.
3. Confirm the public policy/object-role information available to every method and the causal decision points.
4. Review the normal-control/scenario matrix and prospective held-out conditions before larger collection.
5. Keep the existing software/dashboard as an integration shell. Its old binary models and high scores do not describe the new pilot or proposed experiment.

The next technical implementation is a separate generator/validator version and four unscored qualification captures. Final collection remains conditional on those checks and the methodology decision. Student-owned preprocessing, training, interpretation and viva demonstration remain later work; no claim is made that the student has already performed them.
