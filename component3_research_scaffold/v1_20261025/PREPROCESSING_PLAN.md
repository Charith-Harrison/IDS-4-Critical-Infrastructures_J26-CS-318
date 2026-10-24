# Student preprocessing plan - design only

**Nothing in this document has been applied to real data.** The student will implement and
demonstrate this stage later. The scaffold exercises invented contract violations only.
Do not run the repository's old binary `prepare_data`/model workflow against the new captures.

## 1. Wait for accepted evidence, then freeze the question

The current main status is STOPPED, two accepted executions out of 104; MX003 has capture
drops. First finish the manual frozen collection with intact seals and all acceptance checks.
The final marker must be `ALL_104_VALIDATED`. Collection success is necessary, not proof of
an adequate experiment. Separately record agreement on the testbed-primary academic claim;
the repository currently records no supervisor acceptance of that amendment.

Use this question: in this declared simulator, do earlier observable Modbus exchanges add
useful information beyond the current message for the two defined injections? Compare
simple causal rules as well as the same learner with/without history. Do not claim unseen
industrial campaigns, physical safety, malicious intent in every valid command, or an ML win.

## 2. Make the later implementation reproducible

Create a new versioned preprocessing workspace. Record code/config/environment hashes,
original capture and annotation hashes, frozen protocol/roster identities, exact commands
and later feature definitions. Preserve raw files, private evidence, accepted labels and
their lineage. Never write model outputs into an original capture folder.

Keep three distinct channels:

| Channel | Contents | Later access |
|---|---|---|
| Observations | Current raw/decoded public wire information, connection/stream order | Input reader; only declared information reaches predictors |
| Truth | Accepted `normal`, `command_injection`, `response_injection` with direct evidence | Evaluator/target reader only |
| Provenance | Run/group/role, IDs, file/frame/byte references, hashes, private scenario/audit state | Auditor/group allocator only |

One ADU is one complete request or reply, not one Ethernet frame. A transaction usually
contains request and reply ADUs. Use the verified pairing and connection generation/stream
position. Literal TID 5 is not unique. Preserve real repeated equal PDUs at different stream
positions; contain copied/mirrored observations rather than dropping all equal payloads.

## 3. Respect prospective whole-execution roles

Do not randomly split rows. Resolve actual accepted runs against the already frozen roster:
32 train, 16 validation, 24 final repeat, and 8 each final values/map/order/timing. These are
planning roles until later accepted-evidence allocation; this task created no split files.
Every continuation, mirror, export and shared-history/counterfactual twin stays in its related
group. Retries do not add extra planned samples. Keep the separate final stress tests separate.

Pilots, Q01-Q04 and EQ01-EQ14 are engineering evidence only. They cannot fit transformations,
choose features/thresholds, tune or score a model. Old derivative CSVs, old models and original
CIC rows do not enter this simulator study. Do not inspect final-test message values to decide
features or hyperparameters. Operational seal/hash/support checking is not model tuning.

## 4. Define information available at the decision

For an injected command, decide when the complete request arrives, before its ACK.
For an injected response, decide when the complete reply arrives, with its earlier paired
request and earlier acknowledged updates available only to contextual methods.

| Information | Current-message B | Contextual C/D | Notes |
|---|---|---|---|
| Current function/unit/direction/PDU contents | Eligible | Eligible | Decode only fields present in that ADU |
| Address/quantity of current read request | Eligible | Eligible | Public map supplied equally |
| Address of a current FC3 response | Absent | Earlier paired request may supply role | Never pretend address is in reply bytes |
| Earlier trusted mode read | No | Eligible when valid | Latest eligible observation, not private server mode |
| Earlier successful setpoint FC6 ACK | No | Eligible when valid | Exact observed echo, not a planned write |
| Current numeric TID/endpoints/ports | B-wire companion | D-wire companion | Primary semantic comparison excludes these nuisance fields equally |
| Absolute time, run/episode/step/seed/group/role | No | No | Pair/order identifiers may route evidence, never be predictors |
| Label, private hook/state/scenario | No | No | Used only to establish truth/audit |
| Future ACK/recovery read/next step | No | No | Never available to an earlier decision |

These are eligibility rules, not a selected feature vector. Student code should use an
explicit allow-list and fail on undeclared columns. Do not rely on dropping only a few known
label names. A re-labelled copy of a forbidden field is still leakage.

## 5. Implement causal history later, with understandable state

First draw the messages on paper. An ON request needs the latest genuine mode observation;
a readback needs the earlier associated request and latest acknowledged setpoint update.
Use only observations that precede the decision. Writes/transitions may invalidate old
anchors. The trust model assumes one writer, one outstanding transaction, genuine mode
observations and FC6 ACKs, and no autonomous setpoint changes.

Reset at a new recording/connection generation or unresolved capture gap. Do not reset at a
private episode boundary, which a real detector cannot see. No eligible anchor means
unknown/abstain. Do not fill it with mode 0, a guessed setpoint, normal, or attack.
Report warm-up/abstention coverage for every method. The frozen design spans 0/2/4
intervening ADUs for command anchors and 1/3/5 for response anchors; the declared maximum
intervening-ADU budget is six. That is a design constraint, not an implemented window here.

The primary plan separates whole runs, so no history crosses roles. Any later approved
within-run temporal analysis would require explicit lookback and reply/label horizons,
purging and warm-up, quiet/dependency-safe boundaries, no cut request/reply or burst, and
containment of connections/mirrors. No such alternate split is authorized or created now.

## 6. Define a common evaluation cohort before scoring

Use public task definitions: pump-ON requests and paired setpoint-readback responses.
The evaluator may use verified associations to identify the same tasks for all methods.
Do not select examples by private scenario name. Request-derived response role is an audit
eligibility fact, not a B predictor. Report all validated traffic and dispositions alongside
task-conditioned scores. Also report common supported-cohort comparison and each method's
coverage/abstention; never silently discard difficult or unanchored examples to improve D.

## 7. Decide transformations from training only, then lock

Only after the student has defined causal inputs and checked training support:

1. Keep targets and provenance outside predictor tables. Record a column dictionary with
   source bytes, derivation, availability time, units (raw lab words only) and missingness.
2. Distinguish absent protocol fields from lost/unknown context and malformed messages.
   Do not force a response address into existence or globally remove unknown observations.
3. Decide which transformations, if any, are needed by the chosen learner. No universal
   requirement to scale/normalize every field is imposed here. If a transform learns means,
   categories, ranges, imputations or profiles, fit it only on training groups.
4. Freeze fitted state and apply it unchanged to validation/final data. Define unseen category
   handling from training-time design. Never fit separately to make test data look familiar.
5. Choose model/threshold settings with training and permitted validation only. Record every
   choice before opening final test scores. No feature selection using final-test labels.
6. Retain the measured prevalence and normal-only controls. Do not oversample to repair
   missing independent support. No resampling method is selected or authorized by this plan.

No context/lag/rate features, sequence windows, X/y matrices, imputation, encoding, scaling,
normalization, resampling, feature selection or normal-profile fitting was performed now.

## 8. What to demonstrate in the viva

Show one real example only after authorized later implementation. Trace frame/byte lineage,
current ADU, earlier visible anchor, direct truth evidence and actual decision time separately.
Explain why the same current PDU can be normal in another history. Show why an injected
command's genuine ACK remains normal. Demonstrate a missing-anchor abstention, literal TID
5 reuse, new-connection reset and an attempted forbidden metadata column.

Then explain which groups fitted each learned transformation, where its saved parameters
came from, how validation was used, why final tests stayed sealed, and why one simulator is
not independent industrial generalization. A synthetic contract test is a rehearsal of those
explanations, not a substitute for the future implementation or its results.
