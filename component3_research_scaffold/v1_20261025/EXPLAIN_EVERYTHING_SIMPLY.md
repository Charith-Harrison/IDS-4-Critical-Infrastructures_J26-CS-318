# Component 3: the whole story in simple words

**As of this review on 25 October 2026: we have built and checked a small Modbus laboratory.
The main collection has two accepted recordings out of 104. It is stopped because the
third recording lost captured packets. We have prepared the next-stage plans and synthetic
checks, but have not preprocessed this dataset or trained a new testbed model.**

This is a dated explanation. Later manual collection may change live counts. Exact input
hashes, audit results and current-at-review counts are in this package's `evidence/` snapshots.
The guide explains the important technical details as well as the simple story; linked source
reports contain the full row-level evidence rather than repeating millions of records here.

## 1. What you are trying to teach the detector

Imagine a controller is a person giving instructions to a little robot, and the software
PLC is the robot. Modbus/TCP is the language they use to talk across a TCP connection.

There are three labels:

| Label | Simple meaning in this experiment | Evidence needed |
|---|---|---|
| normal | A genuine message without the defined intervention | The accepted observation and experiment's evidence contract |
| command_injection | A compromised controller deliberately sends ON while the observed mode forbids it | Direct intervention plus captured request and earlier genuine mode observation |
| response_injection | A compromised server deliberately changes a readback word | Direct intervention plus captured reply, paired request and earlier genuine update/ACK |

The key question is whether remembering earlier messages helps. The words **"turn ON"**
can be perfectly well formed in both cases:

- Earlier the robot said "ON is permitted" -> this ON can be the genuine normal control.
- Earlier the robot said "ON is not permitted" -> this experiment deliberately injects ON.

Likewise, a reply saying "the stored number is 172" can be genuine after an acknowledged
update to 172, or forged after an acknowledged update to 157. Those are lab words, not
degrees, litres, pressure or a real machine's safe operating limits.

The same present message can therefore have different meanings in different histories.
That is the reason for studying context. It does not prove a learned model will beat rules.

A genuine "OK, I received your command" reply to an injected request stays **normal**.
It is associated with an injection; it is not itself a forged response.

## 2. What the TAF and proposal originally asked for

Component 3 is **Command and Response Injection Detection in Modbus/TCP Using Context-Aware
Command Analysis**, within the team's four-component framework. Other components and their
data are preserved. The wider team also studies DoS, reconnaissance and replay; they are
not extra attack mechanisms produced by this Component 3 laboratory.

The team TAF contemplates controlled physical or simulated primary data and describes
protocol/context relationships. The individual proposal describes CIC as the primary
dataset, normal/command/response detection and Random Forest comparisons; a testbed was
secondary. The actual proposed change is to make this controlled testbed the primary
experiment and retain CIC as a separate evidence/capability case study.

**Supervisor acceptance of that change is NOT RECORDED in the repository.** That does not
prove no conversation happened outside the repository, and software readiness is not
academic acceptance. Record the agreed narrow objective before claiming a completed
methodology change. The cached TAF/proposal page text is under
`component3_preparation/output/reference_review/`; the main-design decision explains the
amendment. Current user instructions exclude MSU, New Gas Pipeline, water-storage and every
other outside dataset despite historical proposal references.

## 3. Why the old files and high scores did not solve the problem

The repository already had an application, exported CSVs and old models. The old CSV
inventory has **342,920 rows**, with inherited binary labels **247,960 normal and 94,960
command/response injection combined**. The supplied normal/attack CSV file names and row
counts are not the same thing as accepted original-source three-class labels.

Some old provenance, values, times and target rules could not be established as original
truth. A high historical score could learn export/campaign/protocol shortcuts. It does not
prove causal context helped, separate command/response detection, independent generalization
or performance of the new testbed. The old application remains an integration shell; its
existing models are not new results. Old CSVs are diagnostic references only.

So we went back to the original material rather than copying old labels into new rows.

## 4. What the original CIC rebuild actually did

The actual original location on your machine is:

```text
data/raw/Modbus Dataset
```

It was never replaced with the independent reviewer's G: path. The verified inventory has
**207 files / 15,761,969,012 bytes**: 170 PCAPs, 34 original CSV logs, one workbook, a README
and a setup image. All observed classic-PCAP timestamps use microsecond storage precision.
An original CIC "external attacker" scenario is still CIC; it is not an imported dataset.

The first stage selected complete canonical endpoint/view chains, decoded actual bytes,
rebuilt TCP streams across chunks and recorded source/frame/file-byte lineage. It did not
take only convenient attack packets or silently replace gaps with invented values.

| Original CIC preparation item | Result |
|---|---:|
| Selected original captures | 21 |
| Selected capture bytes | 1,815,936,064 |
| Selected frames | 20,923,685 |
| Complete ADUs | 3,767,894 |
| Incomplete candidate records | 393 |
| Total application/candidate records | 3,768,287 |
| Accepted normal ADUs | 1,404,306 |
| Accepted command injections | 100 |
| Accepted response injections | 54 |

Most other observations did not receive one of those accepted labels. **Unknown does not
mean normal.** Label acceptance used original log/workbook and packet evidence, with
explicit identity/timing and ambiguity rules. Old derivatives supplied no truth values.

There are four conservative parent campaign groups. Accepted normal is concentrated in
one benign campaign; accepted commands in one SCADA campaign; accepted responses in one
IED campaign. Chunks and mirrored views stay inside their parent group. A day or file
rotation is not automatically a new independent experiment.

The candidate whole-campaign allocation had normal+commands in train, no accepted targets
in validation, and responses only in test. It is explicitly **UNSUPPORTED for independent
supervised three-class evaluation**. Shuffling rows into 70/15/15 would hide the problem.
The pairing audit kept **1,982,133 relations** within groups, with zero partition crossings;
**595 sampled mirror clusters** were contained. These are audit results, not proof of every
possible duplicate's absence. No model preprocessing or training was performed in this stage.

## 5. The important CIC shortcomings

| Accepted CIC class | Malformed PDU | Parser-ok | Total |
|---|---:|---:|---:|
| command_injection | 98 | 2 | 100 |
| response_injection | 53 | 1 | 54 |

That is **151 malformed targets out of 154 attacks**. Simple format checks can already
spot much of this particular cohort. All 54 forged-response PDUs contain `ABCD` and use
only three patterns. Endpoint sets, addresses, dates and repeated values also risk shortcuts.
This is a poor basis for claiming that broad valid-looking attacks require contextual ML.

Among accepted commands, 82 have an observed exception reply with code 3; 18 have no
observed matched reply. The two parser-ok commands have no observed reply. No reply does
not prove an attack failed or succeeded. A rejected request, missing reply, genuine ACK,
forged reply and physical effect are separate facts. Parser-ok means structurally decoded,
not permitted, physically sensible or safe.

Original CIC does not establish all the register meanings, units, signedness, authorization
rules, normal profiles or expected physical values needed for the broad semantic claim.
We did not invent them. Extraction success is not experimental feasibility.

Sources: `component3_preparation/FEASIBILITY.md`, `SPLIT_VALIDATION.md`, `INVENTORY.md`,
`LABEL_POLICY.md`, `REFERENCE_AUDIT.md`, raw-byte/label/pair reports under its `output/`.

## 6. What the independent review and reassessment added

The independent review was checked locally without changing the frozen baseline. It asked
whether different timing or a broader capture view could recover evidence.

Hold the matching identities, edges, stream-risk filters and zero offset fixed, then vary
only the allowed residual window:

| Window | Unique diagnostic command candidates | Parser-ok candidates | Frozen 100 retained |
|---|---:|---:|---:|
| Exactly equal time | 82 | 34 | 0 |
| 1 ms | 400 | 63 | 97 |
| 5 ms | 187 | 10 | 100 |
| 25 ms | 100 | 2 | 100 |

These are **diagnostic candidates, not accepted replacement labels**. The exact and 1 ms
sets have zero overlap: changing a window changes which events compete for uniqueness,
not just how many events fit. All 63 parser-ok 1 ms candidates use `050001ff00` and lack an
observed matched reply in that audit. Choosing 1 ms because it gives more targets would be
choosing an answer, not independently justifying clock/identity accuracy.

The selected SCADA IED1a view has **99,290 FC5 requests**, including **46,297 parser-ok**;
**96,200** literally use TID 5. None of those numbers automatically counts attacks. A log
TID is not assumed to mean a range. A reused wire TID cannot uniquely identify an event.

Original CSVs serialize naive decimal times at up to milliseconds; workbook serials carry
full dates/fractions; PCAPs store microseconds. Original naive values were preserved. The
join used ADU completion time, with first/completion/frame times retained. Accepted command
residuals were 32-1,560 us (median 540); forged-response residuals 267-5,717 us (median 969.5).
Observed zero-offset support versus +/-3 hours does not establish one global timezone,
offset, call order, jitter or drift for all logs. Storage precision is not clock accuracy.
No original attacker source/configuration was found in the supplied CIC inventory.

There are **153,560 original brute-force log signatures** outside the selected endpoints:
123,325 for .5 and 30,235 for .8. These are not 153,560 captured packets or independent attacks.
A bounded inspection of **22,895 frames over 20 log windows** found broader .4/.5/.8 coverage.
A possible canonical SCADA/HMI expansion has **17 files / 1,664,745,012 bytes**, with benign
comparison **19 files / 1,858,748,158 bytes**. Sampled overlaps found 1,050 SCADA observation
copies and 18 benign write copies. Full TCP continuity/loss was not established. Sampled
benign FC5 controls remained .5 addresses 15/25, leaving attack-address comparability gaps.
No full expanded extraction, cross-view merge or new label acceptance occurred.

Independent-campaign three-class generalization remains UNSUPPORTED. A within-campaign
temporal study is a different conditional claim. Early/middle/late campaign probes had
normal 465,934/468,838/469,534; command 57/34/9; response 13/18/23 before purge. They combine
different calendar periods and reuse campaigns. Parser-ok examples are still scarce; some
boundaries cut connection generations. No replacement split, warm-up or feature window was
created. Extra days/views do not manufacture independence or response diversity.

Source: `component3_reassessment/v1_20261024/DECISION_REPORT.md`, `PROPOSED_POLICY.md` and
`output/` machine-readable diagnostics, examples, policy/expansion/temporal plans.

## 7. Why you now have a small Modbus laboratory

You then authorized a controlled simulator route. This creates **new laboratory data**;
it does not improve or become original CIC data. The CIC evidence and its limitations stay
unchanged and separate. No MSU or other outside rows are mixed in.

There is a real TCP conversation inside an isolated Docker Linux container. A software
controller sends real Modbus requests to a software server. `tcpdump` records actual bytes.
Private intervention records say exactly when a deliberate change happened; an independent
decoder/state replay checks the capture and those records before accepting labels.

This is not a made-up CSV labelled from a folder name. It is also not a real power plant,
physical PLC qualification, deployed MITM/spoofing attack or independent industrial campaign.
The response hook changes the compromised server's reply; it is not a network interception
demonstration. The command hook changes the controller. Software state effects do not prove
physical process manipulation.

## 8. The pilot and qualification steps

| Stage | Accepted measured recordings | Normal / command / response ADUs | Transactions | Purpose |
|---|---:|---:|---:|---|
| v0.1 small pilot (each default accepted run) | One run per invocation | 208 / 4 / 4 = 216 | 108 | Prove basic traffic, bytes, labels and controls |
| v0.2 Q01-Q04 | 4 | 1,822 / 8 / 16 = 1,846 | 923 | Check initial scenario collection |
| v0.3 EQ01-EQ14 | 14 | 33,646 / 108 / 216 = 33,970 | 16,985 | Qualify expanded engine and observation controls |
| Main accepted so far | 2 of 104 | 4,534 / 18 / 36 = 4,588 | 2,294 | Fresh prospective research collection |

These stages must not be pooled into one scored dataset. The local pilot was
`pilot-20261024T170840Z-d137ea97`; the earlier collaborator pilot has its own identity.
The documented pilot capture has 12 related episodes, 224 frames and zero reported kernel drops.
An initial PowerShell block came from the downloaded-file mark on an unsigned script;
only the reviewed script's mark was removed, leaving script bytes and system execution
policy unchanged. That old signing issue is separate from the current packet-capture loss.

v0.2 has 80 episodes and zero reported capture drops in its four accepted runs. An earlier
failed Q01 attempt, caused by a missing import, was preserved and excluded, not silently
relabelled. The initial qualified condition was only M0/V0/S1; anchors were just 0/1 ADU
away and wire TIDs incremented sequentially. That was not enough engineering evidence for
all the proposed new conditions.

The initial 48-run draft therefore gave way to a prospective 104-run design with separate
engineering probes. v0.3 qualified the new TID/gap profiles, maps, values, orders, timings
and normal-only mode in 14 fresh-seed unscored probes. Twelve mixed probes give nine command
and 18 response targets each; two normal-only probes contain zero attack targets. All have
zero reported kernel drops. There are 1,260 episode slots; 33 offline tests passed. All
324 target lineages were checked; 108 literal-TID-5 targets also have exact full-ADU normal
controls. These checks support collection, not a model score or an absence of all shortcuts.

Engineering captures remain excluded from fitting, tuning, feature/threshold selection and
scoring. More engineering rows do not fix that exclusion. v0.2's historical summary calls
the environment one campaign; that means one simulator setting, not an industrial campaign.
v0.3 explicitly reports one software environment and zero independent industrial campaigns.

Sources: `component3_testbed_pilot/`, `component3_testbed_v02/`, `component3_testbed_v03/`;
captures under `component3_collection_runs/design-v1/` and `engineering-v03/`.

## 9. Exactly what the frozen experiment contains

There is one controller/server connection per run, one outstanding transaction, unit 1,
IPv4 loopback `127.0.0.1:15020`, and FC1/3/5/6. Docker networking is disabled and no host
ports are published. The server has a mode word, setpoint word and pump coil.

| Public map | Mode register | Setpoint register | Pump coil |
|---|---:|---:|---:|
| M0 | 0 | 1 | 1 |
| M1 | 10 | 11 | 7 |
| M2 | 40 | 41 | 21 |

Mode 0 forbids ON; mode 1 permits ON. OFF is allowed in either mode. **Setpoint writes are
allowed in either mode.** The software server deliberately has no enforcement interlock for
the valid unauthorized ON, so it may act in software. The lab policy is supplied to every
comparison, not discovered from private labels. Raw unsigned value ranges are V0 20-180
and V1 1,000-1,160; these are lab variation ranges, not physical safety limits.

There are six normal families (permitted ON, inhibited idle, authorized update, repeat write,
mode transition, genuine readback) and two intervention families (blocked ON and changed
readback). That means **two attack mechanisms, not eight**. Forged readback changes a to b
and b to a. Same-cell genuine controls carry the same target PDU. A normal-only run uses
comparable templates without interventions.

Each run has **90 episode slots in nine blocks**. Blocks cross three wire TID policies
(incrementing from a random start, literal 5, random 16-bit with replacement) and three
anchor gaps (0/1/2 intervening benign transactions). That corresponds to command anchors
0/2/4 ADUs away and response anchors 1/3/5 ADUs away. The declared maximum intervening-ADU
budget is six. Related episodes and blocks are not independent campaigns.

| Prospective role | Mixed | Normal-only | Whole runs |
|---|---:|---:|---:|
| Train | 24 | 8 | 32 |
| Validation | 8 | 8 | 16 |
| Final repeat | 16 | 8 | 24 |
| Final values | 8 | 0 | 8 |
| Final supplied map | 8 | 0 | 8 |
| Final order | 8 | 0 | 8 |
| Final timing | 8 | 0 | 8 |
| Total | 80 | 24 | 104 |

Core conditions cross two maps, two orderings and two timing ranges. Stress tests change
one axis at a time. Each mixed main run expects nine commands and 18 forged replies, so
**720 commands and 1,440 forged replies are conditional full-collection totals**, not counts
already collected. Normal/ADU/frame totals are measured, not invented quotas. Seeds are
720001-720104; EQ seeds are separate. Fourteen condition cells were directly measured in
qualification and 22 others supported by the same engine's composition checks, for 36
intended cells. Do not call all 36 physically measured qualification cells.

Group whole executions and their mirrors, continuations, twins, histories and exports.
Matching a repeated PDU does not make two genuine positions one event. A different seed
does not make a new industrial campaign. Role order is not counterbalanced, so time/host
drift is a real limitation. Separate role allocation is prospective; no final model matrices
have been created. M2 is supplied legitimate configuration to all methods, not hidden
semantic knowledge. There are no hidden writers/autonomous setpoint changes in the core
claim; mode observations and FC6 ACKs are trusted. Forged anchors are outside this scope.

## 10. What the manual launcher protects

The frozen package is `component3_main_collection/v1_20261025/`.
It preserves source/config/roster/image identity, exact-byte stream/frame associations,
direct intervention/state evidence, causal anchors, matched controls and duplicate containment.
All 24 launcher tests passed at preparation. Historical preservation checks reported 494
protected prior files unchanged. Those are previous checks, not a new 494-file rehash here.

Start/resume is your manual choice. A run counts only after runtime validation and host
verification, not when a timer reaches 100% or the generator exits. Failed/interrupted
attempts remain unaccepted with their evidence preserved. Retries get fresh attempt IDs;
maximum three attempts per planned ID, no endless automatic retry loop.

The central 104-run original-artifact estimate is about **706 MB**; conservative allowance
**1.238 GB**. With two planned copies, 2x safety factor, temporary/retry allowance and 2 GiB
each output/Docker reserves, initial shared-drive headroom is about **9.29 GB / 8.65 GiB**.
A backup copy is budgeted, not automatically made. Both Docker's virtual free space and
its real Windows backing drive matter. Nothing is automatically deleted to free space.

Measured engineering timings projected roughly **2.31 hours** before real main runs; it is
an estimate, not a deadline. Intentional pacing, scheduling, mounted-file writes, capture,
validation and per-run setup all take time. T0/T1/T2 have different waits. A fast first run
does not make the whole roster equally fast. Loss/retries add time.

We did not shorten delays, reduce runs or parallelize generation to improve the ETA. Those
could change timing/load or the research design. Frozen collection integrity takes priority;
performance engineering would need a separately versioned and checked implementation.

## 11. What happened in your latest terminal output

Think of packet capture as a camera recording the conversation. The people can finish
talking while the camera misses some words. We cannot pretend the missing recording exists.

- MX001 passed: 2,253 normal, nine commands, 18 forged replies; zero kernel drops.
- The first MX002 was cancelled; preserved, not accepted.
- Your fresh MX002 retry passed: 2,281 normal, nine commands, 18 forged replies; zero drops.
- MX003's application ledger finished, but its camera reported **372 packets dropped by
  kernel**. Its validation failed. It has no accepted labels or sealed completion.

So the accepted total remains **two runs / 4,588 ADUs**, not three runs. The failed ledger's
2,302 messages and proposed counts are not accepted training examples. The last terminal
progress update at 97.6% was a sampled display, not proof that only 97.6% was generated.

Disk headroom passed. The exact underlying CPU/IO/buffer cause is not recorded. Subsequent
Docker inspection found no running containers; current idle status cannot reconstruct the
failed interval. Each collection container is limited to one CPU/256 MiB, irrespective of
the larger guest-wide resources. We kept the freeze and zero-drop rule unchanged.

One manual retry under reduced avoidable load is reasonable after the earlier zero-drop
successes. If loss repeats, stop for bounded capture-path investigation instead of changing
labels, tolerances or source to make it pass. See [CAPTURE_FAILURE.md](CAPTURE_FAILURE.md)
for exact commands, resources and stop conditions. The agent did not resume collection.

## 12. What was built while waiting

We prepared the recipe and the empty tools for the student's next stage. We did not cook
the real data yet. In `component3_research_scaffold/v1_20261025/` there are:

- A separate [preprocessing plan](PREPROCESSING_PLAN.md), with the later steps and viva demos.
- A separate [model/evaluation plan](MODEL_PLAN.md), including protocol, current-message,
  causal-rule and contextual comparisons, plus wire-header companions.
- Synthetic contracts that reject future evidence, private/unknown columns, misleading FC3
  response addresses, cross-role shared/copy histories and validation/test fitting intent.
- Eleven passing tests using invented identifiers only. No actual message is turned into
  features by these tests, and no model is imported or trained.
- Five real-data stage placeholders that raise `NotImplementedError` if called.
- A machine-readable scope contract and reproducible bounded audit snapshots with commands,
  source/config/input hashes, accepted counts, failed-attempt evidence and test output.

The audit hashes frozen and sealed evidence and compares reports/receipts; it does not
rerun all wire/state validation, re-extract CIC or establish the capture-loss root cause.
Historical CIC/qualification counts in this guide come from the cited preserved reports;
they are not represented as new full-source reproductions in this turn.

## 13. What happens after collection

The student performs and explains preprocessing. Raw decoding and verified truth already
exist; model preprocessing is a separate task. Keep label/private state and run/source/group
metadata out of predictors. Keep all related histories in one role. Any fitted encoder,
imputer, scaler, profile or other learned transform uses **training groups only**, then
remains fixed for validation/test. No transform is fitted now and not every transform is
automatically necessary. No oversampling can repair missing independent campaigns.

History must be causal: an ON request cannot use its future ACK, and a forged reply cannot
use a later recovery read. Reset at a new run/connection or unresolved gap, never at a private
scenario boundary. Missing/stale/untrusted anchors require abstention, not guessed normality.

Later comparisons are A protocol checks, B current-message RF, C simple causal rules and
D contextual RF using the same learner family as B. B-wire/D-wire give both numeric TID
and endpoint/port headers. Use common publicly defined pump-ON/setpoint-readback tasks and
report all-traffic coverage/abstention too. A response's request-derived address is not
present-message input for B. No hidden scenario-based eligibility shortcut is permitted.

Train on declared train groups, choose permitted settings with validation, lock everything,
then evaluate the separate final tests. Report per-class/task counts, confusion, precision/
recall/F1, normal-only false alarms, coverage, latency and whole-run uncertainty. Do not tune
on final tests or qualification. A result that simple rules equal or beat contextual ML is
valid. Do not promise high accuracy or engineer an ML win.

## 14. Useful words, without mystery

| Word | Meaning here |
|---|---|
| PCAP / frame | Original packet recording / one recorded network frame |
| TCP stream | Ordered bytes of one connection; one message may span frames |
| ADU / PDU | Full Modbus message / function and data body inside it |
| FC | Function code; FC1 reads coils, FC3 holding registers, FC5 writes one coil, FC6 one register |
| TID | Transaction identifier; it may repeat, so it is not a unique event ID |
| ACK | Here usually a Modbus write echo; distinct from TCP ACK flags |
| Pairing | Associating the right request and reply with stream/connection evidence |
| Parser-ok | Structurally decoded; not a permission or physical-safety verdict |
| Label / lineage | Evidence-based target / where its original bytes and log evidence came from |
| Anchor / causal | Earlier observable supporting message / using no information from the future |
| Episode / block | Related scenario slot / controlled collection arrangement within a run |
| Run / campaign | One fresh lab execution / broader related recording origin; not interchangeable |
| Qualification | Unscored engineering evidence that tools and conditions work |
| Group split | Keeping related recordings/history/copies in one evaluation role |
| Preprocessing | Later conversion of observations into legitimate model inputs |
| Leakage / shortcut | Giving away answers / exploiting an accidental cue instead of the intended task |
| Hash / seal | Fingerprint / receipt tying accepted artifacts to their exact bytes |
| Abstain | Explicitly say insufficient observable evidence rather than guess |

## 15. What is established, recoverable, and unknown

**Established:** the CIC extraction/audit is useful evidence but cannot support the broad
independent three-class claim. The controlled simulator produces actual recorded Modbus
messages with two declared interventions, genuine controls and checked causal lineage.
Engineering qualification passed. Two main recordings are accepted. The next-stage design
and synthetic contracts are ready; real preprocessing/training is deferred.

**Recoverable with justified additional work:** resume fresh main attempts while preserving
all failures; if drops repeat, qualify any new capture implementation in a separate version.
Complete accepted main evidence, then have the student implement preprocessing and a locked
within-testbed comparison. CIC's proposed broader chain might recover some event coverage
after timing/identity/continuity/control checks; it cannot manufacture independence.

**Cannot be inferred:** independent industrial campaigns, real physical damage or safety,
all Modbus attack coverage, MITM/spoofing capability, malicious intent in policy-compliant
messages, missing original CIC semantics, absence of every shortcut, or an ML advantage.

**Single best next action:** after reducing avoidable host load, manually resume once with
the unchanged frozen launcher and `-Resume -RetryFailed`. Stop for a bounded engineering
investigation if capture loss repeats. Do not begin real preprocessing/model fitting yet.
