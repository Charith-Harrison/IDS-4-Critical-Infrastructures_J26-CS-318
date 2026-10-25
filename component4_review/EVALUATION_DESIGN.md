# Defensible experiment design and split feasibility

## Available units

| Unit | Established from present files? | Meaning |
| --- | --- | --- |
| CSV row identity | YES | Input CSV SHA256 + zero-based source row |
| Source PCAP filename | Normal only | Six names; recording/run origin not established; replay names absent |
| Observed chronological segment | YES, heuristic | Ten normal and ten replay cuts; not a campaign count |
| Bidirectional four-tuple/lifetime proxy | CONDITIONAL | 80,639 observed scopes, partial handshake flags; no full TCP stream identity |
| Request observation / unique observed proxy+TID request | YES, conditional association | 80,753 requests; 2,074 request-labelled positive observations, 2,074 distinct positive proxy+TID/unit/function keys |
| Unique complete replay-request-associated pair | CONDITIONAL | 1,141 request-positive observations have an observed reply; 1,039 of those reply labels are normal |
| Independently verified replay transaction | NO | No original attack log-to-message lineage or complete bytes |
| Attack episode/campaign/run | NO | Neither a 100-second gap nor a capture chunk is proof |

The highest available **mechanical** grouping for unknown replay data is the entire derivative CSV, with possible observed-segment diagnostics underneath it. This is not a proven independent campaign unit. If all replay-derived evidence is conservatively held together, positive examples cannot populate three independent train/validation/test partitions. If its ten segments are treated separately, eight have positives but seven contribute only 35 positive message rows in total; all might still belong to the same recording/run. Splitting the dominant segment into three blocks changes temporal distance, not independent campaigns. Final independent evaluation is therefore **UNSUPPORTED from the present repository alone**.

The public source is broader than the selected extracts. CIC describes device-interface and bridge views, captures chunked into sequential 100MB PCAPs, and timestamped attack logs. This directly cautions against treating filenames or interface views as independent runs. It does not certify which source file produced an unproven derivative row. [CIC dataset description](https://www.unb.ca/cic/datasets/modbus-2023.html).

## Locked comparison once evidence exists

1. Declare run/campaign groups using external recording logs, unite all chunks/views/related replay instances, and reserve independent train/validation/final-test groups before feature/model decisions. Keep both classes in each. Use an embargo if evaluating within-recording diagnostics, and label them as such; never substitute them for campaign independence.
2. Use the same request observations and request-label annotation convention for every comparison. Report pair/orphan/conflict coverage and packet-positive support separately. Do not relabel normal replies, remove difficult normal examples, or treat every duplicate request as attack ground truth.
3. A: a fixed bounded TID/observed-command recurrence rule. B: fixed XGBoost on current-request features only. C: identical XGBoost plus causal history. Retain a current+timing comparison to isolate value beyond conventional temporal behavior. Repeat ablations for TID, duplicates, timing and absolute TID only after fixing the design.
4. Bound/reset histories by held-out group/partition and observed recording/connection. Cold-start evaluation is explicit. If operational warm history is allowed, use only earlier observations from the same permitted held-out group, document the protocol, and never import later or train labels into it.
5. Fit any learned preprocessing only on training. New code uses native XGBoost NaNs and training-only class weights, with no oversampling. Use validation for any justified tuning; freeze hyperparameters/threshold before accessing final test. Do not repeatedly select from the same final test.
6. Report TP/FP/TN/FN, support, precision, recall, F1, FPR, balanced accuracy, ROC-AUC and average precision, both overall and by independent run. A campaign-level bootstrap/interval is meaningful only when enough independent campaigns actually exist. Report uncertainty rather than treating correlated rows as thousands of independent trials.
7. Define decision points separately: complete request arrival, observed response, and timeout-bound completion. Benchmark per-event parsing, feature update, inference and end-to-end delay on a logged replay schedule, including false alarms on normal repetitive polling.

The supplied manifest helper validates assignment mechanics and refuses shared groups, shared known source files, repeated observation identities, exact observed events crossing partitions, missing assignments or missing classes. It never invents groups, shuffles rows, silently moves labels or drops an embargo. The corrected training module was exercised only on a synthetic three-group unit-test fixture; it was not used to claim a final current-data model.

## Bounded source work versus testbed

A limited alternative is to recover the original producer manifest and map a few retained rows at the long replay segment boundary (zero-based derivative rows 5000-5003) to the corresponding specific recording and attack log, checking exact timestamp/TID/direction/stream/payload. That can resolve provenance of those examples; it cannot establish multiple independent campaigns by itself. No such raw PCAP was available in this checkout, and no scan/extraction of the 170-PCAP archive was launched.

The team's TAF explicitly includes capturing labelled testbed replay, and the individual proposal describes complementing CIC when transaction evidence is insufficient. A small isolated, independently logged normal/replay testbed supplement is justified now. Preserve complete ADUs, true TCP connection identity, capture/run IDs, normal repeated polls/retries, replay source identity, injection times and multiple delays. At least three independently restarted labelled runs are needed even for a minimal three-way experiment; more variation will be required for meaningful uncertainty/generalization claims. Do not mistake three arbitrarily named windows for three independent runs.
