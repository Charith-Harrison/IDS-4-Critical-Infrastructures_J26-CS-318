# Completed Component 3 experiment: 25 October 2026

The104accepted producer-PC runs were verified, a separate reproducible preprocessing/model implementation was built,18tests passed, train/validation choices were frozen, and the five final roles were evaluated once. The raw collection, previous failed attempts and historical CIC/scaffold work remain preserved. The existing binary application is separate.

## Data and preprocessing

Full accepted stream:250,066ADUs,125,033complete transactions,247,906normal,720command injections,1,440response injections. There are104accepted runs and107attempt folders. Load accepted paths from the final completion index, never a glob.

Development used48whole runs:32train and16validation. It processed114,604ADUs, with12,720public task rows and8,976context-supported rows. The models fitted5,984training cohort rows and selected parameters on2,992validation cohort rows. All normal context was replayed before selecting scoring tasks.

The adapter decodes raw ADUs, preserves absent response fields, reconstructs pairing and earlier mode/FC6-ACK state, applies a six-intervening-ADU context budget, keeps observation order and actual run memberships, and separates numeric predictors from labels/routing. Median imputation (including explicit missing indicators and retained all-missing columns) is fitted on train only. RF needs no scaling. There is no row-random split, SMOTE, equal-PDU deduplication, private-state feature or future ACK in a command decision.

Files are in `artifacts/development/`: `all_adus.csv.gz`, `all_adus.parquet`, `candidate_features.parquet`, `labels.csv`, `routing_and_eligibility.parquet`, `prepare_report.json`. Raw/audit fields retained in the combined export must not automatically become X; the implementation selects explicit allowlists. Final observations are read from the preserved source by the locked final command; final predictions and reports are in `artifacts/final/`.

## Selection and locked final result

All four RF variants received the same4candidates: two tree complexities crossed with balanced/unweighted class weights,160trees,seed42. B/B-wire selected unweighted; D/D-wire selected balanced by the fixed tie order. Validation macroF1: B=0.320851, D=1.000000, C=1.000000. The initial balanced-only development attempt was preserved under `development_balanced_only/`; its equal-budget revision occurred before any final payload access and is recorded in `reports/development_revision.json`.

The experiment lock SHA256 is `f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9`. Code, source identity, development data, membership and model hashes were checked before final access. The final command did not fit or tune anything. Its marker prevents silent re-evaluation. No model/code choices were changed after final results.

Scores below are three-class macroF1 on the SAME context-supported public task cohort for every method. They are not accuracy on all network traffic.

| Final role | All ADUs | Public tasks | Common scored | Context abstentions | B current RF | D contextual RF | C rules | B-wire | D-wire |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| repeat | 57,364 | 6,360 | 4,488 | 1,872 | 0.316479 | 1.000000 | 1.000000 | 0.316438 | 1.000000 |
| values | 19,136 | 2,120 | 1,496 | 624 | 0.307397 | 1.000000 | 1.000000 | 0.307397 | 1.000000 |
| map | 19,150 | 2,120 | 1,496 | 624 | 0.307397 | 1.000000 | 1.000000 | 0.307397 | 1.000000 |
| order | 20,622 | 2,120 | 1,400 | 720 | 0.305470 | 0.998698 | 1.000000 | 0.305470 | 1.000000 |
| timing | 19,190 | 2,120 | 1,496 | 624 | 0.307397 | 1.000000 | 1.000000 | 0.307397 | 1.000000 |

A protocol validity equals the all-normal prediction on these valid current messages and does not detect the injections. The selected B also mostly predicts normal, reflecting the same-current-message controls; this is why accuracy alone would be misleading. B-wire makes one additional error in the repeat cohort. D misses one of144response injections in the order cohort (143detected); C and D-wire classify all supported cases correctly. No explanation of that individual RF error is claimed as a proven causal diagnosis, and it was not used to retune.

There are10,376common-supported final task decisions and4,464context abstentions. Across final roles, normal traffic totals134,166ADUs. C/D produce zero false alarms on their scored normal task rows, with coverage disclosed in each report. Only the repeat holdout contains normal-only runs: its1496scored normal-only task rows have zero false alarms; the full19118normal-only ADUs include substantial out-of-scope/unscored traffic. The other final roles have no normal-only runs; their corresponding rate is undefined, not evidence of zero false alarms. Missing/stale anchors are abstentions, and other messages are out of scope rather than successful normal predictions.

The report JSON files include confusion matrices, class/task support, normal-only/mixed false-alarm denominators, all-traffic coverage, and paired whole-run bootstrap intervals stratified by mixed/normal-only runs. Bootstrap confusion counts are pooled before macroF1; normal-only runs are not treated as class-complete attack experiments. These are simulator replication intervals, not independent-industrial-campaign uncertainty.

## What the result supports

Earlier observable command/response context distinguishes these deliberately matched, valid-looking lab messages better than the current-message RF representation. The fully specified causal rule baseline solves the supported policy and slightly exceeds the contextual RF on ordering. There is no demonstrated ML advantage over those rules. The context RF receives an engineered readback-minus-acknowledged-value representation; it is not learning physical process semantics from raw traffic.

This is one software simulator, two intervention mechanisms and supplied public maps/policy. It does not establish real-plant effects, broad attack diversity, independent campaigns or industrial generalization. A known new map is configuration portability, not semantic discovery. Timing holdout changes collection delays while the predictor excludes clock timing; it does not establish robustness of timing features. Online CPU/end-to-end detection latency was not benchmarked. Causal availability is checked at current complete-ADU arrival, with no future information.

Three clock-order attempts were rejected and preserved; their fresh attempts passed unchanged checks. MX040 retains its post-capture recovery record. Accepted wall time is not a guaranteed monotonic/accurate clock. Fixed roster execution order can confound host/time drift. Supervisor acceptance of the testbed-primary academic amendment remains unrecorded. No CIC/MSU records or qualification/pilot samples were fitted or scored in this new experiment.

## Reproduction and preservation

Read `README.md`, `RUN_ON_THIS_PC.md`, and `VIVA_EXAMPLES.md`. Reports copied under `reports/locked_results/` are small tracked evidence; large data/models remain local and ignored. The raw producer work is under `producer_work_20261025/` at repo root, with2198files and a byte-verified import manifest. The old root-level partial collection is historical and not the modelling source.

Train/final model binaries and development tables can be handed over with the new pipeline archive; the95MiBcomplete raw-evidence ZIP is preserved separately in the producer import. Git commits carry source, documentation and small reports rather than raw/binary bulk. Collection and modelling ran on the producer PC, not Kaveesha's laptop.
