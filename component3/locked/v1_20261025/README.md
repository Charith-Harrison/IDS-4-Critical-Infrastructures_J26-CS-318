# Component 3: verified lab preprocessing and model pipeline

This is the implementation for the completed104-run collection. It is separate from the old binary CSV application and the historical research scaffold. Use Python3.12+. The default source is the verified producer import in this repository; the root-level partial collection is not used.

## Run the stages

From the repository root, install only this implementation's dependencies in a virtual environment. GitHub sign-in is unrelated to these local computation steps.

```powershell
python -m venv .venv-c3
.\.venv-c3\Scripts\python.exe -m pip install -r component3_model_pipeline\v1_20261025\requirements.txt
$env:PYTHONPATH = (Resolve-Path component3_model_pipeline\v1_20261025).Path
.\.venv-c3\Scripts\python.exe -B -m unittest discover -s component3_model_pipeline\v1_20261025\tests -v
.\.venv-c3\Scripts\python.exe -B -m c3model verify
.\.venv-c3\Scripts\python.exe -B -m c3model prepare
.\.venv-c3\Scripts\python.exe -B -m c3model train
```

`verify` checks the accepted104-run source and immutable receipts. `prepare` reads only32train and16validation runs, decodes all their messages, reconstructs causal state, then identifies the public task cohort. It creates compressed CSV and typed Parquet, a separate candidate feature table, labels, routing/eligibility, and actual membership files under ignored `artifacts/`. IDs/timestamps/labels are retained for evidence and joins, not admitted to the models. CSV can round nanosecond timestamps if opened and saved with Excel; use Parquet/Python for processing.

`train` fits the imputer and RF only on training data. It gives B/D and their wire companions the same four-candidate budget (two tree complexities crossed with balanced/unweighted class weights), selects using validation common-cohort macroF1, verifies saved/reloaded predictions, and writes selection/validation reports. The initial balanced-only development run was preserved separately before final-data access; the equal-budget expansion avoids comparing only an unnecessarily aggressive weighted baseline. No scaling is required for these trees. There is no SMOTE, row shuffle, equal-message deduplication or normal-profile fit on validation/test.

After input definitions, model selection and tests have been reviewed, freeze before accessing final payloads:

```powershell
.\.venv-c3\Scripts\python.exe -B -m c3model freeze
.\.venv-c3\Scripts\python.exe -B -m c3model evaluate-final
```

The lock hashes code, selected models, membership and development artifacts. Final evaluation refuses changed code/artifacts and records its start before opening final rows. It never refits. Repeat, values, supplied-map, order and timing results are separate. A second final run is refused, including after an interrupted first run; investigate and preserve that history rather than deleting markers to rerun silently. Subsequent tuning after final inspection is exploratory.

All commands accept `--source` and `--artifacts` for portable paths. Keep at least1GiB free; the raw producer import is about1.73GiB and is preserved separately. Processed data/models are local artifacts; do not add them to ordinary Git history. Retain the complete handoff archive for moving the raw evidence to another machine.

## What is actually being compared

- A: current protocol validity/available consistency checks. The valid injections can pass.
- B: current-message Random Forest. FC3 replies have no wire address or current request-derived object role.
- C: simple causal rules for mode permission and acknowledged-setpoint readback.
- D: the same RF family plus legitimate earlier context. The residual between current readback and earlier acknowledged setpoint is an explicit context representation, not evidence of a new attack mechanism.
- B-wire/D-wire: equal current numeric TID/endpoints/ports access, reported alongside the semantic comparison.

Primary cohort: public map/function-defined pump-ON requests and paired setpoint-readback responses. The latter's request association may define the auditor's task stratum; it is never smuggled into B's current-message inputs. The cohort is selected after replaying the full stream. Missing anchors or more than6interveningADUs cause contextual abstention. Command decisions precede their ACK. Context resets at run/connection/gap boundaries, never private episode boundaries. Mode writes invalidate stale mode-read anchors. A successful exact FC6 acknowledgement establishes the setpoint anchor. TID is not unique identity.

The feature allowlists are explicit in `records.py`. Oracle/scenario/step/episode/block/seed/anchor-gap/tid-profile labels and true past labels never construct features. IDs, groups, role membership and absolute time stay outside X. The current wire fields, their missingness and public maps are legitimate. All baselines receive the same public policy/configuration.

Reports include support/confusion/per-class metrics, separate tasks, all-traffic eligibility, contextual abstention, normal-only/mixed false-alarm denominators and paired whole-run bootstrap uncertainty. Common-cohort scores compare the same supported observations; full coverage tables disclose exclusions. Out-of-scope traffic is not silently counted as a successful normal classification.

## Viva walkthrough

1. Explain the byte-preserved capture and independent labels. Show an accepted completion receipt and one PCAP.
2. Run `prepare` into a fresh artifacts folder. Show ADU/PDU hex, decoded FC/address/word, absent FC3 response address, and separate labels/routing/features.
3. Follow an earlier mode read or FC6 write/ACK to a current target. Explain why future replies/private simulator state cannot be used.
4. Show the fixed run memberships and explain why equal PDUs at different positions remain real observations.
5. Show the training-only imputer, explicit model inputs, matched B/D selection budget, C rule baseline and final lock.
6. Explain failures, abstention, uncertainty and scope limits even if a score is perfect.

## Scope and limitations

This is one software simulator and two interventions. Multiple seeds/runs are not independent industrial campaigns. C already expresses the lab policy; D may add no value. High synthetic scores do not establish real-plant performance, physical consequences or broad unseen-attack coverage. Supplied M2 tests portability with a known new map, not automatic semantic discovery. Fixed execution order may confound host/time drift. Application wall time is adjustable: three rejected clock-order attempts and one recovered progress-write failure remain documented; no timing-feature claim or repaired monotonic timestamps are invented. Supervisor acceptance of the testbed-primary methodology remains unrecorded.

The old CIC preparation code is useful as protocol/reference material. Its old labels/splits/source filters and the binary app orchestration are not reused. CIC is a separate limited evidence study; MSU is excluded. Historical frozen snapshots are preserved, not edited to imply they contained this implementation.

Implementation references: [scikit-learn leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html), [RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html). Actual installed versions and selected parameters are recorded in `selection.json`.
