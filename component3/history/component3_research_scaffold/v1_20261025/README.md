# Component 3 preparation scaffold - 25 October 2026

**Design and synthetic checks are ready. Real preprocessing and modelling have not started.**
The collector, CIC baseline, qualification data and accepted annotations are unchanged.
This package is separate from the frozen collection engine and the old application.

Start with [the simple complete walkthrough](EXPLAIN_EVERYTHING_SIMPLY.md).
Use [PREPROCESSING_PLAN.md](PREPROCESSING_PLAN.md) for the student's later viva work,
[MODEL_PLAN.md](MODEL_PLAN.md) for the future comparisons, and
[CAPTURE_FAILURE.md](CAPTURE_FAILURE.md) for the current collection interruption.

The observed collection has two accepted runs out of 104. MX003 has 372 reported kernel
capture drops and is unaccepted. This is a dated snapshot, not a live progress display.
The complete plan is not yet a complete dataset. Historical frozen READINESS.md and
`actual_collection_started: false` describe the preparation moment; they must not be edited
to track live progress. Live progress is `collection_state.json` and sealed receipts.

## Safe commands now

Run these from the repository root. Neither starts Docker, opens sockets, reads observation
rows for modelling, builds features or fits anything.

Run only the invented contract examples:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s .\component3_research_scaffold\v1_20261025 -p test_contracts.py -v
```

Create a fresh bounded status/provenance snapshot and run those same tests:

```powershell
.\.venv\Scripts\python.exe -B .\component3_research_scaffold\v1_20261025\audit_status.py
```

Each audit creates a new `evidence/snapshot-<UTC>-<id>/snapshot.json`; it never overwrites an
earlier snapshot. It hashes frozen manifest-listed files, selected historical reports,
sealed main evidence and saved failed-attempt input hashes. It reads receipt/report counts,
not modelling values. It does not rerun the wire/state validator or rehash/re-extract the
15.76 GB original CIC tree. Its records explain those limits.

If collection is actively changing an inspected file, the audit refuses an inconsistent
snapshot. Run it while the collector is stopped. Do not use operational verification counts
to tune models. The existing collector's inspect tool can separately rerun validation;
that heavier operation is not needed for this scaffold.

## Contents and deliberately deferred work

| File | What it does |
|---|---|
| `contracts.py` | Synthetic-only identity, causal-availability, predictor-name and grouping checks |
| `test_contracts.py` | Eleven tests with invented in-memory identifiers; no real examples or scores |
| `stages.py` | Five real-data entry points, each raises `NotImplementedError` |
| `plan_contract.json` | Machine-readable scope, prerequisites and stop conditions |
| `audit_status.py` | Bounded provenance/count/hash audit; writes only under this package |
| `PREPROCESSING_PLAN.md` | What the student should implement, understand and demonstrate later |
| `MODEL_PLAN.md` | Comparisons and evaluation design; no model instance or hyperparameter selection |
| `CAPTURE_FAILURE.md` | Actual MX003 evidence, manual retry and repeated-failure stop condition |
| `EXPLAIN_EVERYTHING_SIMPLY.md` | Project story, exact totals, terminology, paths and limitations |
| `WORK_LOG.md` | Commands, observed results and scope of preservation checks |

The synthetic checks illustrate contracts. Prefix checks are not a security sandbox, and
passing these tests does not establish real-data or experimental feasibility. There is no
real-data loader, context implementation, window builder, X/y output, fitted transformer,
normal profile, resampling routine, model or score here. Future implementation belongs in a
separate version with the student's explanation and authorization.
