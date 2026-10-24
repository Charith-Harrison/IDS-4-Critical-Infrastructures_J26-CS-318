# Component 3 v0.3 — targeted engineering qualification

The user adopted the proposed engineering scope on 25 October 2026. The separate
`design/engineering_adoption.json` records that instruction and hashes the unchanged
proposed main design/roster. It **does not record supervisor approval**, freeze the 104
main executions, or create actual train/validation/test memberships.

Only **EQ01–EQ14** can run. Each addresses the specific question recorded in the adopted
engineering roster. All probe data is excluded from fitting, tuning, feature/threshold
selection and scored evaluation. Original CIC work, previous pilots, v0.2 captures and the
main-design review package are preserved. No external dataset supplies rows or labels.

## Implemented controls

Each mixed probe has 90 episode slots in nine blocks: three TID policies crossed with
three dependency gaps. Every block has distinct raw words a/b, the six normal families,
one inhibited-ON intervention and reciprocal changed replies. Normal-only probes use
the corresponding permitted/genuine control slots with no interventions.

- TIDs: sequential, literal 5, random with replacement; one outstanding transaction.
- Command anchors: 0/2/4 intervening ADUs; response anchors: 1/3/5.
- Maps: M0/M1/M2 supplied publicly, decoded separately by the validator.
- Value profiles: V0/V1 raw unsigned words; no physical units or safe-range claim.
- Orderings: O0/O1 and the two adopted O2 transaction skeletons with safe refreshes.
- Requested delays: T0 8–15 ms, T1 30–60 ms, T2 80–160 ms, independently drawn.

The generator's process is in `protocol.py`; `validation.py` decodes/replays independently.
TID alone never identifies a transaction. Exact capture bytes, stream/ordinal lineage,
private intervention/state audits, genuine write echoes, public-policy observations,
per-cell controls and zero recorded kernel drops are required. Literal-5 targets also
require identical full-ADU normal examples. An ordinary ACK stays normal.

Private scenario/block/step/TID-profile/gap/seed fields are audit metadata, never future
predictors. Gap calculations are evidence diagnostics, not engineered model features.
Request-derived roles/addresses in response annotations are audit/context information;
they must not be treated as fields present in the current response for its baseline.
Actual IO/scheduling affects timing; requested sleep is not measured wire timing.

## Launch once, from repository root

Docker Desktop Linux containers and the cached qualified `c3-qualification:0.2.0` image
are required. The new image installs nothing; build/runtime networking is disabled.
Runtime exposes no host port and checks that loopback is the only interface.

```powershell
powershell -NoProfile -File .\component3_testbed_v03\start-qualification.ps1 -CheckOnly
powershell -NoProfile -File .\component3_testbed_v03\start-qualification.ps1
```

The launcher verifies local/image source equality and runs the offline regression suite
before any capture. An existing accepted EQ recording prevents accidental repeat collection.
For a single probe use `-RunId EQ01`; `-RetryFailed` permits only preserved failed attempts
to be retried. The launcher rejects main IDs and arbitrary seeds.

Raw captures and private audits live in `component3_collection_runs/engineering-v03/EQ*`.
Each run has a source/config/policy identity and host record with self-reported machine,
OS/timezone/clock, Docker/Compose versions, immutable image/base identity and exact argv.
Keep all files together. The recording directories are ignored by Git.

## Review without collecting

```powershell
.\.venv\Scripts\python.exe -B component3_testbed_v03/summarize_engineering.py
.\.venv\Scripts\python.exe -B component3_testbed_v03/evidence/audit_shortcuts.py
.\.venv\Scripts\python.exe -B component3_testbed_v03/evidence/seal_handover.py
.\.venv\Scripts\python.exe -B component3_testbed_v03/audit_workspace.py
```

`ENGINEERING_REPORT.md` is generated only when all 14 actual captures revalidate.
`evidence/engineering_summary.json` retains artifact hashes and source/machine/image lineage;
`evidence/evidence_examples.json` and `nuisance_cell_counts.csv` are audit diagnostics.
The separately hashed `evidence/audit_shortcuts.py` rereads byte references and independently
replays state/labels/anchors, then reports aggregate observed timing, positions and lengths.
It does not create predictor features or score a detector.
`evidence/HANDOVER.md` explains the exact runtime image archive and portable evidence manifest.
Offline synthetic fixtures can be checked separately:

```powershell
Set-Location .\component3_testbed_v03
..\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

No model preprocessing, fitting, model scoring, final partitions or main capture is enabled.
After engineering, review measured controls and explicitly resolve/adopt the main protocol
and academic methodology change before any separate main-collection authorization.
Simple causal rules express this process; no ML advantage or industrial generalization follows
from engineering success.
