# Migration and preservation record

The repository was clean at baseline Git commit `08f0ebc` (full identity in the JSON inventory). Sixteen Component3 roots were relocated intact. **2,952 files,1,810,006,193 bytes** were inventoried before moving and all2,952 files passed preservation verification after moving. No frozen bundle internals, original model bytes, labels, lock or final markers were edited.

Machine-readable records:

- [`preservation.json`](../reports/preservation.json): every old/new root and relative file SHA256/size before moves.
- [`preservation_verification.json`](../reports/preservation_verification.json): post-move full set/hash check.
- [`path_references_before.txt`](../reports/path_references_before.txt): tracked text/script/import/manifest references captured before relocation.
- `tools/preservation.py`: reproducible snapshot/check logic; refuses to replace original inventory.
- `tools/relocate.ps1`: exact native-PowerShell relocation procedure used. It validates all resolved paths remain inside the repository, refuses existing destinations and checks pre-move hashes. **One-time historical operation: do not rerun on the already relocated tree.**

## Before → after

| Previous repository path | Current path | Treatment |
|---|---|---|
| component3_model_pipeline | component3/locked | Entire original version/source/reports/artifacts together; internal bytes unchanged |
| component3_raw | component3/data | Canonical completed raw collection, intact |
| component3_collection_design | component3/history/component3_collection_design | Initial design history |
| component3_collection_runs | component3/history/component3_collection_runs | Partial/pilot/qualification recordings; never model sources |
| component3_dataset | component3/history/component3_dataset | Earlier c3prep work |
| component3_local_verification | component3/history/component3_local_verification | Earlier check/merge evidence |
| component3_main_collection | component3/history/component3_main_collection | Original frozen collector package |
| component3_main_design | component3/history/component3_main_design | Prospective roster/design history |
| component3_portable_handover | component3/history/component3_portable_handover | Historical packaging and ZIP evidence |
| component3_preparation | component3/history/component3_preparation | Original CIC preparation and artifacts |
| component3_reassessment | component3/history/component3_reassessment | CIC coverage/evidence reassessment |
| component3_research_scaffold | component3/history/component3_research_scaffold | Superseded plans/tests |
| component3_testbed_pilot | component3/history/component3_testbed_pilot | Initial pilot |
| component3_testbed_v02 | component3/history/component3_testbed_v02 | Earlier qualification |
| component3_testbed_v03 | component3/history/component3_testbed_v03 | Engineering qualification |
| producer_work_20261025 | component3/history/producer_work_20261025 | Exact imported files; original import manifest retained |

New active files live directly under `component3/`, with tests/tools/docs/reports. They are version2 engineering work, separate from `locked/v1_20261025`. No additional duplicated active experiment tree was created.

## Paths, references and compatibility

Updated the repository README, producer-work index, active root entry point, .gitignore and .gitattributes. Added the old/new map above and retained full reference-search results. The original producer import manifest retains original source/destination names as historical provenance; map them through this relocation record rather than rewriting it.

Frozen and historical documents/scripts retain their original paths and assumptions **intentionally**. They are preserved evidence, not maintained entry points. Running old collection launchers, packaging scripts or their repository-parent assumptions directly from history is unsupported. The new `c3.py` explicitly supplies canonical paths for current checks/demos; it never invokes historical collection/training stages. The whole locked model bundle still resolves its own relative artifacts/code, but its old default source path must not be used.

The original CIC raw directory `data/raw/Modbus Dataset` remains in place and is not part of the new model source. The legacy app, other group components, original proposal/TAF content and imported producer manifest were not rewritten. An unchanged copy of the supplied rubric was placed in docs so the traceability evidence can travel with the repo.

`.gitattributes` marks all relocated historical/locked files `-text` to preserve original LF/CRLF bytes. `.gitignore` excludes canonical raw data, original artifacts/models, new local outputs and heavy historical captures/ledgers/archives. Some historical partial raw files had already been committed before this audit; their old paths are removed from the new tree's tracked content while local bytes remain preserved. **Past Git commits were not rewritten**, so this change cannot erase their existing Git-history size.

No conflicting versions were overwritten or deleted. Historical duplicates/imports are preserved in history and must not be treated as additional independent observations. A partial producer import is not a substitute for the completed canonical collection.

## Recorded operations

```powershell
.\.venv\Scripts\python.exe -B component3/tools/preservation.py snapshot
& ./component3/tools/relocate.ps1
.\.venv\Scripts\python.exe -B component3/tools/preservation.py verify
.\.venv\Scripts\python.exe -B component3/tools/audit.py --output component3/reports/audit_v2_20261025
.\.venv\Scripts\python.exe -B c3.py test
.\.venv\Scripts\python.exe -B c3.py replay-check --output component3/reports/runtime_development_final.json
.\.venv\Scripts\python.exe -B c3.py check
.\.venv\Scripts\python.exe -B c3.py demo --run MX001 --output component3/local/demo-development-final.jsonl
```

Reports retain commands, source identities and code hashes. The initial sandbox test log is preserved separately from the successful run. No global Git identity, original experiment lock or evaluation marker was changed. Read-only audits and development predictions are distinct from research training/final evaluation.

The preservation script can detect missing/changed historical local files on this laptop. On another laptop, transferring only canonical raw and model bundles is sufficient for the active audit/demo but cannot reproduce every local historical file in the migration inventory. For recovery of a historical tool, use an isolated checkout of the recorded baseline and its documented original layout; do not copy history into the canonical data directory.
