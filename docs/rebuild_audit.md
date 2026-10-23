# Repository audit and rebuild record

Project: J26-CS-318. Rebuild date: 2026-10-23.

The complete pre-rebuild file inventory (paths and sizes, excluding environment
dependencies and Git internals) is saved in
`legacy_backup/pre_rebuild_2026_10_23/repository_inventory.json`. Original raw
SHA-256 checksums are in the same archive's `raw_checksums.json`.

## Classification before replacement

| Category | Original locations | Decision |
| --- | --- | --- |
| Source | app/, src/, scripts/, run_pipeline.py | Archive and replace with the new architecture |
| Tests | tests/ | Archive and replace; old tests asserted the old target semantics |
| Configuration | config/project_config.json, pyproject.toml, .vscode/ | Archive; centralize behavior in config/config.yaml |
| Models | models/baseline/, models/contextual/, model_verification.json | Archive stale models and metadata; train new binary artifacts |
| Generated data | data/processed/, splits/, validation/, manifests/ | Archive; regenerate from unchanged originals |
| Results/evidence | results/ | Preserve in archive, including all old CSVs, figures and reports |
| Research documentation | docs/, README.md | Preserve in archive; author current documentation separately |
| Caches | .pytest_cache/, .ruff_cache/, source __pycache__/ | Archive with associated code; excluded from Git |
| Environment | .venv/ | Preserve and reuse; update required dependency PyYAML |
| Raw datasets | data/raw/*.csv | Preserve in place; verify checksums after rebuild |
| Git history | .git/ | Preserve unchanged |

No original datasets, proposal/report files, or research evidence were deleted.
No unused notebooks or PDF/Word documents were found in the project inventory.
The archive is deliberately ignored by Git, but remains available locally.

## Findings motivating replacement

The old `src/data/preprocess.py` derived a Command Injection class from write
function/register combinations, removed attack-labelled responses, and excluded
some otherwise labelled requests. This cannot support the requested temporary
target. The new implementation preserves `attack_category` directly and never
derives a label from request direction or feature values.

The old `src/utils/config.py` hard-coded the unsupported class names. Old model
artifacts and reports therefore do not describe the new experiment. The old
README also simultaneously said that the final test partition was untouched
and that it had been evaluated. New evaluation documents explicitly disclose
the prior exposure of these source data.

Old pipeline and candidate-model scripts overlapped in responsibilities and
included additional algorithms outside the requested RF baseline/context
comparison. All active entry points now share one implementation and YAML
configuration. Preserved archives are never imported or discovered as tests.

## New active tree

```text
app/
  dashboard.py
  ui_utils.py
  pages/{overview,detection_events,event_investigation,model_performance,system_health}.py
config/config.yaml
data/
  raw/                  original CSVs, unchanged
  processed/            events.parquet and quarantine.parquet
  manifests/            preprocessing.json and split.json
models/{baseline,contextual}/
  model.joblib          pipeline, metadata, training reference profile
  metadata.json
  feature_names.json
  label_mapping.json
  feature_importance.csv
results/{metrics,predictions,figures}/
src/                    modular ingestion, context, features, training, inference
scripts/                inspect, prepare, train, evaluate, demo
tests/                  small software fixtures, no large-data dependency
docs/                   current research limitations and implementation notes
legacy_backup/          preserved old project, excluded from active application
README.md
requirements.txt
pyproject.toml
.gitignore
```
