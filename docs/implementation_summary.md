# Rebuild verification — 2026-10-23

## Files replaced and preserved

Old source, scripts, tests, configurations, trained models and generated results
were moved to `legacy_backup/pre_rebuild_2026_10_23/` and replaced with the new
modular implementation. No raw dataset, research document, old report or Git
history was deleted. The raw CSV SHA-256 checksums match the pre-rebuild record.
The archive includes the full previous file inventory and research documentation.
Current editor launch settings target the new dashboard and tests.

The active tree is documented in `README.md` and `docs/rebuild_audit.md`: app,
config, src, scripts, tests, docs, data, models, and results. Experiments are
automatically archived when configuration or input checksums change.

## Dataset findings and measured model results

342,920 original records were retained: 247,960 Normal and 94,960
Command_Response_Injection. Neither raw file has exact duplicate rows or missing
source cells. The input has 35 columns in the attack CSV and 36 in the normal
CSV, whose extra field is file_source. No labels were reconstructed or split by
request/response direction. There are six supplied normal capture names and six
inferred attack reset segments. Training/validation/test counts are
156,376 / 70,984 / 115,560.

| Internal holdout measure | Baseline RF | Context-aware RF |
| --- | ---: | ---: |
| Accuracy | 99.6106% | 99.6106% |
| Macro F1 | 0.996030 | 0.996030 |
| Attack recall | 100.0000% | 100.0000% |
| False-positive rate | 0.8999% | 0.8999% |
| Feature count, including missingness | 22 | 114 |

There is no demonstrated macro-F1 improvement from context on this split.
Full metrics, AUC, latency and confusion matrices are recorded in
`results/metrics/comparison.json` and `.csv`, with a readable `.md` summary.
Training used two 200-tree candidates per model, selected on validation macro F1.

## Leakage protections

An exact whitelist rejects target columns, raw identifiers, filenames, IPs/ports,
absolute timestamps and any unexpected feature. Metadata remains available for
grouping and investigations. Context respects partition, capture, scenario and
session boundaries. Supplied capture IDs are reconciled across CSV files. Pair
features use past observations only. Imputation and explanation reference
quantiles are fitted on training rows. No label-informed normal-access profile,
test resampling, or direction-derived target is used.

## Verification

- Inspection, preprocessing, both RF training runs and holdout evaluation completed.
- Saved artifacts reload and the demo emits real prediction JSON.
- 44 automated tests passed using small software fixtures.
- All five Streamlit pages passed integration rendering with both models: 10 checks.
- Ruff passed; source formatting was checked using Black's serial API.
- Raw data checksums are unchanged.

The dashboard shows preliminary status, filters, upload inference, event history,
feature evidence, measured comparisons and processing health. A per-row global
importance recalculation was fixed; the ranking is now cached per loaded model.

## Limits and transition

Current labels remain temporary binary labels. Validation contains only 98 attack
rows. Attack grouping is inferred and source data had prior legacy test exposure;
these scores are not pristine final validation. Explanations are descriptive,
probabilities uncalibrated, and full PCAP reconstruction/external validation/full
ablation/integration remain pending.

For the final dataset: add new CSVs, change config/config.yaml to
final_three_class, provide verified label evidence, choose canonical or verified
MSU mapping, and set actual column/group/timestamp mappings. Run inspect, prepare,
train and evaluate again. The previous experiment is automatically preserved.
The existing inference API and dashboard use the new class schema without a
redesign. See README's “Transition to Final Three-Class Dataset” for exact steps.
