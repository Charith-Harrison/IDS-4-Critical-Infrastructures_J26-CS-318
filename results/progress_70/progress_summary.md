# Progress summary (approximately 70% implementation)

Approximately 70% of the planned implementation is demonstrated. The current model provides preliminary Normal/Command Injection detection. Genuine response-injection completion, held-out evaluation, ablation, full explainability and final integration remain pending.

## Completed in this stage
- Dataset audit of both CSVs (checksums, schema, missing values, duplicates, timestamps, labels) — `results/data_audit/`
- Capture reconstruction: 6 genuine baseline captures (`file_source`) and 6 reconstructed attack captures (`atk-0`…`atk-5`, from frame-number/timestamp resets)
- Duplicate investigation: 0 cross-file duplicate pairs on the key (timestamp, endpoints, ports, transaction ID, function code, frame length); timestamp ranges of the two files do not overlap; 0 rows removed
- Label evidence and mapping (Normal / Command Injection), with ambiguous and unsupported records excluded and documented
- Preprocessing: 342,920 packets read and retained, 0 invalid
- Request-response pairing: 209,115 requests, 133,805 responses, 132,481 matched pairs, 1,324 orphan responses, 76,634 requests without a response
- Baseline (7), protocol/pair/sequence/access/value/rate contextual features (46 total); unavailable and invalid features documented
- Capture-grouped split: 9 development captures, 3 reserved test captures (19.9% of labelled events); no capture, record or pair overlap
- Grouped 5-fold CV with fold-specific profile fitting; both Random Forests trained and saved; models reloaded and verified
- Single-event, batch, validation-record and authorized-CSV detection; Streamlit dashboard (9 pages); 44 automated tests; Black and Ruff clean

## Preliminary cross-validation results (final test evaluation pending)
| Model | Features | Macro F1 (pooled out-of-fold) |
|---|---|---|
| Isolated-event baseline | 7 | 0.99996 |
| Context-aware | 46 | 1.00000 |

These scores must be read with the circular-labelling caveat in `docs/limitations.md`: a rule restating the label construction also scores 1.0, so context benefit is not demonstrated at this stage.

## Not done in this stage
See `remaining_30_percent.md`.
