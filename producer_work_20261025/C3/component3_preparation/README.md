# Component 3: original-CIC extraction and grouped preparation

This directory is separate from the existing application, its models and the unfinished `component3_dataset/pipeline/c3prep` parser. It prepares original CICModbusDataset2023 records for inspection and a later researcher's preprocessing stage. Raw sources remain under `data/raw/Modbus Dataset/`; the supplied reference pack is under `references/component3_reference/`.

The authorized stage is source inventory, lossless protocol extraction, evidence-supported annotation, request-response audit and whole-recording candidate partitions. This is extracted and annotated data, not an untouched capture. No model preprocessing, engineered history, sequence windows, fitted transformations, resampling or training belongs to this run.

The accepted evidence cohort contains **1,404,306 normal, 100 command-injection and 54 response-injection ADUs**. Each class occurs in only **one whole recording campaign**, so the independent three-class experiment remains **unsupported**. Of the injection targets, 98 commands and 53 responses have malformed current PDUs; only two commands and one response are parser-ok. These are narrow event-evidence results with substantial protocol-shape shortcut risk, not a demonstrated context-aware detector.

## Read the evidence before accepting a split

- `INVENTORY.md` and `output/inventory.json`: actual file identity, source hashes, capture format and time coverage.
- `FEASIBILITY.md`: salvage decision, supported capabilities and unresolved requirements.
- `REFERENCE_AUDIT.md` and `output/reference_audit.json`: old derivative diagnostics and proposal scope, separate from final row provenance.
- `EXTRACTION_SCOPE_AND_GROUPING.md`: the selected 21 complete available endpoint/interface chunks (1,815,936,064 bytes), excluded mirrored views, parent campaign membership and scope limitations.
- `schema/data_dictionary.md`: exact Arrow field types, byte/time/value semantics, missingness and audit-only relationship metadata.
- `output/pilot/pilot_report.json`: real-packet checks, accounting, timing, memory, disk and independent TShark examples.
- `SPLIT_VALIDATION.md` and the machine-readable split/quality reports: recording membership, pair containment, duplicate-view relationships, class-bearing groups and unsupported evaluation claims.
- `PREPROCESSING_PLAN.md`: future-only guide for the researcher; those transformations have not been executed here.
- `EXTRACTION_VIVA_NOTES.md`: lineage demonstrations and rerun commands.

The presence of train/validation/test membership files does not establish a valid three-class experiment. Candidate assignments must remain explicitly unsupported when class-bearing independent groups or label evidence are insufficient. A continuous attack run must not be divided into shuffled rows to manufacture class support.

## Reproduce from the repository root

Use the existing local virtual environment. The pipeline is offline and does not generate network traffic. Its configuration and reports record parser/audit parameters; those parameters are not learned normality profiles.

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json inventory
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json logs
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json pilot
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json extract
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json pair
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json annotate
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json split
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json verify
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json reports
```

The `all` command runs the staged workflow, including the pilot gate before the larger extraction:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json all
```

Historical export diagnosis is independently reproducible:

```powershell
./.venv/Scripts/python.exe component3_preparation/reference_audit.py
```

The actual local pilot passed its byte/frame accounting and independent TShark 4.6.0 checks for the FC3 returned word 9 and TID 7485 malformed response `01abcd`. The pilot sources are representative verification views; their rows are not appended to the final endpoint-chain partitions. Full selected-view scope is `benign_ied1b`, `external_bridge`, `scada_ied1a`, `ied_ied1b`; see the scope document for exact source paths and coverage.

The completed selected extraction contains 3,768,287 retained records: 3,767,894 ADUs and 393 incomplete byte runs, reconciled from 20,923,685 frames. These counts establish extraction coverage, not class-label validity or scoring-ready partitions. Refer to the final label and split reports for accepted class/group support and remaining limitations.

Offline parser, pairing and membership tests can be rerun with an isolated temporary directory:

```powershell
./.venv/Scripts/python.exe -m pytest component3_preparation/tests -q --basetemp=component3_preparation/output/tests_stage1
```

Read the execution/quality reports for what was actually run, exact results and any failed/unresolved gate. Commands above are reproducibility instructions, not a substitute for their recorded outcomes. The bounded pilot can be rerun on its own without training anything. Extraction checkpoints are keyed to source bytes, configuration and parser code; a matching completed checkpoint is reused rather than appended. A changed contract requires a new extraction, preserving the immutable raw source.

## Source and record rules

Only original CIC captures and their original CIC logs/documentation can produce final evidence and records. Other datasets and old derivative rows are excluded, including fallback or validation use. The reference audit reads the old CSVs solely to diagnose loss of provenance, inconsistent labels, timestamp precision and misleading value fields.

Prefer complete canonical observation chains for each selected parent recording, carrying TCP state over verified rotating chunks. Device/bridge copies of a campaign stay in the same parent group even when their rows are not extracted as an additional view. Do not treat filenames, contiguous chunk numbers, days or log episodes as independent experimental replications. The exceptional small March 23 `compromised-scada/substation-0.pcap` must follow its actual observed origin/overlap evidence, rather than its folder's apparent scenario.

One complete ADU contains MBAP plus PDU. Keep malformed, partial, unsupported and nondecoded candidates visible with status/reason and lossless bytes; count non-Modbus traffic separately. TCP retransmissions are stream observations, not automatically new application commands. Payload-equal polls at different stream positions remain separate events.

Labels are distinct from parsing and pairing status. An unmatched response, exception, write function or attack folder does not establish injection. Command evidence applies to directly injected requests; a real acknowledgement of such a request is not automatically response injection. Original attack names, candidate matches, accepted targets, association-only links, ambiguous cases and out-of-scope mechanisms remain separately auditable.

Read-response addresses are absent on wire and can be associated only through request lineage. Association belongs to pairing audit metadata; it must not quietly enter a current-response baseline. Raw words/arrays preserve observed values while device units, signedness and process semantics remain unknown unless independently documented.

The package stops at extraction, annotation and partitioning. The later researcher must assess feasibility and perform the preprocessing work described in the separate plan before attempting any model comparison.
