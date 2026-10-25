# Component 3 completed dataset handoff

Send `C3_KAVEESHA_COMPLETE_HANDOFF_20261025.zip` and its `.zip.sha256` file. Extract the ZIP into a new local folder, for example `D:\Component3Data\main-v1`. Open that folder together with Kaveesha's repository in Codex. Keep the returned collection unchanged. Do not commit the data or Docker image to Git.

## What was actually completed

The original frozen, independent decoder/replay inspection was rerun after collection and reported `ALL_104_VALIDATED`: 104 accepted runs, 107 total attempt folders, 250,066 complete ADUs, 125,033 transactions. The accepted counts are 247,906 normal, 720 command injections and 1,440 response injections. This was collection, extraction and evidence annotation. No model features, scaling, imputation, resampling or training were performed.

There is no CSV or Parquet yet. Original JSONL is already machine-readable: each line is a JSON record, and `adu_hex`/`pdu_hex` preserve the exact application bytes. She can make her own typed CSV/Parquet and preprocessing scripts from these records. CSV is an output format, not a prerequisite for training.

The complete output is about 721 MiB uncompressed. All 107 PCAPs together are only about 28 MiB; accepted PCAPs total 27.26 MiB. The ZIP includes the captures, all original ledgers, private verification evidence, original source, frozen protocol, and Docker image. Allow about 2 GiB free for extraction and working files initially; fitted features/models may require more. Docker is not needed to read or preprocess existing data.

## Check on her laptop

From the extracted folder, use her Python 3.11+ interpreter:

```powershell
python -B handoff/check_handoff.py
```

This checks the original return-manifest hashes and accepted completion receipts. It prints metadata counts only. For a full independent wire/replay revalidation, with no Docker or additional packages:

```powershell
python -B collection/_handover/source/collector/tools/inspect_collection.py --output collection
```

The second command can take several minutes without progress output. It creates/removes its own temporary verification views, and does not start traffic. Do not run the collection launcher against this returned evidence. The `delivery/BUNDLE_MANIFEST.json` describes the historical collector delivery; use `RETURN_MANIFEST.json` and the outer ZIP checksum to verify this results package.

## Files needed for her pipeline

1. `collection/collection_complete.json`: the only authoritative list of accepted attempt folders, related groups and intended evaluation roles. Read its `completed` dictionary. Do not glob all folders: that would also load three rejected attempts.
2. Each accepted attempt's `application_ledger.jsonl`: full ordered request/reply observations, including normal context. Its scenario/step/label metadata are audit fields, not predictors.
3. `verified_labels.jsonl`: independently reconciled labels, exact ADU/PDU bytes and frame/file lineage. Join its label by unique `event_id`, never by TID alone. Do not use every remaining column as X.
4. `completion.json`, `validation_report.json`, `capture.log`, `host_execution.json`, `run_manifest.json`: integrity and provenance. Their private evidence/causal annotations are not model inputs.
5. `collection/_handover/source/collector/frozen/protocol.json`, `main_roster.json`, `schema.json`, `freeze_manifest.json`: public map/policy, comparison design, groups and source identity.
6. `capture.pcap`: available for Wireshark, viva demonstrations, lineage checks and independent extraction.

Start a clean adapter that separates:

- Observations: `event_id`, `run_id`, `connection_id`, `transaction_index`, `role`, `direction`, `tid`, `unit`, `adu_hex`, `pdu_hex`, `stream_offset`, `observed_at_ns`, `source_ip`, `source_port`, `destination_ip`, `destination_port`. Keep IDs/order for joins and grouping, not as predictors.
- Targets: `event_id`, `label` from verified evidence.
- Run/group membership and configuration: from the completion index and accepted `planned_run.json`; retain for grouping, configuration and audits.
- Private evidence: scenario, step, episode, block, tid profile, anchor gap, intervention/state and validation dependency annotations. Keep outside predictor tables.

Preserve all normal context and repeated genuine messages. Do not deduplicate equal PDUs or filter to attacks. Retain original line order per run/connection; never sort event IDs lexically or sort by TID. Pair with connection generation + transaction ordinal + direction/role; literal TID 5 is deliberately reused. Keep nanosecond values as integers/decimal strings; Excel can round them.

## Memberships and leakage controls

| Intended role | Runs | Normal ADUs | Command | Response |
|---|---:|---:|---:|---:|
| train | 32 | 75,738 | 216 | 432 |
| validation | 16 | 38,002 | 72 | 144 |
| final_test_repeat | 24 | 56,932 | 144 | 288 |
| final_test_values | 8 | 18,920 | 72 | 144 |
| final_test_map | 8 | 18,934 | 72 | 144 |
| final_test_order | 8 | 20,406 | 72 | 144 |
| final_test_timing | 8 | 18,974 | 72 | 144 |

These are the recorded prospective roles, not a newly randomized split. Create explicit actual membership files from these accepted identities in her pipeline, keeping each entire run/related group together. Do not use final roles for feature selection, normal profiles, imputation/scaling/encoding fitting, threshold tuning or repeated model selection. Use train to fit and validation to select. Preserve final roles separately for the locked evaluation.

Use an explicit predictor allowlist, never `df.drop(columns=['label'])`. Exclude scenario, step, episode, block, anchor gap, tid profile, private state, intervention flags, true prior labels, source filenames, seeds, run/group IDs, role/membership and absolute collection time from predictors. A request's `pair_state` can use a future reply and is not a request-time feature. An FC3 reply has no wire address: its annotated `object_role` is request-derived context and cannot enter a current-message-only baseline as if it were on wire.

Primary semantic comparisons use numeric TID for pairing, not as a covert scenario feature. The protocol also specifies equal B-wire/D-wire companion comparisons retaining legitimate numeric TID/current headers; inspect the frozen design rather than banning or adding them silently. Earlier observations may be used causally; future ACKs cannot classify a current command. Missing anchors mean abstention. Reset at run/connection boundaries, not private episode boundaries.

The policy is mode-0 pump-ON forbidden, mode-1 ON permitted, OFF permitted, setpoint writes permitted in both modes. Readback is checked against an earlier observed successful FC6 write and genuine acknowledgement. All methods receive the same public map. Protocol checks, isolated-message ML, simple causal rules and contextual ML are different comparisons; rules may already solve this lab policy. Report per-class/task support, false alarms, abstention and run-level uncertainty, not just aggregate accuracy on the many normal rows.

## Acquisition history and scientific scope

Three earlier attempts, MX086/87/88, failed application wall-clock ordering checks and remain excluded. Their fresh retries passed unchanged frozen acceptance checks. MX040's captured data passed post-capture validation after a progress-file write failure; the accepted attempt retains its recovery record. No timestamps were repaired, failed raw data relabelled, or frozen acceptance rules relaxed. Passing checks does not certify absolute clock accuracy. Keep timing features exploratory or separately justify them using measured observation sources and these limitations.

This is one controlled software testbed with two intervention mechanisms. Runs are replications, not independent industrial campaigns. The data support a within-testbed study; industrial generalization, physical effects and ML superiority are not established. Supervisor acceptance of the testbed-primary methodology is not recorded in the frozen protocol; collection completion is not academic acceptance. Historical frozen status fields describe the precollection plan; the completion index records what actually happened.

## Relevance of the previous CIC pipeline

The included `references/cic_preparation` is the local CIC extraction/preparation code and selected documentation, with hashes in `handoff/REFERENCE_MANIFEST.json`. It is not an already completed ML feature/training pipeline. Its protocol decoder, stream/pairing logic, integrity checks and tests can be inspected for reuse. Its old labels, source-specific log matching, scope selection, candidate partitions, port assumptions and timestamps must not be applied to this lab dataset.

The lab already has validated ADUs, so the quickest adapter reads JSONL rather than repeating TCP extraction. PCAP re-extraction remains available for spot checks. The supplied CIC code is reference only and has not been rerun or adapted in this handoff. No CIC data rows are included. MSU is excluded entirely. Keep CIC as a separate, limited evidence case study; do not mix its labels/groups with lab train/test data or call it a class-complete independent external evaluation.

Paste `handoff/PROMPT_FOR_KAVEESHA_CODEX.txt` into her repository chat after extraction. It asks for the fastest reproducible adapter/preprocessing route and keeps actual model work on her laptop.
