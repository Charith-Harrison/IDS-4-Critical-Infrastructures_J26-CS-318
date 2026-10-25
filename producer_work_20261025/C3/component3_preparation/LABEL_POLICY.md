# CIC source annotation policy, version 1

These rules annotate extracted protocol records. They do not engineer model
features, fit transforms, construct histories/windows, or train a model. The
extracted tables are processed/annotated records, not untouched raw captures.

Only original CIC captures, original CIC CSV/XLSX logs, and the original README
enter this pipeline. Old derivative CSVs are diagnostic references. No external
dataset supplies rows, labels, fallback evidence, or validation.

## Preserve original evidence

`output/logs.parquet` preserves every original CSV and workbook row, with source
SHA256, path, sheet/row, original attack text, original timestamp/serial, original
transaction text and separate parsed fields. Timezone-naive timestamps remain
timezone-unknown. `timestamp_us` is an explicitly named candidate UTC
interpretation used for calibration. XLSX numeric serial text and exact decimal
epoch microseconds remain available alongside the rounded integer join time.

The 1900/1904 Excel date system is read from the workbook. All three sheets are
inspected. The March 21 CSV is retained as a shortened timestamp version of the
IED4C worksheet and is ineligible for an additional label join; it does not
become an independent attack episode. Rowwise non-time agreement and short
display differences are recorded in `workbook_reconciliation.json`.

`1048575` exceeds the 16-bit wire transaction ID range. It is retained as tool
metadata and never reduced modulo 65536. Missing target/TID/time fields stay
missing. A completion log is not automatically a network message. Adjacent
family start/completion intervals are exposed in `log_episodes.parquet` as
candidate tool intervals, not packet ground truth or independent episodes.

Identical log signatures collapse only for ambiguity auditing, retaining the
original source rows and a repetition count. This operation never deletes a
legitimate repeated wire poll/write. `log_signatures.parquet` links signatures
back to the first source row; all repeated source rows remain in `logs.parquet`.

## Core mechanism targets

The fixed join tolerance is 25,000 microseconds. It is an audit parameter, not a
learned normal profile. The report compares zero offset against minus/plus
three hours. A family/campaign receives a calibrated zero-offset join only when
at least three unique behavior-supported log/packet correspondences exist and
zero offset has more support than either alternative. Residuals, dates and
1/5/25 millisecond sensitivity counts limit the scope of that conclusion.

`normal`: original README benign-campaign provenance supports the source label
for decoded normal/exception ADUs. Malformed, partial and stream-uncertain
records are withheld from normal targets. A valid exception alone is not an
attack.

`command_injection`: an original brute-force/specific-coil start record must
uniquely match a request by campaign, target, literal 16-bit TID and time. The
request must decode as FC5 and carry the exact logged coil address. At least
three unique same-family clock correspondences are required. An arbitrary FC5
or FC6 request never receives this target. The common start-TID 5/completion-TID
65535 pattern is not interpreted as a range of wire transaction IDs.

`response_injection`: an original false-data-injection log must uniquely match
a response by campaign, target, literal TID and time, with calibrated clock
evidence and an observed request/reply lineage. Pair inconsistency or malformed
response shape stays visible and does not erase this independent log evidence.
A legitimate acknowledgement of an injected request, a changed process report,
an exception, an orphan response, and a delayed response are not automatically
response injection.

Connections with conflicting or unverified suppressed retransmission bytes
cannot receive confident mechanism/normal targets under this conservative
policy. A record emitted after a declared stream gap is also withheld. The
retained raw bytes and original evidence allow later manual review.

## Other annotation states and relationships

Unknown or multiple candidate correspondences remain `unknown_or_ambiguous`;
an event without relevant evidence remains `unlabelled`. A unique original-log
association to another mechanism is marked `out_of_scope`, with a null core
target and an explicit note that association alone does not prove a malicious
ADU. No unknown state silently becomes normal.

Every extracted event receives an annotation row. `component_label` is nullable;
`annotation_state`, parsing status and pairing status are distinct dimensions.
The original labels, candidate/accepted log signatures, reasons and lineage are
separate from protocol fields. Legitimate replies associated with an injected
request keep a separate association, rather than inheriting response injection.

Distinct log/packet matches count event evidence. They do not prove independent
episodes or recordings. All contiguous chunks, simultaneous viewpoints and
related events stay inside their parent recording group. Four observed capture
campaigns cannot manufacture three independent groups for each class. Scoring
readiness is reported separately from annotation and containment checks.

## Code locations and reproducibility

`c3prep/logs.py`: `make_row` preserves originals and rejects invalid wire TIDs;
`xlsx_rows` reads all worksheets; `reconcile_workbook_versions` audits versions;
`run_logs` retains source rows and candidate tool intervals.

`c3prep/labels.py`: `load_log_index` builds original-evidence signatures;
`event_matches` performs exact identity/time joins; `run_labels` applies
uniqueness, clock, pair and stream-byte gates, then writes one annotation per
event plus candidate relations and reports. No previous label heuristic is
inherited. Re-running annotations replaces deterministic tables instead of
appending duplicate rows.

From the repository root, use the project Python executable:

```powershell
.\.venv\Scripts\python.exe -m component3_preparation.c3prep.cli logs
.\.venv\Scripts\python.exe -m component3_preparation.c3prep.cli pair
.\.venv\Scripts\python.exe -m component3_preparation.c3prep.cli annotate
```

Run annotation after all selected chains publish successful extraction and pair
audits. Temporary chain directories are excluded. This policy is conservative;
its successful execution does not establish valid three-class evaluation.
