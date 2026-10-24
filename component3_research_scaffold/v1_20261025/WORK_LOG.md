# Work record - 25 October 2026, Asia/Colombo

Scope: separate preprocessing/model design and synthetic scaffold, comprehensive simple
explanation, and bounded diagnosis of the user's reported MX003 stop. No live collection,
new capture, model preprocessing or model fitting was executed by the agent.

## Inputs and bounded verification

Read the two attached historical requests (v0.2 design and v0.3 manual freeze), current frozen
protocol/roster/schema/source manifest and launcher/recorder/validation implementation;
reviewed the supplied collection log, current status, attempts, reports and receipts.
Consulted preserved CIC preparation/reassessment, old README inventory, qualification/design
reports and the already extracted TAF/proposal text. Historical reports remain references;
this task did not independently repeat multi-GB extraction or all qualification captures.

No applicable AGENTS.md was found in the repository search or the checked ancestor paths.
No sub-agent work or external messaging was launched for this task.

Observed state: STOPPED, 2/104 accepted. MX003 kernel drops = 372, failed labels unaccepted.
MX001 and fresh MX002 accepted counts total 4,588 ADUs (4,534/18/36), 2,294 transactions.
The earlier interrupted MX002 and failed MX003 are excluded. The audit snapshot verifies
accepted receipt artifact hashes and report/identity/count agreement, plus saved input hashes
for unaccepted attempts; it does not rerun the wire/state validator.

## Exact reproducible commands from repository root

```powershell
git status --short
Get-Content .\component3_collection_runs\main-frozen-v1-20261025\collection_state.json
Get-Content .\component3_collection_runs\main-frozen-v1-20261025\MX003-20261024T220351Z-0669c201\capture.log
Get-Content .\component3_collection_runs\main-frozen-v1-20261025\MX003-20261024T220351Z-0669c201\validation_report.json
.\.venv\Scripts\python.exe -B -m unittest discover -s .\component3_research_scaffold\v1_20261025 -p test_contracts.py -v
.\.venv\Scripts\python.exe -B .\component3_research_scaffold\v1_20261025\audit_status.py
```

The standalone synthetic test command passed 11 tests in 0.002 seconds. Snapshot execution
reruns those same small tests and records its own exact output and inputs; tests are not
claimed as validation of an unimplemented real preprocessing pipeline.

Read-only Docker inspection (no Docker run/start/build/stop):

```powershell
docker ps --format '{{.Names}} {{.Status}}'
docker info --format 'CPUs={{.NCPU}} MemoryBytes={{.MemTotal}}'
Get-Process -Name 'com.docker.backend','vmmemWSL','python','tcpdump' -ErrorAction SilentlyContinue | Select-Object ProcessName,Id,CPU,WorkingSet64
```

Initial sandbox Docker access was denied. The read-only inspection was rerun with the required
execution approval; no permission workaround or container mutation was used. `docker ps`
returned no containers; guest-wide resources were 8 CPUs / 6,056,243,200 memory bytes. The
PowerShell batch returned exit 1 because some optional named processes were absent; the
Docker information itself succeeded. These are later observations, not a historical pressure
trace. Frozen per-run limits remain one CPU / 256 MiB; root cause of loss is unresolved.

## Preservation and output interpretation

All edits are new files under `component3_research_scaffold/v1_20261025/`. No git add/commit,
reset, clean, deletion, raw-data write, collector invocation or changes to other components
were performed. Existing main output changes/untracked retry folders were present on entry
and belong to the user's manual collection. Do not present them as scaffold edits.

The snapshot includes exact hashes and sizes for the frozen manifest-listed files, selected
historical inputs, real accepted/unaccepted evidence inspected, and the scaffold code/config/
documentation. It checks those inputs again before completing. It does not rehash the entire
original CIC directory, claim a new full preservation audit of every prior file, or alter
older historical READINESS/protocol status fields to act as a live progress log.

New snapshots use exclusive new directories. No old evidence is overwritten. Their timestamp
is UTC, explicitly distinguished from Sri Lanka user-facing times. Later user resumes will
make snapshots historical, which is expected. See snapshot limitations and CAPTURE_FAILURE.md
for the manual retry decision and repeated-loss stop condition.

Final bounded verification passed: **36 frozen manifest-listed source/configuration files**
match; **122 input/code/documentation files** are fingerprinted in the snapshot, accepted
receipt artifacts and failed-attempt saved input hashes agree, all 11 synthetic tests pass,
and the snapshot reports no errors. `data/raw/Modbus Dataset` exists at the original local
repository location. These are specifically scoped checks, not a claim to re-audit all raw
CIC files. Earlier snapshots are retained when the scaffold documentation/code changes;
the last timestamped snapshot covers the final delivered version.

The external historical attachments were read, not modified. Their SHA256 values at review:

- `94ef0f3c-b5d2-4067-be43-74088e2fbd85/Pasted text.txt` (manual-freeze request):
  `d49c0bd33a1ba20968b8838cac164be11c9f2a51c09dfdc423661640889f2135`.
- `56f29067-6c11-4d5f-a0ad-314bb1c96d7c/Pasted text.txt` (v0.2 design request):
  `f3db4d14278643ae5c9565a1da831faffa17b0e4f9947f527d93f81be7e674ed`.

They reside under `C:\Users\ASUS\.codex\attachments\`; they are historical authority context,
not dataset sources or predictors. The bounded snapshot restricts its input inventory to the
repository, so these external attachment hashes are recorded here explicitly.
