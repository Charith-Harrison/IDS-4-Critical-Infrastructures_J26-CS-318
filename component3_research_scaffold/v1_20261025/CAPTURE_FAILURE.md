# MX003 capture failure - evidence and next action

Observed live files: `component3_collection_runs/main-frozen-v1-20261025/`.
This note describes the stopped attempt on **25 October 2026 at 03:35:24 Sri Lanka time**
(24 October 22:05:24 UTC). It does not change the frozen collector or accept the attempt.

## What happened

| Planned ID / attempt | Disposition | Kernel drops | Accepted normal / command / response ADUs |
|---|---|---:|---:|
| MX001 / `MX001-20261024T214901Z-cdaccfbf` | Validated | 0 | 2,253 / 9 / 18 |
| MX002 / `MX002-20261024T214954Z-34650c65` | User interrupted; preserved | 0 | None |
| MX002 / `MX002-20261024T220214Z-7a737be7` | Validated fresh retry | 0 | 2,281 / 9 / 18 |
| MX003 / `MX003-20261024T220351Z-0669c201` | Failed; preserved | 372 | None |

Accepted total: **4,534 normal + 18 command + 36 response = 4,588 ADUs**, from two
whole accepted executions and 2,294 request/reply transactions. This is not a scored dataset.
The failed MX003 manifest records 2,302 application messages, but these are not accepted
labels. Its 2,275/9/18 proposed counts must not be added to the accepted totals.

MX003's `capture.log` says:

```text
2956 packets captured
6284 packets received by filter
372 packets dropped by kernel
```

The three counters have different meanings. In particular, do not subtract the first from
the second and call the difference lost packets, or confuse packets with Modbus messages.
The evidence contract requires one explicit zero-drop footer. The validator checks this
before state replay and reports `ValidationError: Missing/nonzero capture-drop footer`.
Here the footer exists and its value is nonzero. `accepted_labels` is false, and the failed
folder has no active `verified_labels.jsonl` or sealed `completion.json`.

The application can complete while the recorder misses packets. A capture process can
also exit with code 0 despite reported drops: its exit does not certify complete evidence.
The terminal's 1,123/1,151 was the last sampled progress display before stop, not the final
ledger total. Host verification correctly did not increment the completed counter.

## What we know about the cause

The immediate failure is packet-capture loss. The underlying resource/scheduling cause is
**not established**. The frozen recorder uses `tcpdump` on container loopback, flushes capture
output with `-U` and writes into the mounted run directory. It has no explicit `-B` override.
These are inspection facts, not proof that a specific flag or mount caused the loss.

Disk capacity was ample: the recorded pre-run host free space was 126,248,058,880 bytes,
against 9,244,835,648 bytes required. Docker reported 8 CPUs and 6,056,243,200 bytes of
guest memory during the subsequent read-only check. No containers were running then.
Those are guest-wide resources: the frozen launch command limits each collection container
to **one CPU and 256 MiB**, with a 64-process limit. They are the same declared limits as
before; no saved pressure trace establishes whether throttling or memory pressure occurred.
There is no saved per-second CPU, memory pressure or IO trace for the failed interval.
Current idle status cannot reconstruct past pressure. Do not blame a particular application.

Earlier engineering probes and MX001/MX002 captured with zero reported kernel drops. They
support trying the unchanged collector once under reduced avoidable load; they do not
guarantee that retries will pass or establish an exact root cause.

## One controlled manual retry

Keep Docker Desktop running. Pause avoidable heavy builds, downloads or other capture jobs
and keep the computer awake. Do not restart the entire experiment or delete any attempt.
The agent has not started/resumed collection for you.

From the repository root:

```powershell
$c3Launcher = '.\component3_main_collection\v1_20261025\collect-main.ps1'
& $c3Launcher -Preflight
& $c3Launcher -Resume -RetryFailed
```

Use the same `-Output` as before if you selected a custom output. Preflight checks identities,
accepted evidence and capacity; it cannot guarantee a future capture will avoid drops.
Resume preserves MX003's failed folder and starts a fresh attempt for that planned condition.
It verifies/skips intact MX001/MX002. If the retry passes, it continues the remaining roster;
this is a resume command, not a command to retry only MX003 and stop.

There is a maximum of three total attempts for each planned ID. **If capture drops repeat,
stop and investigate instead of spending the retry budget blindly.** Preserve both logs,
capture hashes and host records. Do not change zero-drop validation, labels or timing to pass.

The next engineering investigation would measure host/container pressure during a bounded
unscored probe, then assess capture buffering or container-local capture/spool IO. Any
implementation change belongs in a new version with source/image hashes, bounded capture
qualification and an explicit compatibility/collection decision. Never edit the frozen
engine/image or pretend a changed recorder is the same frozen version. None of these
changes or new probes was performed in this scaffold task.

Cancellation: Ctrl+C once and allow cleanup, or the existing `-Cancel` switch from a second
terminal. A stale `cancel.request` is archived by the existing resume logic; do not manually
delete it or operate on unrelated containers. A future successful collection must end with
`collection_complete.json` reporting `ALL_104_VALIDATED`.
