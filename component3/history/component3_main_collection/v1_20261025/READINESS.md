# Readiness decision — 25 October 2026

**READY FOR MANUAL EXECUTION. No main collection has been started.**

Read [INSTRUCTIONS.md](INSTRUCTIONS.md) before typing Start. The user explicitly authorized
preparation/freeze for manual execution, not agent-run collection. Academic supervisor
acceptance is **NOT RECORDED** and is not implied by engineering readiness.

The original proposed 104 slots are retained without changing IDs, seeds, condition factors,
groups, intended roles or order. There are 80 mixed and 24 normal-only executions. All pilots
and qualification captures remain excluded from model work and scoring. CIC and MSU rows
are not imported. Role/group metadata is prospective provenance, not processed model data.

## Evidence and scope

- All 14 v0.3 captures were revalidated through read-only mounts; no probe was recaptured.
- Copied generator, protocol, server, capture and decoder/replay files match their qualified
  source hashes. No new intervention, parser, map, value profile or ordering was invented.
- Fourteen main condition cells were directly measured; all 36 distinct intended combinations
  pass offline composition checks using fresh engineering seeds. The remaining 22 are supported
  compositionally by the same parameterized engine, not claimed as physically measured.
- All **24** launcher tests pass on Windows and in the Linux image using the repository layout.
  Checks cover no-traffic default/dry run, source/hash refusal, storage, locks, interrupted
  attempts, explicit retry limits, artifact changes, duplicate traces, validation gating and
  cancellation before/after a mocked transaction. Synthetic test fixtures are not data.
- The Docker SIGINT test used a short-lived process that opens no sockets/capture and exited
  cleanly. No background collection/test container remains.
- The exact user-facing preflight returned READY_FOR_MANUAL_START, validated **0/104**, and
  did not create the main output directory.
- All **494** prior source/evidence files remain unchanged, including original CIC
  preparation/reassessment, previous pilots, main-design proposal and qualification captures.

The orchestration adapter adds lifecycle, progress, identity and validation envelopes. It
does not change generated PDUs, evidence labels or tolerances. Current-run progress counts
actual flushed request/reply observations. Completion requires runtime AND host verification;
a generator exit code alone is insufficient. Host verification compares annotations with
the qualified reconstruction in a temporary view, preserving original evidence on disagreement.

No known material defect remains in the tested scope. The **traffic-producing main Start path
was intentionally not executed**. The first manually launched run will pass the same complete
evidence checks before it can count. Packet loss, ambiguous pairing, failed controls,
validation disagreement, source changes or insufficient headroom stop acceptance.

Windows stale-lock checks query process status without signaling the process. This choice
follows the [Python Windows signal behavior](https://docs.python.org/3/library/os.html#os.kill)
and [Microsoft process-status API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess).

## Frozen identities

| Artifact | SHA256 |
|---|---|
| `frozen/protocol.json` | `7634b3187e53c029db5d4755c6c3cf9df6a7985ab8ad1c67d3ebf00662a43c48` |
| `frozen/main_roster.json` | `6d689dcc9c22faf49347082a55890ad76591fde2fa7652a4f5bf5bf61ecf11ad` |
| Source/configuration bundle | `1fe2b0eb6f44807bc6759d3f3e998ce5064047516585d9e8e313f01b24050663` |

The complete per-file source/configuration hashes are in `frozen/freeze_manifest.json`.
The exact prepared image is `sha256:4abe62902059561c7e2d383a301b6fa4cee8015a4f1ce76245177c0d76ed4ffd`. Its archive is
`evidence/manual-runtime.tar` (45,318,144 bytes), SHA256 `2630bc09d1124842ef356be58c341003ac1256117f99f45fdbdab0aa63257ed1`.
No automatic image pull, rebuild, software installation or Docker cleanup occurs at collection.

## Capacity and time

Measured v0.3 artifacts total 95.2 MB. Estimated originals for the main roster are **706 MB**;
the conservative allowance is **1.238 GB**. Defaults budget original plus future handover copy,
2x margin, two temporary/retry run allowances, 2 GiB output reserve and 2 GiB Docker reserve.
If output and Docker share a drive, required headroom is **9,292,430,536 bytes (8.65 GiB)**.
The checked host had **126,590,861,312 bytes (117.9 GiB)** free; Docker guest capacity was also
checked along with the actual VHDX backing drive. Those figures are a preparation snapshot;
preflight and each run recheck them. No data/resources are deleted to free space.

Cold ETA is approximately **2.31 hours** from measured qualification wall times. It is not a
guarantee: controller checks, verification, IO, concurrent workloads and retries can add time.
Later ETA uses comparable completed main runs. Backup capacity is reserved; no extra dataset
copy is silently generated. Margins are documented/configurable operational options.

## What remains outside this decision

The protocol is a single software testbed with two declared injection mechanisms and supplied
public object roles. It cannot establish independent industrial campaign generalization,
physical-process impact or ML superiority over causal rules. Actual future measured timing
must be reported; configured sleeps are not exact wire delays. Execution order is the existing
MX001–MX104 sequence and is not counterbalanced across intended roles, so temporal/host drift
remains a limitation. No feature engineering, sequence/model matrices, transformations,
resampling, fitted normal profiles or training/evaluation occurred.

**Next action: you review the instructions and, only when ready, type the manual Start command.**
No further engineering authorization question is required to use this prepared launcher.
Academic acceptance of the methodology change must be documented honestly for the thesis;
this package does not invent it.
