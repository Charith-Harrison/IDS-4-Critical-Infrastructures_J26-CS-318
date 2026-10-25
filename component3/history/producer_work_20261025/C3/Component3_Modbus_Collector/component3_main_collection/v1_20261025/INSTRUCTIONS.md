# Manual Component 3 main collection

**Prepared for you to launch manually. Preparation did not start collection.**
The frozen protocol retains the existing 104 execution slots: 80 mixed and 24 normal-only.
It preserves the proposed IDs, seeds, conditions, related groups, intended roles and order
MX001â€“MX104. Academic supervisor acceptance of the testbed-primary amendment is **not recorded**.
Engineering readiness and academic acceptance are separate.

## 1. What you are about to generate

Actual TCP conversations between one software controller and a small software PLC, on
container loopback only. Each run has 90 episode slots, three TID policies and three causal
context gaps. Mixed runs deliberately insert nine inhibited-ON commands and alter eighteen
readback replies; normal-only runs contain no interventions. All observations retain actual
PCAP bytes, private label evidence, exact pairing/stream/frame lineage and matched controls.

These are raw research evidence and annotations. The launcher creates no context features,
X/y or sequence matrices, imputation, encoding, scaling, resampling, normal profiles or models.
All earlier pilots and EQ01â€“EQ14 are excluded from fitting, tuning, feature/threshold selection
and scored evaluation. CIC stays separate; MSU and all other datasets are excluded.

This is one declared simulator and two intervention mechanisms. It does not establish
industrial campaign independence, real-plant effects, unseen-attack generalization or ML
superiority. Simple causal rules can express the policy. Supplied public maps are legitimate
configuration for every comparison; private scenario/state fields are not detector inputs.

## 2. Before opening the start command

- Read `READINESS.md`, `frozen/protocol.json`, `frozen/main_roster.json` and
  `frozen/freeze_manifest.json`. Hashes in the freeze detect changed code/configuration.
- Start Docker Desktop with Linux containers. Use Python 3.11+ on the host; this repository's
  `.venv/Scripts/python.exe` is selected automatically. Use `-Python` to select another executable.
- Keep this package and its frozen image identity together. The prepared image is cached;
  the launcher never pulls an image, rebuilds one, downloads packages or prunes Docker.
- Use a local output directory without commas. Network-share paths are unsupported. A fresh
  unrecognized nonempty directory is refused. Raw/source/qualification directories are protected.

From the **repository root**, the exact default preflight is:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Preflight
```

`-DryRun` and `-CheckOnly` are aliases; no switch also defaults to preflight. This checks frozen
hashes, local/image agreement, Docker, completed artifacts if present, and disk headroom.
It generates **no Modbus traffic, no capture and no main output directory**. A short-lived,
network-disabled read-only Docker process checks image identity and guest disk space.

The default output is resolved relative to this repository, independent of your current shell:

```text
component3_collection_runs/main-frozen-v1-20261025/
```

To choose a portable user-relative location instead:

```powershell
$c3Output = Join-Path $env:USERPROFILE 'Component3Data\main-frozen-v1'
.\component3_main_collection\v1_20261025\collect-main.ps1 -Preflight -Output $c3Output
```

Use the **same Output argument on start, resume and cancel**. Absolute paths on an actual
available local drive are also supported; the launcher does not substitute another person's
drive letter. If Docker storage auto-discovery fails, provide `-DockerStoragePath` with an
existing directory on the real Docker data drive, then rerun preflight. Do not guess a drive.

If Windows blocks this downloaded script, review it and remove only its downloaded-file mark:

```powershell
Unblock-File -LiteralPath .\component3_main_collection\v1_20261025\collect-main.ps1
```

No system execution policy change is required by this package.

## 3. Start only when you choose

Default output:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Start
```

Or, for the custom location above:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Start -Output $c3Output
```

Start is explicit. No scheduled task or background collection service is installed.
Leave this terminal open. The header identifies the planned run and map/value/order/timing
configuration and the resolved output. Progress shows observed complete request/reply pairs,
capture/validation phase, **completed AND validated runs / 104**, approximate ETA and output
free space. Pair progress comes from actual flushed observations, not a timer. A run at 100%
observed transactions is still pending until runtime and host verification pass.

ETA initially uses the 14 measured engineering runs and then measured completed main runs
of comparable timing/mode. It updates at validated completions; it is approximate, not a
promise or a simulated progress counter. New disk/host load and verification overhead matter.

## 4. Resume, retries and cancellation

Resume the same output root:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Resume
```

Add `-Output $c3Output` if you used the custom location. Resume verifies frozen identities,
all completed artifact hashes and the exact evidence/annotations again before skipping them.
It never resumes a half TCP stream. A complete captured attempt interrupted during validation
may finish validation without generating new traffic. Otherwise a failed condition requires
an explicit fresh attempt:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Resume -RetryFailed
```

Every earlier attempt remains. There is no automatic retry loop; at most three attempts are
allowed for any planned ID. A failure stops the invocation by default. Do not change labels,
tolerances, counts, frozen source or conditions to make a failure pass. Changed completed
artifacts or incompatible source/config/image identities are refused and require review.
Multiple successful attempts for one planned ID cannot count as extra data.

To cancel, press **Ctrl+C once** and allow cleanup (normally within about 30 seconds). Or use
a second terminal at the repository root:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Cancel
```

Again use the same custom `-Output` if applicable. Cancellation signals only the owned
container, stops capture, retains available evidence and marks unfinished work unaccepted.
Use Ctrl+C/Cancel rather than closing the window. If the computer/engine crashes, restart
Docker, use Cancel if a prior owned container remains active, then Resume. A stale own-host
lock is archived only when its process is gone; an active or foreign-host lock is refused.

## 5. Storage and safeguards

The measured v0.3 artifacts total about **95.2 MB across 14 runs**. The central estimate for
104 originals is **706 MB**; the conservative per-run allowance is **11,898,722 bytes**, or
**1.238 GB for 104 originals**. That includes PCAPs, ledgers, private audits, annotations,
reports/plans and extra adapter metadata. These are estimates from one host, not guaranteed
upper confidence bounds. `frozen/storage_policy.json` retains the measurements and formula.

Defaults reserve two planned copies (original plus future handover copy), a **2x safety
factor**, two run-sized temporary/retry allowances, **2 GiB output reserve** and **2 GiB Docker
reserve**. When output and Docker share a host drive, their requirements are added. Initial
required headroom is about **9.29 GB / 8.65 GiB** on that shared drive; preflight prints exact
current figures. The planned handover copy is budgeted, not silently duplicated as a dataset.
An exact runtime image archive and small source/schema handover are included separately.

Operational margins are configurable and recorded with each invocation, for example:

```powershell
.\component3_main_collection\v1_20261025\collect-main.ps1 -Preflight -SafetyFactor 2 -PlannedCopies 2 -ReserveGiB 2 -DockerReserveGiB 2
```

Pass the same settings on start/resume. Free space is checked before starting, before every
run, and on host filesystems during each run. Docker guest space and its actual backing host
drive are both checked; the nominal VM capacity alone is insufficient. Low space stops
collection cleanly with available evidence retained. No raw outputs, previous data or Docker
resources are deleted to free space. Temporary verification views created by this collector
are cleaned after their own checks; original recording files are never removed.

Concurrent unrelated programs can consume disk between checks. IO/capture/validation failures
still stop acceptance; they are never repaired by changing the evidence contract.

## 6. What successful completion produces

`collection_complete.json` must say **ALL_104_VALIDATED**. Each successful planned ID has one
sealed `completion.json`. Expect 104 accepted recordings: 80 mixed, 24 normal-only. If all
fixed controls pass, the direct attack totals are 720 commands and 1,440 forged replies;
normal/message/frame counts remain actual measured quantities, not row quotas.

Each attempt retains the original `capture.pcap`, capture log, application ledger, private
server/intervention audits, exact configuration/plan, validation report, verified annotations,
host execution record, source/image identities and file hashes. Failed/interrupted attempts
remain distinct and are not counted. `collection_state.json` is current progress; the initial
`collection_manifest.json` records identity, not completion. The final index records intended
roles/groups as provenance, not a processed training/validation/test matrix.

For read-only inspection without collection:

```powershell
.\.venv\Scripts\python.exe -B .\component3_main_collection\v1_20261025\tools\inspect_collection.py --output .\component3_collection_runs\main-frozen-v1-20261025
```

Retain `_handover/` and every original recording for Kaveesha. It contains the frozen source,
protocol/roster/schema and runtime identity/archive. File/stream duplicates across planned
groups stop acceptance; legitimate repeated PDUs at separate stream positions stay distinct.
Do not combine retries, mirrored/derived copies or shared histories into independent units.
Do not use qualification data or private label evidence as future predictors.
