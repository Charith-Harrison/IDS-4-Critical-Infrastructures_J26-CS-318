# Start the transferred collector on Thithira's PC

Receiver check:25 October2026. All51 delivered files and36 frozen source/configuration files passed the supplied verifier. The exact saved Linux/amd64 image was loaded and image/source/storage preflight returned `READY_FOR_MANUAL_START`,0/104 validated, with no traffic or main output directory created. The supplied collector was not edited or rebuilt.

The collector's PowerShell wrapper was blocked by a signing rule. These commands use its documented Python entry point and the working Python3.12.14 already on this PC. No execution-policy setting was changed.

## Start manually

Open a normal PowerShell terminal. Paste these three lines:

```powershell
Set-Location -LiteralPath 'D:\VSCode\GitHub\4th Year Cyber\C3\Component3_Modbus_Collector\component3_main_collection\v1_20261025'
$c3Python = 'C:\Users\Thithira\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $c3Python -B -m runtime.launcher --start
```

Keep Docker running, the terminal open and the PC awake. The measured qualification-based estimate is about2.31hours, not a guarantee. Progress counts validated recordings, not just completed generation. No CIC files or model libraries are needed.

Default output:

`D:\VSCode\GitHub\4th Year Cyber\C3\Component3_Modbus_Collector\component3_collection_runs\main-frozen-v1-20261025`

The initial reserve check passed with about16.76GiB free onD: versus6.65GiB required there, and about32.6GiB free onDocker'sC: backing drive versus2GiB reserved. Checks run again during execution; this snapshot does not reserve the free space against other programs.

## If it stops

Keep every attempt and the exact error. Her source PC previously reported capture drops; moving hosts does not guarantee they disappear. Do not weaken zero-drop or byte/state/label checks. Do not repeatedly retry a failing condition without diagnosis.

Ctrl+C once requests a cooperative stop. From the same working directory and Python variable, ordinary resume is:

```powershell
& $c3Python -B -m runtime.launcher --resume
```

If a run failed, inspect the error first. The distinct command below creates a fresh preserved retry and then continues the roster; it is not a one-run test:

```powershell
& $c3Python -B -m runtime.launcher --resume --retry-failed
```

The launcher caps attempts at three per plannedID. Do not change frozen source, image receipts, timing or capture behavior to bypass a failure. A required recorder fix belongs in a separately versioned, qualified change.

## Confirm and hand over

Success requires104 accepted sealed runs and `collection_complete.json` saying `ALL_104_VALIDATED`. The prospective roster contains80 mixed and24 normal-only runs. Conditional expected attack totals are720 injected commands and1,440 forged replies; other totals are measured, not fabricated quotas.

After clean completion, use the same directory/Python variable:

```powershell
& $c3Python -B .\tools\inspect_collection.py --output '..\..\component3_collection_runs\main-frozen-v1-20261025'
```

Only if inspection succeeds, change back to the delivery root and package:

```powershell
Set-Location -LiteralPath 'D:\VSCode\GitHub\4th Year Cyber\C3\Component3_Modbus_Collector'
& $c3Python -B .\pack_results.py
```

Send Kaveesha both the resulting `C3_RESULTS_....zip` and its `.zip.sha256` file. Retain originals until the transfer is verified. The package preserves failed attempts, source/configuration/image identities and actual collection-machine provenance. Do not combine her partial runs and new runs of the same planned seeds as additional independent samples.

These outputs are measured raw records and evidence annotations, not a model-ready matrix. Student-owned preprocessing and a defensible model comparison remain later work. Academic acceptance of the testbed-primary methodology is recorded as `NOT_RECORDED`; engineering checks do not invent it.
