# Generate Component 3 on another PC

This delivery contains everything specific to the frozen Modbus collector, including its
**saved Linux/amd64 Docker image**. It starts a **fresh 104-run collection** when you manually
choose Start. It contains no existing capture, partial collection, CIC data or model.

The receiving machine still needs Python and Docker installed. Those system applications
are not installers bundled in this ZIP. No repository clone, original CIC directory, pip
requirements, virtual environment, host Wireshark/tcpdump, old qualification images or model
libraries are required. The saved image includes the runtime and packet recorder.

## 1. Check the receiving PC

Primary instructions: Windows on an Intel/AMD x86_64 PC, Docker Desktop running **Linux
containers**, and host **Python 3.11+**. The image is linux/amd64. ARM, Apple Silicon and
Windows containers are not qualified by this handover; do not silently rebuild/emulate.

Install prerequisites from their official sources if missing:

- [Docker Desktop Windows installation and current system requirements](https://docs.docker.com/desktop/setup/install/windows-install/).
  WSL 2/virtualization setup may require administrator help and a restart; use that guide.
- [Python for Windows](https://www.python.org/downloads/windows/). The source PC used host
  Python 3.14; the frozen launcher requires 3.11+. No third-party host Python packages are
  imported by the collector. The generation environment is pinned inside the saved image.

The archive preserves an **OCI image index**, including its frozen identity. Use Docker's
[containerd image store](https://docs.docker.com/desktop/features/containerd/), not the classic
store. In Docker Desktop, Settings > General > **Use containerd for pulling and storing
images** should be enabled. Source preparation used Docker Desktop 4.78.0 / Engine 29.5.3;
another compatible version is acceptable only if it preserves the exact ID and passes
preflight. Switching stores hides the other store's images/containers until switched back;
setup never changes this setting automatically. A classic store cannot preserve this image
index; do not replace the frozen ID with a different config/image ID to get past the check.

Use a local, writable SSD folder with a short path **without commas**, for example
`C:\C3Lab\Component3_Modbus_Collector`. Extract the entire top-level folder; preserve the
`component3_main_collection/v1_20261025` nesting. Avoid cloud-synced/network output folders.
The frozen initial disk check requires about **8.65 GiB** when output and Docker share a
drive, plus this extracted delivery/image. Leave additional room for existing Docker use.
The original-artifact estimate is 706 MB centrally / 1.238 GB conservatively, excluding
unbounded retries. The collector checks actual host and Docker backing storage.

## 2. Verify, load the image and preflight (no collection)

Open PowerShell **inside the extracted `Component3_Modbus_Collector` folder**.

```powershell
python --version
docker version
docker compose version
$c3Python = (Get-Command python).Source
python -B .\verify_bundle.py
```

Review `setup-other-pc.ps1` and the frozen `collect-main.ps1`. If Windows blocked them because
they were downloaded, remove only those reviewed files' download marks:

```powershell
Unblock-File -LiteralPath .\setup-other-pc.ps1
Unblock-File -LiteralPath .\component3_main_collection\v1_20261025\collect-main.ps1
.\setup-other-pc.ps1 -Python $c3Python
```

Setup verifies every delivered file, loads the saved image only if its exact ID is absent,
checks Linux/amd64 and containerd identity, and runs the frozen **traffic-free preflight**. Docker's
[image-load command](https://docs.docker.com/reference/cli/docker/image/load/) restores the
saved archive; no image build/pull is needed. It does not start the main collection or
generate Modbus traffic. Loading a local image changes the receiver's Docker image cache.
No system execution policy is changed by these scripts.

If `python` is unavailable or resolves to the Microsoft Store alias, install Python first,
or use `py -3 -c "import sys; print(sys.executable)"` to find its actual executable, then set:

```powershell
$c3Python = 'C:\the-actual-python-installation\python.exe'
& $c3Python -B .\verify_bundle.py
.\setup-other-pc.ps1 -Python $c3Python
```

The path above is an example: substitute the receiving PC's real path. Do not copy ASUS or
another person's drive paths. If Docker's backing disk is not discovered, supply the real
existing directory containing its backing storage:

```powershell
.\setup-other-pc.ps1 -Python $c3Python -DockerStoragePath 'D:\actual-docker-data-directory'
```

Use that same `-DockerStoragePath` on Start/Resume below if needed. A managed signing policy
may still block unsigned scripts; do not weaken a managed policy. The frozen Python CLI
offers equivalent explicit commands under `RUN_WITH_PYTHON.md`.

## 3. Start manually, only after preflight succeeds

Keep the same PowerShell window open, or define `$c3Python` again in a new one.

```powershell
$c3Launcher = '.\component3_main_collection\v1_20261025\collect-main.ps1'
& $c3Launcher -Start -Python $c3Python
```

Default output is **inside this extracted delivery**:

```text
component3_collection_runs/main-frozen-v1-20261025/
```

For a different local SSD output, use `-Output 'D:\C3Data\main-frozen-v1'` on Preflight,
Start, Resume, Cancel, inspection and result export consistently. Do not use an existing
unrecognized nonempty folder or copy the source PC's partial runs into this fresh output.

Leave the terminal open, keep the PC awake and avoid competing heavy jobs. Earlier measured
qualification projected about 2.31 hours; another PC can be faster or slower. The progress
counter reflects validated runs, not simply completed generator messages. A stronger PC is
not a guarantee against capture drops: frozen per-run limits remain one CPU and 256 MiB.
No optimization or capture-loss fix has been smuggled into this delivery.

## 4. Stop/resume safely

Ctrl+C once cancels cooperatively and preserves evidence. Do not close the terminal midway.
For an ordinary resume:

```powershell
& $c3Launcher -Resume -Python $c3Python
```

After inspecting an interrupted/failed attempt, one explicit fresh retry is:

```powershell
& $c3Launcher -Resume -RetryFailed -Python $c3Python
```

A retry preserves old folders and continues the roster if successful. It is not a command
to run just one slot and stop. The maximum is three attempts per planned ID. Repeated packet
drops, missing evidence, byte/pair/control disagreement or a changed hash mean stop and
investigate. Never relax zero-drop validation, change frozen source, delete failures or
edit labels. A new recorder version would need separate qualification and a documented
compatibility decision. A receiving host remains unqualified operationally until its actual
captures pass all frozen checks.

To cancel from a second terminal in this folder:

```powershell
& .\component3_main_collection\v1_20261025\collect-main.ps1 -Cancel -Python $c3Python
```

## 5. Confirm completion and send the results back

Successful completion requires **104 accepted sealed runs** and
`collection_complete.json` with status **ALL_104_VALIDATED**. There are 80 mixed and 24
normal-only runs. Conditional expected attack totals are 720 command and 1,440 forged reply
ADUs; actual normal/frame totals are measured. No model/preprocessed dataset is generated.

Read-only operational revalidation:

```powershell
& $c3Python -B .\component3_main_collection\v1_20261025\tools\inspect_collection.py --output .\component3_collection_runs\main-frozen-v1-20261025
```

After that succeeds, package all original evidence and all preserved attempts:

```powershell
& $c3Python -B .\pack_results.py
```

For custom output, append `--output 'D:\C3Data\main-frozen-v1'` to both commands. The packer
refuses incomplete/active output, checks final index/receipt/artifact hashes, creates a new
`C3_RESULTS_<collection-id>_<UTC>.zip` outside the collection folder and a `.zip.sha256`
sidecar, verifies ZIP CRCs and checks source hashes again. It does not rerun wire/state
validation itself; that is the preceding inspect command's job. Send **both** return files
to the researcher. Do not send only a CSV, PCAP or `verified_labels.jsonl`.

Keep the original output and this delivery until the researcher verifies the return ZIP.
Do not edit, truncate, delete failed attempts or reorganize originals. `_handover/` retains
source, schema, identities and runtime archive; each run retains actual machine/time and
Docker identity, raw capture, observed bytes, private truth evidence and accepted lineage.

## 6. What "reproduce" means here

This reproduces the **frozen protocol, planned seeds/configuration, collection and checks**.
New captures have new timestamps, ports, TCP behaviour, host jitter and recording IDs; they
are not promised byte-identical copies of the source PC's recordings. Qualification is
excluded from model fitting/tuning/scoring; it is not included as new scored data here.

Do not add local and remote executions of the same planned seed as extra independent
samples, put counterparts in different roles, or choose between copies using model results.
Keep separate collection IDs and host provenance. The recommended operational path is one
complete accepted receiving-PC collection as the proposed primary collection, with the
source-PC partial collection preserved separately; document the final choice before model
work. This ZIP does not alter existing memberships or merge any recording.

Fresh hosts, seeds and days still use one simulator and two declared intervention mechanisms.
They do not establish independent industrial campaigns, real plant effects or an ML advantage.
Academic acceptance of the testbed-primary change is NOT_RECORDED. Preprocessing and models
remain the student's later task. See `PROJECT_CONTEXT.md` and frozen `INSTRUCTIONS.md` for
the evidence, privacy of oracle fields, grouping, causal assumptions and scope.
