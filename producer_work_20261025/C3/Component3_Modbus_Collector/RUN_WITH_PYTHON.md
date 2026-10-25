# Equivalent manual CLI without running PowerShell script files

These use the same frozen Python controller. They do not change execution policy. Install
Python 3.11+ and Docker first. Windows/Linux Intel/AMD x86_64 is the delivery target. This
archive is not qualified for ARM emulation or Mac Docker storage discovery.

From the extracted top-level directory, in PowerShell:

```powershell
$c3Python = (Get-Command python).Source
& $c3Python -B .\verify_bundle.py
docker info --format '{{.OSType}}/{{.Architecture}}'
docker info --format '{{json .DriverStatus}}'
docker image load --input .\component3_main_collection\v1_20261025\evidence\manual-runtime.tar
docker image inspect --format '{{.Id}}|{{.Os}}|{{.Architecture}}' sha256:4abe62902059561c7e2d383a301b6fa4cee8015a4f1ce76245177c0d76ed4ffd
Set-Location .\component3_main_collection\v1_20261025
& $c3Python -B -m runtime.launcher --preflight
```

**Stop if any command fails.** Verify DriverStatus contains `io.containerd.snapshotter.v1`
(the containerd image store; see START_HERE.md). Verify Docker reports `linux/x86_64` or `linux/amd64`, and
inspect reports the exact supplied ID followed by `|linux|amd64`. No build/pull is required.
The load operation imports a local archive only. The preflight generates no Modbus traffic.

Then choose the explicit action manually, from that same collector directory:

```powershell
& $c3Python -B -m runtime.launcher --start
# Later, if needed: ordinary resume
& $c3Python -B -m runtime.launcher --resume
# Or, after inspecting failed evidence: one explicit retry and continuation
& $c3Python -B -m runtime.launcher --resume --retry-failed
# Cancel from another terminal at this collector directory:
& $c3Python -B -m runtime.launcher --cancel
```

These are alternatives, not four commands to run one after another. Use the same `--output`
on each action if nondefault. `--docker-storage-path` must name an actual receiving-PC
directory on the Docker backing filesystem if auto-discovery fails. Relative output paths
are resolved from the delivery root, independently of the shell directory.

On native Linux x86_64, use `python3` instead of the `$c3Python` expression and `/` paths;
verify `python3 --version`, `docker version`, `docker compose version`, load the same archive,
then `cd component3_main_collection/v1_20261025` and use the same `python3 -B -m runtime.launcher`
actions. Docker must be local and the operator must have permission to use it. The actual
Docker backing directory must be inspectable or supplied; do not guess another filesystem.
Windows is the primary receiving-PC walkthrough; a second physical Linux host was not tested.

Read START_HERE.md for storage, completion, retries, evidence export and scientific limits.
