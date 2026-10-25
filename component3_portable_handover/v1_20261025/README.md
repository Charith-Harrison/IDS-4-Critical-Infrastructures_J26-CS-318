# Portable Component 3 handover - 25 October 2026

Send the ZIP in `artifacts/` and its `.zip.sha256` sidecar. The receiver opens START_HERE.md
inside the extracted top-level folder. This is a fresh frozen-protocol collection package,
not a copy/resume of the source PC's partial data. No existing output, CIC data, old model,
virtual environment or credentials is shipped. Prerequisites remain Python 3.11+ and
Docker Linux/amd64 with the containerd image store and compose plugin.

Final delivery:

`artifacts/Component3_Modbus_Collector_v1_20261025_20261024T225842Z-11b59eb9.zip`

- 45,074,551 bytes (45.07 MB / 42.99 MiB), 52 ZIP members.
- SHA256: `1a96015013afc58487257a9e9a542a472f268486b7014d5a16ea3d7e57a39842`.
- Frozen collector bundle: `1fe2b0eb6f44807bc6759d3f3e998ce5064047516585d9e8e313f01b24050663`.
- Runtime: `sha256:4abe62902059561c7e2d383a301b6fa4cee8015a4f1ce76245177c0d76ed4ffd`.

The ZIP includes the unchanged 36 manifest-listed source/configuration files, freeze/image
receipts, original instructions/readiness, selected historical preparation evidence, saved
runtime archive/checksum, portable setup/verifier/export helpers and concise research context.
The builder uses an allow-list, verifies copied source hashes and checks the original inputs
again afterwards. Whole-ZIP CRC and extracted file/hash verification passed.

Rebuild from repository root (new unique ZIP, no overwrite, no collection):

```powershell
.\.venv\Scripts\python.exe -B .\component3_portable_handover\v1_20261025\build_handover.py
```

The builder reads the saved image's OCI index, platform manifest and config with verified
digests, rather than incorrectly treating a config digest as the frozen index identity.
The delivery explicitly requires containerd storage; it does not translate/change the
frozen image ID for a classic Docker store. Original sources/image/labels remain unchanged.

Verification performed:

1. 24 original launcher offline tests passed from the ZIP's extracted repository layout.
   Fixtures are synthetic; no traffic or measured dataset was generated.
2. Windows PowerShell **5.1** ran the actual extracted `setup-other-pc.ps1`. Full delivery
   verification, cached-image/platform/containerd checks and the frozen no-traffic Docker
   preflight passed: READY_FOR_MANUAL_START, 0/104, expected 104; exit 0. The extracted
   output directory was not created. The runtime was already cached, so the cold `docker
   load` branch was not exercised on a second host. Saved archive hash and OCI contents
   were independently checked, and cold-load instructions use the documented Docker CLI.
3. No physical second PC was available. Its actual captures must pass all existing zero-loss,
   byte/pair/state/control/hash checks. This package is not a tested capture-loss fix or a
   promise of faster generation. Do not weaken validation or edit the freeze.

Machine-readable packaging verification is next to the ZIP (`.verification.json`). Setup
smoke observations are in `setup_smoke_verification.json`. The temporary setup check used
a separately extracted copy, not the user's main output. Its source-PC record was 4 accepted
runs with MX005 stopped for 36 kernel drops, after MX003 had previously reported 372.
No main Start/Resume/Cancel was executed by the agent. No model preprocessing/training ran.

Official setup references checked for the handover:

- https://docs.docker.com/desktop/setup/install/windows-install/
- https://docs.docker.com/desktop/features/containerd/
- https://docs.docker.com/reference/cli/docker/image/load/
- https://www.python.org/downloads/windows/

The same seeds on another PC are related reruns. Keep collection IDs/host provenance
separate, preserve the local partial collection, and document which accepted collection
is primary before model work; do not pool counterpart runs as extra independent samples.
No split or existing membership was changed to make this ZIP.
