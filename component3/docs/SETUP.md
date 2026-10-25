# Setup and safe demonstrations

## Current laptop

Run from the repository root. These commands bypass the need to execute an unsigned PowerShell launcher; they do not change execution policy.

```powershell
.\.venv\Scripts\python.exe -B c3.py check
.\.venv\Scripts\python.exe -B c3.py test
.\.venv\Scripts\python.exe -B c3.py demo --run MX001
```

Use `python c3.py ...` instead when your intended Python environment is active. No Docker or running simulator is needed for inspecting the completed dataset or loading models. `check` validates the expected experiment lock, code and four model hashes before deserialization; it checks the collection identity but does not rehash every raw file.

`test` runs synthetic unit tests only. One unchanged original test fits tiny synthetic forests to verify train-only imputation and serialization; it does not train on the research collection. In the restricted audit sandbox, original tempfile tests initially failed on Windows access permissions and passed outside it. On a normal laptop they use the user's writable temporary directory. Do not interpret a permission failure as a changed research result.

The demo reads **all** messages from one accepted training or validation run, builds state without labels/private transaction ordinals, and writes a new JSONL file under ignored `component3/local/`. It does not score against labels or open a final role. MX001 produces 2,280 statuses: 175 completed D predictions, 90 eligible insufficient-context abstentions and 2,015 out-of-scope observations. Other runs can differ.

```powershell
.\.venv\Scripts\python.exe -B c3.py demo --run MX001 --method D --output component3/local/my-demo.jsonl
```

An existing output is refused. B/D/B-wire/D-wire use the saved models; B variants may classify eligible messages without contextual anchors. D variants abstain before imputation when anchors are unavailable. Do not compare their differently covered outputs as if denominators were equal.

## Full evidence verification and development equivalence

```powershell
.\.venv\Scripts\python.exe -B c3.py audit
.\.venv\Scripts\python.exe -B c3.py replay-check
.\.venv\Scripts\python.exe -B component3/tools/preservation.py verify
```

`audit` checks all accepted source seals, independently reconstructs TCP bytes, checks frame/file lineage and injection evidence, reconstructs development data and checks saved training medians/reload. It independently recounts the **already saved** final predictions and independently checks final causal eligibility/rules. It never calls research train/freeze/evaluate-final, never produces new final RF predictions and writes only a fresh audit directory under `component3/local/`.

`replay-check` compares the new v2 adapter to saved development features/anchors/rules and validation predictions. It also measures warm prepared-event inference on validation only. It does not assess a new model on final data. Explicit `--output` is available; use a new directory for audit or a new JSON filename for replay-check.

`preservation.py verify` hashes every relocated file against the pre-move inventory, including historical local files. A laptop with only the canonical raw/artifact ZIPs will not have every historical local file and cannot pass that whole-repository preservation check. Use `audit` for the complete experiment on that laptop.

## Another laptop

1. Pull this reorganized repository.
2. Transfer the completed raw bundle separately. Place the directory **containing** `collection_complete.json`, `collection_manifest.json`, `_handover/` and the attempt folders at `component3/data/collection/`. Do not nest another `collection/` inside it. The required collection ID is `40ae7a846cce48fc8e3c52ebfca7e2cd`.
3. Transfer the original model/processed-artifact bundle separately to `component3/locked/v1_20261025/artifacts/`, with `experiment_lock.json`, `development/`, `models/` and `final/` directly inside it. Do not replace the locked source code with a different ZIP version.
4. Create an environment and install dependencies. The original producer used Python3.12.14 and the preserved requirements file. This audit used Python3.14.3 and `requirements-local-tested.txt`; scikit-learn is1.8.0 in both. Prefer one documented environment; a successful load is not proof of arbitrary-version compatibility.

```powershell
python -m venv .venv-c3
.\.venv-c3\Scripts\python.exe -m pip install -r component3/requirements-local-tested.txt
.\.venv-c3\Scripts\python.exe -B c3.py check
.\.venv-c3\Scripts\python.exe -B c3.py audit
.\.venv-c3\Scripts\python.exe -B c3.py test
.\.venv-c3\Scripts\python.exe -B c3.py demo --run MX001
```

The producer's exact pins remain in `component3/locked/v1_20261025/requirements.txt`. A clean installation on another laptop was not performed in this audit. Package availability/OS compatibility must be checked there; record versions and do not silently substitute incompatible model serializers. On Unix use `.venv-c3/bin/python`. Current tools resolve their own repository path; no ASUS/Thithira drive path is embedded in the active entry point.

For raw evidence kept elsewhere:

```powershell
.\.venv-c3\Scripts\python.exe -B c3.py audit --source 'D:/Evidence/collection'
```

The old instruction `--source component3_raw/collection` refers to the pre-migration location. On this repository the canonical equivalent is `--source component3/data/collection`. Do not substitute the reviewer’s G: path or a partial historical collection. `check`, `demo` and `replay-check` also accept `--artifacts`; the full audit deliberately expects the intact locked bundle at its canonical location.

Only load model binaries received from the trusted project bundle. The loader checks the known lock and model hashes before `joblib.load`; pickle/joblib is not a safe interchange format for arbitrary downloaded models.

## Structured inference contract (v2 proposal, not yet a team agreement)

`Detector(mapping, trusted_single_writer=True).observe(row)` consumes one complete, ordered ADU. The transport layer must establish connection generation, direction, contiguous direction-specific stream offsets and loss/closure events. It is responsible for reassembly and TCP retransmission handling. The detector is **not** a live sniffer or a general TCP parser.

Required input: event ID, integer observation timestamp, connection generation, direction (`client_to_server`/`server_to_client`), stream offset and ADU hex. Wire companions additionally need source/destination IP and ports. Private labels, simulator step/episode/seed, transaction ordinal and true state are not needed. Connection/event IDs are lineage/state keys, never numeric model inputs.

Outputs include schema/adapter/model/preprocessing versions, observation and decision timestamps, public task eligibility, context availability, processing status, predicted class or `abstain`/`out_of_scope`, optional uncalibrated probability, function, **wire address** and separately an affected address derived from the earlier request when applicable. `address_origin` makes that distinction explicit. FC3 replies retain missing `wire_address`; request-derived address is never added to B's current-response predictors. Evidence carries earlier request/anchor IDs and the rule outcome, expressly **not RF feature attribution**.

Statuses: `complete`, `insufficient_context`, `out_of_scope`, `invalid_input`, `unsupported_input`, `stream_gap`, `ambiguous_pair`, `unmatched_response`, `pair_mismatch`. Unknown eligibility remains null for invalid/unresolvable input; it is not counted as normal. New connections start without anchors. Mode writes invalidate old mode observations; a setpoint write invalidates the old value until its exact successful ACK. Anchors older than six intervening ADUs are unavailable.

Only unit1, one outstanding request/writer and the supplied single-object FC1/3/5/6 map are qualified. Map changes clear state. After loss/trust changes, start a fresh transport generation/offset basis and observe new anchors; there is no automatic midstream resynchronization. The transport must call `invalidate(connection)` on timeout, loss, reconnect or trust loss. Upstream generation/offset errors or forged anchor messages remain outside demonstrated operational reliability.

No network publication, collection start, original experiment retraining or final evaluation is part of these commands.
