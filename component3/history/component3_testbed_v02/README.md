# Component 3 controlled Modbus testbed v0.2

This separate version implements the proposed eight-family engineering qualification.
It preserves `component3_testbed_pilot` v0.1, CIC preparation/reassessment, and the original
collection design. **Only Q01–Q04 are enabled.** No main research collection, model split,
features, sequence windows, transformations, profiles, training or model evaluation occurs.

Read `QUALIFICATION_REPORT.md` after collection and `evidence/qualification_summary.json`
for actual measured outcomes. The original design's `ready_now:false` and implementation
notes remain historical; this new version's evidence records what was subsequently completed.

## Implementation

`c3qual/scenarios.py` implements permitted ON, inhibited idle, lawful updates in both modes,
repeated legitimate writes, visible mode transitions, genuine readback, inhibited ON injection
and reciprocal changed readback. Each run uses two independently drawn raw-word pairs and
20 shuffled episodes, with normal examples for both genuine readback values.

M0/M1/M2 public object maps are parameterized in both process and independent decoder.
Only M0/V0/S1 is measured in qualification. S1 adds 0–2 complete benign polling transactions
before anchors using the same distribution across families; mode observations are refreshed
before ON. Attack anchors stay within six intervening ADUs. S0/S2 templates and value ranges
are implemented prospectively; this does not qualify them or collect proposed held-outs.
Setpoint writes remain lawful in both modes, preserving the original policy.

The generator uses `protocol.py`; the validator implements its own MBAP/PDU decoder and
state replay in `validation.py`, with no import of the process or scenario generator. Both
share the public design specification. The reviewed v0.1 TCP reassembly/byte-lineage and
tcpdump recorder definitions are vendored unchanged; see `evidence/vendor_receipt.json`.
Reused TIDs are handled by connection plus transaction/stream lineage, never TID alone.

The validator requires actual PCAP bytes, capture readiness and zero reported drops,
successful exact write echoes, complete causal ordering, private intervention records,
independent software state replay and current-PDU normal controls. It withholds all labels
on any failed run; failed revalidation quarantines previously verified annotations. Repeated
equal PDUs at genuine stream positions remain distinct. Metadata is annotation evidence only.

## Reproduce on this Windows repository

The cached `kaveesha-c3-pilot:0.1.0` image supplies Python/tcpdump; the v0.2 build installs
nothing and has build networking disabled. The launcher records the actual base/result image
IDs, source hashes, config/design hashes, exact Docker argument arrays and console transcript.
It checks local/image source equality before collecting. Runtime uses Docker `network:none`,
only loopback, no published ports and the original limited capture capabilities.

From the repository root:

```powershell
powershell -NoProfile -File .\component3_testbed_v02\start-qualification.ps1 -CheckOnly
powershell -NoProfile -File .\component3_testbed_v02\start-qualification.ps1
```

The second command is intended once. Existing Q recordings are preserved and prevent
accidental repeat collection. Use `-RunId Q01` for one planned run; `-RetryFailed` permits
a documented failed attempt to be retried, preserving it. `-SkipBuild` still checks source
identity and runs offline tests. Main roles and arbitrary seeds are rejected.

To inspect/recheck existing outputs without Docker, from the repository root:

```powershell
.\.venv\Scripts\python.exe -B component3_testbed_v02/evidence/build_report.py
.\.venv\Scripts\python.exe -B component3_testbed_v02/audit_workspace.py check
```

The reporting adapter unwraps Windows PowerShell 5's one-item Docker image
metadata wrapper in memory. It preserves raw host records and the exact frozen
collection source bundle, including its original report helper.

To run offline adversarial fixtures:

```powershell
Set-Location .\component3_testbed_v02
..\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Fixtures are synthetic test files, never measured research records. They cannot emit accepted
measured labels. Measured captures live in `component3_collection_runs/design-v1/Q*` and stay
local under that directory's `.gitignore`; keep them and their private evidence together.

## Research boundary

These runs qualify engineering, not experimental generalization. One simulator, isolated
loopback transport, fixed simple policy and deterministic contextual rules remain limitations.
Forged replies are a compromised-server hook, not demonstrated MITM packet spoofing.
An injected request can change this software state; it does not establish physical impact.
The future claim is within-testbed and requires the academic methodology decision and a
prospective main-design freeze. The draft 48-run budget is not a power analysis or an actual
split. Qualification is excluded from future model fitting, selection and scoring.

The student will separately implement and explain causal features, training-only fitted
transformations and protocol/signature/rule baselines at the later authorized stage.
No external datasets or CIC derivatives establish any of these measured lab annotations.
