# Local pilot card — user's new run

Run: `pilot-20261024T170840Z-d137ea97`. Started **2026-10-24T22:38:39.643919+05:30** (Asia/Colombo), corresponding to `2026-10-24T17:08:39.6439199Z` UTC. This is the user's reported local execution in the current repository. Hardware ownership/operator identity is not independently attested by the manifests.

This card describes the new local run, not the collaborator's earlier `pilot-20261024T145730Z-4a7f6472`. Keep the original `component3_testbed_pilot/DATASET_CARD.md` and handover provenance unchanged.

| Measurement | Actual local result |
|---|---:|
| Transactions | 108 |
| Complete messages | 216 |
| Normal | 208 |
| Command targets | 4 |
| Response targets | 4 |
| Captured frames | 224 |
| Reported kernel drops | 0 |
| Message-byte and protocol checks | 216 each |
| Targets sharing role/PDU with normal controls | 8 of 8 |

Validation: **PASSED**. Current raw inputs and generator sources match the recorded hashes. The read-only follow-up check found 0 errors. Capture SHA256: `cf952c39c51ee0ca7dcdba584747cbd16d4eff34cc234de68d3f1212b8092928`.

## Explain two matched normal/attack pairs

Event suffixes and frame numbers below refer only to this capture. Each earlier anchor was observed before the current message; none uses a future recovery read as predictive evidence.

| Event | Direct label | Frame | Current PDU | Earlier visible anchor |
|---|---|---:|---|---|
| e10 | command_injection | 16 | `050001ff00` | e3, frame 9: `03020000` |
| e28 | normal | 34 | `050001ff00` | e21, frame 27: `03020001` |
| e27 | response_injection | 33 | `03020034` | e25, frame 31: `0600010056` |
| e9 | normal | 15 | `03020034` | e7, frame 13: `0600010034` |

For the command pair, the current pump-ON PDU is identical; the earlier mode is the relevant difference. For the reply pair, the reported PDU is identical; the relevant difference is the earlier acknowledged setpoint write. The separate private audit establishes the intervention and simulated before/after state. Private state, scenario/step IDs and true labels remain audit evidence, not detector inputs.

## What this supports

These are actual packets from a simulated software process. The run demonstrates collection, exact evidence and causal observability for this minimal lab. It does not establish physical-plant effects, multiple independent campaigns, adequate training size or ML superiority. Twelve episodes in one connection remain related observations.

All original run files are preserved. This run and the collaborator's run are engineering demonstrations excluded from the proposed main collection. No new labels, preprocessing, feature windows or model artifacts were created by this check. Detailed hashes, frame/file-byte references and examples are in `output/local_pilot_evidence.json`.
