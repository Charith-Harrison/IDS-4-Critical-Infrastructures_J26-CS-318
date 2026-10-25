# Dataset card: controlled Modbus/TCP feasibility pilot

**Collection date:** 24 October 2026, approximately20:27 Sri Lanka time (14:57UTC).  
**Collection machine:** Thithira's Windows PC; shared with Kaveesha afterward.  
**Run:** `pilot-20261024T145730Z-4a7f6472`.  
**Status:** real capture, message bytes/state/labels VERIFIED; small feasibility pilot only.

| Measurement | Actual result |
|---|---:|
| TCP transactions | 108 |
| Complete Modbus messages | 216 |
| Normal messages | 208 |
| Command-injection requests | 4 |
| Response-injection replies | 4 |
| Captured network frames | 224 |
| Complete reconstructed TCP payload bytes | 2532 |
| Reported kernel capture drops | 0 |
| Independent original-byte-reference disagreements | 0 |
| Structural disagreements with existing CIC decoder | 0 |

## What was generated

Two Python programs act as a controller and a machine, sending actual Modbus/TCP over loopback15020 inside one Docker container with no external network. tcpdump records real frames. No spreadsheet rows were invented as measured traffic. Synthetic PCAP fixtures exist only inside software tests.

The lab implements only FC1/3/5/6, unit1, holding registers0/1 and coil1. Register0 is mode; pump ON is permitted only in mode1 under the declared lab rule. Register1 stores a setpoint that changes only on an acknowledged FC6 write. There are no hidden writers or autonomous setpoint changes. Those are toy assumptions, not claims about a real industrial process.

A compromised-controller hook sends a valid pump-ON command in mode0. A compromised-server hook returns a valid but incorrect stored-setpoint reply after an acknowledged write. Normal observations include the same target PDU/value patterns. No malformed-target or ABCD-marker rule labels the attacks. The threats are already-compromised endpoints, not a demonstrated network break-in or TCP-spoofing attack.

## Label meanings

- `normal`: genuine unaltered communication under this experiment's direct-message task. A real acknowledgement of an injected command stays normal.
- `command_injection`: the direct deliberately unauthorized FC5 pump-ON request while mode0 was observed.
- `response_injection`: the specific reply whose value was deliberately changed from the genuine server answer.

Labels depend on exact application bytes/stream positions, recorded frame-byte lineage and a separately audited intervention/state ledger. Whole attack periods are not blanket-labelled malicious. Private state, scenario IDs, run IDs and labels are audit evidence, never model predictors.

## Locate every accepted target

The event suffix below belongs to `pilot-20261024T145730Z-4a7f6472`. Frame numbers refer only to this supplied `capture.pcap`.

| Event | Label | Frame(s) | PDU |
|---|---|---|---|
| e10 | command_injection | 16 | `050001ff00` |
| e27 | response_injection | 33 | `03020034` |
| e46 | command_injection | 52 | `050001ff00` |
| e64 | command_injection | 70 | `050001ff00` |
| e81 | response_injection | 87 | `03020056` |
| e136 | command_injection | 142 | `050001ff00` |
| e189 | response_injection | 195 | `03020097` |
| e207 | response_injection | 213 | `03020061` |

See `outputs/pilot-20261024T145730Z-4a7f6472/EVIDENCE_WALKTHROUGH.txt` for paired normal examples and earlier observable context. Each row in `verified_labels.jsonl` also contains exact frame and file byte references.

## Verification and provenance

The Docker image build and27 tests inside the container passed. The captured run passed byte/state/label checks and repeat verification. All216 messages were independently recovered from their file-byte references and structurally checked with the existing CIC decoder. This last check does not make this CIC data; this is newly collected lab data, kept separate from CIC.

Capture SHA256: `54560fd05077665e580ad247d433732087bbb336601bfe2d4a475edef118972d`.

Original manifest, application ledger, server audit and PCAP remain unchanged. The successful run is approximately386.2KiB including its current human-readable/check reports. One failed recorder-startup attempt is separately retained and contributes zero accepted messages. The original permission failure was fixed by adding SETGID alongside NET_RAW, with runtime networking still disabled.

## Limits and allowed interpretation

This is ONE related run with12 shuffled toy episodes and8 direct attack targets. It establishes collection/annotation feasibility. It is not a complete training dataset, an independent-campaign evaluation, proof of realistic physical process behavior, or evidence that contextual ML beats simple rules. Fixed templates can introduce shortcuts. Changing seeds alone does not establish independent environments.

No model feature preparation, preprocessing, imputation, encoding, scaling, resampling, training or final split was performed. Before larger collection, agree on research scope, controls, causal decision time, varied scenarios and genuinely held-out conditions. A deterministic history-rule baseline may solve this toy task completely.

Read `HANDOVER.md` for inspection without regeneration and for optional exact-image reuse. This data must be described as collected on the collaborator's PC; Kaveesha can receive, inspect, understand and demonstrate it without claiming collection on her own laptop.
