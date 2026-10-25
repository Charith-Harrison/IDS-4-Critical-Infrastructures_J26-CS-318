# Conditional controlled Modbus/TCP supplement

This design is activated only if the completed CIC source audit cannot establish the proposal's temporal hypothesis with valid normal lookalikes and independent campaigns. It is not a claim that CIC is insufficient before reconstruction, and it is not authorization in this audit to execute traffic or train a model. The source audit/full report determine necessity. The proposal already plans controlled primary Modbus traffic (pp13-14,21).

## Objective

Generate real Modbus/TCP master-to-slave requests and responses captured into immutable PCAP, with ground truth from a separate experiment ledger. Test whether order, coverage, repetition and timing add predictive value when legitimate and recon requests overlap in present-message function, unit, address, quantity and length. A current-packet classifier is allowed to perform well if the data warrants it; do not conceal static differences or claim shape overlap mathematically forces F1 near chance.

## Topology and evidence

Use an isolated local/virtual master, multiple Modbus server units/devices, and passive capture on one canonical interface. Additional monitor views may be kept for source validation but remain dependent. Use real request/response library calls against configured server state. Capture TCP handshakes, data, exceptions and closures. Record interface/link type, capture tool/version/options, offload settings, time source and capture drops. Packet size is measured, not assumed to be always 78 bytes; Ethernet/IP/TCP headers/options and capture link type can change it.

For each run retain an immutable run manifest, configuration/seed, source-code version, state initialization, start/end and clock calibration, full PCAP and hashes, and a separate action ledger. The ledger records run/episode ID, legitimate or attack action intent, target, unit, function, requested address/count/value, scheduled and actual timestamps, request ID/transaction evidence, success/error and response reference. Exported model predictors exclude intent, labels, ledger IDs, file/run/campaign names, private confidence and audit features. Ambiguous delivery, capture gaps and unmatched actions remain explicit.

## Scenario matrix with matched controls

| Normal workload | Recon workload | Required overlap / confound check |
|---|---|---|
| Regular cyclic or round-robin polling | Sequential address sweep | Reuse normal-accessible function/address/count combinations; differ in history/coverage/order where possible |
| Polling intervals changing with operation | Fast and slow scans | Overlap rates across labels; attack must not be uniquely fast or uniquely slow |
| Legitimate multi-register reads | Register-range sweep | Same quantities/ranges available in normal maintenance; no `attack=large quantity` rule |
| Maintenance bursts over broad diagnostic blocks | Sparse/strided scan | Normal bursts and broad reads exist; compare full progression, not burst presence alone |
| Repeated reads of important registers | Randomized scan / repeated probing | Same current addresses/functions; distinguish repetition versus coverage without making every unfamiliar address malicious |
| Normal work across multiple unit IDs/devices | Unit/device enumeration | Both classes contact overlapping units/devices; avoid attack-only endpoint or unit IDs |
| Normal mixed-function diagnostics | Function-code probing | Same allowed functions under legitimate operation; a unique attack FC is not the only signal |
| Normal jitter and scheduled rate drift | Jittered and stealth scan | Overlap jitter/rate distributions; test order/coverage contribution separately |

Include legitimate exception responses where operationally justified, and successful valid-address reconnaissance, so `len3=attack` is not built in. Keep exceptions and writes as evidence; do not label them reconnaissance merely because an attack script is running. Do not make controlled datasets by writing fabricated CSV rows. Retain actual on-wire outcomes even when the intended probe fails.

## Independent runs and run count

A run is a separately initialized acquisition with documented experiment orchestration, independent randomized workload schedule and capture lifecycle. A rotated PCAP, another NIC view, another TCP connection, a new seed alone, or another episode within a continuous unchanged acquisition is not automatically an independent run. Document shared server configuration, toolkit and schedule families; hold related dependencies together when evaluating generalization.

Begin with a small feasibility pilot covering the difficult matched normal/recon pairs. Measure whether intended messages are captured and uniquely attributable, whether static feature marginals overlap, how variable temporal behavior is across separately initialized acquisitions, and whether valid causal windows can be formed without crossing episodes/idle boundaries. The pilot estimates run-level variation and effect sizes and informs a subsequent prespecified sample-size/precision rationale. Do not invent an 18-run or other magic count. More windows within one run do not replace independently initialized runs.

Before any final fit/validation/test experiment, collect enough independent class-bearing runs for all partitions and for useful run-level uncertainty, with the intended scenario diversity represented without reusing the same episode. Freeze held-out run ownership and sample-size rationale before training. If the pilot fails shape overlap or source attribution, fix collection and repeat the pilot rather than using an LSTM score as proof of valid data.

## Pilot acceptance evidence

The reviewable pilot result is a PCAP/log reconciliation and distributions/examples: address progression, span/unique-address coverage, function/unit/target transitions, inter-request intervals, drift, speed and repeated probes, all compared with legitimate lookalikes. Also report current-message static rules and a small untuned static baseline using run-held-out diagnostics only when enough true runs exist. Preserve failed runs and exclusions. The pilot does not claim successful temporal learning and does not authorize final LSTM fitting.
