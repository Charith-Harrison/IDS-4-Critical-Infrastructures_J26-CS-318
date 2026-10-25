# Component 3: controlled Modbus/TCP feasibility pilot

This pilot asks a small, concrete question: **can we record valid Modbus messages whose attack meaning depends on earlier messages, and prove exactly which recorded message was deliberately changed?**

It is a technical feasibility demonstration. It is not a training dataset, a completed research experiment, evidence of generalization, or proof that machine learning improves detection. No model preprocessing, model training, resampling, or final train/validation/test split belongs in this pilot.

The existing CIC preparation and reassessment folders remain useful evidence and must stay unchanged. MSU and other public datasets are excluded. Using a new controlled testbed as the principal experimental source would change the individual proposal's CIC-primary methodology and needs an explicit discussion with the supervisor. Building this exploratory pilot does not settle that academic decision.

## What runs, and where

The pilot runs actual TCP communication between two small Python programs:

- A simulated PLC, representing the machine.
- A simulated HMI/client, representing the control computer.

They run inside one Docker container, communicating over `127.0.0.1:15020`. Docker uses `network_mode: none`, and no port is published to the laptop or another machine. The nonstandard port is intentional; a validator must decode the bytes rather than decide that traffic is Modbus only because its port is 502.

The container records its loopback communication using `tcpdump`. This produces a real PCAP of the software exchanging messages. It does not reproduce an industrial controller, a real physical process, a field network, or a network attacker obtaining access. The attack hooks model an already-compromised client or server.

Building the Docker image initially requires internet access to obtain the base image and capture utility. A successfully built pilot runs with its runtime network disabled. Docker Desktop must use its Linux container engine.

## The machine's deliberately simple rules

The experiment defines its own register map and operating policy. These are lab definitions, not claims about CIC devices or an actual factory.

| Item | Address | Meaning |
|---|---:|---|
| Holding register | 0 | Operating mode: `0` blocks permission to turn the pump on; `1` permits it |
| Holding register | 1 | Setpoint; it changes only through an accepted FC6 write in this experiment |
| Coil | 1 | Pump command: off or on |

Only four function codes are needed:

| Code | Plain meaning | Used for |
|---|---|---|
| FC1 | Read coils | Read the simulated pump state |
| FC3 | Read holding registers | Read mode and setpoint |
| FC5 | Write one coil | Turn the simulated pump off or on |
| FC6 | Write one register | Set mode and setpoint |

The PLC intentionally accepts a correctly formed FC5 pump-on request even in mode `0`. The lab operating policy says that request is unauthorized in mode `0`. This separates valid protocol encoding from allowed operation. If the PLC merely rejected every test attack as malformed, we would recreate the main CIC shortcut problem.

The detector's declared observation point is the conversation between this HMI and PLC. The operating mode is explicitly read before the pump command. Setpoint writes and their acknowledgements are also visible before readback. There are no unobserved background writers or autonomous setpoint changes in this toy process.

Those assumptions make the intended context available. They also limit the result: the same consistency rules may be inappropriate in a plant with hidden writers, autonomous changes, multiple controllers, or missed captures.

## The two attack mechanisms

### Command injection

A compromised HMI sends a well-formed FC5 request that turns coil 1 on while the most recently observed mode is `0`.

The same FC5 PDU (function, address and output value) is used by normal episodes when mode is `1`; transaction headers vary. That PDU alone does not reveal whether its use is allowed. The earlier mode observation supplies the difference. This matching does not prove that timing, headers or the rest of the toy schedule are free of every possible shortcut.

The PLC executes this simulated action regardless of the operating policy. The server audit records its internal state so that the experiment can verify what actually happened. That private state is not an input to a future detector.

This demonstrates an unauthorized command from a compromised client. It does not demonstrate source impersonation, bypassing network authentication, or exploiting a real PLC.

### Response injection

A compromised-server reply hook changes the setpoint returned by the designated FC3 readback. The forged response keeps a valid function code, byte count, transaction identifier, and normal-sized register value.

For a pair of distinct lab values `a` and `b`, the experiment includes both:

- The server's real setpoint is `a`, but the response reports `b`.
- The server's real setpoint is `b`, but the response reports `a`.

Normal episodes also return both values. A fixed response value should therefore not identify an attack. The relevant evidence is that the response disagrees with the last acknowledged write to the same register in a process where no other setpoint change is allowed.

The forged target is one response message. Its genuine preceding request is an associated normal message; the request does not inherit the response's attack label.

This demonstrates a forged value emitted by a compromised server. It does not implement an on-path network interception or claim that every physically false sensor value can be detected from traffic alone.

## Episode construction

Each seed group uses two distinct setpoint values and contains six episodes:

| Episode family | Mode | Written setpoint | Reported target readback | Pump-on target |
|---|---:|---|---|---|
| Normal A | 1 | `a` | `a` | Allowed |
| Normal B | 1 | `b` | `b` | Allowed |
| Command A | 0 | `a` | `a` | Unauthorized command |
| Command B | 0 | `b` | `b` | Unauthorized command |
| Response A-to-B | 1 | `a` | `b` | Allowed |
| Response B-to-A | 1 | `b` | `a` | Allowed |

All six families use the same nine-exchange template:

1. FC6: write mode register 0.
2. FC3: read mode register 0.
3. FC5: turn pump coil 1 off.
4. FC6: write setpoint register 1.
5. FC3: read setpoint register 1; this response is the response-injection target when the episode calls for it.
6. FC5: turn pump coil 1 on; this request is the command-injection target when the episode calls for it.
7. FC1: read pump coil 1.
8. FC5: turn pump coil 1 off.
9. FC3: read setpoint register 1 again as a recovery/control observation.

The initial mode write and explicit reads make episode state visible. The pump is also reset before and after the target action. All families have the same message count and exchange order. Episodes are shuffled and share a connection and source identity, reducing obvious family-specific endpoint and length shortcuts. These measures do not certify freedom from all shortcuts.

The default two-group run has:

- 12 episodes.
- 108 request/response exchanges.
- 216 application data units (ADUs): 108 requests and 108 responses.
- Four command-injection target requests.
- Four response-injection target responses.
- 208 other, normal ADUs.

The eight attack targets are repeated toy mechanisms, not eight independent attack techniques. Two groups are a small debugging default, not a sample-size argument. A different seed or a restarted TCP connection does not automatically make a new independent experimental campaign.

## Evidence and labels

Three records have different jobs:

| File | Job |
|---|---|
| `capture.pcap` | The messages that actually crossed the local TCP connection |
| `application_ledger.jsonl` | Application-side lineage and exact sent/received message bytes |
| `server_audit.jsonl` | Private experiment truth, including actual server state and deliberate reply mutation |

The validator must relate exact message bytes to their reconstructed TCP stream positions and captured frame lineage, then check the corresponding ledger and oracle evidence. Matching only an IP address, a time window, or a transaction identifier is insufficient. Repeated message bytes also need their occurrence and connection/stream identity resolved.

Application timestamps help explain a run, but do not replace byte and stream evidence. Request/response identifiers must be checked as protocol relationships, not used as an answer key for attack labels.

The run also produces `run_manifest.json`, `capture.log`, and `validation_report.json`. A passing verification may produce `verified_labels.jsonl`. If verification fails, the run must not be presented as a verified labelled dataset. Read the failure report before changing anything; generating more runs is not a repair.

The manifest, private oracle, scenario family, injection flag, episode ID, seed, run ID, capture filename, and experiment schedule are audit metadata. They must not become model features. Giving a model a private `is_attack` flag or a label-generating scenario ID would leak the answer.

## What a passing pilot means

A passing pilot supports the following limited statements:

1. The local programs exchanged actual protocol messages that were captured.
2. The designated targets were encoded as valid messages under the implemented protocol subset.
3. Normal controls contain comparable current-message value and command patterns.
4. The deliberate targets can be traced to original capture bytes and experimental truth.
5. The lab's declared observable history supplies a reason to distinguish the target behavior.

It does **not** establish useful ML performance, adequate data quantity, absence of every confound, industrial realism, novel attack detection, or generalization beyond this setup.

No algorithm can distinguish an attack and a normal event that are identical in everything available to the detector. Private truth that a response is false does not make that falsehood observable. The next experiment must preserve a clear account of which available context can help and which cases remain inherently ambiguous.

## Baselines required in any later experiment

A later study should compare at least:

- Basic protocol validity checks.
- Current-message-only features, with the observation point and classification unit declared.
- Simple contextual rules: pump-on requires the last observable mode to be 1; setpoint readback should agree with the last acknowledged write under the toy process assumptions.
- The proposed contextual ML method, if the supervisor accepts the study and the data support it.

In this intentionally simple pilot, deterministic contextual rules may solve the targets. That is useful feasibility evidence, but it means an ML model must justify what it adds. A strong rule baseline is necessary; defeating only an isolated-message classifier would be an incomplete comparison.

Context must be causal: a detector cannot use a future recovery read or later acknowledgement to claim it detected an earlier message at arrival. If a later method waits for a reply before deciding, its decision time and detection delay need to be reported.

Do not use random row splitting, duplicate examples, SMOTE, or arbitrary run counts to claim independence. A future design needs explicit independent units, held-out runs/configurations where appropriate, controls for source/address/time/value shortcuts, conversation-boundary handling, and a justified uncertainty analysis. The correct design depends on the final claim; this pilot does not choose it.

## The next decision gate

First complete one default run and its verification. Inspect at least one normal/attack pair for each target family in the PCAP, ledger, and private audit. Kaveesha should be able to explain the earlier observation that makes the target suspicious without reading the target's label.

Then discuss this wording with the supervisor:

> The verified CIC cohort does not support the originally intended independent three-class contextual-ML evaluation. I have built a small controlled Modbus/TCP pilot to test valid-looking command and response manipulations with explicit ground truth and observable context. May I revise the main experimental data source and evaluate a clearly bounded within-testbed comparison, with CIC retained as a separate limited case study? The comparison will include protocol checks and simple context rules, and may find no added value from ML.

Only after the pilot and academic scope are accepted should the team design a larger collection. Record the methodology change, state the testbed assumptions, and agree what held-out evidence would make the final claim credible before collecting training data.
