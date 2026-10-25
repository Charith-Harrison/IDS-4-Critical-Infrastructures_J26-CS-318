# Kaveesha's Component 3: controlled testbed pilot

This is a **small feasibility pilot**, not the final research dataset. It tests whether a controlled local Modbus conversation can produce protocol-valid injections with matched normal examples, real packet capture and exact message-level evidence. It does not train, preprocess or split model data. Original CIC preparation/reassessment stays separate; MSU is not used.

**A real captured run has now passed on the collaborator's PC.** If you received the verified handoff, start with `DATASET_CARD.md` and `HANDOVER.md`. You can inspect the supplied recording and evidence without generating another run. Docker is needed to rerun the lab, not merely to read its JSON/text evidence. Collection-machine provenance is preserved in the handoff.

Start with [the Discord walkthrough](docs/DISCORD_LESSON.md). Scientific assumptions, limitations and the next research gate are in [EXPERIMENT.md](docs/EXPERIMENT.md).

## Run on her Windows laptop

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/), use the WSL2/Linux-container backend, and start it. Restart Windows if the installer requires it. A local Python installation or Wireshark installation is not required for the Docker path.
2. Put this folder directly inside her repository:

   ```text
   IDS-4-Critical-Infrastructures_J26-CS-318/
     component3_preparation/          existing, keep
     component3_reassessment/         existing, keep
     component3_testbed_pilot/         this folder
   ```

3. In PowerShell, change into `component3_testbed_pilot`, then run:

   ```powershell
   .\start-pilot.ps1 -CheckOnly
   .\start-pilot.ps1
   ```

   If Windows blocks the downloaded script, inspect it first, then use a process-only policy override:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\start-pilot.ps1 -CheckOnly
   powershell -NoProfile -ExecutionPolicy Bypass -File .\start-pilot.ps1
   ```

The initial image build needs downloads. During the experiment, [Docker networking is disabled](https://docs.docker.com/engine/network/drivers/none/); only container loopback exists. No host ports, host-network mode or production target are used. The launcher runs offline tests before the captured pilot. Its actual image identity is saved in `host_execution.json`; the moving base-image tag/apt repositories mean a later rebuild need not be bit-identical.

## What should appear

Each invocation uses a fresh `outputs/pilot-.../` folder and preserves failed runs. Default seed4010/two groups produces12 episodes,108 transactions,216 messages:208 normal,4 command-injection and4 response-injection messages. These repeated messages and episodes are not independent campaigns and are not a recommended training size.

- `capture.pcap`: actual network recording made by tcpdump.
- `capture.log`: capture readiness/errors/drop statistics.
- `application_ledger.jsonl`: message intent/observations and proposed labels; audit-only.
- `server_audit.jsonl`: true simulated state and pre-alteration reply; private label evidence, not model input.
- `run_manifest.json`: status, source hashes, seed, software and artifact identities.
- `validation_report.json`: byte/sequence/message/label verification or failure reasons.
- `verified_labels.jsonl`: produced only when validation accepts the complete run.
- `host_execution.json`: Docker image/build-launch identity recorded on her laptop.

Read `validation_report.json`, not merely the presence of a PCAP file. Do not call a failed or smoke-only run a verified dataset. Recheck an existing captured run using:

```powershell
.\verify-pilot.ps1 -Run pilot-REPLACE-WITH-ACTUAL-FOLDER-NAME
```

## What is simulated

One Python controller and one Python PLC simulator exchange actual TCP messages on127.0.0.1:15020. Only FC1/3/5/6 and the documented small register map are implemented. A compromised-controller hook emits a valid coil-ON instruction when lab policy forbids it; a compromised-server hook changes one valid readback reply. This is not a TCP-spoofing/MITM demonstration or a real physical process.

An ordinary acknowledgement of an injected command remains normal. Only the directly inserted command or altered reply receives the corresponding injection label. Identical current PDU patterns also occur in normal controls. No marker, filename, attack flag or private oracle field belongs in later model predictors.

The server deliberately does not enforce the lab permission policy as an interlock. That permits demonstrating a syntactically valid but policy-violating command. The declared policy and stored-setpoint consistency can be checked with deterministic contextual rules; ML superiority is neither assumed nor proved.

## Local software checks without Docker

With a working Python3.11+ interpreter:

```powershell
python -B -m unittest discover -s tests -v
python -B -m c3lab smoke --output outputs --groups 1
```

Smoke mode exercises actual local TCP but does not capture packets or produce verified labels. Synthetic PCAPs used in tests are test fixtures only and must never be described as measured research data. Do not use the local smoke path as a replacement for the captured Docker run.

## Stop after the pilot

Explain one normal command, one injected command, one normal reply and one forged reply using both packet bytes and evidence. Confirm causal information available to a real detector. Then agree the revised research objective, a broader scenario/control design, held-out runs/configurations and later preprocessing responsibilities before larger collection or modelling. Multiple runs on this same simulator do not prove performance on real industrial plants.
