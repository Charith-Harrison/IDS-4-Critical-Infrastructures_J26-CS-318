# Teaching this pilot on Discord

Use Kaveesha's laptop and repository as the main place to run and understand the pilot. That keeps the code, environment, captures, and explanations together for her viva. You can guide her over screen share, but she should type the commands and explain what each result means.

The portable folder is `component3_testbed_pilot`. Put it at her repository root, alongside the existing `component3_preparation` and `component3_reassessment` folders. Do not paste its files over either existing folder. There is no need to copy the large CIC download into this pilot folder.

## Start with this explanation

Say:

> We are making a tiny pretend machine and control computer. They send real network messages to each other inside a closed local container. We deliberately send a bad command or fake answer, and record exactly what changed. First we are checking whether that recording and proof work. We are not training a model yet.

Translate the four terms as they come up:

- **PLC:** our pretend machine.
- **HMI:** our pretend control computer.
- **PCAP:** a recording of network messages.
- **Ground truth/oracle:** the private experiment log that tells us what we deliberately did.

The oracle is the teacher's answer sheet. It is useful for marking answers, but you cannot hand it to the detector as an input.

## Before opening a terminal

1. Docker is not installed yet. Install Docker Desktop from the [official Windows installation guide](https://docs.docker.com/desktop/setup/install/windows-install/), using its WSL 2 backend and the current requirements shown there. Complete the installer and restart Windows if asked.
2. Open Docker Desktop on her laptop and finish any first-start setup.
3. Wait until Docker Desktop says its engine is running.
4. Confirm it is using Linux containers. If it is not, use Docker Desktop's supported switch to Linux containers; do not improvise system changes during the call.
5. Open her repository in Codex or her editor.
6. Open a PowerShell terminal at the repository root.

Building the image needs internet the first time. The actual pilot then runs without external networking. Everything is simulated; no factory equipment, public host, router configuration, or real controller is needed.

If Docker is missing or its engine cannot start, stop at the environment check and work from the actual error. Do not tell her a run succeeded just because the files extracted successfully.

## Run these commands one at a time

From the repository root:

```powershell
Set-Location .\component3_testbed_pilot
```

Check the environment:

```powershell
.\start-pilot.ps1 -CheckOnly
```

Read its result together. If it reports missing prerequisites, use that report to fix the environment before starting the experiment. If Windows blocks a script under her existing policy, retain the error and use her normal trusted development setup; do not bypass organizational controls.

Once the check succeeds:

```powershell
.\start-pilot.ps1
```

The first run may take longer while the image builds. Let the script complete and note the new folder name printed under `outputs`. A successful application run is not yet the same as successful independent verification.

Verify that run using the exact folder name printed by the launcher. For example, if it says it created `outputs\pilot-20261024T120000Z-a1b2c3d4`, use:

```powershell
.\verify-pilot.ps1 -Run pilot-20261024T120000Z-a1b2c3d4
```

The name above is an example, not a folder that already exists. Replace it with the actual `pilot-...` folder printed on her machine. Pass just that folder name, not the full path, and do not add angle brackets. Do not use an old example or a run from your laptop.

## What to open after the run

The run lives under:

```text
component3_testbed_pilot/
  outputs/
    <unique-run>/
      run_manifest.json
      application_ledger.jsonl
      server_audit.jsonl
      capture.pcap
      capture.log
      validation_report.json
      verified_labels.jsonl   # only after verification passes
```

Open `validation_report.json` first. A passing result should establish the expected message counts, protocol checks, stream/byte correspondence, and labelled targets. The default two-group pilot expects 12 episodes, 108 exchanges, and 216 messages: four command targets, four response targets, and 208 normal messages. These are tiny repeated demonstrations, not a completed ML dataset.

If the result fails or counts differ, preserve that run and its logs. Read the specific failure before rerunning. Do not edit labels, remove inconvenient messages, or change expected counts just to make a check green.

Next open `application_ledger.jsonl` and `server_audit.jsonl`. They are text files with one JSON record per line. Each line describes an observation or experiment event. Use them to follow a target; do not worry about understanding every field immediately.

If Wireshark is installed, open `capture.pcap`. The packets are recorded inside the container, so the address is local and the port is 15020. Wireshark may need **Analyze → Decode As → Modbus/TCP** for that port. The validator does not rely on Wireshark recognizing a default port.

The loopback capture may include TCP acknowledgements or multiple frame references for application messages. Packet count and Modbus-message count are different things. A TCP packet is an envelope, and a Modbus message is a letter; one envelope is not guaranteed to equal one letter.

## Walk through a command example

Say:

> The rule says the pump may turn on only when the mode is 1. The machine does not enforce that permission itself, so our detector needs to notice it.

Ask her to follow these observations in order:

1. The control computer writes mode 0 and reads it back.
2. It later sends a correctly written pump-on command.
3. The private audit confirms that this was the deliberately unauthorized target.
4. A normal episode uses the same pump-on command after mode 1.

Ask her to explain, in her own words, why the command bytes alone cannot tell these cases apart. The intended answer is that the earlier observable mode changes whether the command is permitted under the lab rule.

The attack is a malicious instruction from a simulated compromised control computer. We are not teaching the programs to break into a network.

## Walk through a response example

Say:

> We set a value, the machine acknowledges that write, and then we read it. In this tiny process the value cannot change by itself. A fake reply reports a different value while still looking like a valid reply.

Follow:

1. An FC6 write sets register 1 to value `a`, and the acknowledgement is visible.
2. The control computer requests that register with FC3.
3. The compromised reply hook returns value `b` with a valid message shape.
4. The private server audit shows that the actual stored value remained `a`.
5. A normal episode returns `b` after a legitimate write of `b`.

Ask her what information the detector can use. It can use the observed write, acknowledgement, request, and reply. It cannot use the server's hidden `attack` flag or future recovery messages if it claims to decide immediately.

Explain the limitation too: if a real machine can change a value by itself, a different readback might be legitimate. Our rule works because this pilot explicitly excludes that behavior. She must state that assumption in the viva.

## The questions she should answer before collecting more data

Ask one at a time, without reading the answers for her:

1. What is the difference between an invalid message and a valid message used at the wrong time?
2. Which exact request is the command target, and which exact response is the response target?
3. Where does the evidence show that the captured bytes actually match those targets?
4. Which earlier observation makes each target suspicious?
5. Why is the private experiment log forbidden as a detector input?
6. Why does this successful toy run not prove that ML is better than a simple rule?
7. Why would changing the random seed not automatically prove performance on a different factory?

If she can answer those, she understands the pilot's purpose and its main limits. She does not need to memorize every Python function to understand the experiment, but should be able to find the scenario definitions, protocol messages, attack hook, and validator when asked.

## What to give her Codex after this folder is copied

Paste this into her existing project chat:

> Read `component3_testbed_pilot/README.md`, `docs/EXPERIMENT.md`, and `docs/DISCORD_LESSON.md`, plus the existing CIC preparation and reassessment decision reports. This is a local controlled feasibility pilot, not a final training dataset. Help me run `start-pilot.ps1 -CheckOnly`, then one default pilot and `verify-pilot.ps1` for its exact run folder. Explain each step in plain language and inspect the actual results before claiming success. Preserve all CIC outputs and failed runs. Exclude MSU and other datasets. Do not perform ML preprocessing, model training, mass collection, final splits, or internet-facing deployment. If the environment fails, diagnose the concrete error and propose the smallest fix. After a passing run, walk me through one normal and attack pair for each family using the ledger, private audit, and exact captured message evidence. End with the pilot's limitations and the supervisor decision still needed.

The initial task is one verified run and understanding its evidence. Do not ask Codex to generate a large dataset yet.

## Message for the supervisor

> Our evidence-linked CIC extraction currently cannot support the original independent three-class evaluation. We have prepared a small isolated Modbus/TCP pilot to test valid-looking command and response manipulations with explicit ground truth and observable history. May we revise the main experimental source to a controlled testbed and compare current-message methods, simple context rules, and contextual ML within a clearly limited scope? CIC would remain a separate limited case study. A successful pilot will not be presented as proof of ML benefit or generalization.

Record the response and the accepted research claim. If accepted, design the larger experiment before collecting it: varied but relevant conditions, comparable normal controls, clear independent units, held-out conditions, and transparent assumptions. There is no magic number of runs that makes the research sound.

## What to send back for review

For a successful first run, send the small `run_manifest.json`, `validation_report.json`, and the terminal's final status. A short explanation from Kaveesha of one command and one response example is useful too.

For a failed run, send the exact terminal error, `capture.log` if it exists, and `validation_report.json` if it was generated. Keep `capture.pcap` and both ledgers available for a deeper check, but there is no need to send the entire repository or CIC download again.
