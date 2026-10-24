# Handover to Kaveesha

You are receiving already-collected **controlled feasibility data**, its source code, exact evidence and a recorded software environment. Collection occurred on Thithira's Windows PC on24 October2026. Preserve that provenance and describe the implementation assistance accurately.

## Inspect without generating anything

1. Extract the evidence ZIP into your repository. It contains `component3_testbed_pilot/`; keep that folder beside existing CIC preparation/reassessment folders.
2. Open `DATASET_CARD.md` in this folder.
3. Open `outputs/pilot-20261024T145730Z-4a7f6472/validation_report.json`: status must be PASSED; counts208 normal/4command/4response.
4. Read that run's `EVIDENCE_WALKTHROUGH.txt`. It shows normal and malicious messages with matching PDU patterns and exact frame numbers.
5. Inspect `capture.pcap` in Wireshark if available. Use Decode As Modbus/TCP for port15020 if required. The event IDs/frame numbers belong to this capture, not to a CIC file.
6. Follow those events in `verified_labels.jsonl`. The application ledger and private server audit explain label evidence; they are not a model-ready feature table.

Docker is not needed to read JSON/text evidence. Wireshark or a comparable packet reader is needed for graphical packet inspection. You do not need to regenerate the supplied run merely to receive or demonstrate it.

## Evidence files

| File | What it establishes |
|---|---|
| capture.pcap | Actual recorded traffic |
| capture.log | Recorder startup/statistics/drop count |
| application_ledger.jsonl | Sent/received bytes and message identities |
| server_audit.jsonl | Original state and genuine-versus-altered reply evidence |
| run_manifest.json | Original seed, source hashes, platform and raw-artifact hashes |
| host_execution.json | Actual image identity and launch information |
| validation_report.json | Stream, state and label verification result |
| verified_labels.jsonl | Accepted messages with frame/file byte references |
| EVIDENCE_WALKTHROUGH.txt | Human explanation of specific matching examples |
| INDEPENDENT_CAPTURE_CHECKS.json | Extra byte-reference and decoder checks |

The included failed initialization attempt is debugging history, not training data. Test fixtures and Windows smoke checks are not extra measured captures. Preserve the supplied original files; do not edit labels to change a result.

## Optional reproduction

To rebuild from source and generate a NEW uniquely named run, install/start Docker Desktop's Linux engine and run from this folder:

```powershell
.\start-pilot.ps1
```

For the separately supplied exact image archive, replace the sample path below with its downloaded location:

```powershell
docker image load --input 'C:\YOUR-DOWNLOAD-FOLDER\KAVEESHA_C3_DOCKER_IMAGE.tar.gz'
.\start-pilot.ps1 -SkipBuild
```

Docker supports loading gzip image archives; see [its official load documentation](https://docs.docker.com/reference/cli/docker/image/load/). Loading an image does not install Docker. It avoids rebuilding image dependencies. A fresh run has new timestamps, TCP headers, source port and capture hash even with the same seed. Never overwrite the supplied capture to make a rerun identical.

To verify and explain the existing supplied recording using the image:

```powershell
.\verify-pilot.ps1 -Run pilot-20261024T145730Z-4a7f6472
```

Your drive letters need not match the collection PC; the scripts resolve paths from their own folder. Do not import MSU or mix CIC rows into this lab. New runs remain feasibility demonstrations until a larger design is agreed.

## Be able to explain

- Messages were actually transmitted and captured, not invented CSV rows.
- A valid message can be unauthorized: identical pump-ON PDU, different earlier mode.
- A reply can be structurally valid but conflict with a prior acknowledged write under this toy process's rules.
- Genuine acknowledgements do not inherit response-injection labels.
- Bytes, stream positions and frame references establish the exact targeted messages; time/IP proximity alone does not.
- The private oracle is the answer sheet for labelling, not an input available to a deployed detector.
- Simple contextual rules may already solve this pilot; ML superiority and real-factory performance remain unproved.

Use `docs/DISCORD_LESSON.md` for the walkthrough. Future preprocessing remains separate. Discuss the main-data-source change with the supervisor before treating this pilot as the final assessed experiment.
