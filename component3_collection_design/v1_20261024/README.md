# Component 3 collection design — v1

This package turns the passing local Modbus/TCP pilot into a reviewable collection protocol. It does **not** launch a larger collection or create model datasets. Current status: **design checked; generator extension and qualification pending**.

Read these in order:

1. [LOCAL_PILOT_CARD.md](LOCAL_PILOT_CARD.md): your actual local capture and two matched normal/attack examples.
2. [COLLECTION_PROTOCOL.md](COLLECTION_PROTOCOL.md): scope, scenarios, controls, evidence, prospective hold-outs and acceptance gates.
3. [RESEARCH_ALIGNMENT.md](RESEARCH_ALIGNMENT.md): how the work retains the Component 3 question and changes the proposal's main data source.
4. [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md): what must be added in a separate generator version before qualification.

`collection_design.json` is the machine-readable contract. `PROSPECTIVE_RUN_ROSTER.csv` is an uncollected roster: four engineering qualification runs, followed by a **draft** main budget of 48 captures. That budget is not statistical power, a final split or evidence of independent campaigns. Every row is marked `NOT_COLLECTED`.

## What is already checked

The existing local run has 216 verified messages: 208 normal, four command targets and four reply targets. Read-only checks verify recorded input/source hashes, actual packet byte references, protocol structure, direct intervention/state evidence and normal PDU overlap. Its new card preserves the difference between your run and the collaborator's earlier handover.

Protected CIC preparation/reassessment files, existing pilot code, handover documentation and actual captures remain unchanged. Check results and provenance are in `output/plan_checks.json`, `output/local_pilot_evidence.json` and `output/provenance.json`.

Reproduce the design and existing-run checks from the repository root:

```powershell
./.venv/Scripts/python.exe -X utf8 -B component3_collection_design/v1_20261024/check_design.py
```

This command reads existing evidence and writes only into this design directory. It does not start Docker, open a TCP connection, collect traffic, rewrite labels, fit preprocessing or train/evaluate a model.

## What comes next

Implement the new scenario/control families, configurable object maps, dependency-safe schedules and independent validator in a **separate version**, then run the four bounded qualification captures. Only after their acceptance, the methodology decision and a prospectively frozen main design should larger collection start.

The existing `start-pilot.ps1` remains a v0.1 feasibility launcher. It **does not consume this JSON plan** and cannot generate the proposed held-out maps/schedules. Do not repeatedly run it or raise its groups limit and call that the planned dataset.

No model preprocessing, engineered histories, sequence windows, X/y matrices, transforms, resampling or training have been performed in this design stage. The researcher will implement and demonstrate those later steps separately.
