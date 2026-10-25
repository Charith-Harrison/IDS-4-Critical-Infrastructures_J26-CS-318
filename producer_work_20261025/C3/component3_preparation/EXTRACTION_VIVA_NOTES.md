# Extraction and evidence demonstration notes

These notes support a reproducible explanation of Stage 1. They do not claim that the researcher has already run the demonstrations, performed model preprocessing or understood a later experiment. Use the generated machine-readable reports for exact observed counts, tool versions, stage completion and unresolved checks.

## What this stage does

The chain is immutable original CIC files -> source inventory -> decoded ADUs with byte/frame lineage -> separate pair and label evidence -> whole-parent-group candidate membership -> stop. Decoding, deduplication of proved stream observations, annotation and partitioning are data processing. The resulting Parquet tables are extracted records; the original PCAPs remain the raw evidence.

Only CICModbusDataset2023 and its original logs/documentation are permitted. Proposal references to other datasets are superseded. Old CIC CSVs diagnose earlier export defects but cannot contribute final rows, restore missing payloads or establish a response-injection target.

## Commands to run locally

Open PowerShell in the repository root. For the bounded parsing demonstration:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json pilot
```

For the complete reproducible authorized workflow, including source inventory, pilot gate, extraction, evidence audit and grouped membership:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json all
```

To recheck the published outcome without initiating model work:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json verify
```

The pair audit and human-readable report stage can also be run explicitly after their extraction/annotation/split prerequisites:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json pair
./.venv/Scripts/python.exe -m component3_preparation.c3prep.cli --config component3_preparation/config.json reports
```

To reproduce only the historical CSV findings:

```powershell
./.venv/Scripts/python.exe component3_preparation/reference_audit.py
```

For a read-only demonstration using the completed extraction, pair, label and candidate membership:

```powershell
./.venv/Scripts/python.exe -m component3_preparation.c3prep.demo
```

This command was executed successfully and saved `output/demonstration.json`. It traces FC3 frame5/PDU03020009 to raw word9 and IED frame531107/TID7485/PDU01abcd through its pair, original-log annotation and candidate-test membership. These are audit examples, not model inputs. `output/accepted_command_review.json` separately records independent original-PCAP and original-CSV/XLSX checks for all100 accepted command events.

The execution/quality reports distinguish successfully executed stages from commands merely shown here. A reused verified checkpoint is a resume outcome, not another set of appended records. Record its source/config/code signature when demonstrating determinism.

The local representative pilot **passed** its accounting and independent TShark 4.6.0 comparisons. Its benign 100,000,059-byte source took 73.56 seconds and produced 19,066,905 bytes of extraction outputs; its IED 100,000,047-byte source took 60.48 seconds and produced 14,889,087 bytes. The pilot reported a 607,117,312-byte process peak working set including verification material and 33,962,475 total output bytes including the reports/dissector references. These are pilot measurements, not claims about every extraction worker. Current exact figures are retained in `output/pilot/pilot_report.json`.

The larger selected scope comprises 21 complete available endpoint/interface chunks, 1,815,936,064 source bytes, under `benign_ied1b`, `external_bridge`, `scada_ied1a`, `ied_ied1b`. It preserves background context within those chains but does not represent all dataset endpoints. Full source/parent-group selection is documented in `EXTRACTION_SCOPE_AND_GROUPING.md`.

All four selected chains completed: 20,923,685 source frames produced 3,768,287 retained records, comprising 3,767,894 ADUs and 393 incomplete byte runs. The incomplete records remain explicit instead of being silently dropped. Initial extraction outputs occupied 341,438,613 bytes; subsequent pair/evidence/membership reports add separate disk usage. Completed extraction checkpoints were independently rerun and all four were reused without appending duplicate rows. Source/config/parser/output hashes and accounting live in those checkpoints; final whole-inventory preservation and annotation/split checks are separately established by the final quality reports.

The final accepted targets are 1,404,306 normal, 100 command_injection and 54 response_injection ADUs. Normal occurs only in the January benign campaign, commands only in the compromised-SCADA campaign, and responses only in the compromised-IED campaign. Thus no class-complete independent train/validation/test experiment is supported. The published candidate membership checks report zero pair/candidate crossings and zero missing pair endpoints; they do not repair the class-group scarcity.

`output/accepted_command_review.json` independently checks all 100 accepted commands against direct original-PCAP record bytes and original CSV/XLSX source rows. Every accepted command has one behavior-compatible packet/log candidate on both sides within the frozen 25ms policy. However, 98 command PDUs are malformed and only two are parser-ok; the 54 response targets comprise 53 malformed and one parser-ok PDU. A parser-ok status does not establish correct process values or authorization. This small structurally accepted cohort and the class/campaign separation must be disclosed before any later contextual-ML comparison.

## Demonstration 1: raw bytes, requested quantity and returned value

Locate `benign/scada-hmi/scada-hmi-network-capture/veth5bbeaa2-normal-13.pcap`, frame 5. The bounded pilot checks the FC3 response against TShark and records both outputs in `output/pilot/`. Inspect the source hash and exact frame reference first.

The PDU `03 02 00 09` means function 3, two returned data bytes and one raw register word 9. The source request asks for one register. Its requested quantity is 1; the returned value is 9. The old baseline's corresponding scalar field is 0, showing why final rows were decoded from original bytes instead of copied from the derivative.

The read-response PDU does not contain a starting register address. A matched request may supply an associated address in the pair audit, while the response wire-address field remains inapplicable. Raw register word 9 has no established engineering unit, signedness or multi-register floating-point representation in this extraction.

Open `output/pilot/pilot_report.json` and the `benign_tshark_examples.tsv` output to reproduce the locally passed example and its exact epoch time. No old scalar value was copied into the new extraction.

## Demonstration 2: a response-side candidate and its evidence limits

Inspect the original March 23 compromised-IED log at physical line 35: false data injection, target `185.175.0.2`, TID 7485 and timestamp `16:26:51.793`. Locate frames 833140 and 833142 in `attack/compromised-ied/trust-scada-hmi/trust-scada-network-captures/veth3efd353-1.pcap`.

The pilot checks the raw request/reply identity and the reply PDU `01 ab cd`. Function 1 declares byte count 171 (`ab`) but provides one data byte (`cd`), so the reply is structurally malformed. Read its precise packet time, request lineage, original log reference, clock interpretation and matching residual from the reports. A successful match under zero offset for this example does not validate every scenario clock or every log timestamp.

This is a useful log-linked malformed-response example. It does not show that every FDI event is response injection, that every malformed reply is malicious, or that machine learning is required to detect this structural inconsistency. The annotation audit must state which event is directly supported and which messages are only associated with the attacked transaction.

The final selected IED1B view independently contains this same transaction at frames 531105/531107 in `vethc76bd3f-0.pcap`. `output/pilot/ied_endpoint_crossview.json` records identical request/reply TCP payloads and approximately ten-microsecond inter-view timestamp differences. This is transaction-level copy evidence; it does not assert whole-recording equivalence. The trust-HMI pilot rows are not added to final partitions as separate independent examples.

## Demonstration 3: frame versus event and connection identity

Choose a segmentation or multi-ADU fixture in the offline parser tests and inspect its accounting. Explain why one ADU can span frames/chunks and why one frame can produce several application events. For a real extracted event, trace recording ID -> view -> connection generation -> source chunk/frame references -> stream byte interval -> ADU/PDU bytes.

Transaction ID alone is not global identity. Concurrent requests and ID reuse require outstanding state within one endpoint tuple and connection generation. A new TCP connection may reuse ports and transaction IDs. A response does not need to be the next packet. TShark stream IDs from independently opened files are not globally unique sessions.

Read the pairing report's matched, orphan, ambiguous, late, exception and capture-boundary outcomes. Pair consistency and status are separate from target class. A missing request may result from an incomplete capture; a valid exception is not automatically an injected response. A bounded audit timeout is a configured parameter, not a learned universal Modbus deadline.

## Demonstration 4: provenance, mirrored views and partition boundaries

Inspect `output/inventory.json`, the source-group map and split manifest. Show that every extracted source belongs to the permitted raw root and a declared canonical view, and every event retains exact lineage. Explain why rotated chunks share TCP state and why simultaneous NIC/bridge observations belong to the same independent parent recording group.

The source folder contains a chronological trap: `attack/compromised-scada/substation-wide-capture/substation-0.pcap` spans a small March 23 interval, unlike chunks 1-17 from March 15-22. Filename sorting would concatenate backwards in time. Show the actual timestamp/duplicate evidence used to relate the small file to its parent recording. Do not equate its folder or numeric suffix with independence.

In `SPLIT_VALIDATION.md` and its JSON counterpart, find group disjointness, duplicate-view containment, pair containment, source/event membership reconciliation and within-scope chronology. A check can be verified, unresolved or failed. Display the actual status and consequence. Candidate train/validation/test membership is not a scoring-ready claim when required class evidence or independent group coverage is unresolved.

Count class-bearing **groups and episodes**, not just target rows. Related attack episodes from one continuous run remain one group. If response evidence occurs in only one parent run, cutting it into random packet subsets does not provide independent response-injection training, validation and test support. An unavailable class metric must be reported unavailable.

## Demonstration 5: zeros, missingness and repeated observations

Show one address zero or data zero as an actual protocol value. Compare it with a read reply's inapplicable wire-address field, a truncated value and an unknown engineering interpretation. No absent field was replaced with zero during extraction.

Compare a proved TCP retransmission with two legitimate identical polling PDUs at distinct stream positions. The retransmission repeats already observed stream bytes; the repeated poll is another command. An equal payload alone is insufficient evidence to remove an observation. Mirrored capture copies need source/time/packet evidence and remain contained in one group.

## Demonstration 6: what the historical audit establishes

The reference-pack CSVs contain 150,000x36 baseline and 215,830x35 attack rows/columns; the attack derivative lacks capture provenance. The diagnostic script reproduces 96 rounded-timestamp exported-record overlaps and 48 stored-label conflicts. Its function/length expression reproduces attack-derivative labels exactly, without training a model. These are warnings about annotation and shortcuts, not validated detection performance.

Also identify the distinct 192,920-row attack copy under `data/raw/`. Source hashes and paths prevent conflating it with the 215,830-row reference version. The historical conversation's perfect score and unspecified 70/30 split cannot be independently reconstructed without its missing original extractor/evaluation scripts and indices. None was rerun here.

## Stage boundary to state accurately

Executed work is established by the source, pilot, extraction, pair, label and split reports. No imputer, encoder, scaler, normal profile, classifier, balancing procedure, generated context window or model matrix was fitted or created by this preparation package. The researcher will separately implement and explain future model preprocessing using `PREPROCESSING_PLAN.md`, subject to the actual class/group feasibility findings. Do not claim personal completion or validated three-class performance from the existence of these files.
