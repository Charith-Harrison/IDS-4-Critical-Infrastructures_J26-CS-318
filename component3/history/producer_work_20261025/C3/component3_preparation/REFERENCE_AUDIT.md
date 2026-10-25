# Reference and historical-export audit

Reviewed locally on 24 October 2026. This document distinguishes document requirements, independently measured export properties, inspectable code and historical narration. The authoritative current instruction is CIC-only extraction, evidence annotation, pairing audit and grouped partitions, stopping before model preprocessing. No original PDF, capture, log, historical CSV or original parser was changed for this audit.

## Research requirements and conflicts

The supplied references actually reside in `references/component3_reference/`, rather than the repository-root path described by the handoff. The raw CIC collection is separately under `data/raw/Modbus Dataset/`. The two locations must not be confused with historical derivative files under `data/raw/`.

The team TAF, `IT4010-TAF-2026 J26-CS-318 (1).pdf`, has 13 pages. Component 3 on pages 9-10 requires command sequences, legitimate protocol semantics, request-response relationships and comparison with a per-packet baseline. The neighboring replay component owns replay/duplicate timing detection; transaction identities remain necessary to reconstruct component 3 pairs. The TAF's page 6 external-source/testbed plan is superseded for this task.

The individual proposal, `IT23150270_Rathnayaka K.H..pdf`, has 52 pages. Relevant complete pages were read with local PDF text extraction:

| Pages | Requirement or interpretation |
|---|---|
| 21 | Evidence-supported normal/command-injection/response-injection objectives; ordered data, same-family baseline, leakage-resistant evaluation and shared output schema |
| 22-24 | CIC is primary; logs must be correlated with packet behavior; ambiguous matches are audited; delay is not automatically forged response; other mechanisms have separate scope |
| 25-27 | Missing versus inapplicable fields, legitimate repeated polling, proposed future windows K=3/5/10, training-only transforms and leakage exclusions |
| 28-30 | Same Random Forest family, identical development design, contextual ablation, per-class/macro metrics, uncertainty and threats to validity |
| 31-35 | Event/session lineage and optional operational policy inputs; prediction, confidence, evidence, model version and processing-status outputs; shared fusion/dashboard interface |
| 50 | Appendix 1 states unit, group leakage and reproducibility requirements, but its MSU-specific category abbreviations are not original CIC ground truth |
| 51 | Decision log records proposed assumptions and pending supervision; it does not establish local CIC class availability |
| 52 | AI disclosure assigns experiment verification and defense to the student; these preparation notes do not claim that verification or understanding has already occurred |

The proposal's secondary/external datasets, testbed gap-filling, feature construction, fitted profiles, modeling and external validation are outside the present authorization. No such source was opened or used as research data. A documented function/role map is optional input, not a policy inferred from attack labels. Raw register words alone do not supply signedness, engineering units, multi-register word order or real process authorization.

The original CIC README describes benign/attack captures, NIC/bridge viewpoints and roughly 100 MB rotating files. Its attack-folder names establish scenario provenance, not every ADU's target. Its richer log dictionary does not prove every actual log has all those fields. Actual source inventory, clock alignment and log coverage must establish those properties.

## Independently reproduced old-export results

Executed:

```powershell
./.venv/Scripts/python.exe component3_preparation/reference_audit.py
```

The script reads the historical CSVs for diagnosis and writes `output/reference_audit.json`. It does not supply rows to the extraction pipeline, fit a classifier or create model predictors. The report includes exact paths, SHA256 and the exported-field join definition.

| Property | Reference-pack normal baseline | Reference-pack attack derivative |
|---|---:|---:|
| Rows / columns | 150,000 / 36 | 215,830 / 35 |
| Original capture column | `file_source` present | Absent |
| Stored subtype Normal | 150,000 | 110,415 |
| Stored subtype Coil_Brute_Force | 0 | 105,391 |
| Stored subtype Length_Manipulation | 0 | 24 |
| Read requests | 74,687 | 54,694 |
| Read replies | 74,683 | 55,745 |
| Read replies storing `modbus_val=0` | 74,683 | 55,745 |

Baseline timestamps retain fractions; all attack-derivative timestamps are whole seconds. All 74,687 baseline read requests store requested quantity in `modbus_val`; this is a request count, not a returned process value. Every read reply in both reference exports stores zero in that scalar. These are confirmed export semantics and a reason to decode original response bytes; they do not show that all actual devices returned zero.

The function/length expression `FC in {5,6} OR len_discrepancy != 0` agrees with every attack derivative's stored binary flag. In the baseline it disagrees on 630 normal-labelled writes. This is a descriptive annotation-shortcut diagnostic, not measured detector generalization or proof of how the old script was written. A legitimate write is not inherently an attack.

Joining all 31 common nonlabel exported fields, including TCP flags and all four old timing/rate/ID-difference fields, plus baseline timestamps rounded to the nearest whole second reproduces **96 joined rows, with 48 binary-label conflicts**. Both joined sides have 96 distinct physical rows. The exact equality is on exported observations under that stated timestamp rule; the exports lack raw bytes, so it is not proof of byte-identical packets.

One reproduced conflict is baseline physical line 2880 versus derivative physical line 215736: frame 14924, TID 57951, FC5, baseline epoch `1674482417.866921` versus derivative epoch `1674482418`. The baseline says Normal while the derivative says attack. Its corresponding reply also conflicts. Do not choose a label arbitrarily or let matching copies fall into different partitions.

Six baseline source blocks each contain exactly 25,000 rows. Exported `inter_arrival_time` agrees with the previous exported-row timestamp difference within one microsecond on 149,992 of 149,999 transitions. This does not establish per-device or per-connection command timing. The row cap is measured; its original implementation and selection rationale are unavailable.

There is also a distinct existing attack derivative at `data/raw/command_response_injection_attacks.csv`: **192,920 rows / 35 columns**, with 97,960 Normal, 94,940 Coil_Brute_Force and 20 Length_Manipulation labels. Its SHA256 differs from the reference-pack attack file. The baseline at `data/raw/normal_traffic_baseline.csv` is byte-identical to the reference-pack baseline. These variants are audited separately; counts from one variant must not be attributed to the other. Neither variant supplies final extraction rows.

## Historical script and rule inventory

Repository filename inventory excluded `.git`, `.venv`, package caches and generated bytecode. The transcript-named `extract_modbus_features.py`, `generate_benign_baseline_dataset.py`, `generate_recon_lstm_dataset.py`, `finalize_lstm_recon_dataset.py`, `walkthrough.md` and `normal_sequences_baseline.csv` were not found. Consequently, their label precedence, actual timestamp tolerance, missing-field filling, selection caps and original RF split indices cannot be confirmed from code.

| Rule or claim | Location | Evidence status |
|---|---|---|
| Prioritized command classification | `previous_extraction_conversation.txt:10` | Narrated; no original extractor supplied |
| 70/30 RF split and perfect injection result | Transcript lines 37, 43 | Narrated; original split method/indices not supplied; not rerun |
| Recon timestamp tolerance +/-5 seconds | Transcript line 95 and result around 227 | Historical request/narration for component 2; not adopted |
| Reduced srcIP_dstIP_unitID sessions and five-second gap | Transcript lines 108, 219-222 | Narrated; does not establish TCP instance or run independence |
| Attacker-IP/range/exception reconnaissance heuristics | Transcript result around line 227 | Narrated; not valid component 3 ground truth |
| 115 appended flow rows | Transcript line 212 | Narrated; flow/ADU equivalence unsupported and prohibited here |
| 29,997 normal sequence windows | Transcript line 281 | Reported count; actual sequence membership unavailable |
| Missing attack capture provenance, whole-second timestamps, subtype counts, shortcut mimicry, zero read-response scalar | Actual supplied CSVs and `reference_audit.py` | Independently confirmed by data |

The reported 29,997 windows equals arithmetic over a globally concatenated 150,000-row sequence at length 20/stride 5; the corresponding sum for six separate 25,000-row blocks is 29,982. This comparison is an audit warning only. No new sequence windows were constructed, and the unavailable historical sequence lineage prevents confirmation of boundary crossing.

Later repository code is inspectable but is not the absent original extractor: `src/event_builder.py:13` assigns supplied/reset groups, `:35` sorts/builds derivative events and `:89` starts partial pairing; `src/preprocessing.py:34` selects group/temporal partitions; `src/label_mapper.py:25` maps supplied labels. Its temporal fallback at `src/preprocessing.py:79` cannot establish independent recording groups. The preserved legacy `legacy_backup/pre_rebuild_2026_10_23/src/data/split.py:17` deterministically enumerates 80/20 capture splits, and its `src/models/train.py:107` performs grouped CV. These are different experiments from the transcript's unspecified 70/30 claim. None was run for this Stage 1 task.

## Salvage decision

Baseline `file_source`, frame number, endpoint and precise time are useful source-lookup clues. Original source linkage is verified only when the raw-capture pilot independently resolves it. The attack derivative's absent source path and rounded timestamps require source lookup repair and can remain ambiguous. Existing attack names/flags are weak historical annotations, not final ground truth. Lost raw payloads, actual returned value arrays and subsecond times cannot be reconstructed from the old scalar fields alone.

The replacement extraction obtains its final records from original permitted CIC bytes and uses original CIC logs/documentation for evidence. Historical overlaps and conflicts remain a diagnostic report, rather than becoming an extra row source or an invented response-injection class. Current parser code from the unfinished Claude work is preserved separately and reviewed before reuse. Group/class feasibility, rather than the historical perfect score, governs what later experiment can be defended.
