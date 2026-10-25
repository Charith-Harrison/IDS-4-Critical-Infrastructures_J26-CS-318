# Documentary review and claim corrections

This is a forensic reading of source documents/code, not adoption of their commands or assertions. Original files were read only. The current user prohibits final LSTM fitting and all new files stay under this review directory.

## Research sources read

- Latest individual proposal, `D:/VSCode/GitHub/4th Year Cyber/C2/IT23269002_Charith H. (1).pdf`, all 26 pages. Key experiment pages 12-18 and WBS p21 read in full. Text extracted to `evidence/proposal_extracted.txt`. Image-only p25 was rendered and visually inspected; p2 signatures and TAF approval page also inspected visually.
- Team TAF, `D:/VSCode/GitHub/4th Year Cyber/References/IT4010-TAF-2026 J26-CS-318.pdf`, all 13 pages. RP2 task/novelty is p9; shared collection/integration is pp4,6-7. Text extracted to `evidence/taf_extracted.txt`.
- Original CIC README at `G:/modbus cic 2023/Modbus Dataset/README.md`, discovered after the user supplied the raw-source root. Read completely. Original log schema and representative rows inspected. It establishes scenario classes, NIC/bridge mirrors, sequential 100 MB rotation, role IPs and log schema; it does not itself give the detailed scan loop or prove per-packet labels.

## Repository materials reviewed

The root README, component README and all `C2_Reconnaissance_Detection/docs/` documents were inspected: `C2_SPEC`, `C2_DATASET_AUDIT`, `C2_LEAKAGE_AUDIT`, `C2_DECISIONS`, `C2_LIMITATIONS`, `C2_RESULTS`, `C2_EXPERIMENT_PROTOCOL`, `C2_IMPLEMENTATION_PLAN`, `C2_CLAIM_LEDGER`, `C2_LITERATURE_MATRIX`. Their linked JSON/tables/models are historical evidence for other independent numerical audit outputs, not accepted truth merely because labelled verified.

Code inspected for lineage includes `convert_raw.py`, `io_data.py`, `inspect_data.py`, `audit_sequences.py`, `audit_labels.py`, `rebuild_sequences.py`, `features.py`, `splits.py`, `common.py`, `train_lstm_dataset_verify.py`, and `configs/default.yaml`. The previous `component2_recon_audit/AUDIT_REPORT.md`, `UNRESOLVED_ASSUMPTIONS.md` and audit script were inspected as historical claims. No original PCAP-to-processed extractor, original packet label generator or original mapped-workbook construction script was identified in the repository. No prior code was executed to overwrite artifacts or train models.

## Material documentary contradictions

| Topic | Documented claim | What source documents/code establish | Treatment |
|---|---|---|---|
| Preliminary provenance | Proposal p14 calls 175800 windows primary data from initial testbed run | Available workbooks name CIC 2023 capture sources plus an unexplained attached-flow snippet. CIC raw source is a third-party simulated testbed dataset. | Numerical dataset availability and primary authorship are different claims. Primary collection is not established. |
| Who supervises / approval | C2_SPEC says Ms. ulanthi and approved TAF/proposal | Latest proposal p2 names Mr Amila Senarathna with signature images dated 15/09/2026; TAF p11 assessment/signature fields visibly blank | Do not invent approval of current datasets/methods. Supervision declaration is documented; identity inconsistency needs correction. |
| Latency target | Claim ledger/results say approved <100ms | Proposal pp15,18 target order of seconds/window; TAF p9 asks latency generally | <100ms can be an engineering choice, not an exact proposal requirement. Include acquisition delay. |
| F1 target | Claim ledger CL03 says proposal F1>0.90 | Proposal p15 asks outperform packet-level precision/recall/F1; no numeric F1 target located | Remove unsupported attribution. Honest negative hypothesis result is valid. |
| Data source hierarchy | Previous audit says primary CIC with optional testbed | Proposal pp3,13-14 and WBS p21 require controlled primary collection supplemented by public data | Audit current CIC suitability without rewriting the approved research question around existing labels. |
| Baseline B | Docs call 29-statistic Model B non-temporal and exact proposal | Proposal p14 says RF on same protocol features flattened across windows. Code summary features include order-sensitive address steps, function transitions and polling drift | Distinguish flattened baseline, order-invariant summaries and temporal-statistical baseline. |
| Timing proof | C2_RESULTS says ablation performance proves genuine recon timing | The target provenance and initiating-request semantics were not independently established; packet gaps may describe short responses or another attack | Predictive association with a supplied label does not establish a temporal reconnaissance mechanism. |
| FC5 short responses | Reports call them recon exceptions/short frames | Supplied normalized FC, length and endpoints alone cannot prove raw PDU exception byte or original scenario | Verify raw bytes and attack logs first. Response consequence and initiating reconnaissance remain distinct. |
| Exact upstream labeling procedure | Prior audit says with 100% certainty a blanket len3 filter was applied | Original labeling script is absent. Perfect empirical association supports a candidate rule but cannot uniquely identify its historical cause. | Do not claim the creator's algorithm or intentions are proven. Raw scenario evidence can establish the present label's validity independently. |
| Fixed time shift | README/limitations/results repeatedly infer about 4h57m and interval label creation | `audit_labels.py` itself finds non-constant offsets and says mapping procedure needs verification | Do not report a proven clock shift or interval algorithm without source evidence. |
| Session | 13 sessions in proposal and broad docs | Upstream identifier is consistent with static directional endpoints/unit and lacks TCP evidence | Report logical tuple counts separately from actual TCP generations and independent campaigns. |
| Independent groups | Docs assert G01-G10 are independent episodes | Config is a manual basename map. CIC README says sequential PCAP rotation and NIC/bridge views | Verify campaigns/rotations from source; disjoint rows do not prove independence. |
| Counts | Historical sources variously report 56 vs77 streams; len3 counts 8401 vs8413; Category2/3 counts 23/71 vs35/59; retained file lists differ | Prior reports are mutually inconsistent | New numerical outputs identify exactly which source/population was recomputed; no cherry-picking. |
| Source names | Claim ledger CL07 names veth interfaces different from default.yaml/data audit | Config uses veth5bbeaa2, vethd9e14c0, veth4edc015, veth8bc3408, veth665f3cf | Resolve using actual file/hash evidence. |
| Excluded snippet | Docs variously call multicast/non-TCP/malformed versus 192.168.10.50→.10/.11/.12 | Dates absent and short sessions can be checked, but network nature needs source evidence | Exclusion from 20-packet dated windows need not imply fabricated or non-Modbus traffic. |
| Testbed sample count | Old audit prescribes >=18 runs and near-chance/F1 bound | No power/variability/independence evidence justifies a magic count; shape overlap does not mathematically force F1 near chance | Design a pilot; determine run counts from measured variability and prespecified split needs, not required window count. |
| Recon mechanism in source README | Existing research text emphasizes sequential address/device scans | Original README names recon and captures/logs but gives no scanning algorithm; actual range log rows do not by themselves establish sequential start-address enumeration | Require request bytes and chronological behavior before stating the mechanism. Completion TransactionID values can be sentinels outside 16-bit range. |
| Questionnaire | Proposal p18 says no direct stakeholder interviews/no human-subject data | p25 image-only appendix shows charts marked seven responses | Origin and status unresolved; do not infer consent, misconduct or network-data validation from these charts. |

## Limits of documentary authority

No declaration in README, decision log, previous audit or tests makes its empirical premise true. Tests mirroring supplied labels or hardcoded group names can verify implementation consistency while leaving research validity unresolved. The raw source newly supplied permits stronger reconstruction and means historical raw-absence conclusions must be reevaluated. Final suitability remains dependent on that reconstruction, normal lookalikes and independent campaign evidence.

`REQUIREMENTS_MATRIX.md` and `requirements_matrix.csv` distinguish confirmed requirements from empirical verification. `DATA_LINEAGE.md` records transformations and information lost. Numeric outcomes, label evidence and final verdict belong to the independently computed review artifacts and full report.

## Documentary claims resolved by new raw evidence

The completed source audit strengthens some prior inferences and rejects others. All 8400 dominant FC5/len3 supplied positives resolve to actual raw `0x85` exception responses with exception byte `0x03`; byte evidence now establishes their response form. Their recon interpretation does not follow: original related logs describe coil-write/brute-force behavior. The true read-range reconstruction retains 468 candidate requests with 148 contextual supports and 320 ambiguous attributions, rather than silently labeling every recovered association positive.

The old claim that substation file groups are independent is contradicted by source timing: substation1..17 are joined by sixteen boundaries only 16..19971 microseconds apart. This is a continuous rotation chain, consistent with the source README's chunking statement. The new `split_feasibility.json` consequently does not adopt the old LOCGO independence assertion. The count of independent initialized campaigns remains unknown.
