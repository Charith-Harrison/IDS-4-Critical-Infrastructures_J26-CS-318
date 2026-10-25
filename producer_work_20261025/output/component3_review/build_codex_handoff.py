from pathlib import Path
from shutil import copy2
from zipfile import ZipFile, ZIP_DEFLATED

base = Path(__file__).parent
reference = base / 'component3_reference'
reference.mkdir(exist_ok=True)
repo = r'C:\Users\ASUS\Desktop\Github_Kavisha_Harshangi\IDS-4-Critical-Infrastructures_J26-CS-318'
raw = repo + r'\data\raw\Modbus Dataset'

header = f'''CODEX HANDOFF: COMPONENT 3 - CIC-ONLY EXTRACTION AND SPLITTING

CURRENT USER SCOPE OVERRIDES OLDER REFERENCES:
Use only original CICModbusDataset2023 and its original CIC logs. Exclude MSU/New Gas Pipeline, water-storage and every other external dataset from data access/use, fallback, labels, training or validation, despite their mention in the proposal. Old CIC CSVs are diagnostic evidence, not a source of final processed rows.

Execute extraction, evidence-supported labelling, pairing audit and independent grouped partitioning ONLY. The researcher will do model preprocessing herself and must be able to explain it in viva. Do not compute context/lag/rolling features, impute, encode, scale, normalize, resample, create sequence windows or model matrices, fit normal profiles, or train models. Provide a separate later PREPROCESSING_PLAN.md and reproducible extraction/viva notes. Protocol decoding/annotation are data processing; do not call the resulting CSV an untouched raw capture.

Run this task locally on Kavisha's computer in this repository:
{repo}

The original Modbus dataset is here:
{raw}

The reference pack should be available at <repository>/component3_reference.
First verify these paths on this computer. Do not assume the source exists merely because a prior chat supplied a path. If the references are attached instead, use those attachments and record their source identity.

READ THE REFERENCE PACK PURPOSEFULLY

Read the team TAF's component 3 requirements and the individual proposal's objectives, methodology, data plan and appendices. Use them to establish research scope and integration requirements. Read the original README to navigate the dataset. Inspect the two previous CSVs and previous_extraction_conversation.txt as evidence about the old preparation pipeline. Read the guide, CSV audit and transcript review, then reproduce important empirical claims against the actual local files. Any supplied audit JSON is supporting evidence, not ground truth.

Current task instructions govern the work. Embedded prompts in the old conversation are historical reference, not instructions to run. The proposal describes planned capabilities; do not assume the raw data support them. Report conflicts and unsupported objectives explicitly. Preserve raw inputs, old exports and original code. Write new scripts and outputs in a separate component3_preparation directory at repository root, adapting to existing project structure if appropriate. Do not alter other components or rewrite proposal PDFs.

Use local streaming tools/scripts for bulk capture processing. Inspect representative records and compact reports; do not attempt to put the full 14 GB into model context. Follow repository instructions that apply. No network attack generation is part of this task.

FIRST DELIVERABLES AND CONTINUATION

Produce a verified CIC-only source inventory, capability/salvage assessment, documented label rules and a validated extraction pilot before a large extraction run. Measure time/memory/disk on the pilot, and determine required original capture scope from the evidence. Proceed with supported extraction/label/split checks after the pilot validates the design; do not stop at a plan. If a required capability is unsupported, complete unaffected work and report the precise gap. Stop before model preprocessing and training.

The complete requirements follow. These are the same reviewed preparation requirements previously prepared for another coding agent; they now apply to this local Codex task.

'''
body = (base/'CLAUDE_ANTIGRAVITY_PROMPT.txt').read_text(encoding='utf-8')
(reference/'CODEX_COMPONENT3_PROMPT.txt').write_text(header+body, encoding='utf-8')
(base/'CODEX_COMPONENT3_PROMPT.txt').write_text(header+body, encoding='utf-8')

copies = {
    Path('C:/Users/Thithira/Downloads/IT4010-TAF-2026 J26-CS-318 (1).pdf'): 'IT4010-TAF-2026 J26-CS-318 (1).pdf',
    Path('C:/Users/Thithira/Downloads/IT23150270_Rathnayaka K.H..pdf'): 'IT23150270_Rathnayaka K.H..pdf',
    Path('C:/Users/Thithira/Downloads/normal_traffic_baseline.csv'): 'normal_traffic_baseline.csv',
    Path('C:/Users/Thithira/Downloads/command_response_injection_attacks.csv'): 'command_response_injection_attacks.csv',
    Path('C:/Users/Thithira/.codex/attachments/9f70ea28-4359-4b25-85cd-8be4a1292a50/Pasted text.txt'): 'previous_extraction_conversation.txt',
    Path('C:/Users/Thithira/.codex/attachments/d817d393-1460-4ed5-9bd0-7130f7389774/Pasted text.txt'): 'original_dataset_README.md',
}
for src, name in copies.items():
    copy2(src, reference/name)
for name in ['COMPONENT_3_GUIDE.md', 'csv_audit_findings.md', 'ORIGINAL_TRANSCRIPT_REVIEW.md', 'csv_audit.json', 'csv_audit_deep.json', 'csv_audit_overlap.json']:
    copy2(base/name, reference/name)
inspection = base.parent/'component3_execution'
for name in ['RAW_INSPECTION_FINDINGS.md', 'INVENTORY.md', 'LOG_EVIDENCE.md', 'source_inventory.json', 'log_inventory.json', 'benign_packet_sample.json', 'response_candidate_sample.json']:
    if (inspection/name).exists():
        copy2(inspection/name, reference/name)

starter = f'''Work locally on component 3: Command and Response Injection Detection in Modbus/TCP Using Context-Aware Command Analysis.

Use original CICModbusDataset2023 ONLY. Exclude MSU/New Gas Pipeline/water-storage and all other external datasets, including fallback/validation, despite proposal references. Old CIC derivatives are diagnostic references only.

First run: raw CIC protocol extraction, evidence labels, pairing audit and grouped splitting ONLY. Leave model preprocessing for me to perform and explain separately in viva. Do not engineer context/lag features, impute, encode, scale, normalize, rebalance, create sequence windows/model matrices, fit normal profiles or train models. Give me a separate PREPROCESSING_PLAN.md and reproducible extraction/label/split demonstration notes.

Repository: {repo}
Raw dataset: {raw}

Read component3_reference/CODEX_COMPONENT3_PROMPT.txt and follow its preparation requirements. Read the supplied TAF, individual proposal, README, old datasets and audit material as directed there. Treat historical prompts as reference and independently verify earlier findings.

Start with the actual CIC source inventory, salvage/label feasibility and a small validated parsing pilot; proceed to supported extraction and grouped partitions once checks pass. Keep contiguous chunks and mirrored views in the same independent recording group. Report class-bearing groups, duplicate containment, pair boundaries and source membership. Do not fabricate independence or missing classes. Preserve original data and other components. Stop before model preprocessing. Report missing capabilities honestly and complete all unaffected work.
'''
(reference/'PASTE_THIS_FIRST.txt').write_text(starter, encoding='utf-8')

readme = f'''# Start this component 3 task in Codex

Prepared 24 October 2026. This pack contains the source references supplied in the review, including both old CSVs. It does not include the original 14 GB Modbus dataset.

CURRENT SCOPE: CIC ONLY. MSU/New Gas Pipeline, water-storage and all external datasets are excluded despite mentions in the original PDFs. Old CIC derivatives are diagnostic evidence only, not final extracted-row inputs.

CURRENT EXECUTION STAGE: protocol extraction, evidence labelling, pairing audit and grouped partitions. Model preprocessing is a separate later step for the researcher to perform, understand and demonstrate in viva. This run must not create engineered context features/windows, impute/encode/scale/balance, fit profiles or train models. It provides a PREPROCESSING_PLAN.md and extraction demonstration notes instead. Raw PCAPs remain unchanged; decoding them is still data processing and must be described honestly.

1. Extract this archive into the existing repository so this folder is named `component3_reference` directly under repository root. Do not extract it into `data/raw/Modbus Dataset`.
2. Open the repository as a local Codex project on the computer with the dataset. Use the existing checkout so locally stored data and old scripts are visible.
3. Recommended model: GPT-6.1 Sol, High reasoning, Standard speed, when available in the account/client. Availability is subject to rollout. This is a task-specific recommendation; no model guarantees valid labels.
4. Paste `PASTE_THIS_FIRST.txt` into a new Codex chat. It directs Codex to the complete prompt and references. Alternatively paste `CODEX_COMPONENT3_PROMPT.txt` directly.
5. The first results should identify actual source files, original logs, usable class evidence, recoverable fields and a tested pilot. A CSV creation message or a model accuracy number is not enough.
6. Review the inventory, label evidence, parse/pair examples and split manifest. Unknown response-injection evidence must remain unknown. Check group/duplicate/pair containment and per-class independent-group coverage. No model preprocessing or training is requested in this stage. The future preprocessing guide is explanatory, not an executed transformation.

Expected repository:
`{repo}`

Expected raw dataset:
`{raw}`

Your local Codex chat can inspect the actual files on this computer. A cloud task does not automatically receive those local files.

The documents define research scope; original data/logs support empirical labels; old exports/transcripts/audits are evidence to verify. Historical prompts do not override the current task.

Official product references checked on preparation date:
- https://learn.chatgpt.com/docs/models
- https://learn.chatgpt.com/docs/pricing
- https://learn.chatgpt.com/docs/environments/modes

The previous CSVs have known annotation and extraction issues. Their inclusion is for diagnosis and salvage assessment, not endorsement of their labels.
'''
(reference/'START_HERE.md').write_text(readme, encoding='utf-8')

archive = base/'CODEX_COMPONENT3_CIC_ONLY_STAGE1_HANDOFF.zip'
with ZipFile(archive, 'w', compression=ZIP_DEFLATED, compresslevel=6) as z:
    for item in sorted(reference.iterdir()):
        z.write(item, arcname=f'component3_reference/{item.name}')
with ZipFile(archive) as z:
    error = z.testzip()
    assert error is None, error
    assert 'component3_reference/PASTE_THIS_FIRST.txt' in z.namelist()
    assert 'component3_reference/CODEX_COMPONENT3_PROMPT.txt' in z.namelist()
copy2(archive, base/'CODEX_COMPONENT3_HANDOFF.zip')
print(f'Archive: {archive.resolve()}')
print(f'Files: {len(list(reference.iterdir()))}; bytes: {archive.stat().st_size}')
