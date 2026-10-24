# Capability and salvage assessment

The supported result is CIC-only extracted records with conservative evidence annotations and **candidate whole-campaign memberships**. The independent three-class experiment is **unsupported**. No model preprocessing or training was executed.

| Target | Accepted ADUs | Class-bearing recording groups | Groups |
|---|---:|---:|---|
| normal | 1,404,306 | 1 | cic_benign_january |
| command_injection | 100 | 1 | cic_compromised_scada_march |
| response_injection | 54 | 1 | cic_compromised_ied_march |

Command labels are limited to uniquely supported log/packet events; dense ambiguous command bursts remain separate.

| Capability | Status | Evidence / limit |
|---|---|---|
| Local original CIC identity/provenance | Supported locally |207-file hashes, original README, publisher description; no publisher checksum certificate |
| Chronology/raw payload/value arrays | Supported within selected scope | Epoch microseconds, full ADU/PDU bytes, register words/packed bits and frame/byte lineage; reassembly emission order is not chronological table order |
| TCP reconstruction | Partial |IPv4/TCP port502, segmentation/coalescing/out-of-order/retransmission/chunk continuity; explicit loss/gap/partial/conflict status; no IPv6/IP-fragment reconstruction |
| Pair relations | Partial |Connection generations, concurrent/reused IDs, mismatch/ambiguity/orphan/pending status; capture-midstream tuple reuse can remain uncertain |
| Response injection | Supported event evidence |Unique original FDI log+target/TID/time+observed request/reply, explicit clock calibration; does not establish multiple independent response attack runs |
| Command injection | Supported limited event evidence |Logged brute-force requests retained; no function/direction/folder-only targets |
| Independent class-complete70/15/15 | Unavailable |Four conservative campaigns; class support concentrated in individual campaigns; no shuffled rare episode or fabricated independence |
| Physical process/permission meaning | Unavailable or partial |Raw words preserved; units, signedness, register map, authorized policy and valid-looking expected values not established |

The pilot passed both independent real-packet examples and all byte/frame accounting assertions. Its measured peak working set was 607,117,312 bytes. Known response TID7485 has a byte-count171 reply carrying one data byte; this malformed example can be detected by protocol consistency and does not justify a claim that context-aware ML is necessary. Joint class/function/parse/direction counts in `output/quality_report.json` show the actual target composition.

## Accepted target structure and shortcut limits

| Target | Malformed PDU | Parser ok | Exception | Other parse outcomes |
|---|---:|---:|---:|---:|
| command_injection | 98 | 2 | 0 | 0 |
| response_injection | 53 | 1 | 0 | 0 |

These are current-PDU parser outcomes within the accepted evidence cohort, not independent attack repetitions. An `ok` PDU is structurally accepted under this decoder; it does not establish process plausibility, authorization or a correct request-relative value. A concentration of malformed targets creates a protocol-shape shortcut risk. This cohort does not support a broad claim that valid-looking injections require context-aware machine learning or that contextual features improve detection. Any later comparison must disclose this composition and the scarce structurally accepted injection examples.

The old baseline's values/timing/identities and attack CSV labels are diagnostic only. Final records were decoded anew from permitted original captures and annotated against original logs/documentation; old exported timestamps, values and labels were not copied. The pilot verifies specific historical baseline/source links, not complete recovery of every old derivative's missing provenance. Prior exports cannot recover absent payloads or prove forged response labels. Missing original historical scripts make several narrated rules and the claimed perfect RF result unverifiable; see `REFERENCE_AUDIT.md`.

Clock matching tested zero and±3hours with25ms tolerance, unique target/TID/behavior evidence and a minimum three-event calibration criterion by family/campaign. Original naive times and workbook serials remain unchanged. Residuals, tighter-window sensitivity and unmatched/out-of-scope logs remain in label reports. Calibration is limited to observed evidence and does not establish every scenario's timezone/drift.

The selected endpoints limit coverage; unselected-target logs are outside the selected cohort, not absent from the entire raw dataset. Distinct accepted log events are counted separately from independent campaign groups. A related legitimate acknowledgement is association metadata, never automatically response_injection. Unknown/out-of-scope records stay in the stream for later explicit context handling.
