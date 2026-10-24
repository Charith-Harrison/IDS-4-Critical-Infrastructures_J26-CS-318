# Pilot status — 24 October 2026

**Docker build,27 tests inside Docker, real packet capture and exact message/state/label verification PASSED on Thithira's PC.** Successful run: `pilot-20261024T145730Z-4a7f6472`. This is measured feasibility data, not a complete ML training dataset.

Actual results:216 complete messages in108 transactions;208 normal,4command injections,4response injections;224 captured network frames;2,532 accounted TCP payload bytes;0 reported kernel capture drops. All216 message-byte references were independently checked and all PDUs passed the existing CIC decoder's structural checks.

The first attempt `pilot-20261024T145617Z-80339fda` failed before application traffic because tcpdump could not initialize process groups. The fix adds only SETGID alongside NET_RAW; the container keeps network_mode:none, a read-only root filesystem, no published ports and one writable output mount. The failed run is preserved separately and has zero accepted messages.

The source code, raw recording, ledgers, immutable original run manifest, host/image identity, validation results and teaching notes are included in the verified handoff. An optional exact Linux/amd64 image archive is provided separately. The image reports184,449,590bytes; this does not measure all Docker Desktop/WSL/cache overhead. Rebuilding from moving apt/base-image sources may change image bytes; keep the exported image/archive hash for exact environment reuse.

Before Docker execution,27 Windows software tests and a216-message actual-loopback smoke check also passed. Synthetic PCAPs in tests remain fixtures, never measured research data. Smoke outputs are not part of the accepted captured cohort.

Limits: one related run; fixed nine-exchange template; deterministic stored setpoint; no hidden writer; one declared permission rule; one TCP connection. Passing verification does not establish absence of shortcuts, independent plants, ML benefit, or deployment generalization. Private experiment state is not a predictor. Genuine acknowledgements remain normal under the direct-message task.

No bulk collection, final split, model preprocessing, training or deployment occurred. Existing CIC outputs remain separate. Collection-machine provenance must stay accurate when handed to Kaveesha. She can inspect this evidence without regenerating it.
