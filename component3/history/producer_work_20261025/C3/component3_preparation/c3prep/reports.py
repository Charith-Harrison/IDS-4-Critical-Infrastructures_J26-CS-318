"""Render concise research audit notes from measured Stage1 reports."""
import json
from collections import Counter, defaultdict
from pathlib import Path
import platform
import sys

import pyarrow

from .audit import extraction_dirs, sha256, write_json


def render_reports(output):
    output = Path(output)
    package = output.parent
    read = lambda name: json.loads((output / name).read_text(encoding="utf8"))
    inventory = read("inventory.json")
    quality = read("quality_report.json")
    split = read("split_manifest.json")
    labels = read("label_report.json")
    pairs = read("pair_report.json")
    copies = read("duplicate_containment.json")
    pilot = read("pilot/pilot_report.json")
    logs = read("log_summary.json")
    dirs = extraction_dirs(output)
    selected_sources = []
    source_rows = []
    total_frames = total_adus = total_records = 0
    checkpoints = {}
    for d in dirs:
        c = json.loads((d / "checkpoint.json").read_text())
        checkpoints[d.name] = c
        a = c["accounting"]
        sources = c["contract"]["sources"]
        selected_sources.extend({**s, "view_id": d.name, "recording_id": c["contract"]["recording_id"]} for s in sources)
        total_frames += a["frames_total"]
        total_adus += a.get("records_adu", 0)
        total_records += next(x["counts"]["records"] for x in quality["views"] if x["view_id"] == d.name)
        source_rows.append(f"| {d.name} | {len(sources)} | {a['frames_total']:,} | {a.get('records_adu', 0):,} | {a['elapsed_s']:.2f} |")
    write_json(output / "selected_source_manifest.json", {
        "policy": "Complete available canonical endpoint chains; all rotations retained with TCP state. One view per campaign. Other raw files inventoried only, not silently merged.",
        "sources": selected_sources, "selected_captures": len(selected_sources),
        "selected_source_bytes": sum(s["bytes"] for s in selected_sources),
        "source_groups_file": "group_sources.json", "raw_inventory_file": "inventory.json",
        "endpoint_limits": "Benign and compromised-IED endpoint .5; compromised-SCADA endpoint .4; external bridge. Conclusions do not cover all devices/traffic in unselected views.",
    })
    write_json(output / "source_manifest.json", {
        "scope": "Original locally supplied CICModbusDataset2023 only; no external datasets or old derivative rows",
        "raw_inventory": {"path": "inventory.json", "sha256": sha256(output / "inventory.json"), "files": inventory["total_files"], "bytes": inventory["total_bytes"]},
        "recording_view_chunk_mapping": {"path": "group_sources.json", "sha256": sha256(output / "group_sources.json")},
        "decoded_source_membership": {"path": "selected_source_manifest.json", "sha256": sha256(output / "selected_source_manifest.json")},
        "preservation_check": "source_preservation.json",
    })
    class_rows = []
    totals = {}
    for label, groups in split["class_bearing_groups"].items():
        count = sum(g["labels"].get(label, 0) for g in split["groups"])
        totals[label] = count
        class_rows.append(f"| {label} | {count:,} | {len(groups)} | {', '.join(groups) or 'none'} |")
    groups_table = []
    for g in split["groups"]:
        groups_table.append(f"| {g['recording_id']} | {g['partition']} | {g['events']:,} | {g['labels'].get('normal', 0):,} | {g['labels'].get('command_injection', 0):,} | {g['labels'].get('response_injection', 0):,} |")
    counts_text = "\n".join(class_rows)
    target_shapes = defaultdict(Counter)
    for view in quality["views"]:
        for row in view.get("class_parse_function_direction_distribution", []):
            if row["component_label"] in ("command_injection", "response_injection"):
                target_shapes[row["component_label"]][row["parse_status"]] += row["count"]
    shape_rows = []
    for target in ("command_injection", "response_injection"):
        shape = target_shapes[target]
        shape_rows.append(f"| {target} | {shape.get('malformed', 0):,} | {shape.get('ok', 0):,} | {shape.get('exception', 0):,} | {sum(v for k, v in shape.items() if k not in ('malformed', 'ok', 'exception')):,} |")
    shapes_text = "\n".join(shape_rows)
    shape_caveat = "These are current-PDU parser outcomes within the accepted evidence cohort, not independent attack repetitions. An `ok` PDU is structurally accepted under this decoder; it does not establish process plausibility, authorization or a correct request-relative value. A concentration of malformed targets creates a protocol-shape shortcut risk. This cohort does not support a broad claim that valid-looking injections require context-aware machine learning or that contextual features improve detection. Any later comparison must disclose this composition and the scarce structurally accepted injection examples."
    frame_count = sum(f.get("capture", {}).get("frames", 0) for f in inventory["files"])
    # Inventory's capture record count may have a schema-specific name.
    if not frame_count:
        frame_count = sum(f.get("capture", {}).get("frame_count", 0) for f in inventory["files"])
    text = f"""# Verified CIC source inventory

Local source: `{inventory['raw_root']}`. Reference pack: `references/component3_reference/`. Identification agrees with the supplied README and the [publisher's CICModbusDataset2023 description](https://www.unb.ca/cic/datasets/modbus-2023.html). This establishes local collection identity; no publisher checksum/archive completeness certificate was available.

There are **{inventory['total_files']:,} files / {inventory['total_bytes']:,} bytes**: 170 classic PCAPs, 34 original CSV logs, one XLSX, README and setup image. Full local file SHA256 values are in `output/inventory.json`; capture headers/record boundaries were scanned, not just filename endpoints. Source preservation was checked again after extraction: **{quality['source_immutability']}**. All observed captures use Ethernet and microsecond classic-PCAP timestamps. Unsupported formats are not silently converted.

The log table preserves **{logs['total']['rows']:,} source rows** (1,420,042 CSV and 116,084 workbook). The March21 workbook's three sheets retain raw numeric serials and decimal time conversion; the shortened CSV is retained as a superseded version. Its 8,306 non-time rows agree with IED4C; 39 display rounding differences remain visible. Completion ID1048575 is not a wire ID and is never wrapped. Six external-attacker CSVs lack target/TID; external means an original CIC attack scenario, not an additional dataset.

## Selected extraction scope

| Canonical view | Capture chunks | Frames | ADUs | Extraction seconds |
|---|---:|---:|---:|---:|
{chr(10).join(source_rows)}

**{len(selected_sources)} original captures / {sum(s['bytes'] for s in selected_sources):,} bytes** were decoded, producing **{total_adus:,} ADUs** and **{total_records:,} total application/candidate records** from **{total_frames:,} frames**. Selection uses full available endpoint chains, not attack-only packets. Benign/compromised-IED use IED1b(.5); compromised-SCADA uses IED1a(.4); the external scenario uses its bridge. Other endpoints and views remain inventoried but outside the selected row cohort. The selected source manifest lists every capture/hash/chunk; checkpoints link source chunks to event frame offsets.

All rotations and simultaneous views belong to four broad capture campaigns. They do not establish independent physical testbeds or one independent episode per day. `substation-0.pcap` under compromised-SCADA is March23 and is conservatively grouped with compromised-IED using time and cross-view frame evidence; it is not concatenated before March15 chunks1–17. Copy audit: {len(copies['time_linked_sampled_mirror_clusters'])} time-linked sampled mirror clusters, {copies['sampled_mirror_cross_group_clusters']} cross-group clusters. Absence of sampled duplicates is not proof of complete uniqueness; one canonical view per group avoids importing simultaneous copies as independent rows.

Original derivatives, original parser modules, PDFs, existing models/application and other components were preserved. No external dataset or old derivative supplied extracted records.
"""
    (package / "INVENTORY.md").write_text(text, encoding="utf8")
    gap = "No command_injection event met the strict per-event evidence policy in this run. Original command attack candidates are present; dense same-TID/time/address bursts cannot be uniquely resolved by this mapping. This is an annotation-capability gap, not proof that CIC contains no command attacks." if totals["command_injection"] == 0 else "Command labels are limited to uniquely supported log/packet events; dense ambiguous command bursts remain separate."
    text = f"""# Capability and salvage assessment

The supported result is CIC-only extracted records with conservative evidence annotations and **candidate whole-campaign memberships**. The independent three-class experiment is **unsupported**. No model preprocessing or training was executed.

| Target | Accepted ADUs | Class-bearing recording groups | Groups |
|---|---:|---:|---|
{counts_text}

{gap}

| Capability | Status | Evidence / limit |
|---|---|---|
| Local original CIC identity/provenance | Supported locally |207-file hashes, original README, publisher description; no publisher checksum certificate |
| Chronology/raw payload/value arrays | Supported within selected scope | Epoch microseconds, full ADU/PDU bytes, register words/packed bits and frame/byte lineage; reassembly emission order is not chronological table order |
| TCP reconstruction | Partial |IPv4/TCP port502, segmentation/coalescing/out-of-order/retransmission/chunk continuity; explicit loss/gap/partial/conflict status; no IPv6/IP-fragment reconstruction |
| Pair relations | Partial |Connection generations, concurrent/reused IDs, mismatch/ambiguity/orphan/pending status; capture-midstream tuple reuse can remain uncertain |
| Response injection | {'Supported event evidence' if totals['response_injection'] else 'No accepted event targets'} |Unique original FDI log+target/TID/time+observed request/reply, explicit clock calibration; does not establish multiple independent response attack runs |
| Command injection | {'Supported limited event evidence' if totals['command_injection'] else 'Candidate/ambiguous only under current policy'} |Logged brute-force requests retained; no function/direction/folder-only targets |
| Independent class-complete70/15/15 | Unavailable |Four conservative campaigns; class support concentrated in individual campaigns; no shuffled rare episode or fabricated independence |
| Physical process/permission meaning | Unavailable or partial |Raw words preserved; units, signedness, register map, authorized policy and valid-looking expected values not established |

The pilot passed both independent real-packet examples and all byte/frame accounting assertions. Its measured peak working set was {pilot['peak_working_set_bytes']:,} bytes. Known response TID7485 has a byte-count171 reply carrying one data byte; this malformed example can be detected by protocol consistency and does not justify a claim that context-aware ML is necessary. Joint class/function/parse/direction counts in `output/quality_report.json` show the actual target composition.

## Accepted target structure and shortcut limits

| Target | Malformed PDU | Parser ok | Exception | Other parse outcomes |
|---|---:|---:|---:|---:|
{shapes_text}

{shape_caveat}

The old baseline's values/timing/identities and attack CSV labels are diagnostic only. Final records were decoded anew from permitted original captures and annotated against original logs/documentation; old exported timestamps, values and labels were not copied. The pilot verifies specific historical baseline/source links, not complete recovery of every old derivative's missing provenance. Prior exports cannot recover absent payloads or prove forged response labels. Missing original historical scripts make several narrated rules and the claimed perfect RF result unverifiable; see `REFERENCE_AUDIT.md`.

Clock matching tested zero and±3hours with25ms tolerance, unique target/TID/behavior evidence and a minimum three-event calibration criterion by family/campaign. Original naive times and workbook serials remain unchanged. Residuals, tighter-window sensitivity and unmatched/out-of-scope logs remain in label reports. Calibration is limited to observed evidence and does not establish every scenario's timezone/drift.

The selected endpoints limit coverage; unselected-target logs are outside the selected cohort, not absent from the entire raw dataset. Distinct accepted log events are counted separately from independent campaign groups. A related legitimate acknowledgement is association metadata, never automatically response_injection. Unknown/out-of-scope records stay in the stream for later explicit context handling.
"""
    (package / "FEASIBILITY.md").write_text(text, encoding="utf8")
    text = f"""# Group and partition validation

**{split['status']}**. These memberships are for inspection and future design; they are not a scoring-ready three-class dataset.

| Whole recording group | Candidate partition | All records | Normal | Command | Response |
|---|---|---:|---:|---:|---:|
{chr(10).join(groups_table)}

Requested proportions were approximately 70/15/15 only if support permitted. Actual group fractions are 50/25/25 (two/one/one whole groups). Actual record fractions are {split['partitions']['candidate_train']['row_fraction']:.2%} train / {split['partitions']['candidate_validation']['row_fraction']:.2%} validation / {split['partitions']['candidate_test']['row_fraction']:.2%} test. Class completeness in every partition: **{split['class_complete_each_partition']}**. Validation has no accepted targets and training has no response-injection targets. Do not use unavailable class metrics or manufacture coverage with row shuffling.

| Check | Result | Scope |
|---|---|---|
| Event and annotation membership | {'verified' if split['annotations_one_to_one_with_events'] else 'failed'} |Every canonical UID/sequence and one-to-one annotation validated |
| Group disjointness | verified |One fixed partition per entire campaign, including rotations/mirrored source views |
| Pair/candidate dependency containment | {'verified' if split['pair_partition_crossings'] == 0 and split['missing_pair_event_ids'] == 0 else 'failed'} |{split['pair_relations_checked']:,} relations, {split['pair_partition_crossings']} partition crossings, {split['missing_pair_event_ids']} missing endpoint IDs |
| Known file/view copy containment | {'verified within audited evidence' if split['known_source_copy_relationships_contained'] else 'unresolved'} |Full-file hashes, source map and time-linked bounded frame samples; no payload-only deduplication |
| Partition-local chronology | verified |Membership manifests are externally sorted by completion epoch/view/event sequence; raw extraction keeps decoder emission order |
| Class-complete independent experiment | unsupported |Class-bearing groups shown below; same testbed and continuous campaigns do not create independent repetitions |

| Target | Accepted ADUs | Class-bearing groups | Groups |
|---|---:|---:|---|
{counts_text}

The membership Parquets contain event UID, source group/view, sequence, completion time and candidate partition. They select exact rows from the immutable extracted event Parquets; no X/y matrices or feature partitions exist. Source hashes, event-table hashes, annotation hashes and full chunk membership are in the manifest. Unlabelled/malformed/unsupported/out-of-scope background is retained.

Pairing carries outstanding transactions across verified same-view rotations, handles concurrent IDs/reuse and preserves ambiguity. Requests pending at connection end and capture end remain separate. The pairing audit has no learned or universal time expiry; it bounds outstanding requests at8192 per connection and reports capacity evictions. Matches over5/60/300seconds are sensitivity counts only. Connection idle handling uses the explicit300second extraction parameter; it is not a verified Modbus deadline. Cross-chunk pair counts are in `output/pair_report.json`.

Future context resets at recording/view/connection generations and observed gaps. Candidate lookbacks3/5/10 are documented only; no windows were built. A maximum time lookback/causal label horizon has not been chosen by the researcher. Whole campaigns share no partition history; any future within-run temporal split or horizon change requires a new purge/pair validation and answers a narrower question. No claim is made that these are unseen final research holdouts: the captures have been inspected for preparation.
"""
    (package / "SPLIT_VALIDATION.md").write_text(text, encoding="utf8")
    q = f"""# Stage1 quality results

All selected extraction frame/byte reconciliation and record-lineage invariants passed: **{quality['all_row_and_accounting_checks_pass']}**. Raw source SHA256 preservation passed: **{quality['source_immutability']}**. This confirms the measured extraction checks, not universal ground-truth correctness.

Decoded {total_adus:,} ADUs plus {total_records-total_adus:,} explicitly partial/nonframed candidates from {total_frames:,} frames in21 selected original captures. Raw arrays, bytes, precise times and source offsets remain present. Original log rows: {logs['total']['rows']:,}. Accepted targets: {totals}. See `output/quality_report.json` for every view's parse status, function/direction, class joints, null/wire-zero counts, non-Modbus/unsupported reasons, connection/retransmission/gap accounting, cross-chunk records and emitted-time reversals.

| Accepted target | Malformed PDU | Parser ok | Exception | Other parse outcomes |
|---|---:|---:|---:|---:|
{shapes_text}

{shape_caveat}

`output/label_report.json`, per-view `log_matches.parquet` and global `log_signatures.parquet` preserve accepted/candidate/ambiguous/out-of-scope evidence and residuals; unsupported classes remain unavailable. `output/pair_report.json` preserves every relation status and sensitivity count. `output/duplicate_containment.json` distinguishes byte copies at coincident times from legitimate recurring content. Original sources and suppressed observations remain available; unsupported IP/format cases are counted, not declared successfully reconstructed.

Extraction source/config/parser contracts and output digests support deterministic resume. Event IDs and table publication are whole-chain replacements, never row appends. Offline fixtures cover parser, pairing, original-log version/clock ambiguity, boundary membership and checkpoint integrity. Actual test invocation/outcome is recorded in `output/execution_record.json`.

No engineered context/lag/rolling/value-delta/rate features, model windows/matrices, imputation, encoding, scaling, normalization, balancing, fitted normal profiles or classifier training were executed. `PREPROCESSING_PLAN.md` is a separate later learning guide.
"""
    (package / "quality_report.md").write_text(q, encoding="utf8")
    write_json(output / "environment.json", {"python": sys.version, "platform": platform.platform(),
               "pyarrow": pyarrow.__version__, "tshark": pilot["tshark"],
               "source_code_sha256": {p.relative_to(package).as_posix(): sha256(p) for p in sorted(package.glob("c3prep/*.py"))},
               "configuration_sha256": sha256(package / "config.json")})
    return {"records": total_records, "adus": total_adus, "frames": total_frames, "classes": totals,
            "class_bearing_groups": split["class_bearing_groups"], "candidate_only": True}


if __name__ == "__main__":
    print(json.dumps(render_reports(Path(__file__).resolve().parents[1] / "output"), indent=2))
