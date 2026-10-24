"""Seal preparation evidence/doc hashes only. Never invokes collection or Docker."""
from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from runtime.common import read,sha,verify_package,source_inventory


def main():
    freeze=verify_package();receipt=read(ROOT/'image_identity.json')
    prior=read(ROOT/'evidence/protected_after.json')
    qualification=read(ROOT/'evidence/qualification_recheck.json');signals=read(ROOT/'evidence/signal_check.json')
    if prior['status']!='PASSED' or qualification['status']!='PASSED' or signals['status']!='PASSED':
        raise ValueError('Preparation checks must pass')
    default_output=ROOT.parent.parent/'component3_collection_runs/main-frozen-v1-20261025'
    if default_output.exists(): raise ValueError('Unexpected main output directory; investigate before claiming no collection')
    engine=read(ROOT/'frozen/qualified_engine_receipt.json')
    if any(sha(ROOT/name)!=item['sha256'] for name,item in engine.items()): raise ValueError('Qualified engine copy changed')
    archive=ROOT/'evidence/manual-runtime.tar';archive_hash=sha(archive)
    record=dict(status='READY_FOR_MANUAL_EXECUTION',preparation_date_local='2026-10-25',timezone='Asia/Colombo',
                user_scope='Prepare, freeze, check and give instructions only; user manually runs Start',
                agent_executed_main_start=False,main_output_exists=False,new_main_captures=0,
                academic_supervisor_acceptance='NOT_RECORDED',frozen_total=104,
                source_bundle_id=freeze['bundle_id'],protocol_sha256=freeze['protocol_sha256'],roster_sha256=freeze['roster_sha256'],
                frozen_image_id=receipt['image_id'],image_receipt_sha256=sha(ROOT/'image_identity.json'),
                source_engine='Unchanged qualified v0.3 engine files; exact receipt hashes reproduced',
                offline_tests=dict(windows_host=24,linux_image_with_repository_layout=24,status='PASSED',
                                   configuration_composition_cells=36,fresh_engineering_seeds_only=True,
                                   synthetic_fixtures_not_research_recordings=True),
                signal_check=signals,prior_qualification_readonly_revalidation=qualification,
                preflight_observed=dict(status='READY_FOR_MANUAL_START',validated_completed=0,traffic_generated=False,
                    required_shared_host_bytes=9292430536,observed_host_free_bytes=126590861312,
                    observed_docker_guest_free_bytes=1024330240000,estimated_remaining_hours=2.3080536955555564,
                    command='.\\component3_main_collection\\v1_20261025\\collect-main.ps1 -Preflight'),
                initial_container_test_layout='Flat /main_collection layout triggered two host-path guard tests. Correct repository-style read-only mount passed all 24; frozen source was unchanged.',
                preserved_prior_files=prior,
                runtime_archive=dict(file='evidence/manual-runtime.tar',bytes=archive.stat().st_size,sha256=archive_hash),
                limitations=['Main Start with traffic was deliberately not tested or executed',
                             '14 combinations have measured qualification, while 36 intended cells pass offline composition checks with unchanged factors; no claim all 36 were physically captured',
                             'No additional network qualification was needed for unchanged wire/decoder semantics; lifecycle changes were tested using mocks and a protocol-free signal probe',
                             'Source/configuration freeze is hash-enforced. Operational output location/margins are user-configurable and recorded.',
                             'No independence of industrial campaigns or model benefit follows; academic methodology acceptance remains unrecorded'])
    (ROOT/'evidence/preparation_checks.json').write_text(json.dumps(record,indent=2)+'\n')
    (ROOT/'evidence/manual-runtime.tar.sha256').write_text(archive_hash+'  manual-runtime.tar\n',encoding='ascii')
    readiness=f'''# Readiness decision — 25 October 2026

**READY FOR MANUAL EXECUTION. No main collection has been started.**

Read [INSTRUCTIONS.md](INSTRUCTIONS.md) before typing Start. The user explicitly authorized
preparation/freeze for manual execution, not agent-run collection. Academic supervisor
acceptance is **NOT RECORDED** and is not implied by engineering readiness.

The original proposed 104 slots are retained without changing IDs, seeds, condition factors,
groups, intended roles or order. There are 80 mixed and 24 normal-only executions. All pilots
and qualification captures remain excluded from model work and scoring. CIC and MSU rows
are not imported. Role/group metadata is prospective provenance, not processed model data.

## Evidence and scope

- All 14 v0.3 captures were revalidated through read-only mounts; no probe was recaptured.
- Copied generator, protocol, server, capture and decoder/replay files match their qualified
  source hashes. No new intervention, parser, map, value profile or ordering was invented.
- Fourteen main condition cells were directly measured; all 36 distinct intended combinations
  pass offline composition checks using fresh engineering seeds. The remaining 22 are supported
  compositionally by the same parameterized engine, not claimed as physically measured.
- All **24** launcher tests pass on Windows and in the Linux image using the repository layout.
  Checks cover no-traffic default/dry run, source/hash refusal, storage, locks, interrupted
  attempts, explicit retry limits, artifact changes, duplicate traces, validation gating and
  cancellation before/after a mocked transaction. Synthetic test fixtures are not data.
- The Docker SIGINT test used a short-lived process that opens no sockets/capture and exited
  cleanly. No background collection/test container remains.
- The exact user-facing preflight returned READY_FOR_MANUAL_START, validated **0/104**, and
  did not create the main output directory.
- All **{prior['files']}** prior source/evidence files remain unchanged, including original CIC
  preparation/reassessment, previous pilots, main-design proposal and qualification captures.

The orchestration adapter adds lifecycle, progress, identity and validation envelopes. It
does not change generated PDUs, evidence labels or tolerances. Current-run progress counts
actual flushed request/reply observations. Completion requires runtime AND host verification;
a generator exit code alone is insufficient. Host verification compares annotations with
the qualified reconstruction in a temporary view, preserving original evidence on disagreement.

No known material defect remains in the tested scope. The **traffic-producing main Start path
was intentionally not executed**. The first manually launched run will pass the same complete
evidence checks before it can count. Packet loss, ambiguous pairing, failed controls,
validation disagreement, source changes or insufficient headroom stop acceptance.

Windows stale-lock checks query process status without signaling the process. This choice
follows the [Python Windows signal behavior](https://docs.python.org/3/library/os.html#os.kill)
and [Microsoft process-status API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess).

## Frozen identities

| Artifact | SHA256 |
|---|---|
| `frozen/protocol.json` | `{freeze['protocol_sha256']}` |
| `frozen/main_roster.json` | `{freeze['roster_sha256']}` |
| Source/configuration bundle | `{freeze['bundle_id']}` |

The complete per-file source/configuration hashes are in `frozen/freeze_manifest.json`.
The exact prepared image is `{receipt['image_id']}`. Its archive is
`evidence/manual-runtime.tar` ({archive.stat().st_size:,} bytes), SHA256 `{archive_hash}`.
No automatic image pull, rebuild, software installation or Docker cleanup occurs at collection.

## Capacity and time

Measured v0.3 artifacts total 95.2 MB. Estimated originals for the main roster are **706 MB**;
the conservative allowance is **1.238 GB**. Defaults budget original plus future handover copy,
2x margin, two temporary/retry run allowances, 2 GiB output reserve and 2 GiB Docker reserve.
If output and Docker share a drive, required headroom is **9,292,430,536 bytes (8.65 GiB)**.
The checked host had **126,590,861,312 bytes (117.9 GiB)** free; Docker guest capacity was also
checked along with the actual VHDX backing drive. Those figures are a preparation snapshot;
preflight and each run recheck them. No data/resources are deleted to free space.

Cold ETA is approximately **2.31 hours** from measured qualification wall times. It is not a
guarantee: controller checks, verification, IO, concurrent workloads and retries can add time.
Later ETA uses comparable completed main runs. Backup capacity is reserved; no extra dataset
copy is silently generated. Margins are documented/configurable operational options.

## What remains outside this decision

The protocol is a single software testbed with two declared injection mechanisms and supplied
public object roles. It cannot establish independent industrial campaign generalization,
physical-process impact or ML superiority over causal rules. Actual future measured timing
must be reported; configured sleeps are not exact wire delays. Execution order is the existing
MX001–MX104 sequence and is not counterbalanced across intended roles, so temporal/host drift
remains a limitation. No feature engineering, sequence/model matrices, transformations,
resampling, fitted normal profiles or training/evaluation occurred.

**Next action: you review the instructions and, only when ready, type the manual Start command.**
No further engineering authorization question is required to use this prepared launcher.
Academic acceptance of the methodology change must be documented honestly for the thesis;
this package does not invent it.
'''
    (ROOT/'READINESS.md').write_text(readiness,encoding='utf8')
    files=[p for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='package_handover.json']
    package=dict(status='PREPARED_NOT_STARTED',bundle_id=freeze['bundle_id'],main_captures=0,
                 artifact_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(files)})
    (ROOT/'evidence/package_handover.json').write_text(json.dumps(package,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ('status','new_main_captures','source_bundle_id','protocol_sha256','roster_sha256')},indent=2))


if __name__=='__main__': main()
