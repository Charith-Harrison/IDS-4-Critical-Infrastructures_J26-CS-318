"""Versioned decision, proposed policy and audit-only shortcut findings."""
from collections import Counter, defaultdict
import csv
from common import HERE, OUT, BASE, read, write


def run():
    c=read(OUT/'cohort_diagnostics.json');p=read(OUT/'bounded_pilot_summary.json')
    t=read(OUT/'temporal_feasibility.json');clock=read(OUT/'identity_and_clock_audit.json')
    plan=read(OUT/'expanded_scope_plan.json');overlap=read(OUT/'view_overlap_samples.json')
    signatures=Counter();endpoints=defaultdict(set);addresses=defaultdict(set)
    patterns=defaultdict(set);fn=Counter();marker=Counter()
    with (OUT/'accepted_class_campaign_day_endpoint_function_pdu_parse_pair.csv').open(newline='',encoding='utf8') as f:
        for r in csv.DictReader(f):
            label=r['class'];n=int(r['adu_count'])
            endpoints[label].add((r['client'],r['server']))
            patterns[label].add(r['pdu_hex']);fn[(label,r['function'])]+=n
            if 'abcd' in r['pdu_hex'].lower():marker[label]+=n
    for r in c['normal_endpoint_address_day_counts']:addresses['normal_FC5'].add(r['address'])
    for r in read(OUT/'diagnostic_candidates.json')['records']:
        if r['frozen_accepted']:addresses['accepted_command_FC5'].add(r['address'])
    shortcut={'scope':'Descriptive counts only, not trained/evaluated detector results.',
        'accepted_endpoint_tuple_sets':{k:sorted(v) for k,v in endpoints.items()},
        'endpoint_sets_pairwise_disjoint':all(not endpoints[a]&endpoints[b] for a in endpoints for b in endpoints if a<b),
        'accepted_pdu_pattern_counts':{k:len(v) for k,v in patterns.items()},
        'ABCD_containing_accepted_adu_counts':dict(marker),
        'normal_vs_command_fc5_addresses':{k:sorted(v) for k,v in addresses.items()},
        'malformed_accepted_attack_adus':151,'accepted_attack_adus':154,
        'diagnostic_1ms_ok_command_pattern':'050001ff00',
        'simple_future_baselines':['Current-PDU specification checks (FC5 output word and function-specific response byte counts) already expose151 malformed accepted attack ADUs.',
            'A literal ABCD reply signature covers the three observed response attack patterns; this is tool-marker recognition, not proof of deployment generalization.',
            'Endpoint/campaign/time or address shortcuts can separate the frozen accepted cohort; they must not be represented as legitimate general-purpose predictors.'],
        'context_evidence_needed':['Syntactically plausible forged replies without a static marker, with independent expected-response/request/value evidence and varied repetitions.',
            'Justified legitimate-versus-unauthorized command examples on comparable endpoints/objects and independently documented authorization/process semantics.',
            'Causal request/response or historical dependency shown to add information beyond current-message protocol/signature checks on the same eligible cohort.'],
        'not_inferred':['Physical register units/signedness/scaling','Permission policy','Successful process manipulation','That parser-ok equals authorized or plausible','That unlabelled attack-campaign traffic is normal']}
    write('shortcut_risks.json',shortcut)
    alternatives=[]
    for w,r in c['command_candidate_sensitivity'].items():
        alternatives.append({'diagnostic_window_us':int(w),'frozen_command_labels_before':100,
            'two_sided_unique_diagnostic_candidates':r['two_sided_unique_candidates'],
            'old_accepted_retained_in_candidate_set':r['frozen_accepted_retained'],
            'old_accepted_not_unique_in_candidate_set':r['frozen_accepted_not_unique_at_this_window'],
            'new_diagnostic_candidates_not_accepted':r['newly_diagnostic_not_accepted'],
            'accepted_command_labels_after_reassessment':100,'labels_promoted_or_removed':0})
    proposal={'version':'c3-evidence-policy-proposal-v2.0-NOT-ADOPTED',
        'decision':'NO_TIMING_TOLERANCE_CHANGE_JUSTIFIED_BY_AVAILABLE_CLOCK_AND_IDENTITY_EVIDENCE',
        'baseline_policy_remains':'cic-evidence-v1,25ms; labels/checkpoints/configuration untouched',
        'rationale':['Window counts are selection/ambiguity diagnostics, not ground-truth improvement.',
            'CSV millisecond serialization and workbook fractional digits do not establish capture/logger clock accuracy or send/log ordering.',
            '96,200 selected FC5 requests literally reuse TID5; equality alone is weak identity. No local original attacker code/configuration resolves logger semantics.',
            'Accepted residuals are conditioned on the current matching policy; fitting an offset/tolerance to maximize accepted targets would be circular.',
            'Expanded canonical coverage may add competing observations and invalidate present selected-view uniqueness.'],
        'proposed_gates_before_any_replacement':['Preserve v1 accepted labels separately and retain all original log rows/serials.',
            'Establish original logger serialization/call order and independently justified clock uncertainty, scoped by family/source/day/device; otherwise retain ambiguous timing intervals.',
            'Reconcile connection generations, target/unit/function/address and literal TID behavior in a complete justified canonical view; keep all candidate edges.',
            'Require mechanism-specific support independent of malformedness or direction; record injection attempt, pair outcome and physical impact separately.',
            'Publish event-level before/after dispositions with source/log/frame/byte lineage and explicit reasons for every promotion/rejection, then obtain approval before replacing the baseline.'],
        'before_after_diagnostic_table':alternatives,
        'acceptance_after_this_run':{'normal':1404306,'command_injection':100,'response_injection':54},
        'new_labels_accepted':0,'new_policy_activated':False}
    write('proposed_policy_v2_not_adopted.json',proposal)
    table='\n'.join(f"| {int(w):,} | {r['two_sided_unique_candidates']:,} | {r['parse_status_counts'].get('ok',0)} | {r['parse_status_counts'].get('malformed',0)} | {r['frozen_accepted_retained']} | {r['newly_diagnostic_not_accepted']} |" for w,r in c['command_candidate_sensitivity'].items())
    phases=t['claim_B_per_campaign_chronology']['aggregate_phase_counts_before_purge']
    phasetable='\n'.join(f"| {r['diagnostic_phase']} | {r['accepted_adu_counts']['normal']:,} | {r['accepted_adu_counts']['command_injection']} | {r['accepted_adu_counts']['response_injection']} | {r['parse_counts']['command_injection'].get('ok',0)} | {r['parse_counts']['response_injection'].get('ok',0)} |" for r in phases)
    copies=sum(r['matched_observation_copies'] for r in overlap['scada_hmi_vs_current_ied1a'])
    report=f"""# Component 3 evidence and coverage decision — reassessment v1

**Keep the frozen baseline. Independent-campaign three-class generalization remains UNSUPPORTED.** The review's cohort, parser-shape, timing-window and excluded-endpoint counts reproduce locally. No labels, checkpoints, configuration, split memberships or model datasets were changed. Original source root is the verified local `data/raw/Modbus Dataset`, not the reviewer's G: path.

## Established

The baseline retains **1,404,306 normal / 100 command / 54 response** accepted ADUs; each class bears one campaign. All 154 accepted injections were checked again against original PCAP bytes and original CSV/XLSX rows. Commands have 98 malformed and 2 parser-ok PDUs; responses have 53 malformed and 1 parser-ok. Command outcomes are 82 observed exception replies with code 3 and 18 missing replies. Both parser-ok commands lack an observed reply. This establishes logged attempts and observed outcomes, not successful process manipulation. Missing replies prove neither success nor failure.

Selected SCADA IED1a has 99,290 FC5 requests, including 46,297 parser-ok requests; 96,200 FC5 requests literally use TID 5. They are not automatically attacks. Holding candidate edges, zero offset and stream-risk filters fixed:

| Residual window(us) | Unique diagnostic candidates | Parser-ok | Malformed | Frozen100 retained | New diagnostic candidates |
|---|---:|---:|---:|---:|---:|
{table}

No candidate was promoted. All 63 parser-ok candidates at 1 ms share `050001ff00` and have no observed matched reply in this audit. Exact-time and 1 ms candidate sets have zero overlap: broader windows introduce competitors, while different candidates with nonzero residuals enter. **Do not choose 1 ms to increase targets.**

Original CSVs serialize naive decimal times at up to milliseconds; workbook serials retain full dates, hours and fractions. All 170 PCAPs store microseconds. These are storage resolutions, not accuracy guarantees. The join uses ADU completion time; raw first/completion/frame times and log serials are preserved. Accepted command residuals are 32–1,560 us (median 540); FDI residuals are 267–5,717 us (median 969.5). Zero offset has observed family/campaign support versus ±3 hours. Selected matches cannot identify global offset, jitter, drift or logger call order. No original attacker source/configuration was found in the supplied CIC inventory. The precision/accuracy distinction is consistent with [Wireshark's timestamp documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimestamps.html).

## Recoverable coverage, with justified additional work

There are 153,560 brute-force log signatures outside the selected endpoint: 123,325 for `.5` and 30,235 for `.8`. These are not packet or attack counts. Bounded samples found compatible raw requests to `.4/.5/.8` across 20 log windows, including FC5 writes to `.5` with standard output values and PDU shapes. All remain diagnostic observations. No additional labels were accepted.

A concrete replacement canonical chain is **17 SCADA/HMI captures / 1,664,745,012 bytes**, alongside **19 benign/HMI captures / 1,858,748,158 bytes** for controls. The pilot inspected {p['bounded_unique_source_frames']:,} unique frames, plus bounded cross-view comparisons, without full extraction. It confirmed {copies:,} SCADA observation copies and 18 benign write copies. Same-view chronology and sampled boundary sequences support investigating the chains; full TCP loss and continuity remain unverified. Broader benign samples contain reads to all three targets but sampled FC5 controls remain `.5`, addresses 15/25; comparable attack-address controls remain a gap. Exact sources, hashes, bounds, resource estimates and stop gates are in `output/expanded_scope_plan.json`.

## Two evaluation claims

**A. Independent campaigns: UNSUPPORTED.** Extra rows/days/views cannot repair one campaign per class. Current candidate training lacks responses; validation has no accepted targets; test has responses only.

**B. Within-testbed chronology: CONDITIONAL and a different academic objective.** Global calendar blocks lack class completeness. Fixed duration-third probes separately within each campaign give the following aggregate counts before any purge; they combine different calendar periods and reuse campaigns. They are not train/validation/test assignments:

| Corresponding phase | Normal | Command | Response | Parser-ok command | Parser-ok response |
|---|---:|---:|---:|---:|---:|
{phasetable}

The two IED probe boundaries cross 66 and 11 connection generations respectively. No matched pair or original candidate tool interval crosses these probes, but burst semantics and missing/later replies remain uncertain. Boundaries need verified quiet points or entire-connection/dependency exclusions and declared causal lookback/label horizons. No purge, warm-up, window or replacement split was generated.

## Cannot be inferred and best next action

The accepted cohort's endpoint-pair sets are disjoint. All 54 forged replies contain ABCD and only 3 patterns; 151/154 accepted attacks are malformed. Endpoint/address/time recognition, specification checks and a static marker can explain much of this narrow cohort. Recovering commands alone cannot establish response diversity, physical plausibility, authorization, context necessity or deployment/generalization performance. Units, register maps, signedness, process impact and permission rules remain unknown.

**Single best next action: agree a narrower CIC-only within-testbed evidence/protocol study objective with the academic supervisor before authorizing expanded extraction or modelling.** If independent-campaign three-class generalization remains mandatory, retain UNSUPPORTED. The proposed policy revision is explicitly not adopted; it requires independent timing/identity justification and an event-level before/after decision ledger.

All new work is isolated here. Machine-readable lineage, count denominators, unresolved assumptions and stop conditions accompany this report. No context/lag/rate features, sequence windows, X/y matrices, imputation, scaling, encoding, feature selection, resampling, normal profiles or model training/evaluation were performed.
"""
    (HERE/'DECISION_REPORT.md').write_text(report,encoding='utf8')
    policy=f"""# Proposed evidence policy v2.0 — NOT ADOPTED

Decision: **{proposal['decision']}**. Baseline v1 and all 154 accepted injection labels remain frozen. This document does not authorize activating new labels.

| Window(us), diagnostic only | Unique candidates | Parser-ok | Malformed | Existing100 retained | New candidate only |
|---|---:|---:|---:|---:|---:|
{table}

This table is a before/after *candidate* comparison; accepted counts after this run remain 1,404,306 / 100 / 54 at every row. Exact-time excludes all 100 currently accepted commands yet proposes 82 different candidates; 1 ms retains 97, withholds 3 old candidates and introduces 303 new ones. No change is scientifically justified by those counts alone.

Required rationale and activation gates:

"""+'\n'.join(f"{i+1}. {s}" for i,s in enumerate(proposal['proposed_gates_before_any_replacement']))+"\n\nNo global offset, clock precision or transaction-range semantics is invented. Independent logger/clock evidence is absent, and current matching residuals are selection-conditioned. A future revision must retain the current version and publish exact accepted/rejected event/log lineage before seeking authorization.\n"
    (HERE/'PROPOSED_POLICY.md').write_text(policy,encoding='utf8')
    (HERE/'README.md').write_text("""# CIC-only evidence reassessment v1

Start with [DECISION_REPORT.md](DECISION_REPORT.md). The frozen baseline is `../../component3_preparation`; this package never writes there. `config.json` fixes diagnostic windows and bounded sampling limits.

Reproduce from the repository root:

```powershell
./.venv/Scripts/python.exe -B component3_reassessment/v1_20261024/run.py
```

The runner checks baseline preservation, reads existing extracted evidence/logs, performs bounded original-PCAP inspection and records code/config/input hashes and exact commands in `output/execution_manifest.json`. It does not run the original extraction/annotation pipeline or create model datasets. Ordinary reruns verify existing outputs and reuse completed stages when code/config/input/output hashes agree. `--refresh` recomputes these bounded diagnostics only.

Key outputs: `review_reproduction.json`, `cohort_diagnostics.json`, the accepted-cohort joint-count CSV, `diagnostic_candidates.json`, `original_log_timing_and_coverage.json`, `identity_byte_log_examples.json`, `identity_and_clock_audit.json`, `mechanism_parse_pair_impact.json`, `bounded_raw_evidence.json`, `view_overlap_samples.json`, `expanded_scope_plan.json`, `temporal_feasibility.json`, `shortcut_risks.json`, and `proposed_policy_v2_not_adopted.json`.

All row lists are evidence/candidate diagnostics, not accepted-label replacements or model matrices. The CSV contains aggregate counts, not predictor rows. Exact raw frame numbers are retained when known; mid-file pilot records use actual PCAP byte offsets and explicitly unknown global frame numbers. Source signatures are not packet counts or independent episodes. Original naive times and workbook serials remain available; no clock accuracy is assumed from their printed precision.

`PRESERVATION_VERIFICATION` is in `output/preservation_verification.json`: all baseline files are rehashed; raw file size/mtime are compared, original stored source hashes reused, original log hashes checked and sampled raw packet bytes verified. This is not an unnecessary exhaustive rehash of all raw PCAPs.

No new labels, replacement partitions, full expanded extraction, fitted transformations or models are produced. The proposed temporal claim needs academic-objective agreement; independent-campaign three-class evaluation remains unsupported.
""",encoding='utf8')
    write('decision.json',{'established':['Review counts reproduced','154accepted raw/log matches verified','Frozen baseline labels/config/checkpoints retained','Broader HMI target coverage present in bounded samples'],
        'recoverable_with_justified_additional_work':['Complete canonical HMI endpoint coverage and matched benign controls, separately authorized and versioned','Potential additional diagnostic command evidence after justified identity/clock audit'],
        'cannot_infer':['Independent class-bearing campaigns from more rows/days/views','Successful physical manipulation or authorization','Broad stealthy response diversity from ABCD cohort','Context-aware ML necessity/generalization'],
        'claim_A':'UNSUPPORTED','claim_B':'CONDITIONAL_DIFFERENT_OBJECTIVE_NOT_ADOPTED','new_labels':0,'replacement_split':False,
        'single_best_next_action':plan['single_best_next_action']})
    print('decision reports written',flush=True)


if __name__=='__main__':
    run()
