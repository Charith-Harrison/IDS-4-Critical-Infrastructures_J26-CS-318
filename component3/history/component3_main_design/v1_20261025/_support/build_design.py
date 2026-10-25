"""Produce PROPOSED configurations only. Never collect or assign existing records."""
from collections import Counter
from itertools import product
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent.parent
REPO = HERE.parent.parent


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(name, data):
    (HERE / name).write_text(json.dumps(data, indent=2) + '\n', encoding='utf8')


def main():
    evidence = read(HERE / 'evidence_checks.json')
    previous = read(REPO / 'component3_collection_design/v1_20261024/collection_design.json')
    scenarios = [
        dict(id='N_PERMITTED_ON', intervention='None', label='normal',
             control='Primary same-PDU control for C_BLOCKED_ON, same map/TID/gap/timing/value stratum',
             current_message='FC5 pump ON bytes also occur in injected requests; syntax cannot establish permission',
             earlier_observations='Latest genuine FC3 mode-register reply is 1, with no intervening mode write',
             decision='Complete ON request arrival, before its acknowledgement',
             indistinguishable='Unknown/stale mode or an injected request obeying the public policy; no intent inference'),
        dict(id='N_INHIBITED_IDLE', intervention='None; mode 0, lawful OFF and polling', label='normal',
             control='Negative control for inhibited operation; OFF itself is not the matched ON PDU',
             current_message='OFF is permitted in either mode; context is not necessary to authorize that OFF under this policy',
             earlier_observations='Mode observation and lawful operations explain the episode; genuine setpoint replies use prior FC6 ACKs',
             decision='At complete current ADU; readback comparison only on complete paired reply',
             indistinguishable='A policy-compliant injected OFF is observationally identical; this study does not detect such intent'),
        dict(id='N_AUTHORIZED_UPDATE', intervention='None; FC6 changes stored setpoint in modes 0 and 1', label='normal',
             control='Genuine changed readback control for R_CHANGED_READBACK in both numeric directions',
             current_message='Setpoint writes are permitted in both modes; a new readback value alone cannot prove forgery',
             earlier_observations='Visible successful FC6 setpoint update and its exact ACK explain the new FC3 readback',
             decision='Writes at complete request; consistency at complete readback reply',
             indistinguishable='Without the update/ACK history, a legitimate update can resemble a forged value'),
        dict(id='N_REPEAT_WRITE', intervention='None; repeated ON in mode 1, OFF and same-word FC6', label='normal',
             control='Same current ON PDU and repeated genuine value controls; not a replay-detection task',
             current_message='Repetition is lawful here; equal bytes at different genuine positions are separate events',
             earlier_observations='Latest mode 1 for ON, prior visible writes/ACKs for genuine readbacks',
             decision='ON request before ACK; reply consistency at complete reply',
             indistinguishable='An identical policy-compliant malicious repeat cannot be identified from this observation contract'),
        dict(id='N_MODE_TRANSITION', intervention='None; visible 0-to-1 and 1-to-0 transitions', label='normal',
             control='Normal transition/ON control against stale-mode false positives',
             current_message='Current ON does not show whether the most recent mode is 0 or 1',
             earlier_observations='Latest mode write ACK and subsequent mode read; invalidate older mode anchors after writes',
             decision='Complete current request; use only the latest eligible earlier observation',
             indistinguishable='Missing transition or unobserved writer makes mode uncertain; abstain rather than guess'),
        dict(id='N_GENUINE_READBACK', intervention='None; report the actual stored raw word a or b', label='normal',
             control='Exact current response-PDU controls for both reciprocal forgeries',
             current_message='The same FC3 reply bytes can be genuine in one history and forged in another',
             earlier_observations='Associated FC3 request identifies setpoint role; latest genuine FC6 setpoint ACK gives expected word',
             decision='Complete response arrival; no recovery read or future ACK',
             indistinguishable='No acknowledged-write anchor, pairing uncertainty, or autonomous/unobserved writer outside declared process'),
        dict(id='C_BLOCKED_ON', intervention='Compromised-controller hook emits FC5 pump ON after observed mode 0', label='command_injection',
             control='N_PERMITTED_ON plus legitimate repeated/transition ON, exact PDU and matched nuisance strata',
             current_message='Protocol-valid ON is identical to permitted ON apart from nuisance fields that must be controlled',
             earlier_observations='Latest uninvalidated genuine mode read equals 0',
             decision='Complete injected request arrival; never use subsequent ACK/state read as predictor',
             indistinguishable='Compromise emitting an authorized ON or missing/forged mode history is outside identifiable scope; intent alone is unobservable'),
        dict(id='R_CHANGED_READBACK', intervention='Compromised-server hook changes only FC3 setpoint response a-to-b or b-to-a', label='response_injection',
             control='Genuine a and b readbacks plus acknowledged legitimate updates under same public object role',
             current_message='Both returned words occur normally; value, function, direction and parse result alone do not establish forgery',
             earlier_observations='Earlier associated read request and latest successful acknowledged setpoint write; trusted within this threat model',
             decision='Complete forged reply arrival using earlier request and write/ACK only',
             indistinguishable='No-op mutation, missing ACK/history, forged anchor, hidden writer or inconsistent pairing; no-op attempt is not accepted as changed-response injection')]
    tid_profiles = [dict(id='DSEQ', rule='Random initial TID with modulo-65536 increments; value independent of class'),
                    dict(id='DREUSE', rule='Literal TID 5 repeated with one outstanding request; pair by connection generation plus stream/ordinal, never TID alone'),
                    dict(id='DRANDOM', rule='Uniform 16-bit draws with replacement, one outstanding request; no label-conditioned draw')]
    timing = [dict(id='T0', interexchange_delay_ms=[8,15], status='Existing narrow range; future runs still require new source qualification'),
              dict(id='T1', interexchange_delay_ms=[30,60], status='Development operational variation; unqualified'),
              dict(id='T2', interexchange_delay_ms=[80,160], status='Held out of model development; engineering probes allowed, not scored test recordings')]
    orderings = [dict(id='O0', rule='Readback branch before ON branch, with independent 0-2 prefix polls and dependency-safe intermediate polls'),
                 dict(id='O1', rule='ON branch before readback branch; refresh each relevant anchor when needed; same dependency/gap distribution for controls'),
                 dict(id='O2', rule='Held-out interleaving of independent mode/setpoint/coil branches through a declared dependency DAG; accept only legal linearizations with the same bounded anchors')]
    phase_cells = [
        ('train','mixed',['M0','M1'],['O0','O1'],['T0','T1'],'V0',3),
        ('validation','mixed',['M0','M1'],['O0','O1'],['T0','T1'],'V0',1),
        ('final_test_repeat','mixed',['M0','M1'],['O0','O1'],['T0','T1'],'V0',2),
        ('final_test_values','mixed',['M0','M1'],['O0','O1'],['T0','T1'],'V1',1),
        ('final_test_map','mixed',['M2'],['O0','O1'],['T0','T1'],'V0',2),
        ('final_test_order','mixed',['M0','M1'],['O2'],['T0','T1'],'V0',2),
        ('final_test_timing','mixed',['M0','M1'],['O0','O1'],['T2'],'V0',2),
        ('train','normal_only',['M0','M1'],['O0','O1'],['T0','T1'],'V0',1),
        ('validation','normal_only',['M0','M1'],['O0','O1'],['T0','T1'],'V0',1),
        ('final_test_repeat','normal_only',['M0','M1'],['O0','O1'],['T0','T1'],'V0',1)]
    runs = []
    for cell_id,(role,mode,maps,orders,timings,value,reps) in enumerate(phase_cells,1):
        for map_id,order_id,timing_id,rep in product(maps,orders,timings,range(1,reps+1)):
            n=len(runs)+1
            runs.append(dict(planned_run_id=f'MX{n:03d}', status='PROPOSED_NOT_COLLECTED', proposed_role=role,
                             purpose='PROPOSED_MAIN_EXPERIMENT', recording_mode=mode, map=map_id, values=value,
                             ordering=order_id, timing=timing_id, blocks=9, seed=720000+n,
                             tid_profiles=['DSEQ','DREUSE','DRANDOM'], anchor_poll_counts=[0,1,2],
                             repetition_in_cell=rep, cell_id=f'CELL{cell_id:02d}',
                             prospective_related_group=f'MX-GROUP-{n:03d}', actual_recording_id=None,
                             actual_partition_membership=None))
    probes = [
        ('M0','O0','T0','V0','mixed','New 9-block, cross-balanced TID/gap scheduler; all labels and controls'),
        ('M0','O1','T1','V0','mixed','Reversed semantic branch order and wider delays'),
        ('M1','O0','T1','V0','mixed','Nonzero mapped register roles in process and independent validator'),
        ('M1','O1','T0','V0','mixed','Map/order interaction and state-anchor invalidation'),
        ('M2','O0','T0','V0','mixed','Engineering map portability; M2 remains excluded from model development'),
        ('M2','O1','T1','V0','mixed','Held-out map with reversed branch order and delay'),
        ('M0','O2','T0','V0','mixed','Legal DAG interleaving, no stale anchors or fixed target positions'),
        ('M1','O2','T1','V0','mixed','DAG scheduler on alternate public map'),
        ('M0','O0','T2','V0','mixed','Long-delay completeness and timeout/resource behavior'),
        ('M1','O1','T2','V0','mixed','Long-delay map/order interaction'),
        ('M0','O0','T0','V1','mixed','Raw-word range change and reciprocal genuine/forged overlap'),
        ('M1','O1','T1','V1','mixed','Changed range on alternate public map'),
        ('M0','O0','T0','V0','normal_only','Normal-only acceptance without weakening intervention checks'),
        ('M1','O1','T1','V0','normal_only','Normal-only updates/transitions/repeats and matched template slots')]
    quals = [dict(planned_run_id=f'EQ{n:02d}', status='PROPOSED_NOT_COLLECTED', purpose='ENGINEERING_ONLY_UNSCORED',
                  proposed_role='excluded_from_all_model_work', map=m, ordering=o, timing=t, values=v,
                  recording_mode=mode, blocks=9, seed=710000+n, specific_unresolved_question=question,
                  tid_profiles=['DSEQ','DREUSE','DRANDOM'], anchor_poll_counts=[0,1,2],
                  prospective_related_group=f'EQ-GROUP-{n:02d}', actual_recording_id=None,
                  actual_partition_membership=None)
             for n,(m,o,t,v,mode,question) in enumerate(probes,1)]
    purpose_counts = Counter(r['proposed_role'] for r in runs)
    condition_counts = Counter(r['timing'] for r in runs+quals)
    median_size = evidence['storage_measurements']['run_artifact_bytes']['median']
    base_payload = evidence['timing_measurements']['capture_payload_span_seconds']['median']
    base_launch = evidence['timing_measurements']['launch_to_next_or_end_seconds']['median']
    base_transactions = evidence['total_counts']['transactions']/4
    block_multiplier = 9/2
    poll_allowance = 1.25
    overhead = max(0,base_launch-base_payload)
    mean_ms = dict(T0=11.5,T1=45,T2=120)
    costs = {key: overhead + block_multiplier*poll_allowance*base_payload +
             block_multiplier*poll_allowance*base_transactions*(mean-11.5)/1000 for key,mean in mean_ms.items()}
    seconds = sum(costs[k]*n for k,n in condition_counts.items())
    size_central = median_size*block_multiplier*poll_allowance*(len(runs)+len(quals))
    design = dict(schema_version=1, design_id='c3-proposed-main-v1-20261025', status='PROPOSED_NOT_ADOPTED_NOT_FROZEN',
                  engineering_decision='CONDITIONAL_GO', academic_acceptance='NOT_RECORDED_IN_REVIEWED_MATERIAL',
                  qualified_baseline='component3_testbed_v02', evidence_review='evidence_checks.json',
                  question='Within this declared software Modbus/TCP process, how much does causal request-response and prior-state information improve detection of two protocol-valid injection mechanisms over current-message information, and how does any contextual ML method compare with simple causal rules on fresh executions and predeclared held-out conditions?',
                  estimand='Paired method differences on the same eligible messages from held-out whole executions, plus false alarms on normal-only executions; inference restricted to this generator/process/condition design',
                  explicit_nonclaims=['No independent industrial campaigns or real-plant generalization',
                                      'No assumed ML superiority, attack success in a physical process, MITM or broad attack-family coverage',
                                      'Eight scenario families are six normal families plus two injection families, not eight attack mechanisms'],
                  sources=dict(primary='Future newly measured isolated testbed PCAPs and private annotation audits only',
                               qualification='All v0.1/v0.2 and future EQ data permanently excluded from fitting, tuning, feature selection, threshold selection and scoring',
                               cic='Preserved separate evidence case study, never pooled into this main experiment', external='Excluded, including MSU and all other datasets'),
                  scenarios=scenarios,
                  public_detector_configuration=dict(policy=previous['policy'], maps=previous['maps'],
                      units='Unsigned raw lab words, no physical units or invented safe ranges',
                      parity='All comparable baselines receive the same public mode/setpoint/coil map and lab policy, including M2. Supplied map roles are legitimate configuration, not inferred from private scenario flags.',
                      held_out_map_meaning='M2 is held out of model fitting/tuning, not hidden from collection engineers. This tests portability under a supplied new map, not autonomous semantic discovery.'),
                  observation_contract=dict(
                      atomic_observation='Complete raw Modbus ADU on a known connection generation; no packet-as-event assumption',
                      decision_points=dict(command='At complete request arrival, before any response', response='At complete reply arrival with only earlier requests/ACKs/history'),
                      trust_boundary='One writer, one outstanding transaction, no autonomous setpoint changes; mode observations and FC6 ACKs remain genuine in the defined interventions. Forging those anchors is outside scope.',
                      permitted_current_information='Current decoded wire content and public map/policy. FC3 response has no wire address; a current-message baseline must not be handed a request-derived address as if it were present.',
                      primary_nuisance_policy='Absolute time, file/run/episode/step/seed/source/partition identifiers excluded from predictors. TID used for protocol identity/pairing only in primary semantic comparison; numeric counter, endpoints/ports and timing handled by declared nuisance audits/ablations, never covert scenario proxies.',
                      contextual_information='Earlier observed requests, exact ACKs, mode read replies and supported associations only; no oracle state, planned next step or future recovery reads',
                      history_gap_design=dict(complete_benign_transactions_after_anchor=[0,1,2], command_intervening_adus=[0,2,4], response_intervening_adus=[1,3,5], maximum_intervening_adus=6),
                      unknowns='No eligible anchor, unresolved request identity, byte loss/gap or hidden/untrusted writer means insufficient evidence/abstain, not an attack or normal label by default',
                      reset_boundaries='Run/connection generation and unresolved byte gaps reset detector history. Private episode boundaries never reset a detector. Initialization is not a scored private-state assumption.',
                      warmup_purge='Do not score a contextual task until its public on-wire anchor exists. Entire runs/related groups are separated; if a future temporal subanalysis is approved, purge at least declared maximum lookback and response horizon and never cut pairs/bursts/connections.'),
                  comparison=dict(
                      A=dict(name='Protocol validity', purpose='Shape/MBAP/function/echo checks; protocol validity does not establish normality; valid injections may pass'),
                      B=dict(name='Current-message baseline', purpose='Same learner family as D if fitted later; current ADU/public map only, primary nuisance exclusions as above'),
                      C=dict(name='Simple causal rules', purpose='Mode-0 ON prohibition and last acknowledged setpoint/readback consistency, same map/policy/history budget and abstention rules as D'),
                      D=dict(name='Contextual ML, conditional on later feasibility', purpose='Same learner family as B with eligible causal history; fit/tune only on proposed train/validation after separate authorization'),
                      cohort='Public role/function defined pump-ON requests and paired setpoint-readback responses; common auditor-defined task eligibility for every comparison, never scenario-based. Pair-derived role may select the evaluation stratum but is not a current-response predictor. This is explicitly a task-conditioned comparison, not a claim that current FC3 replies reveal their address.',
                      all_traffic='Also report every validated ADU and eligibility/abstention disposition, task support and normal-only false alarms; no hiding low attack prevalence with aggregate accuracy',
                      future_metrics=['Per-task/class support and confusion counts','Macro precision/recall/F1 on the same supported cohort','False-positive rate on normal-only and mixed normal messages','Coverage/abstention and causal decision latency','Paired run/group-level uncertainty, with small cell counts disclosed'],
                      null_result='The policy is fully expressible as simple rules. ML may add no value or be worse; robustness/implementation tradeoffs can be studied without manufacturing a win.',
                      current_wire_sensitivity='Predeclare an additional B-wire/D-wire comparison retaining legitimate current numeric TID and endpoint/port header information for both methods. Absolute capture time and private/source/partition metadata remain excluded. Report this alongside the semantic comparison so a context claim is not based solely on withholding current wire headers. No such baseline is fitted or evaluated on qualification.',
                      possible_ml_value='Only an empirical hypothesis about robustness to supported observation variation, noise or broader future complexity. No extra noise or scenario is added solely to worsen the rules; ambiguous observations retain abstention rather than invented labels.'),
                  collection_factors=dict(maps=previous['maps'], value_profiles=previous['value_profiles'],
                                          orderings=orderings, timing=timing, tid_profiles=tid_profiles,
                                          operating_scope='Single controller/server, single-value FC1/3/5/6, unit1, port15020, Docker network-none/loopback; no concurrent-client or plant realism claim',
                                          normal_only='Same template slots, nuisance distributions and raw-value drawing as mixed runs. Inhibited ON slot becomes permitted ON after observable mode1; response-mutation slots return genuinely. Private scenario names distinguish controls in audit only.'),
                  within_run_design=dict(blocks=9, rationale='3 TID policies x 3 dependency-gap levels, crossed within each run and class/control task, avoiding tied nuisance schedules',
                                         block_contents='Fresh distinct raw a,b; all eight mixed families with genuine-readback a/b and reciprocal forged a-to-b/b-to-a, ten episodes per block',
                                         episodes_per_run=90, planned_mixed_direct_targets=dict(command_injection=9,response_injection=18),
                                         normal_only_targets=dict(command_injection=0,response_injection=0),
                                         controls='Exact role/current-PDU overlap in every map/value/timing/order/TID/gap cell. Literal-TID-5 blocks must additionally match the entire current ADU between attack and normal observations.',
                                         randomization='Separate recorded RNG streams for values, schedule, TID and delays; shuffle whole episodes without class-conditioned pauses/positions or hidden resets. Actual counters/delays audited before any model work.'),
                  grouping=dict(environment_count=1, replication_unit='Fresh whole execution/connection with its own seed and observed initialization',
                                inferential_limit='Replications are conditionally varied executions of the same deterministic simulator; neither seeds, blocks, days nor hosts create industrial campaign independence',
                                containment='A run plus every continuation, replayed capture, mirrored observation, annotation export, derived copy and counterfactual/shared-history twin stays in one related group and one future role. All twins and exact-value controls are generated within the run.',
                                duplicate_policy='Hash whole captures, canonical ordered stream contents and derivation lineage. Quarantine accidental copies across proposed roles; preserve identical PDUs at distinct genuine stream positions. Common public templates/configuration are declared shared design, not proof of independent origins.',
                                no_current_memberships='Roster IDs/roles are planning slots only. No existing capture is assigned, and actual_recording_id/actual_partition_membership remain null.'),
                  prospective_budget=dict(main_runs=len(runs), engineering_probes=len(quals), main_counts_by_proposed_role=dict(purpose_counts),
                                          mixed_runs=80, normal_only_runs=24,
                                          rationale='Core 2 maps x 2 orderings x 2 timing conditions: 3 train, 1 validation and 2 repeat-test executions per cell. Each single-axis stress test has 8 executions. Normal-only: one per core cell for train/validation/repeat-test. Nine within-run blocks cross nuisance controls; rows are not the replication count.',
                                          adequacy='Engineering/coverage budget, not a power calculation or guarantee. Three train and two repeat-test replicates per core cell are a practical first budget; validation and stress-test cell replication remain limited. Revise prospectively before main freeze/test recording if required precision cannot be justified.',
                                          role_handling='Role allocation proposed before collection, not adopted here. One primary final-repeat contrast; single-axis final tests remain separate diagnostics, not pooled to improve results. Never tune on final tests.',
                                          cost_estimate=dict(baseline_successful_recordings=4, measured_run_artifact_bytes=evidence['storage_measurements'],
                                              measured_durations=evidence['timing_measurements'], block_scaling=block_multiplier,
                                              extra_polling_allowance=poll_allowance,
                                              central_all_118_run_storage_bytes=round(size_central),
                                              planning_storage_range_bytes=[round(size_central*.8),round(size_central*1.75)],
                                              disk_reserve='4 GiB including a second copy, image/source/metadata overhead and margin; remeasure after the new probes',
                                              runtime_formula='median(launch span - capture payload span) + 4.5*1.25*median(payload span) + 4.5*1.25*mean(base transactions)*(new mean delay - 11.5 ms)',
                                              estimated_seconds_per_timing=costs, all_118_runs_central_seconds=round(seconds),
                                              rough_runtime_range_hours=[round(seconds/3600*.5,2),round(seconds/3600*2,2)],
                                              uncertainty='Not a confidence interval: n=4, one Windows/Docker machine, variable IO/scheduling, source changes and validation growth. Excludes engineering implementation, manual review and unforeseen retries; no new performance measurements made.')),
                  required_versioned_changes=[
                      dict(id='V03-1', change='New loader/launcher permits only explicitly adopted future engineering configs first; current Q-only v0.2 remains frozen. Seal proposed role ledger separately before later main authorization.'),
                      dict(id='V03-2', change='Nine-block cross-balanced TID/gap profiles, source-separated RNG channels, dependency-DAG orderings and configurable timing. Same nuisance distribution for attack/control slots.'),
                      dict(id='V03-3', change='Normal-only template mode and validator with profile-aware minimums. Mixed-run targets and all byte/intervention/anchor/control checks remain mandatory; no automatic normal labels for unknowns.'),
                      dict(id='V03-4', change='Validator independently handles all maps/ranges/schedules, literal repeated TIDs, stale anchors and normal-only runs; tests for no-op changes, missing replies/gaps, false ACKs and hidden resets.'),
                      dict(id='V03-5', change='Portable provenance adds actual collector machine ID/OS and UTC clock/timezone evidence, Docker engine/Compose versions, immutable image/base identity, exact argv, source/config/policy/role hashes and raw+private-audit bag manifest.'),
                      dict(id='V03-6', change='Collection acceptance audit tabulates nuisance/task/class support, source/copy lineage and causal eligibility without training a shortcut classifier or building model features.')],
                  acceptance_criteria=[
                      'All proposed statuses remain PROPOSED until explicit adoption; no current data memberships or main collection in this review',
                      'All 14 targeted engineering probes pass on new seeds, with no use for model work and no identical repeat of old Q01-Q04',
                      'Exact byte/stream/intervention/state/anchor reconciliation for every direct annotation; genuine command ACKs normal; all target PDUs parser-ok in this designed subset',
                      'Zero recorded kernel drops, complete one-outstanding pairing, no unexplained byte gaps/hidden state changes; label withhold/quarantine on failures',
                      'All crossed nuisance cells have intended target and comparable normal support; matched PDU and literal-5 full-ADU controls verified; no hard-coded class timing/ordering/TID cues',
                      'Prospective checks examine actual elapsed gaps/target positions, template lengths, raw-word distributions and normal-only behavior; unexplained systematic class cues trigger redesign before freeze, not score-driven filtering',
                      'Whole-run/related-copy containment and fresh seed checks pass; qualification excluded from all later model use',
                      'Public map/policy, eligibility/decision/warmup rules, proposed methods/cohorts and reporting criteria adopted before main capture/test access',
                      'Academic source change recorded separately; absence does not invalidate this engineering design review but must be resolved before presenting testbed-primary academic results'],
                  stop_conditions=['Unobservable or untrusted anchors cannot support the declared task',
                                   'No normal controls in required cell, evidence contradictions or unresolved capture/pair errors',
                                   'Uncontrolled generator identity/ordering/time cues or derived-copy leakage',
                                   'Held-out data used for model/policy/threshold tuning, or proposed memberships treated as actual',
                                   'Work would enter main collection, preprocessing, resampling or training without further authorization'],
                  academic_methodology_change=dict(status='PROPOSED_AGREEMENT_NOT_RECORDED',
                      team_taf='Cached page 6 explicitly contemplates primary controlled-testbed data; pages 9-10 define Component 3 context versus packet baseline',
                      individual_proposal='Cached pages 21-22 specify CIC primary and testbed optional; changing that emphasis requires an explicit recorded methodology decision',
                      exact_proposed_text='Component 3 will use newly measured traffic from an isolated Modbus/TCP software PLC/controller testbed as its primary controlled experiment. It will compare current-message information, simple causal protocol/policy rules and, if feasible, the same supervised learner with causally available request-response/history context for two declared protocol-valid injection mechanisms. Generalization claims are restricted to fresh executions and predeclared conditions within this testbed. The preserved CIC extraction/reassessment remains a separate evidence and limitations case study and will not be pooled with testbed rows. MSU and other datasets are excluded. Qualification is excluded from model development and scored evaluation. A finding of no added ML benefit is acceptable; no industrial independence, real-plant impact or broad unseen-attack claim is made.'),
                  next_action='Review/adopt or amend this proposed claim and nuisance-control design, record the academic methodology decision separately, then authorize a separate v0.3 implementation and only its 14 targeted engineering probes before any main collection',
                  provenance=dict(code='_support/build_design.py', code_sha256=sha(Path(__file__)),
                                  baseline_design_sha256=sha(REPO/'component3_collection_design/v1_20261024/collection_design.json'),
                                  evidence_checks_sha256=sha(HERE/'evidence_checks.json')))
    design['ordering_compiler_spec'] = dict(
        units='Each named token is a complete request/response transaction. Polls do not write state. Family-specific legitimate updates/repeats/transitions occur before their required refreshed anchors.',
        token_roles=dict(WM='FC6 mode write plus ACK', WS='FC6 setpoint write plus ACK',
                         RM='FC3 mode read plus reply', RS='FC3 target setpoint read plus reply',
                         ON='FC5 pump ON plus ACK when permitted or deliberately injected; lawful OFF-only families omit ON',
                         RC='FC1 genuine coil read', OFF_setup='FC5 OFF', OFF_restore='FC5 OFF',
                         RS_recovery='Unaltered FC3 recovery read; never predictor evidence for earlier decisions',
                         WS_refresh='Visible same-value FC6 write and ACK', RM_refresh='Latest genuine mode read', RM_pre='Earlier genuine mode read'),
        canonical_templates=dict(
            O0=[['WM','OFF_setup','WS','RS','RM','ON','RC','OFF_restore','RS_recovery']],
            O1=[['OFF_setup','WS','WM','RM','ON','RC','WS_refresh','RS','OFF_restore','RS_recovery']],
            O2=[['OFF_setup','WS','WM','WS_refresh','RS','RM','ON','RC','OFF_restore','RS_recovery'],
                ['WM','OFF_setup','RM_pre','WS','RM_refresh','ON','WS_refresh','RS','RC','OFF_restore','RS_recovery']]),
        constraints=['Most recent mode read must follow the latest mode write and precede ON; no subsequent mode change before that ON',
                     'Most recent successful setpoint write/ACK precedes each target RS; no hidden write between anchor and reply',
                     'Insert exactly the block q=0/1/2 complete benign polls between each refreshed designated anchor and target request; refresh an anchor if template work would otherwise age it',
                     'Request/reply cannot be interleaved with another transaction; preserve complete episodes and run histories',
                     'Use the same template/poll rules for each attack and its matched normal role, not an attack-only refresh or delay'],
        status='Concrete proposed transaction skeletons; new compiler and independent checks are required, not implemented or adopted by this review')
    # Explicit audit of current qualifications versus controls planned above.
    design['shortcut_audit'] = [
        dict(cue='TIDs/counters', observed='v0.2 random initial TID then strictly sequential; reused-5 handling was an offline fixture, not measured qualification', response='Cross DSEQ/DREUSE/DRANDOM within class/control cells; numeric TID excluded from primary semantic predictors, retained for identity audit'),
        dict(cue='Absolute/relative time', observed='All accepted recordings collected in one short session; generator sleeps 8-15 ms before every exchange, application overhead varies', response='No absolute clock/run index predictor; T0/T1 crossed with classes, T2 separate stress test; compare actual distributions by task/class and disclose time ablations'),
        dict(cue='Episode position/order/length', observed='0-2 prefix polls and shuffled episodes coexist with fixed role-specific steps and family-specific lengths', response='O0/O1 plus O2 DAG scheduler, crossed 0/1/2 safe gaps and matched normal template slots; private boundaries/step labels forbidden; retain length/order as audit risks'),
        dict(cue='Endpoints/ports/maps', observed='Loopback/unit1/server15020 fixed; one ephemeral client port per run; only M0 measured', response='Same endpoints within each run/class, identifiers excluded from primary predictors; public maps supplied equally, M2 held out from fitting. Does not test new network topology.'),
        dict(cue='Values/addresses', observed='Command targets have one PDU; response targets have 14 distinct PDUs, all matched by normal observations; full MBAP ADUs differ by sequential TID', response='Fresh unordered a,b pairs, reciprocal forgeries, genuine a/b and updates in each cell; V1 separate stress test. No inferred physical ranges.'),
        dict(cue='Scheduling/reset/missingness', observed='No actual missing-reply/gap qualification examples; initialization once per run with visible episode setup writes, not hidden per-episode process reset', response='Independent nuisance RNG; no detector reset on private episode boundaries; tests/probes validate stale/missing anchors and abstention; no missingness-as-label rule'),
        dict(cue='Duplicate/shared history', observed='Four whole capture hashes distinct; repeated PDUs and shared in-run value-pair histories are deliberate', response='Keep run, twins, continuations and derived/mirrored copies in one related group; audit whole capture and ordered-stream hashes, retain genuine repeat positions')]
    roster = dict(schema_version=1, design_id=design['design_id'], status='PROPOSED_NOT_ADOPTED_NOT_COLLECTED',
                  not_final_partition_memberships=True, qualification_records_assigned_to_model_roles=0,
                  existing_recordings_assigned=0, existing_v02_qualification_ids=['Q01','Q02','Q03','Q04'],
                  seed_policy='New engineering seeds 710001-710014; main 720001-720104, disjoint from old 60001-60004/4010 and the earlier draft 61001-660xx. Seeds are planning identifiers, not independent campaigns.',
                  engineering_runs=quals, prospective_main_runs=runs,
                  main_cell_definitions=[dict(cell_id=f'CELL{i:02d}', proposed_role=role, mode=mode, maps=maps,
                                              orderings=orders, timings=timings, values=v, repetitions=reps)
                                         for i,(role,mode,maps,orders,timings,v,reps) in enumerate(phase_cells,1)],
                  counts=dict(engineering=len(quals), prospective_main=len(runs), main_by_role=dict(purpose_counts),
                              main_by_mode=dict(Counter(r['recording_mode'] for r in runs))))
    def require(ok,reason):
        if not ok:
            raise ValueError(reason)
    require(len(runs)==104 and len(quals)==14,'Unexpected roster size')
    require(len({r['seed'] for r in runs+quals})==118,'Seed collision')
    require(all(r['map']!='M2' and r['values']!='V1' and r['ordering']!='O2' and r['timing']!='T2'
                for r in runs if r['proposed_role'] in ('train','validation')), 'Hold-out condition leaked')
    require(all(r['actual_recording_id'] is None and r['actual_partition_membership'] is None for r in runs+quals),'Actual memberships forbidden')
    save('proposed_main_design.json',design)
    roster['proposed_design_sha256'] = sha(HERE/'proposed_main_design.json')
    save('proposed_run_roster.json',roster)
    print(json.dumps(dict(decision=design['engineering_decision'],main_runs=len(runs),engineering=len(quals),
                          role_counts=dict(purpose_counts),projected_all_bytes=round(size_central),
                          projected_all_hours=round(seconds/3600,2)),indent=2))


if __name__=='__main__':
    main()
