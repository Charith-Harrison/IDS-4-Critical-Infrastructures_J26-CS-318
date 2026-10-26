# Component 2 final collection protocol (frozen)

Project J26-CS-318, RP2 (Reconnaissance Attack Detection Using Temporal Behavior Analysis), Charith H. / Harry.
**Frozen 26 October 2026, before any final data exists.**

Machine-readable freeze:

* `configs/final_v1.json` (SHA-256 `efd9c742…a37a`);
* `final/frozen/frozen_plan_manifest.json` (SHA-256 `93e73788…d27b`): 384 pre-generated run plans, each hashed.

The orchestrator refuses any plan whose hash differs. Plans regenerate byte-identically from the config
(verified: 384/384 hashes identical).

Evidence base, not re-audited here:

* `PILOT_RESULTS.md` and `DESIGN_ITERATIONS.md` (pilots v1–v3);
* `component2_forensic_review/` (the CIC audit).

Any change to this document or the frozen files after collection starts must be recorded as a dated amendment with
its reason, and must not be made after looking at test outcomes.

## 1. Research question and claims

> Given Modbus/TCP requests that are individually legitimate-looking and overlap normal traffic in their
> current-message fields, can recent observable command history distinguish reconnaissance from normal operation?

Pilot v3 fixes the expected shape of the answer. The protocol tests it rather than assuming it:

* **H1 (primary):** on held-out runs, a model using the causal request history detects reconnaissance with
  materially higher recall than a model using only the current message. Both are evaluated at the same operating
  point, set on revisiting normal workloads.
* **H2 (boundary, reported, expected null):** history does **not** reliably separate reconnaissance from legitimate
  *one-pass coverage* workloads (cold start, configuration backup, historian backfill, commissioning checkout).
  Their false-positive rate is reported, never pooled away.
* **H3 (generalisation):** H1 holds on an unseen site (Site C) with different unit IDs and map size.

CIC remains a secondary case study and is never merged; MSU is not used. Proposal conflicts already flagged in
`PILOT_RESULTS.md` §7 still stand.

## 2. Design (frozen)

* **Scenarios:** exactly as pilot v3 (`c2tb/scenarios_v3.py`, wrapped by `c2tb/scenarios_final.py`).
  * Recon R1–R6, each with a legitimate maintenance lead-in.
  * Revisiting normal N1–N4.
  * One-pass normal N5–N8, each with the same lead-in.
  * A background HMI poller in every run.
* **Shared envelope:** one shape envelope per site. Functions FC1–4; per-table read granularity in {1, 2, 4}; the
  attacker stays in-envelope with no exceptions, writes, malformed frames or spoofing (`THREAT_MODEL.md`).
* **Sites:**

| Site | Units | Map size / table | Granularity seed | Role |
|---|---|---|---|---|
| A | 1, 2, 3 | 32 | 11 | train / validation / in-site test |
| B | 1, 2, 3 | 32 | 29 | train / validation / in-site test |
| C | **1, 2, 5, 7** | **48** | 47 | **out-of-site test only** |

  Site C adds two unit IDs (5, 7) never seen in training, a larger map, 16 tables instead of 12, and a heavier
  background (~7,700 requests per run). Plan-level checks confirm that Site C recon shapes are 100 % covered by
  Site C normal traffic in other runs, with no truncated plans. Sites A/B plans are byte-identical to v3 plans for
  the same seed, apart from the end policy below.
* **Run length (wall-clock optimisation without behaviour change):**
  * Planning horizon 75 s.
  * A run ends **5 s after the actor's last planned action**, and only background actions after that point are
    dropped.
  * The actor's lead-in, task and timing are untouched, so N1–N4 still run the full horizon.
  * The background reaches 20 requests within 1.2 s, so causal-history requirements are unaffected.
  * This removes 34 % of traffic time.
  * Run length is not a predictor and never enters a context window.
* **Execution:**
  * Seeded random order over all 384 runs, so site, partition and scenario are not confounded with time or worker.
  * **Two parallel workers**, each with its own isolated `--internal` network and subnet (`10.52.0.0/24`,
    `10.52.1.0/24`), containers, PCAP, ledgers, clock log and run ID.
  * Estimated wall time is ~3.3 h, against ~9.3 h serially at fixed length.

## 3. Evaluation strata (frozen)

Each request is a target. The label is the ledger role of that request (`gt_label_recon`); labels never come from
packet values.

| Stratum | Requests | Role in inference |
|---|---|---|
| **R** reconnaissance | recon-phase requests of R1–R6 | positives |
| **NR** revisiting normal | task-phase requests of N1–N4 | primary negatives; operating point set here |
| **NO** one-pass normal | task-phase requests of N5–N8 | H2 negatives, reported separately |
| **NL** legitimate lead-in | maintenance lead-ins in R and N5–N8 runs | reported separately (pilot FPR ~0.33) |
| **NB** background HMI | background poller, all runs | reported separately (84–92 % of requests; never pooled into headline metrics) |

**Primary analysis view:** recon vs. the actor host's legitimate activity, with the background stream removed and
reported on its own. A pooled all-request metric is reported only as a secondary number.

## 4. Predictors and the raw transaction ID (frozen)

* **Current-message predictors:** wire FC, unit, address, quantity, MBAP length, request frame length.
* **History predictors:** derived only from the causal context defined in §5.
* **Raw TID value is excluded from all predictors.** It is an arbitrary per-connection counter assigned by the
  client stack and carries no Modbus command content, so it is treated like the client TCP port: kept for pairing
  and lineage only.
  * Decided now, before collection, from pilot evidence. In v3 a tree memorised the TID blocks of 12 recon runs
    (within-fold AUC up to 0.85), with a TID-free tree at chance (0.48).
  * The raw-TID variant of G3 is still computed and reported (§6), so the decision is visible.
* **Never predictors:** IPs, ports, run, site, scenario, partition, file/frame identifiers, timestamps as absolute
  values, ADU/response hex, `clock_ambiguous`, and every `gt_*` and `ledger_*` field.
* **Unit IDs:** categorical. Site C's unseen IDs 5 and 7 map to an explicit "unseen" category, which is part of H3.

## 5. History / context definition (frozen)

* **Stream:** (run, client IP, target IP). Contexts never cross runs, clients or targets.
* **Order:** clock-step-corrected capture time `ts_corr_ns`, with ties broken by frame number. Raw timestamps are
  preserved; correction follows `PILOT_PROTOCOL.md` Amendment A, with 10 ms clock sampling.
* **Window:** the last **20** requests ending at and including the target. It resets after a 60 s idle gap (not
  expected within runs). No future packets enter.
* **Partial contexts:** fewer than 20 prior requests are padded and masked.
  * **Primary metrics use targets with full 20-request context.**
  * All-target metrics are secondary.
  * In v3, 21 % of recon targets had partial context, because lead-ins are short by design.
* **Model inputs** use the same window for every representation:
  * **A:** current-message static.
  * **B1:** the proposal's flattened-window RF.
  * **B2:** order-invariant summaries.
  * **B3:** the pilot's pre-specified history statistics (first-seen novelty, unique targets, ascending steps,
    address deltas, FC/unit transitions, interval mean/CV/min).
  * **LSTM.**
* **Timing features** use `ts_corr_ns`. Requests flagged `clock_ambiguous` stay in the data and are counted in
  reporting.

## 6. Acceptance gates (frozen)

**Per run** (all must hold; otherwise the run is rejected, kept, and the reason recorded):

* capture readable with 0 kernel or interface drops; Ethernet link type;
* **no cross-run traffic:** every TCP endpoint in the PCAP belongs to that run's target and two clients;
* no TCP retransmission, gap, truncation or unframed bytes;
* parser agrees with tshark on **every** Modbus ADU;
* ledger ↔ wire 1:1 (client IP, client port, TID, exact bytes); wire fields equal ledger intent;
* the client-received response equals the captured response;
* exactly one response per request, paired in capture frame order; no unmatched responses, exceptions, client
  errors or reconnects;
* all planned actions executed; recon and one-pass plans not truncated;
* clock log covers the run; capture-after-send holds on the corrected timeline; ≤ 1 % `clock_ambiguous` requests;
* frozen-plan hash verified.

**Replacement rule:** a rejected run is replaced by **one** re-collection of the same frozen plan, with a new run ID
suffix `-retry1` and the same seed and partition. A plan that is rejected twice is recorded as failed and not
replaced again, and partition counts are reported as achieved. Replacements may not be selected by outcome.

**Collection level**, on accepted runs, per site and pooled, with run-grouped 5-fold CV:

| Gate | Threshold |
|---|---|
| G1 value coverage | 100 % of recon FC, unit, quantity, MBAP length and frame length values occur in normal traffic; ≥ 95 % of recon (FC, unit, address) values do |
| G2 joint shape | ≥ 90 % of recon joint shapes occur in normal traffic of **other runs of the same site** |
| G3 current message without TID | every model: pooled AUC ≤ 0.80, oracle balanced accuracy ≤ 0.75, **within-fold mean AUC ≤ 0.70** |
| G3-TID (reported) | same models with raw TID; reported, and expected to pass at this scale |

If G1, G2 or G3 fails, stop. Do not train, and report the failure; a redesign requires a new pilot.

The frozen gate code (`c2tb/diagnostics.py`) was sanity-checked on pilot v3:

* G1 passes.
* G2 same-site coverage is 1.00 for both A and B.
* G3 without TID passes: maximum pooled AUC 0.543, balanced accuracy 0.610, within-fold mean AUC 0.579.
* Raw-TID variants: the tree reaches a within-fold mean of 0.704 and the TID lookup 0.635, which is why TID is
  excluded from predictors.

## 7. Split strategy (frozen before collection)

Partition membership is written into every frozen plan (`partition` field) and the manifest.

| Site | Partition | Recon (per scenario) | Revisiting normal | One-pass normal | Runs |
|---|---|---|---|---|---|
| A | train | 4 | 4 | 4 | 56 |
| A | validation | 2 | 2 | 2 | 28 |
| A | in-site test | 6 | 3 | 2 | 56 |
| B | train / validation / in-site test | same as A | | | 140 |
| C | **out-of-site test** | 12 | 5 | 3 | 104 |
| **Total** | | | | | **384** |

* **Train (A+B):** fitting, plus model selection by run-grouped 5-fold CV inside train only, with folds dealt within
  site × scenario.
* **Validation (A+B):**
  * Operating threshold chosen at **5 % FPR on NR task requests**, matching the proposal's FPR < 5 % target.
  * Early stopping and calibration.
  * Nothing else.
* **In-site test (A+B):** opened once, after all models and thresholds are frozen.
* **Out-of-site test (C):** never used for any fitting, tuning, normalisation or threshold. It is opened once, last.
* **Fitting rules:** all scaling, vocabularies and imputation are fitted on train only. Every model uses the same
  targets, windows and partitions.
* No random row or window splits. A run is the unit of independence throughout. Dependencies such as the request
  and its response, overlapping windows and lead-ins all stay inside their run.

## 8. Final run count and its justification

Derived from v3 run-level variance with the frozen strata, using run-grouped out-of-fold history and current-message
random forests on the actor view at a 5 % NR operating point. Scripts:

* `c2tb/run_count.py` → `final/run_count_evidence.json`, `final/v3_run_level_rates.csv`;
* `c2tb/run_count_scenario.py` → `final/run_count_scenario_stratified.json`.

* **The unit is the run.** For each run, the per-stratum rate is recall for R and FPR for NR/NO. The between-run SD
  is pooled **within scenario**, because v3 shows that scenario means differ systematically (N3 maintenance FPR 0.61
  vs N1 0.001; R5 recall 0.56 vs R2 1.00). Because v3 has only 2 runs per scenario, the **80 % upper confidence
  limit** of that SD is used.
* **Requirement:** the smallest n with t₀.₉₇₅,ₙ₋₁ · SD / √n ≤ h.

| Quantity | v3 pooled within-scenario SD (UCL80) | Target half-width h | Required per test population |
|---|---:|---:|---|
| Recon recall, scenario-balanced, and paired history − current recall gain (H1) | 0.303 (0.423) | ±0.10 | **12 runs per recon scenario** |
| Revisiting-normal FPR per scenario | 0.075 (0.117) | ±0.15 | **5 runs per scenario** |
| One-pass FPR per scenario (H2) | 0.038 (0.059) | ±0.15 | **3 runs per scenario** |

* **Two test populations:**
  * In-site (A+B): the 12 recon runs per scenario split 6/6, revisiting 3+3 ≥ 5, one-pass 2+2 ≥ 3.
  * Out-of-site (C): 12 / 5 / 3 runs per scenario.
* **Not powered:** per-scenario *recon* recall to ±0.15 would need 34 runs per scenario per population, because
  per-run recall is bimodal (runs are either detected or mostly missed). It is therefore reported descriptively with
  run-cluster bootstrap CIs, not as a powered estimate.
* **A pooled run-level FPR target is rejected.** An earlier unstratified calculation demanded 267–322 runs, because
  it mixed scenario differences into "noise". That number is recorded in `run_count_evidence.json` and rejected as
  the wrong estimand.
* **Train size (4 runs per scenario per site):** gives every inner CV fold at least 3 training runs of each scenario
  per site. That is above the 2 per scenario per site from which v3 already learned the revisiting/recon distinction
  (within-fold AUC 0.987).
* **Validation size (2 per scenario per site):** gives 16 NR runs for setting the threshold.
* **Total:** 384 runs (~1.49 million planned requests). Expect about 2.2 GB of PCAP and logs from the v3 per-run
  average.

## 9. Execution procedure

1. Confirm the image `c2-recon-testbed:0.1.0` (image ID recorded in every manifest) and the frozen-file hashes
   above.
2. Collect:

   ```
   python component2_testbed/run_pilot.py --config configs/final_v1.json --plans final/frozen/frozen_plan_manifest.json --collection-id final_v1 --workers 2
   ```

3. After collection, process every run with `c2tb.process_run`, which is per-run and cheap, then apply the
   replacement rule. A retry uses the same frozen plan and seed and writes `collection_manifest-retry1.json` beside
   the original:

   ```
   python component2_testbed/run_pilot.py --config configs/final_v1.json --plans final/frozen/frozen_plan_manifest.json --collection-id final_v1 --workers 2 --run-ids <rejected ids> --id-suffix=-retry1
   ```
4. Only after collection and replacement are complete, run the collection-level gates and diagnostics once. The
   expensive full-dataset analysis is postponed to this point.
5. Train and evaluate per §7 under a separate, later instruction. This protocol does not authorise training.

**Parallel benchmark (disposable, `final/parallel_benchmark.json`).** The same two frozen plans (the heaviest Site C
N2 and a Site A R3) were collected serially and with 2 workers:

* both modes: all runs accepted, 0 drops, no cross-run traffic, ledger↔PCAP 1:1, valid clock correction;
* identical request counts;
* schedule lag p99 0.28 ms parallel vs 0.30 ms serial;
* response latency p99 528/501 µs parallel vs 710/606 µs serial;
* peak 1.1 cores and 112 MiB on a 20-core / 15 GiB host;
* wall time 92 s vs 139 s.

Decision: **2 workers**. Benchmark raw data was disposable and has been removed. The benchmark runs are not part of
any dataset.

## 10. Known limits carried into the final study

* Software-only testbed in one Docker VM, with a stepped VM clock (measured and corrected).
* One persistent TCP connection per client.
* The attacker mimics the site's read granularity; out-of-envelope recon is excluded.
* Sites A and B share units and map size, so only Site C tests generalisation.
* H2 is expected to be null by construction of the hard negatives. That is the scientific boundary to report, not a
  defect.

## Amendment 1 (26 October 2026, after collection, before any collection-level analysis)

Recorded without looking at any model or gate outcome; no frozen design element is changed.

* Collection `final_v1` ran 384/384 frozen plans with 2 workers (19:52–23:02 UTC, 0 collection errors).
  Per-run acceptance: **383 accepted**, 1 rejected. Status, achieved-vs-planned counts and clock totals:
  `final/collection_status.json`.
* Rejected run `final_v1-r189` (Site C, out-of-site test, R3 randomized scan): `recon_plan_not_truncated`. Cause is a
  property of the frozen plan, not of collection: 4 Site C tables × 48 addresses at the slowest steady pacing
  (0.40 s) give 156 targets, of which 27 do not fit the 75 s horizon. It is the only truncated plan among the 384
  (checked across the full manifest); the pre-freeze plan check had sampled only 42 Site C plans.
* Replacement rule applied as written: `final_v1-r189-retry1` (same plan and seed) was rejected for the same reason
  and the plan is recorded as **failed, not replaced**. Achieved Site C out-of-site recon: 71 of 72 runs
  (R3: 11 of 12). Its raw evidence is kept; it is excluded from every analysis population.
* Tooling note: the retry flag must be written `--id-suffix=-retry1` (§9 corrected); a first attempt with a space
  was rejected by the argument parser before anything ran.
