# Component 2 final results: reconnaissance detection from Modbus/TCP command history

Project J26-CS-318, RP2 (Reconnaissance Attack Detection Using Temporal Behavior Analysis), Charith H. / Harry.
Results of 26 October 2026, from collection `final_v1`.

Every number below comes from the frozen pipeline:

* `FINAL_COLLECTION_PROTOCOL.md` (data, strata, splits, gates);
* `MODELLING_PLAN.md` (representations, selection, operating point);
* the reports copied to `final/results/`.

Each test population was opened exactly once. The opening logs (`final/results/opened_*.json`) show identical
model and threshold hashes for both openings.

## Answer to the research question

> Given Modbus/TCP requests that are individually legitimate-looking and overlap normal traffic in their
> current-message fields, can recent observable command history distinguish reconnaissance from normal operation?

**Partly.** History separates reconnaissance from normal work that *revisits* registers: polling, trend watching
and maintenance. This holds at the training sites and at an unseen site, where the current message alone barely
helps.

History does **not** separate reconnaissance from legitimate *one-pass coverage* reads: HMI cold start,
configuration backup, historian backfill and commissioning checkout. Those requests are behaviourally the same as a
scan and differ only in intent. Every history model flags almost all of them.

A random forest on a few pre-specified history statistics (B3) matches the LSTM's recall. It also has fewer false
positives and transfers better to the unseen site.

## 1. Data

| | |
|---|---|
| Collection | 384 frozen runs; 383 accepted, 1 failed (frozen-plan defect, see Amendment 1); 1,481,352 requests, 9,805 reconnaissance |
| Sites | A, B (units 1–3, 32-address tables) for train, validation and in-site test; C (units 1, 2, 5, 7, 48-address tables) for the out-of-site test only |
| Collection gates | G1, G2 (per site) and G3 (current message, no TID) pass; the raw-TID variant also stays within limits (`final/results/collection_gates.json`) |
| Partitions | train 112 runs; validation 56; in-site test 112; Site C test 103 |

## 2. Models (selected on train only, `final/results/cv_selection.csv`)

| ID | Representation | Within-fold CV AUC (recon vs revisiting, train) |
|---|---|---:|
| A | current request only (FC, unit, address, quantity, lengths; no TID) | 0.611 |
| B2 | order-invariant summary of the last 20 requests | 0.772 |
| B1 | last 20 requests flattened (proposal p14 random forest) | 0.999 |
| B3 | pre-specified pilot history statistics | 0.999 |
| L | LSTM over the last 20 requests (hidden 64, learning rate 1e-3, 4 epochs) | 0.992 |

**Operating point:** 5 % false-positive rate on validation revisiting-normal task requests, frozen before any test
data was read.

## 3. H1: history beats the current message (recon vs revisiting normal)

Recall is balanced across the six recon scenarios, on targets with a full 20-request context. The gain is each
model's recall minus A's, paired per run. Brackets are 95 % CIs from a run bootstrap stratified by scenario.

| Model | Validation recall* | In-site test recall | In-site gain over A | Site C recall | Site C gain over A |
|---|---:|---:|---:|---:|---:|
| A | 0.059 | 0.108 [0.078, 0.138] | – | 0.145 [0.113, 0.182] | – |
| B2 | 0.204 | 0.221 [0.177, 0.265] | +0.113 [0.059, 0.167] | 0.079 [0.049, 0.112] | **−0.067** [−0.105, −0.030] |
| B1 | 1.000 | 1.000 [1.000, 1.000] | **+0.892** [0.862, 0.922] | 1.000 | **+0.855** [0.818, 0.887] |
| B3 | 1.000 | 1.000 [1.000, 1.000] | **+0.892** [0.862, 0.922] | 1.000 | **+0.855** [0.818, 0.887] |
| L | 0.998 | 0.997 [0.992, 1.000] | **+0.889** [0.859, 0.918] | 1.000 | **+0.855** [0.818, 0.887] |

\*Validation recall is request-level (`validation_report.json`). Validation set the threshold and is not a test.

* **H1 is supported.** B1, B3 and L detect every recon scenario at 0.99–1.00 on both test populations. The
  current message catches 5–27 % of recon requests depending on scenario.
* **The gains are well estimated.** The protocol's precision target for the gain was ±0.10; the achieved interval
  is about ±0.03.
* **H3 (generalisation to Site C) holds for B1, B3 and L.**
* **B2 does not generalise.** Order-free message statistics help a little in-site and fall below A at Site C, so
  the useful signal is order and novelty, not the mix of messages.

## 4. H2: one-pass legitimate coverage (predicted null)

| Model | In-site: one-pass flagged | In-site AUC (recon vs one-pass) | Site C: one-pass flagged | Site C AUC |
|---|---:|---:|---:|---:|
| A | 0.115 | 0.510 | 0.119 | 0.523 |
| B1 | 1.000 [1.000, 1.000] | 0.746 | 1.000 | 0.540 |
| B3 | 1.000 [1.000, 1.000] | 0.671 | 1.000 | 0.489 |
| L | 0.991 [0.973, 1.000] | 0.468 | 1.000 | 0.504 |

* **The null is confirmed.** At an operating point that suits revisiting traffic, every history model flags
  essentially all legitimate one-pass reads, and ranking separation is at chance at Site C.
* **This is a boundary of the method, not a defect.** Within the observable traffic, a one-pass backup and a
  sequential scan are the same command sequence.

## 5. False positives on legitimate traffic

Full-context targets; lead-ins are on all targets.

| Model | Revisiting work: in-site | Revisiting work: Site C | Background HMI: in-site / C | Lead-in maintenance: in-site / C |
|---|---:|---:|---:|---:|
| A | 0.095 | 0.079 | 0.065 / 0.077 | 0.094 / 0.132 |
| B1 | 0.048 [0.033, 0.079] | 0.038 [0.025, 0.063] | 0.044 / 0.054 | 0.446 / 0.455 |
| B3 | **0.025** [0.013, 0.045] | **0.037** [0.012, 0.087] | **0.003 / 0.002** | 0.606 / 0.624 |
| L | 0.038 [0.018, 0.077] | **0.083** [0.037, 0.161] | 0.022 / **0.076** | 0.802 / 0.819 |

* **B3 meets the proposal's FPR < 5 % on revisiting work at both test sites** and flags almost no background
  polling.
* **The LSTM's threshold does not transfer** to the unseen site: revisiting and background false positives roughly
  double.
* **Lead-in maintenance is a second blind spot.** The legitimate reads a host performs just before its main task
  are flagged 45–82 % of the time, for the same novelty reason as H2.

## 6. What this supports and what it does not

**Supported:**

* Temporal context is necessary to detect in-envelope reconnaissance that individual messages cannot reveal.
* The finding holds across six scan styles (sequential, sparse, randomised, slow, function probe, unit probe) and
  at an unseen site.

**Not supported:**

* That an LSTM is required. A forest on simple history statistics is as good or better.
* That reconnaissance can be told from legitimate one-pass engineering reads by traffic alone.
* Any claim about real plants, other register maps, out-of-envelope scanners (bulk quantities, missing units,
  diagnostic function codes) or connection-level behaviour, which were outside the controlled design.

**Practical implication:** a deployment needs context beyond the command stream. Examples are maintenance-window
schedules, the identity of the hosts allowed to do bulk reads, or per-host baselines. Alerts on one-pass coverage
should be treated as "verify intent", not "attack".

## 7. Limitations

* **Software-only testbed.** A pymodbus server in one Docker VM; one persistent TCP connection per client; a VM
  wall clock that steps about every 30 s (measured and corrected, with < 0.4 % of requests flagged ambiguous).
* **Mimicry assumption.** The attacker reads at each site's legitimate granularity. Sites A and B share geometry;
  only Site C tests transfer.
* **Lab conditions.** Normal and recon behaviours are scripted; real plants may contain workloads that behave like
  neither.
* **Run counts are powered for scenario-balanced estimates.** Per-scenario recon recall is descriptive.
* **One failed plan.** Site C has 11 rather than 12 R3 runs.
* **No naive random-split contrast.** It was not run (see §8).

## 8. Deviations from the proposal (flagged, not forced)

| Proposal | Here | Why |
|---|---|---|
| ICSSIM testbed with port mirroring (p13) | pymodbus target, passive capture in the target network namespace, Docker isolation | Smaller, fully controlled stack with byte-level ground truth; same observational evidence |
| "175,800 windows from an initial testbed run" as primary data (p13) | Not used | Shown by the forensic audit to be CIC-derived, with invalid labels and sequences |
| Public datasets incl. MSU (p13) | CIC kept as a secondary case study only; MSU not used | CIC fails the matched-message requirement; MSU excluded by instruction |
| GroupKFold plus a naive random-split comparison (p15) | Run-grouped CV for selection; frozen train / validation / two one-shot test populations; no random split | Random splitting leaks overlapping windows; the protocol forbids it |
| "LSTM outperforms baselines" as the expected result | Stratified answer: history beats the current message; the LSTM does not beat simple history statistics; one-pass reads are a blind spot | Reported as measured |
| Window of 20 timesteps × 7 features | 20 timesteps × 19 causal per-step features; raw transaction ID excluded | Raw TID is an arbitrary counter and produced a pilot artifact; the extra features are protocol-observable |

## 9. Reproduce

* **Collection:** `FINAL_COLLECTION_PROTOCOL.md` §9.
* **Modelling:** run each of the following in the `c2-recon-model:0.1.0` image:
  1. `python -m c2tb.model_data --partition train` (and the same with `--partition validation`);
  2. `python -m c2tb.train_models`;
  3. `python -m c2tb.evaluate_test --open-test <population>`.

  The test openings are guarded and one-shot.
* **Raw data:** captures, ledgers and model inputs are not in git (≈ 2.5 GB). They are reproducible from the frozen
  plans; hashes are in the run manifests.
