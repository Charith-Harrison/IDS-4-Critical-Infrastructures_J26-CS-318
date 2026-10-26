# Component 2 controlled Modbus/TCP pilot: results

Project J26-CS-318, RP2, Charith H. / Harry. Collected and analysed 25–26 October 2026.
Design: `THREAT_MODEL.md`, `PILOT_PROTOCOL.md` (gates fixed before collection, Amendment A before v3),
`DESIGN_ITERATIONS.md`. This is a methodology pilot. **No final dataset was generated and no LSTM was trained.**

## Bottom line

| | v1 (rejected) | v2 | **v3 (current)** |
|---|---|---|---|
| Design | random tag lists, 64-address tables | site envelope, poll-mimic recon timing | v2 + one-pass legitimate coverage workloads (N5–N8), 2 sites, clock monitoring |
| Runs accepted / collected | 20 / 20 | 19 / 20 | **28 / 28** |
| Requests (recon) | 34,288 (722) | 91,763 (463) | **136,556 (433)** |
| G1 value coverage (address ≥ 0.95) | **FAIL** 0.705 | pass 1.000 | pass 1.000 |
| G2 recon shape in other runs' normal (≥ 0.90) | **FAIL** 0.476 | pass 1.000 | pass 1.000 |
| G3 max current-message pooled AUC / bal. acc. (≤ 0.80 / ≤ 0.75) | pass 0.567 / 0.636 | pass 0.519 / 0.576 | pass 0.675 / 0.724, driven by TID (§3) |
| History, actor-only (pooled / within-fold mean AUC) | 0.990 / 0.915 | 0.973 / 0.939 | **0.927 / 0.728** |
| History, recon vs one-pass legitimate coverage | – | – | **no separation** (single statistics ≤ 0.56) |

Three conclusions:

1. **The methodology works.** Real traffic, write-protected PCAPs, ledger-derived labels and full lineage are in
   place. Every Modbus ADU was checked against tshark with 0 mismatches. The ledger and wire are joined 1:1, VM
   clock steps are measured and corrected, and causal contexts never cross runs.
2. **Matched current messages are achieved.** Recon cannot be identified from FC, unit, address, quantity, length,
   endpoint or response shape. The one remaining static signal is the raw transaction-ID value, which is a
   small-sample counter artifact. It must be decided before the full collection, not deleted after it (§3).
3. **History separates recon from *revisiting* normal work but not from legitimate *one-pass coverage* work.**
   Recon vs polling/trend/maintenance (N1–N4): within-fold AUC 0.987. Recon vs HMI cold start, configuration
   backup, historian backfill and commissioning checkout (N5–N8): no stable separation. These pairs are
   **indistinguishable from observable traffic by design**, because the same request sequences differ only in intent.
   That is the honest boundary of RP2's research question, and the final study must report it rather than hide it.

## 1. What was built

`component2_testbed/` is separate from CIC, Component 3 and the existing `C2_Reconnaissance_Detection/` code, which
was not modified. It uses one pinned Docker image (`c2-recon-testbed:0.1.0`: pymodbus 3.6.9, tcpdump 4.99.5,
tshark 4.4.19, Python 3.12).

Each run is a separately initialised acquisition:

* a fresh `--internal` network;
* a pymodbus target with units 1–3 and a seeded, evolving process image;
* passive tcpdump in the target's network namespace;
* two client containers at random IPs: a background HMI poller, plus an actor that runs either a normal workload or,
  after a legitimate lead-in, reconnaissance;
* (v3) a clock-monitor sidecar.

The clients are a small custom Modbus master, so the ledger records exact bytes, TID, local port and send time.
The PCAP reader is reused read-only from `component2_forensic_review/scripts/pcapio.py`.

Raw evidence in `data/<collection>/runs/<run_id>/` is write-protected and hashed in `run_manifest.json`:

* `capture.pcap`;
* `plan.json` (the seeded configuration, including the units, functions and addresses selected);
* `ledger_*.jsonl`;
* `clock.jsonl` (v3);
* logs, software versions, git commit and testbed code hashes.

Derived outputs live under `derived/` and `analysis/`.

## 2. Lineage and verification (v3)

* 28 runs: 14 scenarios × sites A and B, executed in seeded random order. That is 8 normal + 6 recon runs per site.
* **136,556 requests** were parsed:

  | Phase | Requests |
  |---|---:|
  | Background HMI | 125,406 |
  | Normal workloads | 10,474 |
  | Legitimate lead-ins | 243 |
  | Reconnaissance | **433** |

* **Lineage:** every ADU keeps its run, PCAP, frame number, record offset, ADU offset in the TCP payload, raw and
  corrected nanosecond timestamps, endpoints, TID, unit, wire FC and exact hex.
* **Parser vs tshark:** every ADU in every run was compared, with 0 mismatches.
* **Ledger ↔ wire 1:1** in all 28 runs; wire fields equal the ledger intent.
* **Responses:** every request has exactly one paired response, and the bytes the client received equal the
  captured response.
* **No transport anomalies:** 0 exception responses, 0 retransmissions or gaps, 0 kernel drops, 0 reconnects, and
  no truncated recon or one-pass plans.
* **VM clock:**
  * The Docker Desktop VM wall clock runs ~50–60 ppm fast and is stepped about every 30 s. v3 observed 77 steps in
    28 runs (2–5 per run), from −3.1 to +2.0 ms with a median of −1.9 ms.
  * Raw timestamps are untouched. The derived `ts_corr_ns` removes the measured steps.
  * 144 requests (≤ 20 per run, < 1 % in every run) fall within one 10 ms sample of a step and are flagged
    `clock_ambiguous`.
  * On the corrected timeline, the capture always follows the client send (minimum 9.2 µs).
  * History timing features use `ts_corr_ns`.
  * The same steps explain the v2 r09 rejection. A retrospective scan of the v1/v2 captures shows that frame order
    was never disturbed by more than 1 µs, but intervals spanning a step in v1/v2 are ~1–2 ms short.
* **Parser fix found by v3:** one config-backup run had a response timestamped 1.34 ms *before* its request
  because a backward clock step fell between them. Response pairing now uses capture (frame) order instead of
  wall-clock order. Reprocessing v1/v2 with this fix leaves their acceptance unchanged.
* **Contexts:** 136,556 causal contexts with 0 integrity violations. 342 recon targets have the full 20-request
  context and 91 have partial context.

## 3. Matched current messages (v3)

All recon values of FC, unit, address (per FC/unit), quantity, MBAP length and frame length occur in normal traffic,
and 100 % of recon joint shapes occur in other runs' normal traffic (G1, G2).

Run-grouped 5-fold CV, holding out whole runs:

| Current-message model | pooled AUC | bal. acc. | within-fold AUC mean [min, max] |
|---|---:|---:|---|
| joint-shape lookup | 0.466 | 0.513 | 0.473 [0.378, 0.542] |
| logistic regression | 0.486 | 0.547 | 0.520 [0.359, 0.632] |
| random forest | 0.546 | 0.545 | 0.526 [0.419, 0.823] |
| decision tree depth 6 | **0.675** | 0.703 | **0.704 [0.476, 0.850]** |
| TID lookup | 0.649 | **0.724** | 0.635 [0.156, 0.806] |
| *diagnostic:* decision tree without TID | 0.470 | 0.519 | 0.483 [0.383, 0.555] |
| *diagnostic:* shape unseen in training normal | 0.500 | 0.500 | 0.500 |
| *diagnostic:* client-IP lookup | 0.526 | 0.575 | 0.643 [0.500, 0.737] |
| *diagnostic:* response frame length | 0.492 | 0.547 | 0.552 [0.479, 0.644] |

**The transaction ID is the only current-message field with signal.**

* **Mechanism.** TIDs are per-connection counters. Each run's actor starts from one random value, so the 12 recon
  runs form 12 narrow TID blocks. By chance none is below 8,192, whereas 16 % of normal TIDs are. A tree memorises
  those blocks.
* **Why it is an artifact.** This is a sampling artifact of 12 random starting points plus counter semantics, not
  reconnaissance behaviour. It would shrink as runs increase. Even so, it brings G3 close to its limits, and per-fold
  values reach 0.85.
* **Required action.** The project requirement is that TID alone must not identify attacks. Before the full
  collection, pre-register how the raw TID value is treated (e.g. as an identity field like client port, used for
  pairing only) and re-run G3 both ways. Dropping it after seeing results would be the post-hoc feature deletion the
  protocol forbids. The pilot reports it as found.

## 4. History signal (informative only, not a model result)

Contexts are built only after acceptance and the label join: per (run, client IP, target IP) stream, ordered by
corrected capture time, the last ≤ 20 requests ending at the target.

| View (v3, run-grouped CV) | pooled AUC | within-fold AUC mean [min, max] |
|---|---:|---|
| recon vs **all** actor activity (background removed), history RF | 0.927 | 0.728 [0.346, 0.983] |
| same, without timing | 0.898 | 0.783 [0.633, 0.890] |
| same, timing only | 0.899 | 0.709 [0.287, 0.944] |
| same, current-message RF | 0.383 | 0.446 [0.274, 0.695] |
| recon vs **revisiting** normal (N1–N4), history RF | 0.987 | 0.987 [0.967, 1.000] |
| recon vs **one-pass** normal (N5–N8), history RF | 0.093 | 0.114 [0.012, 0.261] |
| recon vs one-pass, without timing | 0.141 | 0.250 |
| recon vs one-pass, timing only | 0.187 | 0.276 |
| recon vs one-pass, best *untrained* single statistic | 0.557 (interval CV) | – |

**How to read the below-chance values.**

* **They are not a fold-prior artifact.** They stay low within folds.
* **The mechanism.** Every recon pattern has a legitimate mirror:

  | Recon | Legitimate mirror |
  |---|---|
  | R1 | N6 config backup |
  | R3 | N5 HMI cold start / N7 historian backfill |
  | R5/R6 | N8 commissioning checkout |

  Run-grouped folds place each mirror in the opposite class during training. The model therefore learns that a
  sequential full-table read is *normal* from N6 and inverts on the held-out R1 runs.

* **The interpretation.** Combined with untrained single statistics at 0.52–0.56, this means the two groups are
  interchangeable on these observable history statistics. The pairwise table (`hard_negative_pairwise_history_auc.csv`)
  shows the same pattern for every recon/one-pass pair. The slow R4 scan against N7 backfill (0.45) is closest to
  chance from either direction.

**Leave-one-site-out** (actor-only):

| Model | Train B → test A | Train A → test B |
|---|---:|---:|
| history RF | 0.966 | 0.964 |
| history RF without timing | 0.971 | 0.876 |
| current-message RF | 0.359 | 0.300 |

This is consistent with the history statistics being site-independent at this scale. Both sites share units,
function weights and map size, so this is a weak generalisation test.

## 5. Interpretation for RP2

* The proposal's hypothesis can only be tested meaningfully on this kind of data. In CIC the current message already
  identifies recon (quantities 125/2,000/65,535 versus quantity 1), and in v1/v2 the temporal task was artificially
  easy.
* What history can detect here is **coverage without legitimate revisiting, at rates and in orders that legitimate
  polling/maintenance does not produce**. It cannot distinguish an attacker from an engineer doing the same one-pass
  read. Any final claim must be stratified by normal workload type, and false positives on one-pass legitimate
  workloads must be reported separately. A single pooled score would be dominated by the easy background stream
  (84–92 % of requests).
* Context the proposal does not yet model may help in the full study, but each source must be pre-registered:
  * longer-horizon memory, beyond 20 requests;
  * whether the host normally performs such tasks (a per-host baseline);
  * correlation with maintenance windows.

## 6. Limitations

* Software-only testbed (pymodbus in one Docker VM, shared stepped clock). Two sites share most structure. The
  actor mimics the site's read granularity, and out-of-envelope recon is excluded by design.
* Small and imbalanced: 28 runs and 433 recon requests among 136,556. Per-fold metrics vary widely. This supplies a
  variance estimate, not a sample-size justification.
* One persistent TCP connection per client by construction, so connection-level behaviour is not studied.
* v2's R4 run manifests record `timing_profile` values that R4's slow pacing (`interval_range_s`) overrides. The
  recorded interval range is the correct description.

## 7. Relationship to CIC and to the proposal

* **CIC remains a secondary case study.** No CIC capture, label, log ID or audit field was merged, and no CIC capture
  counts as a run. The bulk-quantity CIC behaviour is out of envelope here.
* **Proposal conflicts, flagged rather than forced:**
  * ICSSIM and port mirroring (p13) are replaced by pymodbus with in-namespace passive capture.
  * The 175,800 CIC-derived windows called an "initial testbed run" (p13) are not reused.
  * MSU (p13) is not used.
  * The naive random-split contrast (p15) is not performed.

## 8. Not done

* Nothing has been committed.
* No final dataset, no LSTM training and no run-count decision.
* Smoke-test collections (`data/smoke_test_*`) were tooling checks and are excluded from all analysis.

## Recommended next step

Freeze the final-collection protocol before collecting:

1. **Target and evaluation strata:** recon vs revisiting normal and recon vs one-pass normal reported separately.
2. **Raw TID treatment:** decided in advance, with G3 run both ways.
3. **Context sources:** history length and per-host baseline features.
4. **Sites:** at least one more site that differs in map size and units.
5. **Run count:** derived from the v3 run-level variance of the within-fold metrics. Then collect.
