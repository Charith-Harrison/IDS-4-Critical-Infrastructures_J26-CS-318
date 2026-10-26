# Component 2 modelling plan (frozen)

**Frozen 26 October 2026, after the collection gates passed and before any model was fit on `final_v1`.**
Machine-readable: `configs/models_v1.json`. Data, strata, splits and the TID rule come from
`FINAL_COLLECTION_PROTOCOL.md` and are not repeated here. Any change after fitting starts is a dated amendment.

## 1. Test-set sealing

* The loader (`c2tb/model_data.py`) reads each run's partition from its hash-checked frozen plan.
* It refuses `test_in_site` and `test_out_of_site` runs unless it is called with `--open-test <population>`. That
  flag is used once per population, only after §6 is complete, under explicit instruction.
* Nothing in §2–§5 touches the test runs.

## 2. Inputs

* **Target:** each request, labelled by the ledger (`gt_label_recon`).
* **Context:** the last 20 requests of its (run, client, target) stream, ending at the target. Ordering uses
  corrected time; padding and masking follow protocol §5.
* **Per-step features (19), computed causally:**

  | Features | Count |
  |---|---:|
  | FC one-hot (1–4) | 4 |
  | Unit one-hot (1, 2, 3, 5, 7) | 5 |
  | Address | 1 |
  | log₂ quantity | 1 |
  | MBAP length | 1 |
  | Frame length | 1 |
  | Same table as previous request | 1 |
  | Address step in units of quantity (same table) | 1 |
  | Contiguous-ascending flag | 1 |
  | First seen in stream | 1 |
  | log₁₀ inter-request interval (corrected; clipped to [−4, 2]) | 1 |
  | Real/padding mask | 1 |

  Site C's units 5 and 7 never occur in training, so their columns are always zero there. That is the declared
  "unseen unit" behaviour.
* **Training population:**
  * every request of the actor view (normal tasks, lead-ins and recon) in train runs;
  * plus a seeded 10 % sample of background-HMI targets per train run. Their contexts are always built from the full
    stream.
* **Evaluation on validation:** every request, so all five strata can be reported.
* **Class imbalance:** handled by balanced class weights only. No oversampling, SMOTE or synthetic rows.

## 3. Representations and models

All five see the same targets and the same 20-request windows.

| ID | Representation | Model |
|---|---|---|
| A | Current request: FC, unit, address, quantity, MBAP length, frame length (no TID) | Random forest |
| B1 | Proposal p14: the 20 × 19 per-step matrix flattened | Random forest |
| B2 | Order-invariant: window means of FC/unit one-hots; mean/SD/min/max of address and log₂ quantity; unique-target fraction; real-step count | Random forest |
| B3 | Pilot history statistics (`h_*` in `diagnostics.build_contexts`, pre-specified in `PILOT_PROTOCOL.md`) | Random forest |
| L | The 20 × 19 sequence | LSTM: 1 layer, masked; last real step feeds a linear head; dropout 0.2 |

## 4. Fitting and selection (train partition only)

* **Folds:** run-grouped 5-fold CV inside train, dealt within site × scenario (seed 20261026).
* **Selection metric:** within-fold mean ROC-AUC on recon vs revisiting-normal task requests with full 20-request
  context (the primary stratum pair).
* **Random-forest grid** (A, B1, B2, B3): `min_samples_leaf` ∈ {1, 5, 20} × `max_features` ∈ {"sqrt", 0.5};
  300 trees; seed 0.
* **LSTM grid:** hidden size ∈ {32, 64} × learning rate ∈ {1e-3, 3e-3}.
  * Adam optimiser, batch 512, at most 15 epochs.
  * Early stopping (patience 3) on an inner run-grouped 20 % of the fold's training runs. The validation partition
    is never used for early stopping.
  * Seed 0.
* **Final fit:** the selected configuration is refitted on all train runs. For the LSTM, the number of epochs is the
  median best epoch across folds.
* **Scaling:** numeric scaling for the LSTM is fitted on train only. Random forests need none.

## 5. Operating point (validation partition only)

For each model, the threshold is the score quantile that gives **5 % FPR on validation revisiting-normal task
requests**. It is frozen before any test run is opened.

## 6. Reported before opening tests (validation)

* Per model and stratum: recall on recon (R), and FPR on revisiting normal (NR), one-pass normal (NO), lead-ins (NL)
  and background (NB) at the frozen threshold.
* ROC-AUC for recon vs NR and for recon vs NO.
* Both full-20-context targets and all targets.
* Run-cluster bootstrap 95 % CIs, 2,000 resamples over runs.

## 7. Test evaluation (later, one shot per population)

* **In-site test (A+B):** opened first; Site C opened last.
* **Primary H1 contrast:** the scenario-balanced recall gain of each history model (B1, B2, B3, L) over A, on R vs
  NR, with run-cluster bootstrap CIs.
* **H2:** NO FPR and R-vs-NO AUC.
* **H3:** the same as H1 on Site C.
* **Not re-tuned:** no threshold, model or feature changes after a test population is opened.

## Clarification 1 (26 October 2026, before any fit)

Train has exactly 4 runs per site × scenario, so dealing folds as `i % 5` *within* each group would fill only folds
0–3. Runs are still shuffled within each site × scenario group (seed 20261026), but fold numbers continue one
round-robin counter across groups so all 5 folds are used and every fold mixes sites and scenarios. Found by the
pre-fit smoke test; no model had been fit.
