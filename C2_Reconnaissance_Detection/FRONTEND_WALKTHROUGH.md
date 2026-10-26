# Explaining the Component 2 dashboard

Open `http://127.0.0.1:8020/#guide` for the same presentation notes inside the application.

## Start with the research question

“A reconnaissance scan can use perfectly valid Modbus requests. We tested whether remembering recent requests helps distinguish a scan from normal work. It helps against repeated polling, but a legitimate one-pass backup can look like a scan. A simple history-statistics model performed about as well as the LSTM.”

This dashboard presents a controlled software testbed experiment and recorded held-out runs. It is not connected to a real plant. Replaying a run is not a live capture.

## A useful demonstration order

1. **Overview.** Explain the comparison: current message versus history. Show the 383 accepted runs and Site C results. Site C is an unseen controlled configuration, not another physical factory.
2. **Metrics.** Start with A+B, revisiting normal work, full histories, B3. Explain the confusion matrix using the actual numbers below. Then change the normal workload to one-pass work. Good detection against polling does not imply good behaviour on legitimate backups.
3. **Traffic replay.** Choose a sequential scan. Press Play or step request by request. Point to what the client asked, what history was available, what each model predicted, and the ledger's ground truth. The colours are ledger labels; rings are alerts.
4. **Compare.** Put the scan beside a configuration backup and normal polling. A backup can legitimately visit new request keys once, explaining its false alarms.
5. **Data checks.** Explain ledger matching, parser cross-checks, isolated acquisition runs, corrected timing and separate train/validation/test runs. A gate pass is a specific declared check, not a proof against every conceivable shortcut.
6. **CIC audit.** Explain why old high-scoring CIC models are historical prototype results. Wrong labels and invalid sequences prevented them from testing the intended temporal question.
7. **Score a file.** Start with a supplied CSV or Parquet sample. This takes parsed request rows, not a raw PCAP. It runs frozen inference; it does not retrain. Without known labels, alert share is not accuracy.

## Where the metrics are

**Metrics** is a dedicated navigation item. It shows precision, recall, F1, accuracy, false-positive rate, ROC-AUC, a confusion matrix and the false alarms for each legitimate workload.

The controls select:

- **Test set:** A+B in-site or held-out Site C.
- **Normal workload:** repeat/revisiting work, legitimate one-pass work, or all normal traffic including background and lead-ins.
- **History length:** full 20-request histories or every request including short histories.
- **Model:** A, B1, B2, B3 or L.

The models and thresholds remain fixed while these selectors change which saved requests are summarised. The CSV download contains the selected model-comparison table with exact counts and rates.

For example, **B3 / A+B / full histories / revisiting normal** contains:

| Outcome | Meaning | Requests |
| --- | --- | ---: |
| TP | Recon and an alert was raised | 2,293 |
| FN | Recon but no alert | 0 |
| FP | Normal but an alert was raised | 928 |
| TN | Normal and correctly quiet | 36,983 |

Explain it as: “It caught all 2,293 recon requests in this selected comparison, but it also interrupted 928 of 37,911 normal requests.”

That is **100% request recall**, **71.2% precision**, **F1 0.832**, **97.69% accuracy**, and **2.45% false-positive rate**. These measures answer different questions. In particular, 100% recall is not 100% accuracy or precision.

The existing paper tables round rates before formatting; the dashboard derives these values directly from saved prediction counts. Minor final-digit differences can reflect that rounding. The overview also uses **scenario-balanced recall**, giving scan styles equal weight. The confusion matrix uses **request-pooled recall**, giving requests equal weight. Both are labelled explicitly.

## The words Harry needs

| Term | Simple meaning |
| --- | --- |
| Precision | Of the alerts, how many were really recon? |
| Recall | Of the real recon requests, how many were caught? |
| F1 | Balance between precision and recall; it excludes true negatives. |
| False-positive rate | Of legitimate requests, how many caused an unnecessary alert? |
| Accuracy | Share of all selected requests given the correct decision. Lots of normal background traffic can make it look impressive. |
| ROC-AUC | How well scores rank recon above normal across thresholds; 0.5 is chance ranking and 1 is perfect. |
| 95% interval | The saved uncertainty interval from resampling experimental runs; it is not a guarantee for a new factory. |
| Score | The model's numeric output, not a verified probability of malicious intent. |
| Threshold | The model-specific cutoff chosen on validation data. The 5% validation target is not a universal test/deployment guarantee. |
| Ground truth | The separate experiment ledger's known label, shown for checking, never given to the detector. |
| Unit / function / address / quantity | Which logical device, what operation, where it starts, and how many items it requests. |
| Request key | Unit + function + address + quantity. A new key is not a new IP address. |
| First seen | A key not previously seen in the current stream segment. This uses causal stream memory, which can reach beyond the displayed 20 rows. |

## Which inspector is which?

- **A:** sees just the current request. This is the baseline.
- **B1:** gives a Random Forest the flattened 20×19 input. It retains positions and history-derived information.
- **B2:** summarises recent request contents without preserving their step order. Its poorer result does not establish order as the only difference.
- **B3:** a Random Forest on prespecified novelty, repetition, address-transition and timing statistics. It is the default alert model.
- **L:** the evaluated LSTM. Its existence does not make it the selected winner.

The old explanation's 20×7 to 20×19 story needs care: the legacy workbook had seven fields, but the old engineered CIC LSTM also had 19. The current 19 columns have different meanings. The current LSTM is a single recurrent layer, not the old two-layer attention/gating architecture.

## Finish honestly

“History helped against revisiting normal work in this controlled experiment, including Site C. It did not establish LSTM superiority. Legitimate one-pass reads and lead-in activity remain false-alarm problems, so traffic-only alerts cannot reliably reveal intent.”

## Metric provenance and reproduction

`demo/export_metrics.py` joins saved held-out score tables to their metadata using unique ADU IDs, then aggregates the existing decisions at the frozen thresholds. It never imports the training pipeline, fits a model, changes thresholds or re-runs one-shot test scoring. Every displayed stratum rate, request recall and AUC is reconciled with the existing reports. The small result is `demo/metrics_report.json`, served by `/api/metrics`; source paths and hashes are recorded there.

`demo/test_metrics_export.py` checks exact-threshold behaviour, undefined measures and request identity alignment. The frozen model bundle remains unchanged.
