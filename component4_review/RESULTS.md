# Results and reproducibility

**Every score in this report uses the historical, scientifically conditional split. No score is an independent final result.** The saved manifest assigns part of inferred `replay_capture_2` to training and part to test, with 53 gap-excluded observations. No validation partition exists. We did not tune hyperparameters or threshold, select a detector from these scores, or save a final refitted model.

## Exact historical experiment

- Inputs: SHA256 `70d08fc730a8572d16a08d860be61536ae7565af048c7c7e283004e54fe55b01` (150,000 normal rows) and `714587f4511b12400a809f3ba6bd533e10167ff25f353414b4151f5d362918b1` (9,494 mixed replay derivative rows).
- Pairing: one-second search bound; normal filename scope and ten heuristic replay segments. 80,753 request observations, 78,620 pairs, 2,133 missing responses, 121 unpaired response rows, 1,047 label conflicts.
- Training: 54,777 requests (53,342 normal; 1,435 replay). Test: 25,923 (25,330 normal; 593 replay). Gap: 53 (7 normal; 46 replay). Request-label target, not packet-positive count.
- Features: the exact 21-field `src.feature_engineering.MODEL_FEATURE_COLUMNS`; see `FEATURE_AUDIT.md` and `feature_dictionary.json` for the saved definitions. Reconstructed request data and saved feature matrices reproduce to float serialization precision (largest per-column difference below 5e-13); discrete features reproduce exactly.
- Model: XGBoost 3.4.1; 100 estimators, depth 4, learning rate .1, subsample .8, column sample .8, seed 42, logloss, threshold .5; training-only median imputer; `scale_pos_weight=53342/1435=37.17212543554007`. No SMOTE/scaling/feature selection. The stored training-loss trace is training loss only, not validation evidence. Saved bundle timestamp: 2026-10-23T12:55:11.646630.
- Inference from the saved model reproduces 100% of stored binary predictions. Calling the original `train_xgboost_model` helper with all output paths unset reproduces the original confusion matrix and AUC/AP as well, in about one second of fit time. Nothing historical is overwritten.
- Explicit single-thread `hist` diagnostic refits yield four extra false positives relative to the original default-thread helper. This illustrates why runtime/thread settings must be recorded; it is not a failed reproduction of saved inference or the original helper. No environment-independent byte-identical model claim is made.

## Metrics (test support: 25,330 normal; 593 replay)

ROC-AUC and average precision use unrounded probabilities. `PR_AUC_AP` means average precision, not trapezoidal PR area. The saved prediction CSV rounds probabilities to four decimals and has slightly different AUC/AP (0.999504 / 0.983435), while unrounded saved-model inference gives the values below.

| Model/diagnostic | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Balanced accuracy | ROC-AUC | PR_AUC_AP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Original saved model inference | 573 | 42 | 25288 | 20 | 0.931707 | 0.966273 | 0.948675 | 0.001658 | 0.982308 | 0.999501 | 0.983806 |
| Original stored protocol rule | 324 | 274 | 25056 | 269 | 0.541806 | 0.546374 | 0.544081 | 0.010817 | 0.767779 | None | None |
| Original training helper refit | 573 | 42 | 25288 | 20 | 0.931707 | 0.966273 | 0.948675 | 0.001658 | 0.982308 | 0.999501 | 0.983806 |
| legacy_21_feature_refit | 573 | 46 | 25284 | 20 | 0.925687 | 0.966273 | 0.945545 | 0.001816 | 0.982229 | 0.999490 | 0.981583 |
| legacy_response_latency_only | 570 | 846 | 24484 | 23 | 0.402542 | 0.961214 | 0.567446 | 0.033399 | 0.963908 | 0.973563 | 0.725437 |
| legacy_outstanding_only | 443 | 318 | 25012 | 150 | 0.582129 | 0.747049 | 0.654357 | 0.012554 | 0.867247 | 0.866309 | 0.374135 |
| A_rule | 0 | 0 | 25330 | 593 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.500000 | None | None |
| B_current_request | 562 | 3689 | 21641 | 31 | 0.132204 | 0.947723 | 0.232040 | 0.145638 | 0.901043 | 0.946765 | 0.415058 |
| C_current_plus_causal_context | 575 | 68 | 25262 | 18 | 0.894246 | 0.969646 | 0.930421 | 0.002685 | 0.983481 | 0.999228 | 0.952848 |
| B_without_absolute_tid | 555 | 4150 | 21180 | 38 | 0.117960 | 0.935919 | 0.209513 | 0.163837 | 0.886041 | 0.889433 | 0.113610 |
| C_without_absolute_tid | 586 | 115 | 25215 | 7 | 0.835949 | 0.988196 | 0.905719 | 0.004540 | 0.991828 | 0.999383 | 0.964315 |
| timing_only | 581 | 1134 | 24196 | 12 | 0.338776 | 0.979764 | 0.503466 | 0.044769 | 0.967497 | 0.992837 | 0.842838 |
| current_plus_timing | 575 | 69 | 25261 | 18 | 0.892857 | 0.969646 | 0.929669 | 0.002724 | 0.983461 | 0.999183 | 0.958539 |
| C_without_timing | 574 | 1368 | 23962 | 19 | 0.295572 | 0.967960 | 0.452860 | 0.054007 | 0.956976 | 0.980354 | 0.650489 |
| C_without_tid_context | 575 | 73 | 25257 | 18 | 0.887346 | 0.969646 | 0.926672 | 0.002882 | 0.983382 | 0.999102 | 0.953443 |

## What the diagnostic comparison does and does not establish

New A/B/C use exactly the same stored historical train/test **request targets**, cold-start histories per partition/segment, fixed classifier settings and threshold, and training-only class weight. B includes current-message fields, including raw TID, so C cannot claim advantage merely by seeing a field denied to B. These are diagnostic refits after the data audit, not the prohibited final model training.

C improves on B inside this split (F1 0.930421 vs 0.232040), but **current fields plus timing alone already reach 0.929669**. Removing TID-context features leaves F1 0.926672, while removing timing reduces F1 to 0.452860. The gain is therefore largely explained by timing/polling differences within a shared scenario. The simple bounded recurrence rule finds zero replay requests under the configured history. Absolute TID also contributes substantially. These results motivate controlled investigation; they do not establish unique replay sequence/payload consistency, unseen-session generalization, or XGBoost superiority.

The chronological embargo is useful for reducing immediate neighbor overlap. It cannot turn one replay recording/scenario into independent attack campaigns. Do not promote these diagnostic results to the final experiment. C remains conditional even though its features are causal and its within-split score is high.

## Importance and shortcuts

Saved gain importance: response latency 0.60043, flawed outstanding count 0.17889, timeout flag 0.08213 (together 86.145%); signed TID diff 0.05154. Gain importance alone is not causal evidence. One fixed-seed per-column permutation on saved test features gives the largest F1 drops for outstanding count (0.23034), register (0.12872), response latency (0.05607), and matched status (0.03261). Correlated features can mask a feature's effect; permutation is descriptive, not an independence test.

New causal C gain importance is dominated by endpoint request IAT (0.40264), time since observed command (0.21722) and absolute TID (0.17085). Actual session-local TID history is almost entirely unavailable. Precise parameters/importances/permutation deltas and all single-rule diagnostics are saved in `evidence/retrospective_v1/` and `evidence/audit_v1/audit.json`. No SHAP dependency was added.

## Detection latency

Historical stored 0.0004ms model inference and 0.0004ms preparation per row are batch-amortized timings; its 24.81ms operational number combines mean observed pair delay or a hardcoded one-second sentinel with batch computation. This is not a measured live end-to-end distribution, especially when unobserved replies may simply have been filtered out. It excludes capture, TCP reassembly, complete feature construction, buffering and scheduling.

New features become available when a complete request ADU has been observed, plus bounded prior history. There is no wait for its future reply, timeout, or later duplicate. A repeated-request feature can flag a later recurrence at that later arrival; it cannot retrospectively detect the first occurrence before the recurrence. Response latency is available only on an observed uniquely matched reply; absence-based consistency can be considered only after a timed search bound **and verified capture completeness**. Such outcomes are retained as audit metadata, not new request-arrival model inputs. Synthetic inference tests validate artifact wiring; no measured operational latency or detection-delay guarantee is claimed.
