# Model card — progress stage

**Models.** `models/baseline/baseline_random_forest.joblib` (isolated-event, 7 features) and `models/contextual/contextual_rf.joblib` (context-aware, 46 features). scikit-learn RandomForestClassifier, `random_state=42`. Version `rp3-progress70-rf-0.1`, feature schema `fs-1.0`.

**Classes.** 0 Normal, 1 Command Injection. The current progress model supports Normal and Command Injection only. Verified response-injection training examples are unavailable in the supplied datasets, so final three-class implementation remains pending.

**Training data.** The 80% capture-grouped development partition (9 captures; 94,532 Normal and 72,873 Command Injection labelled request events). The 20% partition was not used.

**Selection.** Three Random Forest configurations per model, scored by 5-fold StratifiedGroupKFold grouped by capture. In every fold the access profile, value ranges, clip thresholds and fill values are fitted on fold-training rows only. After selection, statistics and models were refitted on the full 80%.

**Selected hyperparameters.** Baseline: 100 trees, no depth limit, min leaf 1, sqrt features, balanced_subsample. Contextual: 100 trees, depth 12, min leaf 5, sqrt features, balanced.

**Preliminary out-of-fold results (not final).** Baseline macro F1 0.99996; contextual macro F1 1.0000. Folds with only Normal records score 0.5 by construction. These results come from a label rule that the inputs can reproduce (see limitations) and do not demonstrate a benefit from context.

**Latency (sandbox CPU).** Contextual: single-event median 8.3 ms, p95 11.8 ms; batch 0.002 ms/event.

**Intended use.** Academic demonstration on authorized research data. Not validated for operational use.

**Outputs.** Class, probabilities, confidence (highest class probability) and "supporting contextual observations" (calculated indicators, not SHAP or causal explanations). The predicted class is the highest-probability class; no tuned threshold is stored.
