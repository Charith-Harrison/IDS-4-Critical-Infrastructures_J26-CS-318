# C2 / RP2 — Frozen Experimental Protocol

This protocol governs all model training, threshold selection, evaluation, and ablation experiments in `C2_Reconnaissance_Detection` (`artifacts/folds.json`, `artifacts/feature_schema.json`).

---

## 1. Evaluation Split Hierarchy

Because `session_id` in the raw dataset spans multiple `.pcap` captures across 57.66 days and five `2023-02-01` `.pcap` files are simultaneous virtual-interface mirrors of the same traffic, the true independent experimental unit is the **independent capture episode (`capture_group`, `G01`..`G10`)**:

1. **Primary Evaluation Scheme — 10-Fold Leave-One-Capture-Group-Out (`locgo_10fold`)**:
   - Iterates over all 10 capture episodes `G01`..`G10`.
   - In fold $k \in \{0..9\}$, capture group $G_{k+1}$ is held out as the unseen test group (`test_groups`).
   - From the remaining 9 capture groups, 1 positive group and 1 normal-only group are held out deterministically as the inner group-independent validation split (`val_groups`), and the remaining 7 groups form `fit_groups`.
   - **Single-Class Normal Folds (`G01`, `G02`, `G09`, `G10`)**: Because these 4 capture episodes contain `0` positive windows (`100%` normal traffic), `ROC-AUC`, `PR-AUC`, `Precision`, `Recall`, and `F1` are mathematically undefined on those folds alone and are recorded as `None`/`null` in JSON (`N/A` in tables). On those folds, **False Positive Rate (`FPR`)** and **Specificity** are evaluated, and all 10 folds are combined in **Pooled Out-of-Fold (`pooled_oof`)** evaluation across all `119,237` windows (`1,878` positives, `117,359` negatives).
2. **Secondary Evaluation Scheme — 5-Fold Paired Capture-Group Cross-Validation (`sgkf_5fold`)**:
   - Pairs the 6 positive capture groups and 4 normal capture groups into 5 disjoint group pairs:
     - `SGKF5_00`: `['G01_0122_normal4', 'G04_0315_sub1']` (`13,977` test windows, `415` pos)
     - `SGKF5_01`: `['G02_0123_normal13', 'G06_0316_sub4']` (`13,960` test windows, `454` pos)
     - `SGKF5_02`: `['G07_0319_sub10', 'G09_0323_veth3e0']` (`13,957` test windows, `470` pos)
     - `SGKF5_03`: `['G08_0320_sub14', 'G10_0323_veth3e1']` (`13,961` test windows, `443` pos)
     - `SGKF5_04`: `['G03_0201_veth', 'G05_0315_sub2']` (`63,382` test windows, `96` pos)
   - Every test fold contains both classes (`test_is_single_class == False`) and has `0` shared packets with `fit_groups` or `val_groups`.
3. **Diagnostic Scheme A — 5-Fold Host-Pair Split (`loso_session_5fold`)**:
   - `StratifiedGroupKFold(n_splits=5)` grouped strictly by `session_id` (`s0001..s0013`), quantifying the effect of holding out `s0004` (`94.20%` of all positive windows).
4. **Diagnostic Scheme B — 5-Fold Random Split (`random_5fold_rebuilt`)**:
   - `StratifiedKFold(n_splits=5, shuffle=True, random_state=42)` across overlapping windows, included solely to quantify overlap leakage inflation.

---

## 2. Feature Sets (`artifacts/feature_schema.json`)

- **Model A (`PACKET_FEATURES`, 5 dims)**:
  - `['func_code', 'modbus_len', 'register_start', 'log_quantity', 'packet_size']`
  - Shortcut-Removed (`PACKET_FEATURES_NO_SHORTCUT`, 3 dims): `['func_code', 'register_start', 'log_quantity']`
- **Model B (`WINDOW_FEATURES`, 29 dims)**:
  - Timing subset (`WINDOW_TIMING`, 8 dims): `['duration_s', 'req_rate', 'dt_mean', 'dt_std', 'dt_min', 'dt_max', 'dt_cv', 'polling_drift']`
  - Non-timing protocol summary subset (`WINDOW_FEATURES_NO_TIMING`, 21 dims): `['n_unique_fc', 'n_unique_reg', 'reg_range', 'seq_step_ratio', 'mean_abs_d_reg', 'back_step_ratio', 'fc_change_ratio', 'log_qty_mean', 'log_qty_max', 'write_ratio', 'modbus_len_mean', 'modbus_len_min', 'modbus_len_max', 'packet_size_mean', 'packet_size_max', 'fc_frac_1..6']`
  - Shortcut-Removed (`WINDOW_FEATURES_NO_SHORTCUT`, 24 dims; `WINDOW_FEATURES_NO_SHORTCUT_NO_TIMING`, 16 dims)
- **Model C (`SEQ_FEATURES`, 19 dims per timestep $\times 20$ timesteps)**:
  - Function code one-hot (`7` dims): `fc_1..6`, `fc_other`
  - Payload fields (`4` dims): `modbus_len`, `register_start`, `log_quantity`, `packet_size`
  - Within-window transitions (`6` dims): `d_reg`, `log_abs_d_reg`, `seq_step`, `back_step`, `fc_change`, `is_write`
  - Explicit timing (`SEQ_TIMING`, `2` dims): `log_dt`, `d_log_dt`
- **Model D (`SEQ_FEATURES_NO_TIMING`, 17 dims per timestep $\times 20$ timesteps)**:
  - Identical to `SEQ_FEATURES` with `['log_dt', 'd_log_dt']` removed.

---

## 3. Threshold Selection & Calibration Discipline

For every model and every fold:
1. Metrics are reported at **both** the fixed default threshold (`0.5`) and the **inner-validation operational threshold (`at_val_threshold`)**.
2. `select_validation_threshold(y_val, scores_val, max_fpr=0.05)` evaluates candidate thresholds on `val_groups` only, selecting the threshold that maximizes validation $\text{F1}$ subject to validation $\text{FPR} \le 0.05$ (with unconstrained validation $\text{F1}$ fallback if no threshold achieves $\text{TP} > 0$ under $\text{FPR} \le 0.05$).
3. Model outputs are treated as **uncalibrated detection scores** (`calibrated: False`), and calibration quality is explicitly measured via **Brier Score** and **10-bin Expected Calibration Error (`ece_10bin`)**.
