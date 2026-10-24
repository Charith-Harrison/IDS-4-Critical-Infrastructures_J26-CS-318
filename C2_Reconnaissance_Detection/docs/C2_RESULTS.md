# C2 / RP2 — Experimental Results and Analysis (`C2_RESULTS.md`)

**Overall Project:** Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis (`J26-CS-318`)  
**Individual Component:** C2 / RP2 — Reconnaissance Attack Detection Using Temporal Behavior Analysis  
**Student:** Charith H. (`IT23269002`)  
**Primary Artifacts:** `artifacts/metrics.json`, `artifacts/baseline_metrics.json`, `artifacts/lstm_metrics.json`, `artifacts/ablation_results.json`, `artifacts/confusion.json`, `artifacts/curves.json`, `artifacts/latency.json`, `artifacts/example_sequences.json`, `artifacts/plots/fig1..fig6_*.png`

---

## 1. Executive Summary of Findings

1. **Primary Research Question (RQ1 — Temporal Sequence Modelling vs Packet & Non-Temporal Baselines):**
   - Under **10-fold Leave-One-Capture-Group-Out (LOCGO-10)** evaluation across `119,237` chronologically rebuilt `20`-packet windows (`1,878` positive, `117,359` negative across `10` independent capture groups), the primary temporal sequence model **`Model_C_LSTM_Full`** (`19` sequence features including explicit timing) achieved a pooled out-of-fold `F1@0.5 = 0.9458` and `F1@val_thr = 0.9401` (`Precision = 0.9437`, `Recall = 0.9366`, `FPR = 0.00089`, `ROC-AUC = 0.9796`, `PR-AUC = 0.9467`).
   - Relative to the linear packet-level baseline **`Model_A_Packet_LogReg`**, `Model_C_LSTM_Full` achieved comparable thresholded F1 (`0.9401` vs `0.9399`) and substantially higher pooled `PR-AUC` (`0.9467` vs `0.8353`, `+0.1114`).
   - However, **tree-based baselines (`Model_A_Packet_DT` and `Model_B_Window_RF`) outperformed `Model_C_LSTM_Full` on the full feature set**: `Model_A_Packet_DT` achieved pooled `F1@val_thr = 0.9717` (`PR-AUC = 0.9600`, `FP = 12`) and `Model_B_Window_RF` achieved pooled `F1@0.5 = 0.9738` and `F1@val_thr = 0.9706` (`PR-AUC = 0.9644`, `ROC-AUC = 0.9859`, `FP = 13`).
   - **Root Cause (Protocol Shortcut Dominance):** Label and feature auditing (`artifacts/label_audit.json`, `artifacts/leakage_audit.json`) revealed that `94.99%` (`1,784 / 1,878`) of all positive rebuilt windows contain at least one packet with `modbus_len == 3` (`packet_size == 75`, `func_code == 5` slave response in `185.175.0.5_185.175.0.3_u1_s0004`), and `100.0%` of packets with `modbus_len == 3` in the dataset are labelled positive (`0` false positives across `588,498` negative packets). A static 1-line rule (`any(modbus_len == 3)`) achieves `TP = 1,784, FP = 0, FN = 94, Precision = 1.0000, Recall = 0.9499, F1 = 0.9743`. Axis-aligned decision trees (`Packet DT`, `Window RF`) isolate `modbus_len <= 4.5` with near-zero false positives, whereas smooth neural sequence encoders (`LSTM`) incur slightly more false positives (`105` vs `12–13`) when generalizing across capture groups with varying background polling rates.
   - **Behavioural Regime (Shortcut-Removed Ablation):** When `modbus_len` and `packet_size` are removed from all models so classification must rely strictly on register addressing, function codes, quantities, and inter-request timing, **windowed behavioural aggregation (`Model_B_Window_RF No-Shortcut`, 24 features)** achieves **SGKF-5 Pooled `F1@val_thr = 0.6624` (`PR-AUC = 0.6253`, `ROC-AUC = 0.9574`)** and **LOCGO-10 Pooled `F1@val_thr = 0.6210`**, outperforming both packet-level `Model_A_Packet_DT No-Shortcut` (`LOCGO F1@val_thr = 0.2131`, `SGKF-5 F1@val_thr = 0.2089`) and sequence-level `Model_C_LSTM_Full No-Shortcut` (`LOCGO F1@val_thr = 0.2171`, `SGKF-5 F1@val_thr = 0.1656`).

2. **Secondary Research Question (RQ2 — Contribution of Explicit Timing Information):**
   - Comparing **`Model_C_LSTM_Full`** (`19` features, including `log_dt` and `d_log_dt`) against **`Model_D_LSTM_NoTiming`** (`17` features, protocol/sequence order only):
     - Adding timing features slightly **increases pooled LOCGO-10 `PR-AUC`** (`0.9467` vs `0.9421`, `+0.0046`), **increases recall** (`0.9366` vs `0.9276`, `+17` true positive windows), and improves detection on the hardest capture group `G05_0315_sub2` (`F1@val_thr = 0.3462` with `TP = 18, FP = 0` vs `F1@val_thr = 0.1895` with `TP = 9, FP = 0`).
     - However, because inter-packet timing varies across capture environments, `Model_D_LSTM_NoTiming` achieves fewer false positives (`FP = 32` vs `105` at validation-selected thresholds; `FP = 17` vs `78` at `0.5`) and therefore a higher pooled thresholded `F1` (`F1@val_thr = 0.9540` vs `0.9401`; `SGKF-5 F1@val_thr = 0.9548` vs `0.9154`).
   - Conversely, when the `modbus_len == 3` protocol shortcut is removed (`NoShortcut` ablation), **explicit timing features are essential for non-shortcut detection**: removing timing features from `NoShortcut Model_B_Window_RF` causes LOCGO-10 pooled `F1@val_thr` to collapse from **`0.6210` (`PR-AUC = 0.4326`)** down to **`0.1379` (`PR-AUC = 0.0530`)**, and SGKF-5 pooled `F1@val_thr` to collapse from **`0.6624` (`PR-AUC = 0.6253`)** down to **`0.1379` (`PR-AUC = 0.0530`)**. Thus, explicit timing (`dt_mean`, `dt_std`, `dt_min`, `dt_max`, `dt_cv`, `burst_ratio`, `rate_pps`) carries critical predictive signal when static packet-length signatures are absent, but introduces cross-capture threshold sensitivity when combined with a dominant static protocol signature.

---

## 2. Primary Evaluation Results: 10-Fold Leave-One-Capture-Group-Out (LOCGO-10)

### 2.1 Pooled Out-of-Fold (OOF) Performance Across All `119,237` Windows (`1,878` Pos, `117,359` Neg)

All predictions in the table below are strictly out-of-fold across the `10` independent capture groups (`G01`..`G10`). Results are reported both at the fixed decision threshold `0.50` and at the inner-validation selected threshold (`max_val_f1_subject_to_fpr_le_0.05`).

| Model | Feature Family (Dims) | Eval Mode | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Specificity | ROC-AUC | PR-AUC | Brier | ECE (10-bin) |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Static Rule (`any(modbus_len == 3)`)** | Single field (`1`) | Deterministic | 1,784 | 0 | 94 | 117,359 | 1.0000 | 0.9499 | 0.9743 | 0.00000 | 1.0000 | N/A | N/A | N/A | N/A |
| **`Model_A_Packet_LogReg`** | Packet -> Window Max (`5`) | Pooled `@0.5` | 1,803 | 133 | 75 | 117,226 | 0.9313 | 0.9601 | 0.9455 | 0.00113 | 0.9989 | 0.9718 | 0.8353 | 0.0149 | 0.0642 |
| **`Model_A_Packet_LogReg`** | Packet -> Window Max (`5`) | Pooled `@val_thr` | 1,783 | 133 | 95 | 117,226 | 0.9306 | 0.9494 | 0.9399 | 0.00113 | 0.9989 | 0.9718 | 0.8353 | 0.0149 | 0.0642 |
| **`Model_A_Packet_DT`** | Packet -> Window Max (`5`) | Pooled `@0.5` | 1,798 | 117 | 80 | 117,242 | 0.9389 | 0.9574 | 0.9481 | 0.00100 | 0.9990 | 0.9776 | 0.9600 | 0.0079 | 0.0442 |
| **`Model_A_Packet_DT`** | Packet -> Window Max (`5`) | Pooled `@val_thr` | 1,786 | 12 | 92 | 117,347 | 0.9933 | 0.9510 | **0.9717** | 0.00010 | 0.9999 | 0.9776 | 0.9600 | 0.0079 | 0.0442 |
| **`Model_B_Window_RF`** | Window Aggregates (`29`) | Pooled `@0.5` | 1,786 | 4 | 92 | 117,355 | 0.9978 | 0.9510 | **0.9738** | 0.00003 | 1.0000 | **0.9859** | **0.9644** | **0.0015** | **0.0086** |
| **`Model_B_Window_RF`** | Window Aggregates (`29`) | Pooled `@val_thr` | 1,783 | 13 | 95 | 117,346 | 0.9928 | 0.9494 | 0.9706 | 0.00011 | 0.9999 | **0.9859** | **0.9644** | **0.0015** | **0.0086** |
| **`Model_B_Window_LogReg`** | Window Aggregates (`29`) | Pooled `@0.5` | 1,791 | 242 | 87 | 117,117 | 0.8810 | 0.9537 | 0.9159 | 0.00206 | 0.9979 | 0.9803 | 0.9428 | 0.0078 | 0.0329 |
| **`Model_B_Window_LogReg`** | Window Aggregates (`29`) | Pooled `@val_thr` | 1,769 | 73 | 109 | 117,286 | 0.9604 | 0.9420 | 0.9511 | 0.00062 | 0.9994 | 0.9803 | 0.9428 | 0.0078 | 0.0329 |
| **`Model_C_LSTM_Full` (Primary)** | Sequence + Timing (`20x19`) | Pooled `@0.5` | 1,755 | 78 | 123 | 117,281 | 0.9574 | 0.9345 | 0.9458 | 0.00066 | 0.9993 | 0.9796 | 0.9467 | 0.0022 | 0.0085 |
| **`Model_C_LSTM_Full` (Primary)** | Sequence + Timing (`20x19`) | Pooled `@val_thr` | 1,759 | 105 | 119 | 117,254 | 0.9437 | 0.9366 | 0.9401 | 0.00089 | 0.9991 | 0.9796 | 0.9467 | 0.0022 | 0.0085 |
| **`Model_D_LSTM_NoTiming` (RQ2)** | Sequence No-Timing (`20x17`) | Pooled `@0.5` | 1,744 | 17 | 134 | 117,342 | 0.9903 | 0.9286 | 0.9585 | 0.00014 | 0.9999 | 0.9791 | 0.9421 | 0.0023 | 0.0091 |
| **`Model_D_LSTM_NoTiming` (RQ2)** | Sequence No-Timing (`20x17`) | Pooled `@val_thr` | 1,742 | 32 | 136 | 117,327 | 0.9820 | 0.9276 | 0.9540 | 0.00027 | 0.9997 | 0.9791 | 0.9421 | 0.0023 | 0.0091 |

### 2.2 LOCGO-10 Per-Fold Breakdown (`@val_thr`)

Note on single-class normal test folds (`G01`, `G02`, `G09`, `G10`): Because `n_pos = 0`, positive-class metrics (`Precision`, `Recall`, `F1`, `ROC-AUC`, `PR-AUC`) are mathematically undefined and recorded as `null` in JSON (`N/A` below). False positives (`FP`), true negatives (`TN`), false positive rate (`FPR`), specificity, Brier score, and ECE are well-defined on all `10` folds.

| Fold ID | Test Capture Group | Windows (`Pos / Neg`) | `Model_A_DT` (`TP/FP/FN`, `F1`, `FPR`) | `Model_B_RF` (`TP/FP/FN`, `F1`, `FPR`) | `Model_C_LSTM` (`TP/FP/FN`, `F1`, `FPR`) | `Model_D_LSTM_NoTime` (`TP/FP/FN`, `F1`, `FPR`) |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- |
| `LOCGO_00` | `G01_0122_normal4` | `0 / 6,994` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` |
| `LOCGO_01` | `G02_0123_normal13` | `0 / 6,980` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` |
| `LOCGO_02` | `G03_0201_veth` | `10 / 56,393` | `1/0/9`, `0.1818`, `0.0000` | `0/0/10`, `0.0000`, `0.0000` | `0/0/10`, `0.0000`, `0.0000` | `0/0/10`, `0.0000`, `0.0000` |
| `LOCGO_03` | `G04_0315_sub1` | `415 / 6,568` | `415/0/0`, `1.0000`, `0.0000` | `414/1/1`, `0.9976`, `0.00015` | `411/67/4`, `0.9205`, `0.01020` | `405/0/10`, `0.9878`, `0.0000` |
| `LOCGO_04` | `G05_0315_sub2` | `86 / 6,893` | `24/0/62`, `0.4364`, `0.0000` | `25/1/61`, `0.4464`, `0.00015` | `18/0/68`, `0.3462`, `0.0000` | `9/0/77`, `0.1895`, `0.0000` |
| `LOCGO_05` | `G06_0316_sub4` | `454 / 6,526` | `454/12/0`, `0.9870`, `0.00184` | `454/11/0`, `0.9880`, `0.00169` | `451/38/3`, `0.9565`, `0.00582` | `440/29/14`, `0.9534`, `0.00444` |
| `LOCGO_06` | `G07_0319_sub10` | `470 / 6,509` | `449/0/21`, `0.9771`, `0.0000` | `448/0/22`, `0.9760`, `0.0000` | `446/0/24`, `0.9738`, `0.0000` | `445/0/25`, `0.9727`, `0.0000` |
| `LOCGO_07` | `G08_0320_sub14` | `443 / 6,538` | `443/0/0`, `1.0000`, `0.0000` | `442/0/1`, `0.9989`, `0.0000` | `433/0/10`, `0.9886`, `0.0000` | `443/3/0`, `0.9966`, `0.00046` |
| `LOCGO_08` | `G09_0323_veth3e0` | `0 / 6,978` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` |
| `LOCGO_09` | `G10_0323_veth3e1` | `0 / 6,980` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` | `0/0/0`, `N/A`, `0.0000` |
| **Dual-Class Mean $\pm$ SD (`6` folds)** | `G03..G08` | `1,878 / 89,427` | `F1: 0.7637 ± 0.3282` | `F1: 0.7345 ± 0.3792` | `F1: 0.6976 ± 0.3775` | `F1: 0.6833 ± 0.4153` |
| **Dual-Class Median (IQR)** | `G03..G08` | `1,878 / 89,427` | `F1: 0.9821 (0.4085)` | `F1: 0.9820 (0.4050)` | `F1: 0.9385 (0.4839)` | `F1: 0.9630 (0.5947)` |

**Why `G03_0201_veth` (`10` positive windows) and `G05_0315_sub2` (`86` positive windows) have lower recall across all models:**
- In `G03_0201_veth`, all `10` positive windows come from `50` packets (`20` in `s0003`, `20` in `s0007`, `10` in `s0009`) where `9 / 10` windows have normal protocol field values (`func_code=1`, `quantity=1`, `modbus_len=6`) and only `1` window contains `quantity=3` (`Category 2`). None contain `modbus_len == 3`.
- In `G05_0315_sub2` (`86` positive windows), `24` windows contain `modbus_len == 3` (`Category 1`) and `1` window contains `quantity > 1` (`Category 2`), while the remaining `61` positive windows (`Category 3`) come from `event_mapped` rows with normal protocol fields (`func_code=1, quantity=1, modbus_len=6`). Thus, every model detects the `~18–25` signature/quantity windows and misses the `61` unlabelled-looking `event_mapped` windows.

---

## 3. Secondary Evaluation Results: 5-Fold Stratified Group K-Fold (SGKF-5)

In `SGKF-5`, each of the `5` folds pairs one positive capture group (or `G03 + G05` in `SGKF5_04`) with one normal-only capture group so that every test fold is dual-class (`n_defined_folds = 5`).

| Model | Pooled `@0.5` F1 | Pooled `@val_thr` TP | Pooled `@val_thr` FP | Pooled `@val_thr` FN | Pooled `@val_thr` Precision | Pooled `@val_thr` Recall | Pooled `@val_thr` F1 | Pooled ROC-AUC | Pooled PR-AUC | 5-Fold Mean $\pm$ SD F1 (`@val_thr`) | 5-Fold Median F1 (`@val_thr`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`Model_A_Packet_LogReg`** | 0.9253 | 1,783 | 100 | 95 | 0.9469 | 0.9494 | 0.9482 | 0.9682 | 0.8058 | $0.8481 \pm 0.2393$ | 0.9722 |
| **`Model_A_Packet_DT`** | 0.9525 | 1,785 | 0 | 93 | **1.0000** | **0.9505** | **0.9746** | 0.9756 | 0.9585 | $0.8754 \pm 0.2379$ | **1.0000** |
| **`Model_B_Window_RF`** | **0.9735** | 1,783 | 22 | 95 | 0.9878 | 0.9494 | 0.9682 | **0.9830** | **0.9652** | $0.8721 \pm 0.2313$ | 0.9779 |
| **`Model_B_Window_LogReg`** | 0.8851 | 1,782 | 68 | 96 | 0.9632 | 0.9489 | 0.9560 | 0.9803 | 0.9481 | $0.8687 \pm 0.2115$ | 0.9652 |
| **`Model_C_LSTM_Full`** | 0.9040 | 1,747 | 192 | 131 | 0.9010 | 0.9302 | 0.9154 | 0.9768 | 0.9355 | $0.7815 \pm 0.3383$ | 0.9660 |
| **`Model_D_LSTM_NoTiming`** | 0.8771 | 1,741 | 28 | 137 | 0.9842 | 0.9271 | 0.9548 | 0.9761 | 0.9293 | $0.8437 \pm 0.2645$ | 0.9750 |

---

## 4. Per-Category Positive-Window Recall Breakdown

As established in `docs/C2_DATASET_AUDIT.md`, the `1,878` positive windows in the rebuilt dataset fall into three mutually exclusive empirical categories:
- **Category 1 (`1,784` windows, `94.99%`):** Windows containing $\ge 1$ packet with `modbus_len == 3` (`packet_size == 75`, `func_code == 5` in `s0004`).
- **Category 2 (`23` windows, `1.22%`):** Windows with no `modbus_len == 3` packets, but containing $\ge 1$ multi-register/multi-coil read (`quantity > 1`).
- **Category 3 (`71` windows, `3.78%`):** Windows from `event_mapped` intervals containing only standard single-coil/register requests (`func_code in {1, 5}`, `quantity == 1`, `modbus_len == 6`) that are protocol-identical to background polling.

| Model (LOCGO-10 `@val_thr`) | Cat 1: `modbus_len == 3` (`1,784`) | Cat 2: `quantity > 1` (`23`) | Cat 3: `event_mapped` Normal-Looking (`71`) | Negative Windows FP (`117,359`) |
| :--- | ---: | ---: | ---: | ---: |
| **`Model_A_Packet_LogReg`** | `1,769 / 1,784` (`99.16%`) | `14 / 23` (`60.87%`) | `0 / 71` (`0.00%`) | `133` (`0.113%`) |
| **`Model_A_Packet_DT`** | `1,784 / 1,784` (`100.00%`) | `2 / 23` (`8.70%`) | `0 / 71` (`0.00%`) | `12` (`0.010%`) |
| **`Model_B_Window_RF`** | `1,782 / 1,784` (`99.89%`) | `1 / 23` (`4.35%`) | `0 / 71` (`0.00%`) | `13` (`0.011%`) |
| **`Model_C_LSTM_Full`** | `1,759 / 1,784` (`98.60%`) | `0 / 23` (`0.00%`) | `0 / 71` (`0.00%`) | `105` (`0.089%`) |
| **`Model_D_LSTM_NoTiming`** | `1,742 / 1,784` (`97.65%`) | `0 / 23` (`0.00%`) | `0 / 71` (`0.00%`) | `32` (`0.027%`) |
| **`NoShortcut Model_A_Packet_DT`** | `1,769 / 1,784` (`99.16%`) | `17 / 23` (`73.91%`) | `0 / 71` (`0.00%`) | `13,182` (`11.232%`) |
| **`NoShortcut Model_B_Window_RF`** | `1,450 / 1,784` (`81.28%`) | `1 / 23` (`4.35%`) | `0 / 71` (`0.00%`) | `1,421` (`1.211%`) |
| **`NoShortcut Model_C_LSTM_Full`** | `1,112 / 1,784` (`62.33%`) | `0 / 23` (`0.00%`) | `0 / 71` (`0.00%`) | `7,251` (`6.178%`) |

**Key Insight:** None of the models (`0 / 71`) can distinguish Category 3 (`event_mapped`) windows from normal traffic under capture-independent evaluation because those `71` windows have identical protocol fields and polling intervals to the `117,359` negative windows, and their labels originate from wall-clock `attack_events_mapped.xlsx` interval matching (`~4h 57m` offset from `sub*` capture timestamps). This ceiling (`1,807 / 1,878 = 96.22%` maximum non-trivial recall) explains why recall across all low-FPR models plateaus at `94.9%–95.1%`.

---

## 5. Shortcut-Removed & Timing Ablation Studies (`artifacts/ablation_results.json`)

To test whether temporal and windowed behavioural features provide value when the `modbus_len == 3` (`packet_size == 75`) protocol-length signature is unavailable, we removed all length/size features (`modbus_len`, `packet_size`, `d_modbus_len`, `modbus_len_mean/min/max`, `packet_size_mean/max`) from every model family:

| Ablation Model | Feature Set (Dims) | LOCGO-10 Pooled F1 (`@val_thr`) | LOCGO-10 Pooled PR-AUC | LOCGO-10 Pooled ROC-AUC | SGKF-5 Pooled F1 (`@val_thr`) | SGKF-5 Pooled PR-AUC | SGKF-5 Pooled ROC-AUC |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`Model_B_Window_RF` (Full)** | Window + Timing + Length (`29`) | **0.9706** | **0.9644** | **0.9859** | **0.9682** | **0.9652** | **0.9830** |
| **`Model_B_Window_RF_NoTiming` (RQ2)** | Window No-Timing + Length (`21`) | 0.9698 | 0.9639 | 0.9828 | 0.9733 | 0.9645 | 0.9815 |
| **`NoShortcut_Model_A_Packet_DT`** | Packet No-Shortcut (`3`: FC, Reg, Qty) | 0.2131 | 0.0975 | 0.9333 | 0.2089 | 0.0882 | 0.9222 |
| **`NoShortcut_Model_B_Window_RF` (With Timing)** | Window No-Shortcut + Timing (`24`) | **0.6210** | **0.4326** | **0.9562** | **0.6624** | **0.6253** | **0.9574** |
| **`NoShortcut_Model_B_Window_RF_NoTiming`** | Window No-Shortcut No-Timing (`16`) | 0.1379 | 0.0530 | 0.8195 | 0.1379 | 0.0530 | 0.8195 |
| **`NoShortcut_Model_C_LSTM_Full` (With Timing)** | Sequence No-Shortcut + Timing (`16`) | 0.2171 | 0.0725 | 0.8617 | 0.1656 | 0.0736 | 0.8588 |
| **`NoShortcut_Model_D_LSTM_NoTiming`** | Sequence No-Shortcut No-Timing (`14`) | 0.1688 | 0.0528 | 0.8224 | 0.1408 | 0.0530 | 0.8198 |

### Interpretation of the Ablation Matrix
1. **Packet vs Windowed Temporal Behavior without `modbus_len` (`RQ1` under No-Shortcut):**
   - Without `modbus_len` and `packet_size`, a packet-level model (`NoShortcut_Model_A_Packet_DT`) only sees `(func_code, reg, quantity)`. Because `func_code = 5` and `reg` values in `s0004` also occur in normal traffic (`13,182` negative windows contain `func_code = 5`), the packet-level model suffers a `11.23%` false positive rate (`F1 = 0.2131`, `PR-AUC = 0.0975`).
   - Adding **windowed temporal and behavioural statistics** (`NoShortcut_Model_B_Window_RF`, `24` features) reduces false positives by nearly `10x` (`1,421` vs `13,182` in LOCGO-10; `864` in SGKF-5) and raises `F1@val_thr` from **`0.2089` to `0.6624`** (`PR-AUC` from **`0.0882` to `0.6253`** in SGKF-5).
   - Why does `NoShortcut_Model_B_Window_RF` (`F1 = 0.6624`) outperform `NoShortcut_Model_C_LSTM_Full` (`F1 = 0.2171`)? Explicit summary statistics (`dt_cv`, `dt_std`, `seq_step_ratio`, `reg_range`) regulated by Random Forest axis splits are more robust to cross-capture timing shifts than raw step-by-step `log_dt` sequences fed into an unregularized recurrent hidden state trained on only `4–8` capture groups.
2. **Timing vs No-Timing without `modbus_len` (`RQ2` under No-Shortcut):**
   - When `modbus_len` is removed, dropping timing features from `NoShortcut_Model_B_Window_RF` (`24 -> 16` features) causes `F1@val_thr` to drop from **`0.6210` to `0.1379`** (and `SGKF-5 PR-AUC` from **`0.6253` to `0.0530`**). Similarly, for the No-Shortcut LSTM, keeping timing features (`NoShortcut_Model_C_LSTM_Full`) improves `LOCGO-10 F1@val_thr` (`0.2171` vs `0.1688`) and `ROC-AUC` (`0.8617` vs `0.8224`) compared with `NoShortcut_Model_D_LSTM_NoTiming`.
   - This proves that **explicit inter-request timing features carry genuine discriminative information separating reconnaissance sessions from normal polling sessions**, even though that signal is masked on the full feature set by the `100%`-pure `modbus_len == 3` signature.

---

## 6. Split-Leakage & Dataset-Reconstruction Diagnostics

### 6.1 Random K-Fold (Leaked) vs Capture-Group Independent Splits on Rebuilt Windows (`119,237` Windows)

Because sliding windows of length `L=20` and stride `S=5` share `15` packets with adjacent windows, `99.99%` of test windows in a random 5-fold split share $\ge 1$ packet with training windows (`artifacts/leakage_audit.json`). The table below quantifies the resulting optimistic bias:

| Model Configuration | Random 5-Fold (Leaked) F1 (`@0.5`) | Random 5-Fold PR-AUC | Random 5-Fold ROC-AUC | SGKF-5 (Group-Independent) F1 (`@val_thr`) | SGKF-5 PR-AUC | LOCGO-10 (Capture-Independent) F1 (`@val_thr`) | LOCGO-10 PR-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`Model_B_Window_RF` (Full 29 dims)** | 0.9747 | 0.9830 | 0.9976 | 0.9682 | 0.9652 | 0.9706 | 0.9644 |
| **`NoShortcut_Model_B_Window_RF` (24 dims)** | 0.6315 | **0.8835** | **0.9939** | 0.6624 | **0.6253** | 0.6210 | **0.4326** |
| **`NoShortcut_Model_C_LSTM` (16 dims)** | 0.1405 | 0.0791 | 0.8787 | 0.1656 | 0.0736 | 0.2171 | 0.0725 |

When `modbus_len` is removed, random 5-fold splitting inflates `NoShortcut_Model_B_Window_RF` `PR-AUC` from **`0.4326` (LOCGO-10)** / **`0.6253` (SGKF-5)** up to **`0.8835`** (`+0.4509` over LOCGO-10) because the Random Forest memorizes session-specific timestamp jitter from overlapping training windows.

### 6.2 As-Provided Corrupted Sequences (`175,800`) vs Chronologically Rebuilt Sequences (`119,237`)

| Dataset & Split | Windows (`Pos / Neg`) | Precision (`@0.5`) | Recall (`@0.5`) | F1 (`@0.5`) | FP Count | FPR | ROC-AUC | PR-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **As-Provided (`recon_sequences_ALL`, Random 5-Fold)** | `18,338 / 157,462` | 0.9999 | 0.9745 | **0.9870** | 2 | 0.00001 | 0.9928 | 0.9851 |
| **As-Provided (`recon_sequences_ALL`, Session-Grouped 5-Fold)** | `18,338 / 157,462` | 0.9440 | 0.9715 | 0.9576 | 1,056 | 0.00671 | 0.9867 | 0.9790 |
| **Rebuilt (`windows.csv`, LOCGO-10 `@0.5`)** | `1,878 / 117,359` | 0.9978 | 0.9510 | 0.9738 | 4 | 0.00003 | 0.9859 | 0.9644 |

Evaluating on the as-provided `recon_sequences_ALL.csv.xlsx` with a naive random split yields an artificially inflated `F1 = 0.9870` (`FP = 2 / 157,462`) because `174,708 / 175,800` (`99.38%`) of its windows are non-chronological cross-pcap slices sorted by `(session_id, func_code, reg)` and duplicated across 5 `veth` interfaces.

### 6.3 Strict `session_id` Holdout Diagnostic (`session_id_strict_holdout_diagnostic`)

In the rebuilt dataset, `94.20%` (`1,769 / 1,878`) of all positive windows belong to a single directional flow (`185.175.0.5_185.175.0.3_u1_s0004`). Under a strict 5-fold split grouped by `session_id` (`SESSION_GROUP_00`..`04`):
- When `s0004` is held out in `SESSION_GROUP_03` (`1,769` test positives), only `109` positive windows remain in the training set (`0` of which are `func_code=5, modbus_len=3` slave responses). Consequently, `Model_B_Window_RF` achieves `ROC-AUC = 0.9946` and `PR-AUC = 0.9053` on `SESSION_GROUP_03` (ranking `s0004` windows above normal windows via `modbus_len_min`), but at the fixed `0.5` threshold recall drops to `0.0124` (`TP = 22 / 1,769`, `F1 = 0.0244`), yielding a pooled OOF `F1@0.5 = 0.0601` (`ROC-AUC = 0.9911, PR-AUC = 0.7978`).
- This confirms why capture-group splitting (`LOCGO-10` and `SGKF-5`) is the appropriate primary evaluation protocol while `session_id` concentration is documented as a fundamental dataset limitation in `docs/C2_LIMITATIONS.md`.

---

## 7. Window-Length Sensitivity Analysis (`L=10`, `L=20`, `L=40`)

We evaluated `Model_B_Window_RF` (both Full `29` dims and No-Shortcut `24` dims) under `SGKF-5` across three window configurations rebuilt from `packets_rebuilt.csv`:

| Window Config | Total Windows | Positive Windows (`%`) | Full RF F1 (`@val_thr`) | Full RF PR-AUC | Full RF ROC-AUC | No-Shortcut RF F1 (`@val_thr`) | No-Shortcut RF PR-AUC | No-Shortcut RF ROC-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`L=10, Stride=5`** | 119,349 | 1,818 (`1.52%`) | **0.9790** | **0.9716** | **0.9860** | 0.5758 | 0.5178 | **0.9598** |
| **`L=20, Stride=5` (Selected)** | 119,237 | 1,878 (`1.57%`) | 0.9674 | 0.9636 | 0.9819 | **0.6624** | 0.6253 | 0.9574 |
| **`L=40, Stride=10`** | 59,519 | 994 (`1.67%`) | 0.9501 | 0.9415 | 0.9771 | 0.6565 | **0.7101** | 0.9563 |

**Interpretation:**
- When using the packet-level `modbus_len == 3` shortcut (`Full RF`), shorter windows (`L=10`) have slightly higher precision/recall (`F1 = 0.9790`) because fewer normal boundary packets dilute a short burst.
- When relying on genuine temporal/behavioural statistics (`No-Shortcut RF`), **`L=20` outperforms `L=10` by `+0.0866` F1 (`0.6624` vs `0.5758`) and `+0.1075` PR-AUC (`0.6253` vs `0.5178`)** because `10` packets are too brief to stabilize inter-arrival coefficient of variation (`dt_cv`) and sequential step ratios (`seq_step_ratio`). Increasing to `L=40` further improves `No-Shortcut PR-AUC` (`0.7101`), validating `L=20` as a strong balance between behavioural context and detection latency.

---

## 8. Inference Latency and Throughput (`artifacts/latency.json`)

Benchmarked on `Windows-11-10.0.26200-SP0` (`Intel64 Family 6 Model 154 Stepping 3`, Python `3.14.3`, PyTorch `2.14.1+cpu`, single-threaded CPU execution, `50` warmup windows + `500` timed iterations):

### 8.1 Single-Window Latency (`Proposal Target: < 100.0 ms at p99`)

| Pipeline Stage / Model | Mean (ms) | Std (ms) | Median (ms) | p95 (ms) | p99 (ms) | Max (ms) | Meets `< 100 ms` Target (`p99`)? |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| **Seq Feature Extraction + Scaling (`20x19`)** | 16.39 | 4.62 | 15.43 | 23.30 | 29.57 | 59.11 | **YES** |
| **Window Feature Extraction + Scaling (`29`)** | 17.45 | 4.88 | 16.37 | 24.78 | 31.79 | 61.55 | **YES** |
| **`Model_A_Packet_LogReg` (Inference Only)** | 0.33 | 0.16 | 0.29 | 0.58 | 0.85 | 2.50 | **YES** |
| **`Model_A_Packet_DT` (Inference Only)** | 0.23 | 0.11 | 0.20 | 0.38 | 0.49 | 1.92 | **YES** |
| **`Model_B_Window_RF` (Inference Only)** | 35.03 | 6.25 | 34.39 | 45.73 | 50.75 | 80.20 | **YES** |
| **`Model_C_LSTM_Full` (Inference Only)** | **1.70** | 0.98 | **1.49** | **2.94** | **4.56** | 17.32 | **YES** |
| **`Model_D_LSTM_NoTiming` (Inference Only)** | **1.38** | 0.82 | **1.18** | **2.54** | **4.38** | 12.57 | **YES** |
| **`Model_B_Window_RF` (End-to-End Raw -> Alert)** | 52.48 | 10.07 | 50.96 | 70.68 | 84.11 | 109.70 | **YES** |
| **`Model_C_LSTM_Full` (End-to-End Raw -> Alert)** | **18.09** | 5.09 | **16.90** | **25.63** | **34.51** | 62.45 | **YES** |

**Key Latency Finding:** Single-window end-to-end latency for **`Model_C_LSTM_Full`** (`18.09 ms` mean, `34.51 ms` p99) is **`2.9x` faster** than `Model_B_Window_RF` (`52.48 ms` mean, `84.11 ms` p99) because a 2-layer PyTorch LSTM forward pass on a `(1, 20, 19)` tensor takes only `1.70 ms` on CPU compared with `35.03 ms` for scikit-learn `RandomForestClassifier` (`300` trees) single-sample dispatch.

### 8.2 Batch Throughput (`Batch Sizes 1, 32, 256, 1024`)

| Batch Size | `Model_C_LSTM_Full` Batch Mean (ms) | `Model_C_LSTM_Full` Per-Window (ms) | `Model_C_LSTM_Full` Throughput (win/s) | `Model_B_Window_RF` Batch Mean (ms) | `Model_B_Window_RF` Per-Window (ms) | `Model_B_Window_RF` Throughput (win/s) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | 2.38 | 2.383 | 419.6 | 42.15 | 42.152 | 23.7 |
| **32** | 3.66 | 0.114 | 8,753.8 | 43.13 | 1.348 | 742.0 |
| **256** | 7.43 | 0.029 | 34,456.7 | 50.56 | 0.197 | 5,063.3 |
| **1024** | 21.72 | **0.021** | **47,145.4** | 65.47 | 0.064 | 15,640.3 |

---

## 9. Sequence Attribution & Explainability (`artifacts/example_sequences.json`)

Using input-gradient $\times$ standardized-activation saliency (`C2InferenceEngine.explain_sequenceTensor`) on `Model_C_LSTM_Full`, we inspected six representative out-of-fold sequences (`artifacts/example_sequences.json`) and generated six figures (`artifacts/plots/fig1..fig6_*.png`):

1. **`TP_Cat1_ModbusLen3_Signature` (`window_id = 51763`, `G06_0316_sub4`, `s0004`):**
   - Ground truth `label = 1`, `n_pos_packets = 20 / 20`, OOF `Model_C_LSTM_Full` score `= 0.9969`, `Model_B_Window_RF` score `= 1.0000`.
   - Top attributed features: `modbus_len` (`mean_abs_attribution = 0.0117`), `packet_size` (`0.0080`), `fc_5` (`0.0068`), `is_write_fc` (`0.0020`).
   - Top time steps: steps `19, 18, 17, 16, 15` (monotonically increasing attribution toward the final recurrent hidden state $h_{20}$, shown in `artifacts/plots/fig5_feature_and_timestep_attribution.png`).
2. **`TP_Cat2_MultiRegister_Quantity_Scan` (`window_id = 35107`, `G04_0315_sub1`, `s0013`):**
   - Ground truth `label = 1`, `n_pos_packets = 1`, contains a multi-register request (`quantity = 3`, `modbus_len = 6`).
   - Detected by `Model_A_Packet_DT` (`score = 1.0000`) and `NoShortcut_Model_A_Packet_DT` via `log_qty`, whereas `Model_C_LSTM_Full` assigns a low score (`0.0005`) because `19 / 20` packets in the window are normal background polling (`quantity = 1, modbus_len = 6`).
3. **`FN_Cat3_EventMapped_NormalLooking` (`window_id = 42159`, `G05_0315_sub2`, `s0002`):**
   - Ground truth `label = 1` (`20 / 20` packets mapped from `attack_events_mapped.xlsx`), but all `20` packets have normal protocol parameters (`func_code = 1`, `quantity = 1`, `modbus_len = 6`).
   - All models score this window near zero (`Model_C_LSTM_Full = 0.0007`, `Model_B_Window_RF = 0.0000`), confirming that Category 3 false negatives are an artifact of unverified wall-clock interval mapping rather than model failure.
4. **`FP_Normal_HighScore_Window` (`window_id = 36835`, `G04_0315_sub1`, `s0004`):**
   - Ground truth `label = 0`, `Model_C_LSTM_Full` OOF score `= 0.7204` (above `G04` validation threshold `0.4649`, causing a false positive), whereas `Model_B_Window_RF` scores `0.0000`.
   - Saliency reveals that `Model_C_LSTM_Full` triggered on `fc_5` (`func_code = 5` write single coil in `s0004`) combined with an unusual inter-packet timing gap (`log_dt`), even though `modbus_len == 6`.
5. **`TN_Pure_Normal_Window` (`window_id = 0`, `G01_0122_normal4`, `s0000`):**
   - Ground truth `label = 0`, `Model_C_LSTM_Full` OOF score `= 0.0004`, `Model_B_Window_RF` score `= 0.0000`.
