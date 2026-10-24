# C2 / RP2 — Data Leakage Audit & Prevention Report

All leakage diagnostics reported below are verified in `artifacts/leakage_audit.json` and `artifacts/folds.json`.

---

## 1. Six Categories of Potential Leakage Audited

### 1.1 Overlapping-Window Leakage Under Random Splitting
With window length $L = 20$ and stride $S = 5$ (`75%` packet overlap), consecutive windows within the same stream share `15` out of `20` packets (`119,181` consecutive window pairs in the Rebuilt dataset; `175,787` in the As-Provided dataset).
Under a standard 80/20 stratified random split (`seed = 42`):
- **Rebuilt Dataset (`119,237` windows, `23,848` test windows)**:
  - **`23,846 / 23,848` (`99.992%`)** of test windows share $\ge 1$ packet with the training set;
  - **`23,739 / 23,848` (`99.543%`)** of test windows share $\ge 15$ of their 20 packets with the training set;
  - On average, **`19.82 / 20` (`99.11%`)** of the packets in a randomly held-out test window were already seen during training (`100.0%` of positive test windows share $\ge 1$ packet with train, and `99.20%` share $\ge 15$ packets).
- **As-Provided Dataset (`175,800` windows, `35,160` test windows)**:
  - **`35,158 / 35,160` (`99.994%`)** of test windows share $\ge 1$ packet with train (`99.670%` share $\ge 15$ packets; mean overlap `19.86 / 20` = `99.30%`);
  - Furthermore, **`1,765 / 35,160` (`5.02%`)** of test windows have an **exact `20 x 7` feature-matrix duplicate** in the training set!
- **Prevention**: Random splits are strictly prohibited for primary model selection or claims. Primary (`locgo_10fold`) and secondary (`sgkf_5fold`) splits group strictly by `capture_group`, where every fold is verified to have **`0` shared packets** between `fit_groups`, `val_groups`, and `test_groups`.

### 1.2 Simultaneous Multi-Interface Capture Leakage (`2023-02-01`)
On `2023-02-01`, five virtual interfaces (`veth5bbeaa2-0`, `veth4edc015-0`, `vethd9e14c0-0`, `veth8bc3408-0`, `veth665f3cf-0`) captured the exact same underlying network traffic simultaneously. Specifically, `veth665f3cf-0.pcap` (`65,610` packets, `50` positive packets) is a `100.0%` duplicate (within $\le 1\text{ ms}$, median $7\ \mu\text{s}$) of session `185.175.0.7_185.175.0.4_u1_s0007` in `veth4edc015-0.pcap`.
- **Prevention**: `src/rebuild_sequences.py` removes all `282,076` secondary-view duplicate packets (`50` positives) and consolidates the remaining `282,135` packets (`50` positives) into a single capture episode `G03_0201_veth`.

### 1.3 Host-Pair (`session_id`) Concentration & Identifier Leakage
In the supplied dataset:
- **`8,432 / 8,699` (`96.93%`)** of raw positive packets and **`1,769 / 1,878` (`94.20%`)** of rebuilt positive windows occur in a single directional host pair: `185.175.0.5_185.175.0.3_u1_s0004`.
- All `12` positive packets in `attached_recon_flows.csv` occur in `192.168.10.112` multicast/broadcast flows (`100%` positive rate).
- **Prevention**: All 21 identifier/metadata columns (`row_index`, `timestamp`, `ts_ns`, `src_ip`, `dst_ip`, `session_id`, `sequence_position`, `file_source`, `capture_group`, `stream_id`, `sequence_id`, `window_id`, `window_start_time`, `window_end_time`, `window_start_utc`, `window_end_utc`, `start_ns`, `end_ns`, `first_row_index`, `last_row_index`, `unit_id`) are hard-excluded from `PACKET_FEATURES`, `SEQ_FEATURES`, and `WINDOW_FEATURES` (verified by `test_09_prohibited_identifiers_absent_from_features`).

### 1.4 Within-Capture Cross-Direction Coupling vs. `session_id` Holdout
Within each physical `.pcap` capture (e.g. `substation-10.pcap` on `2023-03-19`), all directional flows (`s0001..s0006`) are recorded over the same 25-minute physical window. Grouping by `capture_group` (`G01`..`G10`) holds out the entire physical capture episode at once. We also report a diagnostic 5-fold `session_id`-grouped split (`loso_session_5fold`) to show the exact consequence of holding out `s0004` (`94.20%` of all positive windows and `100%` of `s0004` slave responses).

### 1.5 Preprocessing, Imbalance Weighting, and Threshold Leakage
- **Prevention**: Inside every fold of `baselines.py`, `train_lstm.py`, and `ablations.py`:
  1. `StandardScaler` / `SequenceScaler` mean and standard deviation are computed strictly on `fit_groups`.
  2. Positive class weights (`class_weight="balanced"` for sklearn; `pos_weight = sqrt(n_neg_fit / n_pos_fit)` for PyTorch LSTM) are computed strictly on `fit_groups`.
  3. Early stopping, `ReduceLROnPlateau`, and operational decision thresholds (`select_validation_threshold(..., max_fpr=0.05)`) are computed strictly on the inner group-independent validation split (`val_groups`), never on `test_groups`.

### 1.6 Protocol-Field Shortcut Risk (`modbus_len == 3` / `packet_size == 75`)
In the supplied labels, `100.0%` of packets with `modbus_len == 3` (all of which also have `packet_size == 75`) are labelled `1`. On the Rebuilt dataset (`119,237` windows, `1,878` positives), a zero-parameter static rule `"flag window if any packet has modbus_len == 3"` achieves:
- $\text{TP} = 1,784$, $\text{FP} = 0$, $\text{FN} = 94$, $\text{TN} = 117,359$
- $\text{Precision} = 1.0000$, $\text{Recall} = 0.9499$, $\text{F1} = 0.9743$
without using sequence order or timing!
- **Mitigation**: Alongside the primary comparison on all verified protocol features, `src/ablations.py` executes a dedicated **Protocol Size/Length-Shortcut Ablation** removing `modbus_len` and `packet_size` across all model families (`Models A, B, C, D`), plus a per-category recall breakdown across Category 1 (`modbus_len == 3`, `1,784` windows), Category 2 (`quantity` scans without `modbus_len == 3`, `35` windows), and Category 3 (`event_mapped` normal-protocol windows, `59` windows).
