# C2 / RP2 — Dataset, Experimental, and System Limitations (`C2_LIMITATIONS.md`)

**Overall Project:** Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis (`J26-CS-318`)  
**Individual Component:** C2 / RP2 — Reconnaissance Attack Detection Using Temporal Behavior Analysis  
**Student:** Charith H. (`IT23269002`)

---

## 1. Dataset and Ground-Truth Limitations

### 1.1 Dominance of a Single Protocol-Length Signature (`modbus_len == 3`)
- **Finding:** In `recon_labeled_packets_ALL.csv.xlsx` (and the deduplicated `packets_rebuilt.csv`), `8,401 / 8,637` (`97.27%`) of all positive packets and `1,784 / 1,878` (`94.99%`) of all positive `20`-packet windows contain `modbus_len == 3` (`packet_size == 75`, `func_code == 5` in `185.175.0.5_185.175.0.3_u1_s0004`), which never occurs in the `588,498` negative packets (`100.0%` precision from a 1-field rule).
- **Consequence:** Any classifier given access to `modbus_len` or `packet_size` achieves `F1 ~ 0.94–0.97` primarily by thresholding packet length rather than learning complex sequential register-progression patterns. While our `NoShortcut` ablation (`src/ablations.py`) isolates genuine temporal/behavioural performance by removing `modbus_len` and `packet_size`, the underlying dataset contains relatively few examples (`23` windows in Category 2) of classical sequential register/coil enumeration without the `modbus_len == 3` signature.

### 1.2 Concentration of Positive Traffic in One Directional Session (`s0004`)
- **Finding:** Out of `13` directional `session_id` flows with $\ge 20$ packets, a single slave-to-master flow (`185.175.0.5_185.175.0.3_u1_s0004`) contains `8,402 / 8,637` (`97.28%`) of all positive packets and `1,769 / 1,878` (`94.20%`) of all positive windows across `5` separate `.pcap` captures (`sub1`, `sub2`, `sub4`, `sub10`, `sub14`).
- **Consequence:** Holding out `s0004` entirely (`session_id_strict_holdout_diagnostic` in `artifacts/ablation_results.json`) removes `100%` of `func_code = 5, modbus_len = 3` positive examples from the training set, leaving only `109` positive windows (`23` quantity-scan windows and `86` normal-looking `event_mapped` windows) and causing thresholded recall on `s0004` to collapse (`Recall@0.5 = 0.0124`, even though `ROC-AUC = 0.9946`). Therefore, cross-capture generalization can be evaluated rigorously across independent `.pcap` capture groups (`LOCGO-10` and `SGKF-5`), but generalization across completely disjoint functional flow types is constrained by the dataset's single-flow positive concentration.

### 1.3 Unverifiable `event_mapped` Positive Windows (Category 3 Ceiling)
- **Finding:** `71 / 1,878` (`3.78%`) of positive windows (`61` in `G05_0315_sub2`, `1` in `G07_0319_sub10`, and `9` in `G03_0201_veth`) contain zero `modbus_len == 3` packets and zero `quantity > 1` packets. Every packet in these `71` windows has `func_code in {1, 5}`, `quantity == 1`, `modbus_len == 6`, and standard register/timing values identical to normal background polling (`117,359` negative windows).
- **Root Cause:** As shown in `artifacts/label_audit.json`, timestamps in `attack_events_mapped.xlsx` (`158` rows, e.g. `2023-03-15 16:40:27`) are shifted by approximately `4 hours 57 minutes` (`~5 hours`, likely UTC vs local timezone or testbed clock skew) relative to the `sub*.pcap` packet timestamps (`2023-03-15 11:42:54`). When the upstream dataset creator applied time-window label mapping, normal background polling packets inside those mapped intervals were labelled `1`.
- **Consequence:** Under capture-independent evaluation, every model (`Packet LogReg`, `Packet DT`, `Window RF`, `LSTM Full`, `LSTM No-Timing`) achieves `0 / 71` (`0.00%`) recall on Category 3 windows at low false-positive rates, imposing a hard ceiling of `~96.2%` maximum achievable recall on the unaltered packet labels.

### 1.4 Upstream Sequence-File Corruption (`recon_sequences_ALL.csv.xlsx`)
- **Finding:** The pre-windowed `recon_sequences_ALL.csv.xlsx` file provided in the preliminary archive cannot be used as a valid time-series benchmark because `99.38%` of its sequences have non-monotonic timestamps (`packets sorted by (session_id, func_code, reg)` before windowing), `97.32%` cross `.pcap` file boundaries, and `282,076` packets come from duplicate simultaneous `2023-02-01` `veth*` captures.
- **Mitigation & Boundary:** We reconstructed all sequences from the raw packet table (`packets_rebuilt.csv` $\rightarrow$ `windows.csv`), eliminating all backward timestamps, cross-capture windows, and multi-interface duplicates. However, any external comparison against studies that trained directly on `recon_sequences_ALL.csv.xlsx` must account for the fact that those studies evaluated on non-chronological, leaked sequences.

---

## 2. Experimental and Modelling Limitations

### 2.1 Single-Class Normal Capture Groups in `LOCGO-10`
- **Finding:** Four of the `10` independent capture groups (`G01_0122_normal4`, `G02_0123_normal13`, `G09_0323_veth3e0`, `G10_0323_veth3e1`, totalling `27,932` windows) contain `0` positive packets.
- **Consequence:** When these `4` groups serve as outer test folds in `LOCGO-10`, `Precision`, `Recall`, `F1`, `ROC-AUC`, and `PR-AUC` are mathematically undefined (`null` in JSON, `N/A` in tables). Only `FP`, `TN`, `FPR`, `Specificity`, `Brier score`, and `ECE` can be evaluated per-fold on those `4` groups, while dual-class metrics must be aggregated across the `6` dual-class folds (`G03`..`G08`) or via pooled out-of-fold predictions (`119,237` windows) and `SGKF-5` (where all `5` folds are dual-class).

### 2.2 Cross-Capture Threshold Sensitivity When Combining Timing with Protocol Signatures
- **Finding:** Because each `.pcap` capture has a slightly different background polling rate and jitter distribution, models that rely heavily on continuous inter-arrival features (`log_dt`, `d_log_dt` in `Model_C_LSTM_Full`) exhibit higher threshold variance across captures than models restricted to discrete protocol fields (`Model_D_LSTM_NoTiming`, `Model_A_Packet_DT`).
- **Consequence:** Inner-validation threshold selection (`max_val_f1_subject_to_fpr_le_0.05` on `2` held-out validation capture groups) does not always match the optimal threshold of the unseen test capture group (e.g., on `LOCGO_05_G06_0316_sub4`, `Model_C_LSTM_Full` selects threshold `0.03`, yielding `38` false positives vs `0` false positives on `G07` and `G08`). Post-hoc temperature scaling or per-deployment baseline calibration of `log_dt` against the local PLC polling period would reduce this threshold sensitivity.

### 2.3 Fixed Packet-Count Windowing (`L=20`) vs Time-Based Windowing
- **Finding:** Following the approved proposal and preliminary dataset schema, sequences are defined as fixed-length sliding windows of `L=20` consecutive packets (`stride = 5`) per directional session.
- **Consequence:** At a slow polling rate (`~1 packet/sec`), a `20`-packet window spans `~20 seconds` before the first full window is emitted for a new session, whereas during a high-rate scan (`~100 packets/sec`), a `20`-packet window spans `~0.2 seconds`. While compute latency once `20` packets are buffered is `< 35 ms` (`p99`), collection delay for ultra-slow "low-and-slow" reconnaissance depends on the inter-packet arrival rate.

---

## 3. System Integration and Deployment Boundaries

1. **Component Scope (`C2 / RP2` Only):** This implementation provides the complete reconnaissance detection engine (`src/contract.py`, `backend/app.py`), standardized JSON output contract, and behavioural explanations required by the `J26-CS-318` decision-fusion layer, but does not implement DoS (`RP1`), Command/Response Injection (`RP3`), or Replay (`RP4`) classifiers.
2. **Passive Deep-Packet Inspection Assumption:** The feature extractor (`extract_single_window_from_packets`) assumes that Modbus/TCP MBAP and PDU headers (`func_code`, `reg`, `quantity`, `modbus_len`, `packet_size`, `timestamp`) have been parsed from unencrypted TCP port `502` traffic. It does not inspect TLS-wrapped Modbus (`Modbus/TCP Security` on port `802`) without prior TLS termination.
