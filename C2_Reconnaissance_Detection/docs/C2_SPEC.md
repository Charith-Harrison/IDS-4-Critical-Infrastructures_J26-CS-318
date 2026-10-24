# C2 / RP2 — Research & Technical Specification
## Modbus/TCP Reconnaissance Attack Detection Using Temporal Behavior Analysis

- **Overall Project**: Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis (`J26-CS-318`)
- **Individual Component**: `C2 / RP2` — Reconnaissance Attack Detection Using Temporal Behavior Analysis
- **Researcher**: Charith H. (`IT23269002`), B.Sc. (Hons) in Information Technology Specializing in Cyber Security, SLIIT
- **Supervisor / Co-Supervisor**: Ms.ulanthi / Approved per `IT4010-TAF-2026 J26-CS-318` and Individual Proposal `IT23269002_Charith H.`

---

## 1. Component Boundary & Scope

The overall `J26-CS-318` framework comprises four specialized detection modules:
- **RP1 (C1)**: Denial-of-Service (DoS) Attack Detection
- **RP2 (C2)**: **Reconnaissance / Scanning Attack Detection Using Temporal Behavior Analysis (This Component)**
- **RP3 (C3)**: Command and Response Injection Detection
- **RP4 (C4)**: Replay Attack Detection

`C2` is strictly isolated from the internal modelling of `RP1`, `RP3`, and `RP4`. Its sole responsibility is to investigate whether protocol-aware temporal sequence modelling of Modbus/TCP communications improves reconnaissance detection compared with static packet-level and non-temporal window-summary baselines under session/capture-independent evaluation, and to expose a clean JSON output contract for downstream decision fusion.

---

## 2. Research Questions & Hypotheses

### Primary Research Question (`RQ1`)
> **Does temporal modelling of protocol-aware Modbus/TCP request sequences improve reconnaissance detection compared with packet-level and non-temporal baselines under session-independent evaluation?**

- **Null Hypothesis ($H_{0,1}$)**: Under capture/session-independent evaluation, a sequential LSTM model (`Model C`) trained on ordered 20-packet Modbus/TCP communication windows does not achieve higher out-of-fold detection performance ($\text{F1}$, $\text{PR-AUC}$) than a packet-level static classifier aggregated to windows (`Model A`) or a non-temporal window-summary Random Forest (`Model B`).
- **Alternative Hypothesis ($H_{1,1}$)**: Ordered sequence modelling (`Model C`) improves capture/session-independent reconnaissance detection over `Model A` and/or `Model B`, either on the full protocol feature set or when single-packet frame-length shortcuts (`modbus_len == 3`) are ablated.

### Secondary Research Question (`RQ2`)
> **Does explicit timing information provide useful predictive information beyond the ordered Modbus/TCP request features themselves?**

- **Null Hypothesis ($H_{0,2}$)**: Removing explicit inter-packet timing features (`log_dt`, `d_log_dt` in `Model D`; `WINDOW_TIMING` in `Model B No-Timing`) does not degrade capture/session-independent reconnaissance detection compared with the full-feature temporal model (`Model C`).
- **Alternative Hypothesis ($H_{1,2}$)**: Explicit inter-packet timing features provide measurable predictive improvement over ordered non-timing protocol fields alone.

---

## 3. Authoritative Data Sources (Protected Originals)

All three supplied workbooks in `Dataset/` are read-only and verified via SHA-256 checksums (`data/raw/raw_manifest.json`):

| File Name | Physical Format | Size (Bytes) | SHA-256 Checksum | Verified Dimensions |
| :--- | :--- | ---: | :--- | :--- |
| `recon_labeled_packets_ALL.csv.xlsx` | OOXML Workbook (`.xlsx`) | `55,804,545` | `34f24c30b0004ba1a1d209113aade7f7b44e486de2380c33ae0ea79227c1f904` | `879,225` rows $\times$ `14` columns |
| `recon_sequences_ALL.csv.xlsx` | OOXML Workbook (`.xlsx`) | `13,383,761` | `249a6e57ff943d14ce69b855676f98a722f885e692688cc4af652a88df82b399` | `175,800` rows $\times$ `13` columns |
| `attack_events_mapped.xlsx` | OOXML Workbook (`.xlsx`) | `19,321` | `865ee1ef879076c297dc4e3e7ea8d0d991e17a26ed2d4a13b20c62ab4a7af354` | `158` rows $\times$ `12` columns |

---

## 4. Representation & Model Families

All primary models are evaluated on identical 20-packet windows ($L = 20$, stride $S = 5$, `any_positive` label rule) reconstructed from chronological, interface-deduplicated Modbus/TCP streams (`119,237` windows across `10` independent capture episodes `G01`..`G10`):

1. **Model A — Packet-Level Static Baselines (`Model_A_Packet_LogReg`, `Model_A_Packet_DT`)**:
   - Input: 5 per-packet static protocol fields (`func_code`, `modbus_len`, `register_start`, `log_quantity`, `packet_size`) with zero inter-packet timing or transition features.
   - Window Aggregation: Maximum per-packet probability across the 20 packets in each window ($S_w = \max_{t=1..20} p_{w,t}$), matching the `any_positive` window label rule.
2. **Model B — Non-Temporal Window-Summary Baselines (`Model_B_Window_RF`, `Model_B_Window_LogReg`)**:
   - Input: 29 engineered window-level summary statistics (`WINDOW_FEATURES`), collapsing the 20-packet window into a flat vector of rate, interval, register-range, step-ratio, and function-code fraction statistics.
3. **Model C — Primary Temporal Sequence Model (`Model_C_LSTM_Full`)**:
   - Input: Ordered `(20, 19)` sequence tensor (`SEQ_FEATURES`) combining one-hot function codes (`fc_1..6`, `fc_other`), payload fields (`modbus_len`, `register_start`, `log_quantity`, `packet_size`), causal within-window transition features (`d_reg`, `log_abs_d_reg`, `seq_step`, `back_step`, `fc_change`, `is_write`), and explicit timing features (`log_dt`, `d_log_dt`).
   - Architecture: 2-layer PyTorch LSTM (`LSTM(19 -> 64, return_sequences=True) -> Dropout(0.3) -> LSTM(64 -> 32) -> Dropout(0.3) -> Linear(32 -> 16, ReLU) -> Linear(16 -> 1, Sigmoid)`).
4. **Model D — Temporal Sequence Model Without Explicit Timing (`Model_D_LSTM_NoTiming`, `RQ2` Ablation)**:
   - Input: Ordered `(20, 17)` sequence tensor (`SEQ_FEATURES_NO_TIMING`), identical to `Model C` except `log_dt` and `d_log_dt` are removed.
   - Architecture & training hyperparameters: Identical to `Model C`.
