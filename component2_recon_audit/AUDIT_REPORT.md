# Forensic Dataset & Label Provenance Audit Report — Component 2 (RP2)

- **Project:** J26-CS-318 — *Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis*
- **Component 2 (RP2):** *Reconnaissance Attack Detection Using Temporal Behavior Analysis*
- **Student:** Charith H. / Harry (`IT23269002`)
- **Proposed Model:** Long Short-Term Memory (`LSTM`) Sequence Classifier
- **Audit Directory:** [`component2_recon_audit/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit)
- **Companion Machine-Readable Artifacts:**
  - [`audit_metrics.json`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/audit_metrics.json)
  - [`window_integrity_report.json`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/window_integrity_report.json)
  - [`capture_group_summary.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/capture_group_summary.csv)
  - [`shortcut_analysis.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/shortcut_analysis.csv)
  - [`positive_lineage.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/positive_lineage.csv)
  - [`UNRESOLVED_ASSUMPTIONS.md`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/UNRESOLVED_ASSUMPTIONS.md)
  - [`run_forensic_audit.py`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/run_forensic_audit.py)

---

## Executive Answer to the Primary Audit Question

> **Primary Research Question:** *Are the reconnaissance labels scientifically valid for the temporal-reconnaissance research claim, or is the positive class dominated by an obvious static packet signature that makes temporal modelling unnecessary?*

**Forensic Conclusion:**  
While the **rebuilt sequence pipeline** ([`Pre-processed/rebuilt_sequences/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences)) completely fixes the severe chronological inversions, cross-capture window mixing, and duplicate Docker `veth` interface views present in the older derived files, **the underlying reconnaissance packet labels (`label == 1`) are critically compromised by a single-packet static signature shortcut and request/response labeling inversion**:

1. **`97.26%` (`8,400 / 8,637`) of all retained reconnaissance packets** have the identical static signature `func_code == 5 AND modbus_len == 3 AND packet_size == 75 AND register_start == 0 AND quantity == 0`, and another `13` positive packets (`0.15%`) have `func_code in {1..4} AND modbus_len == 3 AND packet_size == 75`. In total, **`97.41%` (`8,413 / 8,637`) of positive packets** and **`94.99%` (`1,784 / 1,878`) of positive 20-packet windows** are identified by the trivial single-field rule **`modbus_len == 3` (or `packet_size == 75`) with `100.00%` precision (`0` false positives across `588,498` normal packets and `117,359` normal windows)**.
2. **Request/Response Labeling Inversion:** All `8,400` `FC5 + modbus_len == 3` packets are **3-byte slave-to-master response frames** (sent from IEDs `185.175.0.5`, `185.175.0.4`, `185.175.0.8` back to SCADA master `185.175.0.3` within `~0.24 ms` of a master `FC5` `Write Single Coil` request). Meanwhile, **100% (`39,371 / 39,371` in the substation captures; `105,323 / 105,323` corpus-wide) of the master-to-slave `FC5, modbus_len == 6` request packets that triggered those responses are labelled `0` (Normal)**.
3. **Collapse Without Static Length/Size Fields:** Under Leave-One-Capture-Group-Out (`LOCGO`) cross-validation across all 10 capture groups, an order-invariant, non-temporal Decision Tree (`max_depth=3`) achieves **`F1 = 0.9880` (packet)** and **`F1 = 0.9782` (window)** when `modbus_len`/`packet_size` are included, but **collapses to `F1 = 0.0005` (packet) and `F1 = 0.0292` (window)** when `modbus_len` and `packet_size` are removed.
4. **Absence of Generalizable Temporal Reconnaissance Signal in the Residual `5.01%` (`94` Windows):** The remaining `94` positive windows (`5.01%`) that do not contain `modbus_len == 3` consist of `23` windows containing bulk read requests (`quantity > 1`) and `71` windows containing `event_mapped` single-register polling (`FC1-4, qty <= 1`) matched to `attack_events_mapped.xlsx` under non-constant clock offsets (`-210 min` to `+141.5 min`). A classifier trained strictly on the 12 temporal sequence-dynamics features (`address_delta`, `unique_addresses_last_20`, `register_span_last_20`, `monotonic_scan_fraction`, `polling_interval_drift_cv`, etc.) achieves **`0.0%` recall (`0 / 23` and `0 / 71`)** on both residual cohorts under `LOCGO`.

---

## Section 4 — Research Requirements Matrix (Proposal & TAF vs. Dataset Evidence)

Authoritative requirements were extracted directly from the approved Topic Assessment Form (`IT4010-TAF-2026 J26-CS-318.pdf`) and Harry's individual proposal report (`IT23269002_Charith H..pdf`, September 2026).

| Proposal claim | Evidence required from dataset | Currently available? | Verified? | Limitation |
|---|---|---|---|---|
| **1. Definition of reconnaissance** — Pre-attack intelligence gathering probing function codes (`FC1`–`FC4`), device IDs, and register maps without necessarily causing physical state changes. | Positive class (`label = 1`) representing read-based probing/scanning traffic from attacker/master to PLC/IED targets. | **Partially** (`224` read/polling packets out of `8,637` positives) | **No** (Contradicted on `97.26%` of positives) | `8,400 / 8,637` (`97.26%`) of positive packets are `FC5` (`Write Single Coil`) **slave-to-master 3-byte responses**, not read-based reconnaissance probes. |
| **2. Sequential scanning** — Systematic sequential sweep across register/coil addresses (`reg[t] = reg[t-1] + step`). | Positive windows exhibiting sustained positive `address_delta`, high `monotonic_scan_fraction`, and `exact_step1_scan_fraction`. | **No** (in retained CIC data) | **No** | In `recon_all` (`1,878` windows), mean `monotonic_scan_fraction` is `0.0085` (median `0.0`), *lower* than Normal (`0.1218`), because `98.3%` of positive packets have `register_start == 0`. Only the excluded 14-row `attached_recon_flows.csv` snippet had synthetic sequential sweeps. |
| **3. Register/coil access order** — Abnormal address transition sequences (`address_delta`, `abs_address_delta`, `register_span_last_k`, `unique_addresses_last_k`) distinguish recon from fixed polling loops. | Positive windows showing higher `unique_addresses_last_20` and `register_span_last_20` than normal polling windows. | **Only in Cohort 2 (`23` windows)** | **Partially** (`1.22%` of positive windows) | In Cohort 1 (`1,784` windows, `94.99%`), mean `unique_addresses_last_20` is `1.026` (`register_span = 0.11`). Only Cohort 2 (`23` `qty > 1` windows) has higher `unique_addresses_last_20` (`3.96` vs Normal `1.98`). |
| **4. Polling-rate drift** — Shifts in request frequency (`requests_per_second`) and inter-arrival regularity (`polling_interval_drift_cv`) during active scanning. | Measurable inter-packet timing (`dt_s`) and window duration changes during attack intervals compared to normal polling. | **Yes** (`dt_s` recomputed from `ts_ns`) | **Confounded** | Cohort 1 (`s0004`) has high burst rate (`median 1,252.4 req/s`), but the **exact same high-rate bursts (`median 1,055.6 req/s`) occur in `23,139` normal-labelled master request windows in `s0003`**. |
| **5. Inter-request timing (`dt_s`)** — Accurate chronological time delta between consecutive packets in a communication stream. | Non-negative, chronologically sorted nanosecond timestamps (`ts_ns`) and within-stream `dt_s`. | **Yes** (in `packets_rebuilt.csv`) | **Yes** (`100%` verified) | Old `time_delta` was `0.0` on `67.70%` of rows; rebuilt `dt_s` is `100%` positive (`min = 25.088 µs`, `0` negatives, `56` expected first-packet `NaN`s). |
| **6. Temporal windows ($L=20$, stride $S=5$)** — Fixed-length chronological sliding windows of 20 packets within a single stream. | `window_index.npy` of shape `(N, 20)` with stride `5`, no cross-stream mixing, and non-decreasing timestamps. | **Yes** (`119,237` windows in `rebuilt_sequences`) | **Yes** (`119,237 / 119,237` verified) | `509` windows (`0.43%`) span `> 60 s` (`11` span `> 1 hr`) across capture pauses because windowing does not split on inactivity gaps. |
| **7. LSTM usage** — Recurrent sequence model learning multi-step temporal dependencies across the 20-packet window. | Temporal sequence structure that cannot be trivially solved by a 1-split static threshold on a single packet field. | **Compromised by static shortcut** | **No** | If `modbus_len` or `packet_size` is fed to the LSTM, it learns a trivial static detector (`modbus_len == 3`). If withheld, `LOCGO` performance collapses because `95%` of positives have constant `register_start == 0, quantity == 0`. |
| **8. Packet-level baseline** — Single-packet classifier (Logistic Regression / Decision Tree) evaluated on the same splits. | Packet-level evaluation (`597,135` packets) under `LOCGO`. | **Yes** | **Yes** | A depth-3 Decision Tree on a single packet achieves `F1 = 0.9880` (`Precision = 1.0000`, `Recall = 0.9764`) via `modbus_len == 3`, outperforming any temporal model without static length features. |
| **9. Non-temporal window baseline** — Order-invariant aggregated window baseline (Random Forest / Logistic Regression on window summary statistics). | Window-level evaluation (`119,237` windows) using bag-of-packets min/max/mean/std without sequence order or timing. | **Yes** | **Yes** | Order-invariant Window Decision Tree (`max_depth=3`) achieves `F1 = 0.9782` (`Precision = 1.0000`, `Recall = 0.9574`) under `LOCGO` with `modbus_len`/`packet_size`, proving sequence order is unnecessary for current labels. |
| **10. Session-independent evaluation** — Train/validation/test splits where no capture session or overlapping window leaks across splits. | Grouping by independent capture episode (`capture_group`) rather than random window splitting or global `session_id`. | **Yes** (`10` `capture_group` episodes) | **Yes** (with `6` positive groups) | Global `session_id` is reused across `8` captures, and simultaneous streams (`s0003`/`s0004`) share timestamps. Splitting **must** group by `capture_group` (`G01`..`G10`), not `session_id`. |
| **11. Data sources (CIC Modbus 2023 + Testbed)** — Primary evaluation on CIC Modbus 2023 dataset, with optional controlled Modbus/TCP testbed traffic. | Traceable CIC Modbus 2023 `.pcap` captures and attack logs, plus testbed captures if needed. | **Partial** (Derived CSV/XLSX from 14 CIC `.pcap`s; no raw `.pcap`s or testbed captures yet) | **Partial** | Only derived Excel/CSV files exist locally; raw `.pcap` binaries and full original CIC log folders are absent, and no controlled testbed capture has been recorded yet. |
| **12. Controlled testbed rescue** — Proposal explicitly permits a virtual/local Modbus/TCP master-slave testbed (`pymodbus` + Wireshark/`dumpcap`) to generate controlled scanning scenarios. | Controlled normal polling + diverse reconnaissance patterns sharing identical current-packet framing (`modbus_len == 6`). | **Not yet executed** (Designed in Section 14) | **N/A** | Required to rescue the temporal-reconnaissance hypothesis from CIC's `FC5 + len3` static artifact. |

---

## Section 5 — Independent Reproduction of Rebuilt Dataset Accounting

All checks below were executed independently from scratch by [`run_forensic_audit.py`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/run_forensic_audit.py) directly on [`Pre-processed/rebuilt_sequences/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences) and [`Dataset/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset).

### 5.1 `packets_rebuilt.csv` Accounting

- **Total retained rows:** `597,135`
- **Class counts:**
  - `label = 0` (Normal): `588,498` (`98.5536%`)
  - `label = 1` (Reconnaissance): `8,637` (`1.4464%`)
- **All 18 columns & Null counts:**

| Column | Dtype | Null Count | Forensic Meaning |
|---|---|---:|---|
| `row_index` | `int64` | `0` | 0-based row index in original `recon_labeled_packets_ALL.csv.xlsx` (`0 .. 879,224`) |
| `timestamp` | `str` | `0` | Original ISO-8601 timestamp string (`+05:30` local offset) |
| `ts_ns` | `int64` | `0` | UTC epoch timestamp in nanoseconds |
| `capture_group` | `str` | `0` | Independent capture episode ID (`G01_0122_normal4` .. `G10_0323_veth3e1`) |
| `session_id` | `str` | `0` | Directed `(src_ip, dst_ip, unit_id)` identifier (`s0001` .. `s0013`) |
| `file_source` | `str` | `0` | Source `.pcap` filename (`12` distinct retained files) |
| `src_ip` | `str` | `0` | IPv4 source address (`185.175.0.2` .. `185.175.0.8`) |
| `dst_ip` | `str` | `0` | IPv4 destination address (`185.175.0.2` .. `185.175.0.8`) |
| `unit_id` | `int64` | `0` | Modbus MBAP Unit Identifier (always `1` in retained data) |
| `func_code` | `int64` | `0` | Modbus Function Code (`1, 2, 3, 4, 5, 6`) |
| `modbus_len` | `int64` | `0` | Modbus MBAP Length field in bytes (`3, 4, 5, 6, 43`) |
| `register_start` | `int64` | `0` | Parsed starting register/coil address (`0` for responses) |
| `quantity` | `int64` | `0` | Parsed register/coil count (`0` for responses and `FC5`/`FC6` writes) |
| `packet_size` | `int64` | `0` | Total captured frame size in bytes (`75` .. `402`) |
| `time_delta` | `float64` | `0` | Legacy `time_delta` from old file (`67.70%` zeros — **do not use**) |
| `dt_s` | `float64` | `56` | Recomputed within-stream inter-packet delta in seconds (`NaN` on first packet of each of the `56` streams) |
| `label` | `int64` | `0` | Supplied packet binary label (`0` = Normal, `1` = Recon) |
| `is_fc5_len3` | `bool` | `0` | Diagnostic flag: `(func_code == 5) & (modbus_len == 3)` |

- **Distinct granularity counts:**
  - **Distinct `capture_group`s:** `10` (`G01_0122_normal4` through `G10_0323_veth3e1`)
  - **Distinct `session_id`s:** `13` (`s0001` through `s0013`)
  - **Distinct `(capture_group, session_id)` streams:** `56`
  - **Distinct retained `file_source` files:** `12` (`9` single-file capture groups + `3` kept interface files `veth4edc015-0.pcap`, `veth8bc3408-0.pcap`, `vethd9e14c0-0.pcap` in `G03_0201_veth`)
- **Chronology & Stream Boundary Checks:**
  - **Do timestamps reverse within any `(capture_group, session_id)` stream?** **`False` (`0` reversals across all `56` streams and `597,135` packets).** By contrast, the old `recon_sequences_ALL.csv.xlsx` had **`174,708 / 175,800` (`99.38%`) windows with backward time jumps** and **`67,489` windows where `window_start_time > window_end_time`**.
  - **Is `dt_s < 0` anywhere?** **`0` negative values** (`0` zero values as well; minimum `dt_s` across the entire dataset is `2.5088e-5 s` = `25.088 µs`).
  - **Does the first packet of each stream account for all missing `dt_s`?** **`True` (`100%`).** There are exactly `56` streams and exactly `56` `NaN` values in `dt_s`, occurring at index `0` of each `(capture_group, session_id)` stream (`0` `NaN`s at any non-first packet).
  - **Does any stream cross unrelated source captures?** **`False` (`0` streams).** Every `(capture_group, session_id)` stream is restricted to a single capture episode and a single retained `.pcap` file (`0` streams contain multiple retained `file_source` files). Conversely, if one grouped by `session_id` alone without `capture_group` (as the old pipeline did), **`12 / 13` `session_id`s cross between `2` and `8` separate `.pcap` captures spanning up to `57.657` days**.

#### First and Last Timestamp per Capture Group (`10` Groups)

| Capture Group | Retained Packets | Recon Packets | Streams | Retained Source File(s) | First Timestamp (`+05:30`) | Last Timestamp (`+05:30`) | Duration (s) |
|---|---:|---:|---:|---|---|---|---:|
| `G01_0122_normal4` | 35,000 | 0 | 2 | `veth4edc015-normal-4.pcap` | `2023-01-22T09:40:36.658912+0530` | `2023-01-23T06:48:11.998005+0530` | 76,055.34 |
| `G02_0123_normal13` | 35,000 | 0 | 6 | `veth5bbeaa2-normal-13.pcap` | `2023-01-23T19:22:04.004201+0530` | `2023-01-23T21:01:33.205086+0530` | 5,969.20 |
| `G03_0201_veth` | 282,135 | 50 | 7 | `veth4edc015-0.pcap`, `veth8bc3408-0.pcap`, `vethd9e14c0-0.pcap` | `2023-02-01T09:18:39.921812+0530` | `2023-02-01T19:31:50.737508+0530` | 36,790.82 |
| `G04_0315_sub1` | 35,000 | 2,001 | 5 | `substation-1.pcap` | `2023-03-15T14:23:29.791436+0530` | `2023-03-15T16:30:08.655967+0530` | 7,598.86 |
| `G05_0315_sub2` | 35,000 | 136 | 6 | `substation-2.pcap` | `2023-03-16T00:32:50.918917+0530` | `2023-03-16T02:26:16.659313+0530` | 6,805.74 |
| `G06_0316_sub4` | 35,000 | 2,140 | 6 | `substation-4.pcap` | `2023-03-16T22:53:27.185458+0530` | `2023-03-17T00:24:32.113512+0530` | 5,464.93 |
| `G07_0319_sub10` | 35,000 | 2,185 | 6 | `substation-10.pcap` | `2023-03-19T07:26:44.444617+0530` | `2023-03-19T08:33:09.884694+0530` | 3,985.44 |
| `G08_0320_sub14` | 35,000 | 2,125 | 6 | `substation-14.pcap` | `2023-03-21T00:11:35.636468+0530` | `2023-03-21T01:27:04.268510+0530` | 4,528.63 |
| `G09_0323_veth3e0` | 35,000 | 0 | 6 | `veth3efd353-0.pcap` | `2023-03-23T08:01:40.940955+0530` | `2023-03-23T09:41:05.198011+0530` | 5,964.26 |
| `G10_0323_veth3e1` | 35,000 | 0 | 6 | `veth3efd353-1.pcap` | `2023-03-23T15:40:37.200544+0530` | `2023-03-23T17:19:42.813745+0530` | 5,945.61 |

#### First and Last Timestamp per Global `session_id` (`13` Retained IDs)

| `session_id` | Packets | Recon Packets | Capture Groups Spanned | First Timestamp (`+05:30`) | Last Timestamp (`+05:30`) | Total Span (Days) |
|---|---:|---:|---:|---|---|---:|
| `185.175.0.3_185.175.0.4_u1_s0001` | 94,609 | 29 | 8 | `2023-01-22T09:40:36.658912+0530` | `2023-03-21T01:27:03.391897+0530` | 57.657 |
| `185.175.0.4_185.175.0.3_u1_s0002` | 79,823 | 33 | 8 | `2023-01-22T09:40:36.659756+0530` | `2023-03-21T01:27:03.392319+0530` | 57.657 |
| `185.175.0.3_185.175.0.5_u1_s0003` | 86,345 | 48 | 7 | `2023-01-23T19:22:04.004201+0530` | `2023-03-21T01:26:59.539827+0530` | 56.253 |
| `185.175.0.5_185.175.0.3_u1_s0004` | 86,269 | **8,432** | 7 | `2023-01-23T19:22:04.004676+0530` | `2023-03-21T01:26:59.540300+0530` | 56.253 |
| `185.175.0.3_185.175.0.8_u1_s0005` | 58,858 | 20 | 7 | `2023-01-23T19:22:07.164175+0530` | `2023-03-21T01:27:04.268510+0530` | 56.253 |
| `185.175.0.8_185.175.0.3_u1_s0006` | 55,621 | 25 | 6 | `2023-01-23T19:22:07.165952+0530` | `2023-03-21T01:27:04.247860+0530` | 56.253 |
| `185.175.0.7_185.175.0.4_u1_s0007` | 65,610 | 50 | 1 | `2023-02-01T09:21:37.648705+0530` | `2023-02-01T18:52:13.415267+0530` | 0.396 |
| `185.175.0.2_185.175.0.5_u1_s0008` | 11,701 | 0 | 2 | `2023-03-23T08:01:40.940955+0530` | `2023-03-23T17:19:42.806734+0530` | 0.388 |
| `185.175.0.5_185.175.0.2_u1_s0009` | 11,701 | 0 | 2 | `2023-03-23T08:01:40.941231+0530` | `2023-03-23T17:19:42.813745+0530` | 0.388 |
| `185.175.0.2_185.175.0.4_u1_s0010` | 11,670 | 0 | 2 | `2023-03-23T08:01:51.912476+0530` | `2023-03-23T17:19:38.109566+0530` | 0.387 |
| `185.175.0.4_185.175.0.2_u1_s0011` | 11,670 | 0 | 2 | `2023-03-23T08:01:51.958807+0530` | `2023-03-23T17:19:38.110037+0530` | 0.387 |
| `185.175.0.2_185.175.0.8_u1_s0012` | 11,630 | 0 | 2 | `2023-03-23T08:02:03.873708+0530` | `2023-03-23T17:19:38.343412+0530` | 0.387 |
| `185.175.0.8_185.175.0.2_u1_s0013` | 11,628 | 0 | 2 | `2023-03-23T08:02:36.810879+0530` | `2023-03-23T17:19:38.343946+0530` | 0.387 |

---

### 5.2 `packet_exclusions.csv` Accounting & Independent Evidence Check

- **Total excluded rows:** `282,090`
- **Exclusion reasons & exact counts:**
  1. `duplicate_interface_view`: `282,076` rows (`282,026` normal + `50` positive)
  2. `excluded_file`: `14` rows (`2` normal + `12` positive from `attached_recon_flows.csv`)
- **Population conservation check:**
  - Retained (`597,135`) + Excluded (`282,090`) = **`879,225`** (exact row count of `recon_labeled_packets_ALL.csv.xlsx`).
  - Duplicate `row_index` in retained: `0`.
  - Duplicate `row_index` in excluded: `0`.
  - Overlap between retained and excluded `row_index`: `0`.
  - Missing original `row_index` in `{0 .. 879,224}`: `0` (`exact_reproduction_of_original_packet_population = True`).
- **Verification of the 14 `attached_recon_flows.csv` exclusions:**
  - All 14 rows (`row_index` `879,211 .. 879,224`) have `file_source == "attached_recon_flows.csv"`, time-of-day-only strings (`00:31:01.700000 .. 00:32:18.900000`) with **no calendar date**, use a non-CIC subnet (`192.168.10.50 -> 192.168.10.10/11/12`), and split across 4 tiny sessions (`2` to `4` packets each, all `< 20` packets). Excluding them is mandatory and verified.
- **Independent Verification of the `282,076` `duplicate_interface_view` Exclusions:**
  - Rather than trusting the exclusion label, [`run_forensic_audit.py`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/run_forensic_audit.py) matched every one of the `282,076` excluded rows (from `veth5bbeaa2-0.pcap` [`216,466` rows] and `veth665f3cf-0.pcap` [`65,610` rows]) against the kept packets in `G03_0201_veth` (`veth4edc015-0.pcap`, `veth8bc3408-0.pcap`, `vethd9e14c0-0.pcap`) requiring **exact equality on all 10 packet attributes** (`session_id, src_ip, dst_ip, unit_id, func_code, register_start, quantity, modbus_len, packet_size, label`):
    - **Matched within `<= 1 ms` (`1,000 µs`):** **`282,076 / 282,076` (`100.0000%`)** (`0` unmatched packets, `0` label disagreements).
    - **Time-delta distribution between dropped and kept interface views:**
      - `<= 50 µs`: `281,672 / 282,076` (`99.86%`)
      - `<= 100 µs`: `281,992 / 282,076` (`99.97%`)
      - **Median timestamp delta:** **`6.0 µs`**
      - **95th percentile delta:** **`13.0 µs`**
      - **Maximum delta:** **`535.0 µs`** (`0.535 ms`)
  - **Forensic Explanation:** On `2023-02-01`, CIC captured the same Docker virtual Ethernet bridge simultaneously on the SCADA master interface (`veth5bbeaa2-0.pcap` / `veth665f3cf-0.pcap`) and the individual IED container interfaces (`veth4edc015-0.pcap`, `vethd9e14c0-0.pcap`, `veth8bc3408-0.pcap`). Every packet traversing the bridge was recorded twice, `~6 µs` apart. Retaining both views in the old dataset duplicated `282,076` packets and caused severe intra-session timestamp jitter when concatenated. The rebuild's deduplication is 100% empirically verified.

---

### 5.3 `window_index.npy` + `windows.csv` Full 100% Validation (`119,237` Windows)

Every single window (`119,237 / 119,237`) was verified programmatically (full report in [`window_integrity_report.json`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/window_integrity_report.json)):

| Validation Check | Expected | Observed Across All 119,237 Windows | Status |
|---|---|---|---|
| `window_index.npy` shape | `(119237, 20)` | `[119237, 20]` (`int32`) | **PASS (`100%`)** |
| Exactly 20 packet indices per window | `True` | `True` (`20` contiguous rows `[a .. a+19]` per window) | **PASS (`100%`)** |
| Intra-stream stride | `5` | `True` (`100%` of consecutive intra-stream windows step by `+5`) | **PASS (`100%`)** |
| All indices valid (`0 <= idx < 597,135`) | `True` | `True` (`min = 0`, `max = 597,134`) | **PASS (`100%`)** |
| Duplicate indices within any window | `0` | `0` windows with duplicate indices | **PASS (`100%`)** |
| All 20 packets in same `capture_group` | `True` | `True` (`119,237 / 119,237` windows) | **PASS (`100%`)** |
| All 20 packets in same `session_id` | `True` | `True` (`119,237 / 119,237` windows) | **PASS (`100%`)** |
| Non-decreasing timestamps (`dt >= 0`) | `True` | `True` (`0` windows with timestamp reversal) | **PASS (`100%`)** |
| `start_ns` matches 1st packet `ts_ns` | `True` | `True` (`119,237 / 119,237`) | **PASS (`100%`)** |
| `end_ns` matches 20th packet `ts_ns` | `True` | `True` (`119,237 / 119,237`) | **PASS (`100%`)** |
| `first_row_index` / `last_row_index` match | `True` | `True` (`119,237 / 119,237` match original `row_index`) | **PASS (`100%`)** |
| `n_pos_packets` matches sum of packet labels | `True` | `True` (`119,237 / 119,237`) | **PASS (`100%`)** |
| `pos_packet_fraction` matches `n_pos / 20.0` | `True` | `True` (`119,237 / 119,237`) | **PASS (`100%`)** |
| Window `label` matches `n_pos_packets >= 1` | `True` | `True` (`1,878` positive windows, `117,359` normal windows) | **PASS (`100%`)** |
| `n_fc5_len3_packets` matches packet data | `True` | `True` (`119,237 / 119,237`) | **PASS (`100%`)** |

#### Window Duration & Intra-Window Inactivity Gap Statistics (`119,237` Windows)

| Metric | Window Total Duration (`end_ns - start_ns`) | Max Intra-Window Single Step Gap (`max(dt_s)`) |
|---|---:|---:|
| **Minimum** | `0.000952 s` (`0.952 ms`) | `0.000189 s` (`0.189 ms`) |
| **5th Percentile (P05)** | `0.006602 s` (`6.60 ms`) | — |
| **25th Percentile (P25)** | `15.361765 s` | — |
| **Median (P50)** | **`20.346471 s`** | **`5.006739 s`** |
| **Mean** | `21.129968 s` | — |
| **75th Percentile (P75)** | `20.364458 s` | — |
| **95th Percentile (P95)** | **`20.600252 s`** | **`5.039046 s`** |
| **99th Percentile (P99)** | **`21.836018 s`** | **`5.150463 s`** |
| **Maximum** | **`58,170.755657 s` (`16.16 hours`)** | **`58,155.337023 s` (`16.15 hours`)** |
| **Count `> 1 second`** | `98,216` (`82.37%`) | `97,885` (`82.09%`) |
| **Count `> 5 seconds`** | `96,477` (`80.91%`) | `96,476` (`80.91%`) |
| **Count `> 1 minute` (`60 s`)** | **`509` (`0.427%`)** | **`91` (`0.076%`)** |
| **Count `> 5 minutes` (`300 s`)** | **`88` (`0.074%`)** | **`76` (`0.064%`)** |
| **Count `> 1 hour` (`3600 s`)** | **`11` (`0.0092%`)** | **`11` (`0.0092%`)** |

> [!WARNING]
> **Flagged Inactivity Gaps Inside Rebuilt Windows:**  
> While normal routine polling in CICModbus2023 consists of 4-packet polling bursts every `~5.0 s` (making a 20-packet window naturally span `~20.35 s`), **`509` windows (`0.43%`) span `> 1 minute`**, **`88` span `> 5 minutes`**, and **`11` windows bridge multi-hour recording pauses (`> 1 hour`)** within a single `.pcap` file:
> 1. **`G01_0122_normal4` (`8` windows: `w000934`–`w000937` in `s0001` and `w004431`–`w004434` in `s0002`):** Bridge a **`58,155.3 s` (`16.15 hour`)** capture pause between `2023-01-22 05:31:24 UTC` and `2023-01-22 21:40:39 UTC`.
> 2. **`G03_0201_veth` (`3` positive windows: `w050067`–`w050069` in `s0007`):** Bridge a **`30,368.6 s` (`8.44 hour`)** pause between `2023-02-01 04:38 UTC` and `2023-02-01 13:04 UTC` in the sparse `185.175.0.7 -> 185.175.0.4` stream.
> 3. **Substation captures (`G04_0315_sub1`, `G05_0315_sub2`, `G06_0316_sub4`):** `69` windows bridge `2-minute` to `10-minute` (`131 s` to `610 s`) pauses in `s0002`, `s0005`, and `s0006`.

---

## Section 6 — Forensic Determination of What `session_id` Actually Means

1. **Exact Construction Formula:**  
   In [`packets_rebuilt.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences/packets_rebuilt.csv) (inherited from `recon_labeled_packets_ALL.csv.xlsx`), `session_id` is a string formatted as:
   $$\texttt{session\_id} = \texttt{<src\_ip>\_<dst\_ip>\_u<unit\_id>\_s<0001..0013>}$$
2. **Exact 1-to-1 Bijection Proof:**  
   Across all `597,135` retained packets, there are exactly **`13` distinct `(src_ip, dst_ip, unit_id)` triples** and **`13` distinct `session_id` values** (`is_exact_1to1_bijection_with_src_ip_dst_ip_unit_id = True`). In the raw dataset including the excluded `attached_recon_flows.csv`, there are `17` `(src_ip, dst_ip, unit_id)` triples and `17` `session_id`s (because 4 `192.168.10.x` pairs in `attached_recon_flows.csv` reused suffixes `_s0001.._s0004` with different IP prefixes).
3. **What `session_id` Represents (and What It Does NOT Represent):**
   - **Actual TCP connection?** **NO.** Neither `src_port` nor `dst_port` nor TCP stream/SYN-FIN state exists in the dataset.
   - **Capture-local communication stream?** **NO.** `12` of the `13` retained `session_id`s are reused across `2` to `8` completely separate `.pcap` files recorded across January, February, and March 2023 (spanning up to `57.66` days).
   - **Directed logical endpoint pair + unit ID?** **YES.** `session_id` is strictly a **global directed `(src_ip, dst_ip, unit_id)` identifier**.
   - **Capture-local communication stream in the rebuild:** Only the composite key **`stream_id = (capture_group, session_id)`** (`56` distinct streams) is capture-local.
4. **Implication for `GroupKFold` / Session-Independent Evaluation:**  
   - **Splitting by `session_id` is scientifically invalid** for two independent reasons:
     1. A single `session_id` (`185.175.0.5_185.175.0.3_u1_s0004`) contains **`97.63%` (`8,432 / 8,637`) of all positive packets** and **`94.20%` (`1,769 / 1,878`) of all positive windows**. Holding out `s0004` puts `97.6%` of positives in one fold and starves training folds of positives.
     2. Within any capture (e.g., `G04_0315_sub1`), the 6 directional streams (`s0001..s0006`) are simultaneous request/response halves of the same SCADA master polling the same 3 IEDs at the exact same millisecond timestamps. Putting `s0003` (`185.175.0.3 -> 185.175.0.5` requests) in train and `s0004` (`185.175.0.5 -> 185.175.0.3` responses) in test splits simultaneous transactions from the same capture across train and test.
   - Therefore, any valid leak-free split **must group by `capture_group` (`G01`..`G10`) or by recording campaign**.

---

## Section 7 — Audit of the Reconnaissance Labels & Source Lineage

### 7.1 What Original Evidence Exists in the Workspace

1. **No Raw `.pcap` Files Exist on Disk:** Only the three derived workbooks in [`Dataset/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset) (`recon_labeled_packets_ALL.csv.xlsx`, `recon_sequences_ALL.csv.xlsx`, and `attack_events_mapped.xlsx`) and the rebuilt files in [`Pre-processed/rebuilt_sequences/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences) are present on the filesystem.
2. **Structure of [`Dataset/attack_events_mapped.xlsx`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset/attack_events_mapped.xlsx):**
   - Contains **158 rows** and **10 columns**: `packet_timestamp`, `packet_epoch`, `src_ip`, `dst_ip`, `func_code`, `quantity`, `file_source`, `log_attack`, `log_timestamp`, `log_file`.
   - Covers **only 2 of the 6 positive capture groups**: `substation-2.pcap` (`G05_0315_sub2`, `107` rows) and `substation-10.pcap` (`G07_0319_sub10`, `51` rows).
   - References **2 original CIC attack log paths**:
     - `attack\compromised-scada\attack logs\03-15-2023\03-15-2023-1.csv` (`107` packet rows mapped to `6` log timestamps labeled `"Recon. Complete"` or `"Recon. Range: 2000"`)
     - `attack\compromised-scada\attack logs\03-19-2023\03-19-2023-1.csv` (`51` packet rows mapped to `2` log timestamps labeled `"Recon. Complete"` or `"Recon. Range: 2000"`)
   - **Zero rows in `attack_events_mapped.xlsx` exist for:**
     - `G04_0315_sub1` (`substation-1.pcap`, `2,001` positive packets)
     - `G06_0316_sub4` (`substation-4.pcap`, `2,140` positive packets)
     - `G08_0320_sub14` (`substation-14.pcap`, `2,125` positive packets)
     - `G03_0201_veth` (`veth4edc015-0.pcap`, `50` retained positive packets)
     - Or for the `2,130` `modbus_len == 3` positive packets inside `substation-10.pcap` and `17` `modbus_len == 3` positive packets inside `substation-2.pcap`!

### 7.2 Complete Reconstruction of the Label-Generation Rule (`label = 1`)

Across all `879,225` raw packets (`8,699` positive) and `597,135` retained rebuilt packets (`8,637` positive), **100% of positive labels (`8,637 / 8,637` retained; `8,699 / 8,699` raw)** are generated by the union of four mutually exclusive empirical rules:

| Forensic Category | Raw Positives | Retained Positives | % of Retained Positives | Reconstructed Label Rule | Original Log Evidence in `attack_events_mapped.xlsx`? |
|---|---:|---:|---:|---|---|
| **Category 1 (`cat1_fc5_len3_75b_response`)** | `8,400` | **`8,400`** | **`97.2560%`** | `func_code == 5 AND modbus_len == 3` (`packet_size == 75`, slave $\to$ master response in `substation-1, 2, 4, 10, 14`) | **NO (`0 / 8,400` rows in log map)** |
| **Category 1b (`cat1b_fc1to4_len3_75b_response`)** | `13` | **`13`** | **`0.1505%`** | `func_code in {1,2,3,4} AND modbus_len == 3` (`packet_size == 75`, slave $\to$ master response in `substation-2, 10`) | **NO (`0 / 13` rows in log map)** |
| **Category 3 (`cat3_event_mapped_substation2_substation10`)** | `158` | **`158`** | **`1.8293%`** | Exact `(timestamp, src_ip, dst_ip)` match to the `158` rows in `attack_events_mapped.xlsx` (`substation-2, 10`) | **YES (`158 / 158`, but with variable clock offsets `-210m` to `+141.5m`)** |
| **Category 2 (`cat2_nonroutine_quantity_gt1_read`)** | `116` (`50` dup dropped) | **`66`** | **`0.7642%`** | `func_code in {1,2,3,4} AND quantity in {4,5,20,125,2000,65535}` in `G03_0201_veth` (`50`), `substation-2` (`12`), `substation-10` (`4`) | **NO (`0 / 66` rows in log map; 11 other `qty>1` rows are inside Category 3)** |
| **Excluded (`attached_recon_flows.csv`)** | `12` (`12` excluded) | **`0`** | **`0.0000%`** | External 14-row lab snippet on `192.168.10.x` with no date (`12` positive rows) | **NO (`0` rows in log map)** |
| **TOTAL** | **`8,699`** | **`8,637`** | **`100.0000%`** | **100% of positive labels accounted for** | Only `158 / 8,637` (`1.83%`) link to `attack_events_mapped.xlsx` |

### 7.3 Per-Capture-Group Positive Provenance Summary

The full 91-row cohort lineage table is saved in [`positive_lineage.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/positive_lineage.csv), and the per-group summary is saved in [`capture_group_summary.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/capture_group_summary.csv). Representative lineage rows across all 6 positive capture groups:

| Rebuilt positive row | Capture group | Source PCAP | Frame / packet identity | Original log evidence | Label rule | Confidence |
|---:|---|---|---|---|---|---|
| `250516` | `G03_0201_veth` | `veth4edc015-0.pcap` | `185.175.0.7->185.175.0.4 \| ts=2023-02-01T09:21:37.648705+0530 \| FC=1 reg=0 qty=65535 len=6 size=78B` | `0` rows in `attack_events_mapped.xlsx` | Rule B: Non-routine `quantity > 1` read (`50` retained packets in `s0007`) | **MODERATE-HIGH** (Genuine abnormal read parameters `qty in {4,5,20,65535}`, but no log file provided) |
| `383444` | `G04_0315_sub1` | `substation-1.pcap` | `185.175.0.5->185.175.0.3 \| ts=2023-03-15T16:29:25.341589+0530 \| FC=5 reg=0 qty=0 len=3 size=75B` | `0` rows in `attack_events_mapped.xlsx` | Rule A1: Static signature `FC5 AND modbus_len == 3` (`2,001` packets) | **CRITICAL SHORTCUT / QUESTIONABLE** (Slave response to unlabelled master `FC5` coil write) |
| `393524` | `G05_0315_sub2` | `substation-2.pcap` | `185.175.0.3->185.175.0.4 \| ts=2023-03-16T01:19:05.273599+0530 \| FC=3 reg=8 qty=1 len=6 size=78B` | Matched to `03-15-2023-1.csv` (`Recon. Complete`, log ts `17:27:36`, offset `+141.5 min`) | Rule C: Direct lookup in `attack_events_mapped.xlsx` (`107` packets) | **LOW-MODERATE** (Routine polling shape `FC3 reg=8 qty=1`; non-constant clock offset) |
| `401405` | `G05_0315_sub2` | `substation-2.pcap` | `185.175.0.3->185.175.0.5 \| ts=2023-03-16T01:53:44.717231+0530 \| FC=1 reg=1 qty=2000 len=6 size=78B` | Co-occurs with `Recon. Range: 2000` burst (`03-15-2023-1.csv`) | Rule B: Non-routine `quantity > 1` read (`qty=2000` / `qty=125`, `12` packets) | **HIGH** (Directly matches `Recon. Range: 2000` multi-register scan semantics) |
| `418018` | `G05_0315_sub2` | `substation-2.pcap` | `185.175.0.5->185.175.0.3 \| ts=2023-03-16T01:53:44.717483+0530 \| FC=1 reg=0 qty=0 len=3 size=75B` | `0.252 ms` after row `401405` (`FC1 qty=2000` request) | Rule A2: Slave `modbus_len == 3` exception response (`FC1..4, len=3`, `12` packets) | **HIGH (as exception response to `qty=2000` scan)**, but creates `len=3` static shortcut |
| `444813` | `G06_0316_sub4` | `substation-4.pcap` | `185.175.0.5->185.175.0.3 \| ts=2023-03-16T23:01:00.346023+0530 \| FC=5 reg=0 qty=0 len=3 size=75B` | `0` rows in `attack_events_mapped.xlsx` | Rule A1: Static signature `FC5 AND modbus_len == 3` (`2,140` packets) | **CRITICAL SHORTCUT / QUESTIONABLE** (Slave response to unlabelled master `FC5` coil write) |
| `481305` | `G07_0319_sub10` | `substation-10.pcap` | `185.175.0.5->185.175.0.3 \| ts=2023-03-19T07:45:55.101026+0530 \| FC=5 reg=0 qty=0 len=3 size=75B` | `0` rows in `attack_events_mapped.xlsx` for `FC5` (`51` rows for `FC1-4` at `08:32`) | Rule A1: Static signature `FC5 AND modbus_len == 3` (`2,129` packets) | **CRITICAL SHORTCUT / QUESTIONABLE** (Occurs 47 min before the logged `08:32` recon burst) |
| `518968` | `G08_0320_sub14` | `substation-14.pcap` | `185.175.0.5->185.175.0.3 \| ts=2023-03-21T00:55:36.200672+0530 \| FC=5 reg=0 qty=0 len=3 size=75B` | `0` rows in `attack_events_mapped.xlsx` | Rule A1: Static signature `FC5 AND modbus_len == 3` (`2,125` packets) | **CRITICAL SHORTCUT / QUESTIONABLE** (Slave response to unlabelled master `FC5` coil write) |

---

## Section 8 — Investigation of the `FC5 + modbus_len == 3` Phenomenon

### 8.1 Complete Distributions: Normal (`588,498`) vs. Reconnaissance (`8,637`)

#### A. Function Code (`func_code`) Distribution
| `func_code` | Modbus Function Name | Normal Packets (`label=0`) | Normal % | Recon Packets (`label=1`) | Recon % |
|---:|---|---:|---:|---:|---:|
| `1` | Read Coils | 191,990 | 32.62% | 75 | 0.87% |
| `2` | Read Discrete Inputs | 96,059 | 16.32% | 61 | 0.71% |
| `3` | Read Holding Registers | 98,410 | 16.72% | 43 | 0.50% |
| `4` | Read Input Registers | 96,116 | 16.33% | 58 | 0.67% |
| **`5`** | **Write Single Coil** | **105,323** | **17.90%** | **`8,400`** | **`97.26%`** |
| `6` | Write Single Register | 600 | 0.10% | 0 | 0.00% |

#### B. Modbus MBAP Length (`modbus_len`) Distribution
| `modbus_len` | Protocol Meaning | Normal Packets (`label=0`) | Normal % | Recon Packets (`label=1`) | Recon % |
|---:|---|---:|---:|---:|---:|
| **`3`** | **1B Unit ID + 2B PDU (Exception / 2B Response)** | **`0`** | **`0.00%`** | **`8,413`** | **`97.41%`** |
| `4` | 1B Unit ID + 3B PDU (`FC1`/`FC2` 1-byte coil/discrete response) | 143,860 | 24.45% | 47 | 0.54% |
| `5` | 1B Unit ID + 4B PDU (`FC3`/`FC4` 2-byte register response) | 95,977 | 16.31% | 30 | 0.35% |
| `6` | 1B Unit ID + 5B PDU (Standard `FC1`–`FC6` request or `FC5`/`FC6` echo) | 348,585 | 59.23% | 147 | 1.70% |
| `43` | 1B Unit ID + 42B PDU (`FC3`/`FC4` 20-register read response) | 76 | 0.01% | 0 | 0.00% |

#### C. Joint `(func_code, modbus_len)` and `packet_size` Distribution
| Joint `(func_code, modbus_len, packet_size)` | Normal Packets (`label=0`) | Recon Packets (`label=1`) | Positive Class Share |
|---|---:|---:|---:|
| **`(FC=5, modbus_len=3, packet_size=75)`** | **`0`** | **`8,400`** | **`97.2560%`** |
| **`(FC in {1,2,3,4}, modbus_len=3, packet_size=75)`** | **`0`** | **`13`** | **`0.1505%`** |
| `(FC=5, modbus_len=6, packet_size=78)` | `105,323` | `0` | `0.0000%` |
| `(FC in {1,2}, modbus_len=4, packet_size=76)` | `143,860` | `47` | `0.5442%` |
| `(FC in {3,4}, modbus_len=5, packet_size=77)` | `95,977` | `30` | `0.3473%` |
| `(FC in {1..4}, modbus_len=6, packet_size=78, qty=1)` | `242,082` | `81` | `0.9378%` |
| `(FC in {1..4}, modbus_len=6, packet_size in {78,342}, qty>1)` | `459` | `66` | `0.7642%` |

#### D. Specific Quantification Requested in Section 8
- **Positive packets with `FC5 + len3`:** **`8,400 / 8,637` (`97.2560%`)** (plus `13` `FC1-4 + len3` = `8,413 / 8,637` [`97.4065%`] with `modbus_len == 3`).
- **Normal packets with `FC5 + len3`:** **`0 / 588,498` (`0.0000%`)** (`0` normal packets have `modbus_len == 3` or `packet_size == 75` for any function code).
- **Positive windows containing $\ge 1$ `FC5 + len3` packet:** **`1,769 / 1,878` (`94.1960%`)** (and **`1,784 / 1,878` [`94.9947%`]** contain $\ge 1$ `modbus_len == 3` packet).
- **Normal windows containing $\ge 1$ `FC5 + len3` packet:** **`0 / 117,359` (`0.0000%`)**.

---

### 8.2 Neighboring Packet Trace & Protocol Forensics: Why Do `FC5 + len3` Packets Exist?

By sorting each substation capture (`G04_0315_sub1` through `G08_0320_sub14`) chronologically across all streams and inspecting the packet immediately preceding each `FC5 + len3` packet (full trace in `audit_metrics.json -> fc5_neighbor_request_response_pairing`), we uncover the exact transaction mechanics:

| Capture Group (`file_source`) | Master $\to$ Slave `FC5, len=6, size=78B` Requests (`label=0`) | Slave $\to$ Master `FC5, len=3, size=75B` Responses (`label=1`) | Median Request $\to$ Response Delay | Example Paired Transaction (`Request [label=0]` $\to$ `Response [label=1]`) |
|---|---:|---:|---:|---|
| `G04_0315_sub1` (`substation-1.pcap`) | `9,452` (`100%` `label=0`) | `2,001` (`100%` `label=1`) | `0.219 ms` | `row 289464`: `185.175.0.3->185.175.0.5 FC=5 len=6 reg=1 qty=0 size=78B (label=0)` $\to$ `+0.437 ms` $\to$ `row 412028`: `185.175.0.5->185.175.0.3 FC=5 len=3 reg=0 qty=0 size=75B (label=1)` |
| `G05_0315_sub2` (`substation-2.pcap`) | `6,526` (`100%` `label=0`) | `5` (`100%` `label=1`) | `1.169 ms` | `row 512275`: `185.175.0.3->185.175.0.8 FC=5 len=6 reg=13 qty=0 size=78B (label=0)` $\to$ `+18.825 ms` $\to$ `row 606758`: `185.175.0.8->185.175.0.3 FC=5 len=3 reg=0 qty=0 size=75B (label=1)` |
| `G06_0316_sub4` (`substation-4.pcap`) | `7,829` (`100%` `label=0`) | `2,140` (`100%` `label=1`) | `0.234 ms` | `row 367328`: `185.175.0.3->185.175.0.5 FC=5 len=6 reg=14 qty=0 size=78B (label=0)` $\to$ `+0.084 ms` $\to$ `row 452228`: `185.175.0.5->185.175.0.3 FC=5 len=3 reg=0 qty=0 size=75B (label=1)` |
| `G07_0319_sub10` (`substation-10.pcap`) | `9,401` (`100%` `label=0`) | `2,129` (`100%` `label=1`) | `0.246 ms` | `row 308887`: `185.175.0.3->185.175.0.5 FC=5 len=6 reg=1 qty=0 size=78B (label=0)` $\to$ `+0.414 ms` $\to$ `row 431445`: `185.175.0.5->185.175.0.3 FC=5 len=3 reg=0 qty=0 size=75B (label=1)` |
| `G08_0320_sub14` (`substation-14.pcap`) | `6,163` (`100%` `label=0`) | `2,125` (`100%` `label=1`) | `0.267 ms` | `row 326621`: `185.175.0.3->185.175.0.5 FC=5 len=6 reg=1 qty=0 size=78B (label=0)` $\to$ `+1.015 ms` $\to$ `row 449180`: `185.175.0.5->185.175.0.3 FC=5 len=3 reg=0 qty=0 size=75B (label=1)` |

#### Concrete Evidence-Based Answers to Questions 8A–8G

- **A. Are these genuinely part of the CIC reconnaissance scenario?**  
  **No for the `8,400` `FC5 + len3` packets; Yes for the `12` `FC1-4 + len3` packets in `substation-2.pcap`.**  
  In `substation-2.pcap` (`G05_0315_sub2`), the `12` `FC1-4 + len3` packets (`row_index 488815`, etc.) occur at `01:53:44.717483+0530` and `02:19:44.726133+0530`, **exactly `0.25 ms` after the SCADA master (`185.175.0.3`) sends `FC1/FC3/FC4` requests with `quantity = 2000` or `quantity = 125`** (which match the `Recon. Range: 2000` attack log entries in `attack_events_mapped.xlsx`). When the master asks for 2000 coils (`reg=1, qty=2000`), the IED (`185.175.0.5` / `185.175.0.8`) rejects the out-of-range read with a **3-byte Modbus Exception Response (`modbus_len == 3`, `packet_size == 75`)**.  
  By contrast, the `8,400` `FC5 + len3` packets are responses to high-rate `FC5` (`Write Single Coil`) floods targeting a fixed set of 5–6 coil addresses (`{1, 5, 13, 14, 15, 25}`) and have **zero corresponding entries in `attack_events_mapped.xlsx`**.
- **B. If yes, what reconnaissance behaviour do they represent?**  
  The `13` `FC1-4 + len3` packets are **slave exception responses (`Illegal Data Address`)** triggered when an attacker probes beyond the IED's valid register/coil map (`quantity = 2000` or `125`). The `8,400` `FC5 + len3` packets are **slave responses to repeated `Write Single Coil` (`FC5`) commands** on coils `{1, 5, 13, 14, 15, 25}`—which is coil-write/command-injection or write-flooding behavior, not read reconnaissance.
- **C. Are they malformed or unusual Modbus requests?**  
  **They are not requests at all—they are Slave-to-Master responses (`185.175.0.5 -> 185.175.0.3`, `185.175.0.4 -> 185.175.0.3`, `185.175.0.8 -> 185.175.0.3`).**  
  In Modbus/TCP, a standard `FC5` request or normal `FC5` echo response has `modbus_len = 6` (`1B unit_id + 1B func_code + 2B address + 2B value`, frame size `78B`). A response with `modbus_len = 3` (`1B unit_id + 2B PDU`, frame size `75B = 78B - 3B`) is the standard framing of a **Modbus Exception Response** (`1B unit_id + 1B (func_code | 0x80) + 1B exception_code`), where the upstream feature extractor stripped the high exception bit (`0x85 & 0x7F = 5`) into `func_code` and filled `register_start = 0, quantity = 0` because an exception PDU has no address or quantity bytes.
- **D. Are they actually reconnaissance, or could another CIC attack class have been accidentally mixed into the recon label?**  
  **Another attack class / heuristic rule was mixed into the positive label.** Specifically, whoever created `recon_labeled_packets_ALL.csv.xlsx` observed that during the `Recon. Range: 2000` scan in `substation-2.pcap`, the IED returned `modbus_len == 3` exception responses (`FC1..4, len=3`), and **applied a blanket rule labeling all `modbus_len == 3` packets (`8,413` packets) as `label = 1`**, which inadvertently swept in `8,400` `FC5, modbus_len == 3` coil-write exception responses across `substation-1, 2, 4, 10, 14`!
- **E. Were they labelled reconnaissance merely because they occurred inside a reconnaissance capture/time interval?**  
  **No—even worse: they were labelled by a static packet filter (`modbus_len == 3`), NOT by a time interval!**  
  We can prove this with 100% certainty because at the exact same millisecond (`0.22 ms` earlier), the master's `FC5, modbus_len == 6` request packet (`185.175.0.3 -> 185.175.0.5`) and interleaved `FC1..4, modbus_len == 6` packets occurring inside the exact same burst are labelled **`label = 0` (Normal)**. If an interval rule had been used, both the request and response inside the interval would be labelled `1`.
- **F. Does CIC's own documentation support treating each such packet as reconnaissance?**  
  **No.** In `attack_events_mapped.xlsx`, the CIC attack logs (`03-15-2023-1.csv` and `03-19-2023-1.csv`) log reconnaissance events as `"Recon. Complete"` and `"Recon. Range: 2000"` on read function codes (`FC1, FC2, FC3, FC4`). Neither CIC's log entries in `attack_events_mapped.xlsx` nor standard ICS taxonomy treats slave `FC5` coil-write responses—while ignoring the master's requests—as reconnaissance.
- **G. Could legitimate normal traffic ever produce the same current-message signature?**  
  In this dataset, **`0` out of `588,498` normal packets** produce `modbus_len == 3` (`packet_size == 75`), because normal SCADA polling only reads valid configured registers (`{1, 5, 8, 13, 14, 15, 25, 35}` with `qty = 1`), and normal `FC5` writes in `G03_0201_veth` receive standard `modbus_len == 6` echo responses (`105,323` normal packets). However, in a real industrial network, any misconfigured HMI/PLC query or transient slave exception (`Server Device Busy 0x06`, `Slave Device Failure 0x04`) produces a `modbus_len == 3` exception frame, meaning a model that learns `modbus_len == 3` as a shortcut will trigger false alarms on any benign device exception while completely missing valid-address reconnaissance scans (`modbus_len == 6`).

---

## Section 9 — Diagnostic Measurement of Static-Shortcut Baselines

All static rules and non-temporal baselines were evaluated on the rebuilt dataset (`597,135` packets; `119,237` windows) and saved in [`shortcut_analysis.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/shortcut_analysis.csv).  
For all **window-level deterministic rules**, a 20-packet window is predicted positive (`1`) if and only if **one or more ($\ge 1$) of its 20 constituent packets** match the static packet rule (matching the dataset's `any_positive` window label rule).

### 9.1 Deterministic Single-Current-Packet Signature Rules (No Training)

| Rule | Level | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Rule 1:** `func_code == 5` | Packet | 8,400 | 105,323 | 237 | 483,175 | 0.0739 | 0.9726 | 0.1373 | 0.1790 |
| **Rule 1:** `func_code == 5` | Window | 1,781 | 23,139 | 97 | 94,220 | 0.0715 | 0.9483 | 0.1329 | 0.1972 |
| **Rule 2:** `modbus_len == 3` | **Packet** | **8,413** | **0** | **224** | **588,498** | **`1.0000`** | **`0.9741`** | **`0.9869`** | **`0.0000`** |
| **Rule 2:** `modbus_len == 3` | **Window** | **1,784** | **0** | **94** | **117,359** | **`1.0000`** | **`0.9499`** | **`0.9743`** | **`0.0000`** |
| **Rule 3:** `func_code == 5 AND modbus_len == 3` | **Packet** | **8,400** | **0** | **237** | **588,498** | **`1.0000`** | **`0.9726`** | **`0.9861`** | **`0.0000`** |
| **Rule 3:** `func_code == 5 AND modbus_len == 3` | **Window** | **1,769** | **0** | **109** | **117,359** | **`1.0000`** | **`0.9420`** | **`0.9701`** | **`0.0000`** |
| **Rule 4:** `packet_size == 75` | **Packet** | **8,413** | **0** | **224** | **588,498** | **`1.0000`** | **`0.9741`** | **`0.9869`** | **`0.0000`** |
| **Rule 4:** `packet_size == 75` | **Window** | **1,784** | **0** | **94** | **117,359** | **`1.0000`** | **`0.9499`** | **`0.9743`** | **`0.0000`** |
| **Rule 5a:** `register_start == 0 AND quantity == 0` | Packet | 8,490 | 305,561 | 147 | 282,937 | 0.0270 | 0.9830 | 0.0526 | 0.5192 |
| **Rule 5a:** `register_start == 0 AND quantity == 0` | Window | 1,818 | 61,067 | 60 | 56,292 | 0.0289 | 0.9681 | 0.0561 | 0.5203 |
| **Rule 5b:** `FC == 5 AND reg == 0 AND qty == 0` | Packet | 8,400 | 65,555 | 237 | 522,943 | 0.1136 | 0.9726 | 0.2034 | 0.1114 |
| **Rule 5b:** `FC == 5 AND reg == 0 AND qty == 0` | Window | 1,772 | 13,109 | 106 | 104,250 | 0.1191 | 0.9436 | 0.2115 | 0.1117 |
| **Rule 6a:** `quantity > 1` | Packet | 66 | 459 | 8,571 | 588,039 | 0.1257 | 0.0076 | 0.0144 | 0.0008 |
| **Rule 6a:** `quantity > 1` | Window | 23 | 134 | 1,855 | 117,225 | 0.1465 | 0.0122 | 0.0226 | 0.0011 |
| **Rule 6c:** `(modbus_len == 3) OR (quantity > 1)` | Packet | 8,479 | 459 | 158 | 588,039 | 0.9486 | 0.9817 | 0.9649 | 0.0008 |
| **Rule 6c:** `(modbus_len == 3) OR (quantity > 1)` | Window | 1,807 | 134 | 71 | 117,225 | 0.9310 | 0.9622 | 0.9463 | 0.0011 |

### 9.2 Simple Static Non-Temporal ML Baselines (10-Fold `LOCGO` Cross-Validation)

To test whether static packet fields alone solve the task under strict Leave-One-Capture-Group-Out (`LOCGO`) cross-validation, we evaluated interpretable static classifiers **with** and **without** `modbus_len` and `packet_size`:

| Model (10-Fold `LOCGO`) | Level | Static Features Used | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **DecisionTree (`max_depth=3`)** | Packet | `FC, reg, qty, modbus_len, pkt_size, unit_id` | 8,433 | 0 | 204 | 588,498 | **`1.0000`** | **`0.9764`** | **`0.9880`** | `0.0000` |
| **LogisticRegression** | Packet | `FC, reg, qty, modbus_len, pkt_size, unit_id` | 8,410 | 1 | 227 | 588,497 | **`0.9999`** | **`0.9737`** | **`0.9866`** | `0.000002` |
| **DecisionTree (`max_depth=3`)** | Packet | `FC, reg, qty, unit_id` (**NO `len`/`size`**) | 20 | 65,555 | 8,617 | 522,943 | `0.0003` | `0.0023` | **`0.0005`** | `0.1114` |
| **LogisticRegression** | Packet | `FC, reg, qty, unit_id` (**NO `len`/`size`**) | 12 | 65,555 | 8,625 | 522,943 | `0.0002` | `0.0014` | **`0.0003`** | `0.1114` |
| **Window Aggregated DecisionTree (`depth=3`)** | Window | Order-invariant `min/max/mean/std` (**WITH `len`/`size`**) | 1,798 | 0 | 80 | 117,359 | **`1.0000`** | **`0.9574`** | **`0.9782`** | `0.0000` |
| **Window Aggregated RandomForest (`depth=6`)** | Window | Order-invariant `min/max/mean/std` (**WITH `len`/`size`**) | 1,797 | 0 | 81 | 117,359 | **`1.0000`** | **`0.9569`** | **`0.9780`** | `0.0000` |
| **Window Aggregated LogisticRegression** | Window | Order-invariant `min/max/mean/std` (**WITH `len`/`size`**) | 1,771 | 3 | 107 | 117,356 | **`0.9983`** | **`0.9430`** | **`0.9699`** | `0.000026` |
| **Window Aggregated DecisionTree (`depth=3`)** | Window | Order-invariant `min/max/mean/std` (**NO `len`/`size`**) | 223 | 13,178 | 1,655 | 104,181 | `0.0166` | `0.1187` | **`0.0292`** | `0.1123` |
| **Window Aggregated RandomForest (`depth=6`)** | Window | Order-invariant `min/max/mean/std` (**NO `len`/`size`**) | 243 | 13,118 | 1,635 | 104,241 | `0.0182` | `0.1294` | **`0.0319`** | `0.1118` |
| **Window Aggregated LogisticRegression** | Window | Order-invariant `min/max/mean/std` (**NO `len`/`size`**) | 146 | 13,277 | 1,732 | 104,082 | `0.0109` | `0.0777` | **`0.0191`** | `0.1131` |

> [!IMPORTANT]
> **Answer to Section 9 Question (*"Can static packet information almost solve the task already?"*):**  
> **YES.** Two redundant static fields—**`modbus_len == 3`** and **`packet_size == 75`** (along with the derived flag `is_fc5_len3`)—solve **`97.41%` of packet positives (`F1 = 0.9869`)** and **`94.99%` of window positives (`F1 = 0.9743`)** with **zero false positives**, and an order-invariant non-temporal Decision Tree achieves **`F1 = 0.9782`** at the window level. When `modbus_len` and `packet_size` are removed, static non-temporal `LOCGO` performance collapses by **97% (`F1 = 0.9782` $\to$ `0.0292`)** because normal `G03_0201_veth` traffic contains `65,555` normal `FC5` packets (`13,109` windows) with `register_start == 0, quantity == 0` that only differ from the `8,400` `FC5` positive packets in `modbus_len` (`6` vs `3`) and `packet_size` (`78` vs `75`)!

---

## Section 10 — Does Temporal Signal Exist Beyond the Static Shortcut?

To test whether the dataset contains the temporal characteristics claimed in Harry's proposal after controlling for the `modbus_len == 3` (`packet_size == 75`) static shortcut, we computed all 12 diagnostic temporal features across all `119,237` windows and compared **Normal windows (`117,359`)** against the **three mutually exclusive Positive Window Cohorts**:
- **Cohort 1 (`1,784` windows, `94.99%` of positive windows):** Positive windows containing $\ge 1$ `modbus_len == 3` packet.
- **Cohort 2 (`23` windows, `1.22%` of positive windows):** Positive windows with **no** `modbus_len == 3` packet, containing $\ge 1$ multi-register read (`quantity > 1`, `10` windows in `G03_0201_veth`, `8` in `G05_0315_sub2`, `5` in `G07_0319_sub10`).
- **Cohort 3 (`71` windows, `3.78%` of positive windows):** Positive windows with **no** `modbus_len == 3` and **no** `quantity > 1` (pure `event_mapped` single-register polling in `G05_0315_sub2` [`59` windows] and `G07_0319_sub10` [`12` windows]).
- **Control Cohort (`23,139` windows):** Normal-labelled windows (`label = 0`) that contain `FC5, modbus_len == 6` requests (`s0003` / `G03_0201_veth`).

### 10.1 Temporal Diagnostic Feature Comparison Across Cohorts (Mean / Median `[P25, P75]`)

| Diagnostic Temporal Feature | Normal All (`n=117,359`) | Recon Cohort 1: `len=3` Shortcut (`n=1,784`) | Recon Cohort 2: `qty>1`, No `len=3` (`n=23`) | Recon Cohort 3: `event_mapped` Routine (`n=71`) | Unlabelled `FC5` Request Windows (`n=23,139`, `label=0`) |
|---|---|---|---|---|---|
| `address_delta` | `-0.038` / `0.0` `[0.0, 0.0]` | `0.001` / `0.0` `[0.0, 0.0]` | `0.121` / `0.0` `[-0.03, 0.0]` | `-0.005` / `0.0` `[0.0, 0.13]` | `0.001` / `0.0` `[0.0, 0.0]` |
| `abs_address_delta` | `3.439` / `0.0` `[0.0, 2.47]` | `0.011` / `0.0` `[0.0, 0.0]` | **`6.382` / `1.368` `[0.42, 16.21]`** | `4.886` / `0.368` `[0.0, 2.53]` | `0.539` / `0.0` `[0.0, 0.0]` |
| `unique_addresses_last_20` | `1.980` / `1.0` `[1.0, 3.0]` | `1.026` / `1.0` `[1.0, 1.0]` | **`3.957` / `4.0` `[3.0, 5.0]`** | `2.239` / `2.0` `[1.0, 3.5]` | `1.205` / `1.0` `[1.0, 1.0]` |
| `register_span_last_20` | `6.093` / `0.0` `[0.0, 6.0]` | `0.109` / `0.0` `[0.0, 0.0]` | **`17.044` / `13.0` `[4.0, 34.0]`** | `8.437` / `6.0` `[0.0, 10.0]` | `1.795` / `0.0` `[0.0, 0.0]` |
| `monotonic_scan_fraction` (`reg_t > reg_t-1`) | `0.122` / `0.0` `[0.0, 0.21]` | `0.001` / `0.0` `[0.0, 0.0]` | `0.185` / `0.158` `[0.11, 0.32]` | `0.139` / `0.053` `[0.0, 0.21]` | `0.019` / `0.0` `[0.0, 0.0]` |
| `exact_step1_scan_fraction` (`+1` step) | `0.008` / `0.0` `[0.0, 0.0]` | `0.0004` / `0.0` `[0.0, 0.0]` | `0.021` / `0.0` `[0.0, 0.05]` | `0.000` / `0.0` `[0.0, 0.0]` | `0.002` / `0.0` `[0.0, 0.0]` |
| `function_transition_rate` | `0.654` / `0.789` `[0.79, 0.79]` | `0.048` / `0.0` `[0.0, 0.0]` | `0.524` / `0.474` `[0.26, 0.84]` | `0.725` / `0.789` `[0.79, 0.79]` | `0.078` / `0.0` `[0.0, 0.0]` |
| `read_request_rate` (`FC1`–`FC4`) | `0.820` / `1.0` `[1.0, 1.0]` | `0.051` / `0.0` `[0.0, 0.0]` | `0.961` / `1.0` `[1.0, 1.0]` | `0.980` / `1.0` `[1.0, 1.0]` | `0.090` / `0.0` `[0.0, 0.0]` |
| `requests_per_second` | `348.4` / `0.983` `[0.98, 1.30]` | **`1115.2` / `1252.4` `[19.7, 1819.5]`** | `0.592` / `0.362` `[0.02, 1.22]` | `1.014` / `0.982` `[0.97, 0.98]` | **`1727.7` / `1055.6` `[593.0, 3049.5]`** |
| `median_interarrival_s` | `0.050` / `0.022` `[0.021, 0.023]` | **`0.0017` / `0.0004` `[0.0003, 0.0006]`** | `15.14` / `0.024` `[0.023, 21.49]` | `0.452` / `0.025` `[0.022, 0.045]` | **`0.0161` / `0.0004` `[0.0003, 0.0016]`** |
| `polling_interval_drift_cv` | `1.738` / `1.896` `[1.89, 1.90]` | `2.013` / `1.419` `[0.86, 3.97]` | `2.059` / `2.018` `[1.42, 2.16]` | `1.833` / `1.895` `[1.87, 1.90]` | `0.808` / `0.253` `[0.07, 1.35]` |
| `same_address_repeat_steps` (of 19) | `13.26` / `19.0` `[8.0, 19.0]` | `18.96` / `19.0` `[19.0, 19.0]` | `10.65` / `14.0` `[3.0, 16.0]` | `11.94` / `18.0` `[7.0, 19.0]` | `18.18` / `19.0` `[19.0, 19.0]` |
| `unique_unit_ids_last_20` | `1.0` / `1.0` `[1.0, 1.0]` | `1.0` / `1.0` `[1.0, 1.0]` | `1.0` / `1.0` `[1.0, 1.0]` | `1.0` / `1.0` `[1.0, 1.0]` | `1.0` / `1.0` `[1.0, 1.0]` |

### 10.2 Forensic Findings on Temporal Signal Beyond the Shortcut

1. **Zero Device/Unit Enumeration (`unique_unit_ids_last_20 = 1.0` Everywhere):**  
   Every retained packet in the entire dataset has `unit_id == 1`. Device/unit enumeration is completely absent.
2. **Cohort 1 (`1,784` windows, `94.99%` of positive windows) Has Zero Address Scanning and Confounded Burst Timing:**  
   Because Cohort 1 consists of slave response streams (`s0004`) where `register_start` is always `0`, **`18.96` out of `19` consecutive steps repeat address `0` (`unique_addresses_last_20 = 1.026`, `register_span_last_20 = 0.109`)**. While Cohort 1 exhibits short inter-arrival times (`median_interarrival_s = 0.0004 s`, `requests_per_second = 1,252.4/s`), **the exact same sub-millisecond burst timing occurs in the `23,139` normal-labelled `FC5` request windows (`median_interarrival_s = 0.0004 s`, `requests_per_second = 1,055.6/s`)** because the master requests were left labelled `0`!
3. **Cohort 3 (`71` windows, `3.78%` of positive windows) Is Indistinguishable from Normal Routine Polling:**  
   Compare Cohort 3 (`recon_cohort3_event_mapped_routine`) against `normal_all` in the table above:
   - `requests_per_second`: Cohort 3 median = **`0.9816 req/s`** vs. Normal median = **`0.9829 req/s`**
   - `median_interarrival_s`: Cohort 3 median = **`0.0245 s`** vs. Normal median = **`0.0220 s`**
   - `polling_interval_drift_cv`: Cohort 3 median = **`1.8948`** vs. Normal median = **`1.8962`**
   - `function_transition_rate`: Cohort 3 median = **`0.7895`** vs. Normal median = **`0.7895`**
   - `read_request_rate`: Cohort 3 median = **`1.0000`** vs. Normal median = **`1.0000`**
   Cohort 3 windows are literally normal 5-second background polling cycles (`FC1, FC2, FC3, FC4` reading single registers `8, 13, 14, 35`) that were tagged in `attack_events_mapped.xlsx` under variable clock offsets.
4. **Cohort 2 (`23` windows, `1.22%` of positive windows) Is the Only Subset with Multi-Register Read Activity—And It Is Too Small to Generalize:**  
   Cohort 2 (`10` windows in `G03_0201_veth`, `8` windows in `G05_0315_sub2`, `5` windows in `G07_0319_sub10`) shows elevated `unique_addresses_last_20` (`median 4.0` vs `1.0`) and `register_span_last_20` (`median 13.0` vs `0.0`). However, `23` windows across `3` capture groups (`0.019%` of the dataset) is far too small to train or evaluate a deep sequence model: when we evaluate a Random Forest or Logistic Regression trained **strictly on the 12 temporal diagnostic features** under `LOCGO` (`audit_metrics.json -> temporal_only_locgo_classifier_evaluation`), it achieves:
   - **Overall `LOCGO` F1:** `0.2831` (`TP = 315`, `FP = 32`, `FN = 1,563`, `Recall = 16.77%`) for Random Forest (`F1 = 0.0002` for Logistic Regression).
   - **Recall on Cohort 1 (`1,784` `len=3` windows):** `17.66%` (`315 / 1,784`, detecting only a fraction of the high-rate `FC5` response bursts).
   - **Recall on Cohort 2 (`23` `qty>1` windows):** **`0.00%` (`0 / 23`)**.
   - **Recall on Cohort 3 (`71` `event_mapped` windows):** **`0.00%` (`0 / 71`)**.

---

## Section 11 — Attack Independence and Class Distribution

### 11.1 Explicit Five-Level Hierarchy of Counts

To prevent inflating sample size by counting overlapping windows or duplicate interface captures as independent experiments, the dataset's true sample hierarchy is:

| Granularity Level | Total Count | Positive Count | Non-Shortcut (`modbus_len != 3`) Positives | Forensic Notes |
|---|---:|---:|---:|---|
| **1. Retained Packets (`packets_rebuilt.csv`)** | `597,135` (`879,225` raw) | `8,637` (`8,699` raw) | **`224`** (`66` `qty>1` + `158` `event_mapped`) | `282,076` duplicate Docker `veth` packets and `14` `attached_recon_flows` rows excluded. |
| **2. Rebuilt 20-Packet Windows (`windows.csv`, stride 5)** | `119,237` (`175,800` old) | `1,878` (`18,338` old) | **`94`** (`23` `qty>1` + `71` `event_mapped`) | Consecutive windows overlap by `15 / 20` packets (`75%` overlap). |
| **3. Discrete Attack Events / Contiguous Positive Bursts** | `77` contiguous stream bursts | `77` bursts (`158` log rows across `7` log timestamps) | `29` non-`len3` bursts | `attack_events_mapped.xlsx` contains `158` packet rows across only `8` `(file, attack, log_timestamp)` entries (`7` unique timestamps). |
| **4. Independent Capture Groups (`capture_group`)** | `10` capture groups (`12` retained `.pcap` files) | **`6` positive capture groups** | **`3` capture groups** (`G03`, `G05`, `G07`) | `G04`, `G06`, and `G08` have **zero** non-`FC5+len3` positives! |
| **5. Independent Experimental Campaigns** | `4` total recording campaigns | **`2` positive campaigns** | **`2` campaigns** (`G03` Docker veth + `G05`/`G07` Substation) | Campaign A: Feb 1 2023 Docker `veth` (`G03_0201_veth`); Campaign B: Mar 15–20 2023 Compromised-SCADA Substation (`G04`–`G08`). |

### 11.2 Concentration & Skew Metrics

- **Percentage of positive packets from the Compromised-SCADA Substation campaign (`G04`–`G08`):** **`99.42%` (`8,587 / 8,637`)**.
- **Percentage of positive packets from a single `session_id` (`185.175.0.5_185.175.0.3_u1_s0004`):** **`97.63%` (`8,432 / 8,637` packets)** and **`94.20%` (`1,769 / 1,878` positive windows)**.
- **Percentage of positive packets from the largest single capture group (`G07_0319_sub10`):** **`25.30%` (`2,185 / 8,637`)**, followed closely by `G06_0316_sub4` (`24.78%`, `2,140`), `G08_0320_sub14` (`24.60%`, `2,125`), and `G04_0315_sub1` (`23.17%`, `2,001`). Together, those 4 capture groups hold **`97.85%` (`8,451 / 8,637`)** of all positive packets, and `99.35%` of their positives are `FC5 + modbus_len == 3` slave responses.
- **Rotated / Multi-Interface Captures:**
  - The 5 `.pcap` files on `2023-02-01` (`veth5bbeaa2-0`, `vethd9e14c0-0`, `veth4edc015-0`, `veth8bc3408-0`, `veth665f3cf-0`) are simultaneous multi-interface views of **one single continuous Docker experiment (`G03_0201_veth`)**.
  - `G09_0323_veth3e0` (`08:01–09:41`) and `G10_0323_veth3e1` (`15:40–17:19`) are two 100-minute benign recording chunks from the same `veth3efd353` topology on `2023-03-23`.

---

## Section 12 — Valid Leakage-Resistant Split Design (Audit Assessment)

1. **Why Random Window Splits and `session_id` Splits Are Invalid:**
   - Consecutive windows share `15 / 20` packets (`75%` overlap), so random window splitting leaks identical packets between train and test (`100%` packet overlap in `C2_LEAKAGE_AUDIT.md`).
   - Grouping by `session_id` is also invalid because `s0004` holds `97.63%` of all positive packets and shares simultaneous millisecond-level request/response transactions with `s0003` inside the same capture.
2. **Minimum Valid Grouping Unit:**  
   The minimum scientifically valid grouping unit for cross-validation or train/validation/test splitting is **`capture_group` (`G01_0122_normal4` .. `G10_0323_veth3e1`)** (or Leave-One-Capture-Group-Out `LOCGO` / Stratified Group K-Fold by `capture_group`).
3. **Can a Train / Validation / Test Split on Current CIC Data Scientifically Validate the Temporal Reconnaissance Claim?**  
   **NO.** Even when grouped cleanly by `capture_group` (e.g., placing `G04, G06, G07` in Train, `G05` in Validation, and `G08` in Test):
   - In `G04_0315_sub1`, `G06_0316_sub4`, and `G08_0320_sub14`, **`100.0%` of positive packets and `100.0%` of positive windows are `FC5 + modbus_len == 3` slave responses**.
   - Only **3 capture groups** (`G03_0201_veth` [`10` windows], `G05_0315_sub2` [`77` windows], and `G07_0319_sub10` [`22` windows]) contain **any** positive windows without `FC5 + len3`, and `71` of those `94` non-`len3` windows are routine-looking `event_mapped` polling windows with `0.0%` temporal separability.
   - Consequently, **no split of the current dataset can fairly evaluate temporal reconnaissance detection**: any split with `G04`/`G06`/`G08` in test evaluates `FC5 + len3` static signature memorization, while holding out `G03`, `G05`, or `G07` without the static shortcut leaves only `10` to `77` noisy/routine windows where temporal models score near zero.

---

## Section 13 — Classification of CIC Suitability for Harry's Original Claim

Evaluating the three candidate classifications strictly on empirical evidence:

- **A — Supported:** *Rejected.* `97.41%` of positive packets (`94.99%` of positive windows) are solved by a single static byte-length field (`modbus_len == 3`), and those frames are slave responses to unlabelled master `FC5` coil writes rather than read reconnaissance scans.
- **B — Conditionally supported (CIC alone with claim narrowing):** *Insufficient without supplemental data.* Even if one deletes or masks `modbus_len` and `packet_size` or restricts evaluation to the `94` non-`len3` positive windows (`23` `qty > 1` windows + `71` `event_mapped` windows), `LOCGO` F1 collapses to `0.0292` (static) and `0.0000` recall on Cohorts 2 and 3 (temporal), because `71` windows are indistinguishable from normal polling and `23` windows are too sparse (`3` groups) to train or validate an LSTM.
- **C — Unsupported (as a standalone benchmark for the temporal-reconnaissance LSTM novelty):** **SELECTED FOR STANDALONE CIC DATA; REQUIRES CONTROLLED-TESTBED RESCUE (OR NARROWING + SUPPLEMENTATION).**  
  The supplied CIC Modbus 2023 derived dataset is fundamentally dominated (`97.41%` of positives) by a static slave-response framing artifact (`modbus_len == 3`, `packet_size == 75`) and request/response labeling inversion, while the residual `2.59%` of positives (`224` packets / `94` windows) lack sufficient campaign diversity and label precision to fairly test or demonstrate the proposed LSTM temporal-behaviour novelty on CIC alone.

---

## Section 14 — Controlled-Testbed Rescue Design (Feasibility Pilot for Component 2)

Because Harry's approved proposal and TAF explicitly authorize a **controlled virtual/local Modbus/TCP testbed** alongside CIC Modbus 2023, the scientifically rigorous path forward is to execute a **small, self-contained Controlled Modbus/TCP Reconnaissance Pilot** (analogous to Component 3's controlled pilot) where ground truth comes from an external experiment ledger and **where Normal and Reconnaissance traffic share identical single-packet framing (`modbus_len == 6`, `packet_size == 78`, `func_code in {1, 2, 3, 4}`)** so no static shortcut can exist.

### 14.1 Architecture & Capture Setup
- **Topology:** Local Docker or virtual-interface (`loopback` / `veth`) Modbus/TCP network running `pymodbus` asynchronous TCP servers (simulating 3 IEDs at `unit_id in {1, 2, 3}`, holding 500 coils and 500 registers each) and `pymodbus` master/client processes, captured to raw `.pcap` via `dumpcap`/`tshark` and parsed with a deterministic extractor that records both requests and responses.
- **Strict Anti-Shortcut Design Rule:**
  1. Model input features are restricted to **Master $\to$ Slave request sequences** (or bidirectional sequences where request/response direction is explicit), so slave exception responses are never mislabelled while master requests are ignored.
  2. Both **Normal** and **Reconnaissance** master requests use standard read function codes (`FC1, FC2, FC3, FC4`) with identical `modbus_len == 6`, identical `packet_size`, and overlapping `quantity in {1, 2, 4, 10}` and `register_start in [0 .. 400]` distributions.
  3. Therefore, **any single-packet static classifier (`DecisionTree`, `LogisticRegression`) is mathematically upper-bounded near chance (`F1` $\ll$ `0.50`)**, forcing classification to rely on multi-packet sequence order (`address_delta`, `monotonic_scan_fraction`, `unique_addresses_last_k`) and inter-request timing (`dt_s`, `polling_interval_drift`).

### 14.2 Episode Matrix (`>= 18` Independent Capture Runs Across Train / Val / Test)
Record at least **18 independent `.pcap` capture episodes** (`6` Train runs, `6` Validation runs, `6` Test runs, with separate random seeds and separate ledger files):

#### Normal Behavior Episodes (Shared Static Signatures with Recon)
1. **Regular Cyclic Polling (`N1`):** Deterministic round-robin reads (`FC1`–`FC4`, `qty in {1, 2, 10}`) over a fixed working set of 15–25 registers at `100 ms`, `500 ms`, and `2,000 ms` intervals.
2. **Repeated Single-Address Monitoring (`N2`):** High-frequency polling of critical status registers (`same_address_repeat_count` high, `dt_s` small) so "fast polling" alone is not a shortcut for attack.
3. **Legitimate Maintenance / Configuration Read Bursts (`N3`):** Periodic burst reads of a known 8-register diagnostic block (`qty in {1, 4, 10}`) so non-unit `quantity` values occur in normal traffic too.
4. **Multi-Frequency / Multi-Unit Normal Polling (`N4`):** Normal master polling across `unit_id in {1, 2, 3}` with scheduled rate changes (`1 Hz` $\to$ `5 Hz`) so static `unit_id` or simple `dt_s` thresholds cannot trivially separate classes.

#### Reconnaissance Behavior Episodes (Distinguished Only by Temporal Order & Timing Dynamics)
1. **Sequential Register Scanning (`R1`):** Step-by-step sweep (`reg = 0, 1, 2, ..., 199`, `qty = 1`, `FC3`/`FC4`) at both fast (`50 ms`) and stealthy normal-matched (`500 ms`) intervals. Every individual packet (`FC3, reg=k, qty=1, len=6`) is 100% identical to a normal `N1` packet!
2. **Sparse / Strided Address Scanning (`R2`):** Strided probing (`reg = 0, 10, 20, ..., 300`, `qty = 1` or `2`) to map memory block boundaries while matching normal polling rates.
3. **Randomized / Permutation Address Scanning (`R3`):** Shuffled non-repeating register sweeps (`unique_addresses_last_20 = 20`, high `abs_address_delta`, low `same_address_repeat_steps`) over valid addresses so simple `+1` step rules do not solve all scans.
4. **Multi-Function-Code Capability Enumeration (`R4`):** Rapidly cycling `FC1 -> FC2 -> FC3 -> FC4` on the same target address before advancing (`function_transition_rate = 1.0`).
5. **Device / Unit ID Enumeration (`R5`):** Sweeping `unit_id = 1, 2, 3, ..., 10` (`unique_unit_ids_last_20 > 3`) using standard `FC3, reg=0, qty=1` requests.
6. **Slow Stealthy vs. Fast Burst Reconnaissance (`R6`):** Scanning with inter-request timing (`dt_s`) either drifted relative to background polling (`polling_interval_drift`) or matched to normal polling intervals (`500 ms`) to test timing-ablation sensitivity (`LSTM Full` vs. `LSTM No-Timing`).

---

## Section 15 — Audit Deliverables Checklist

All required deliverables have been generated inside [`component2_recon_audit/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit) without modifying any existing source or dataset files:

1. [`AUDIT_REPORT.md`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/AUDIT_REPORT.md) — This comprehensive human-readable forensic report.
2. [`audit_metrics.json`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/audit_metrics.json) — Complete machine-readable counts, distributions, chronology checks, shortcut metrics, and temporal-signal diagnostics.
3. [`positive_lineage.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/positive_lineage.csv) — 91-row traceability ledger covering all positive cohorts (`first`, `middle`, `last` packets per stream/file/category) plus the excluded `attached_recon_flows.csv` rows.
4. [`capture_group_summary.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/capture_group_summary.csv) — Per-capture-group packet counts, positive category breakdowns, stream counts, window counts, timestamps, and campaign mapping across `G01`–`G10`.
5. [`shortcut_analysis.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/shortcut_analysis.csv) — Packet-level and window-level performance of all deterministic static rules and `LOCGO` static non-temporal baselines (with and without `modbus_len`/`packet_size`).
6. [`window_integrity_report.json`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/window_integrity_report.json) — 100%-coverage validation across all `119,237` windows, duration percentiles, and inactivity-gap flags.
7. [`UNRESOLVED_ASSUMPTIONS.md`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/UNRESOLVED_ASSUMPTIONS.md) — Explicit documentation of every upstream fact that cannot be proved from local files alone.

---

## Final Verdict

*Sequence reconstruction:* **PASS** (with minor `CONDITIONAL` note that `509 / 119,237` windows [`0.43%`] bridge intra-capture inactivity pauses `> 60 s`; all `119,237` windows have 20 valid contiguous indices, stride `5`, `0` cross-stream mixing, and `0` timestamp reversals)  
*Positive-label provenance:* **FAIL** (`97.26%` [`8,400 / 8,637`] of retained positive packets are slave-to-master `FC5, modbus_len == 3` coil-write exception/short responses absent from `attack_events_mapped.xlsx` while the preceding master `FC5` requests are labelled `0`; only `158` packets [`1.83%`] match `attack_events_mapped.xlsx`, and those have non-constant clock offsets from `-210 min` to `+141.5 min`)  
*Static shortcut risk:* **CRITICAL** (The single static field `modbus_len == 3` or `packet_size == 75` achieves `100.0%` precision and `97.41%` recall [`F1 = 0.9869`] at the packet level and `100.0%` precision, `94.99%` recall [`F1 = 0.9743`] at the window level; removing `modbus_len`/`packet_size` causes static `LOCGO` `F1` to collapse from `0.9782` to `0.0292`)  
*Temporal-recon signal:* **NOT ESTABLISHED** (In `94.99%` of positive windows [`Cohort 1`], `register_start` is constant `0` [`unique_addresses_last_20 = 1.026`] and high-rate burst timing is confounded by `23,139` unlabelled master `FC5` request windows; in the remaining `94` non-`len3` positive windows [`23` `qty > 1` + `71` `event_mapped`], a temporal-dynamics classifier achieves `0.0%` recall under `LOCGO`)  
*Independent evaluation feasibility:* **UNSUPPORTED** (on current CIC labels alone: `97.63%` of positive packets reside in a single `session_id` [`s0004`], `3` of the `6` positive capture groups contain `100%` `FC5 + len3` positives, and only `94` non-shortcut positive windows exist across `3` capture groups)  
*CIC suitability for RP2:* **UNSUPPORTED** (as a standalone benchmark for temporal reconnaissance detection; **CONDITIONAL** only if used as a documented negative/audit case study alongside a controlled Modbus/TCP testbed dataset)  

### Single best next action

Execute the **Controlled Modbus/TCP Reconnaissance Testbed Pilot** outlined in Section 14 (generating $\ge 18$ independent `.pcap` capture episodes of normal cyclic/burst polling and sequential, strided, randomized, multi-function, and unit-enumeration reconnaissance that share identical single-packet framing `modbus_len == 6, packet_size == 78` with ground truth recorded in an external experiment ledger), while retaining the audited CIC Modbus 2023 dataset strictly as a documented forensic case study of static-signature shortcut leakage.
