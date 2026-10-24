# C2 / RP2 — Hostile Dataset, Sequence, and Ground-Truth Label Audit

All findings in this document are verified directly from the supplied files in `Dataset/` (`artifacts/dataset_profile.json`, `artifacts/sequence_audit.json`, `artifacts/label_audit.json`, and `artifacts/rebuild_report.json`).

---

## 1. File Inventory & Format Verification

Although two of the supplied files carry `.csv.xlsx` double extensions, byte-level header inspection (`PK\x03\x04`) confirms that all three supplied files are Office Open XML (`.xlsx`) workbooks:

| Supplied File | Worksheet | Rows (excl. header) | Columns | Missing Values | Duplicate Rows |
| :--- | :--- | ---: | ---: | ---: | ---: |
| `recon_labeled_packets_ALL.csv.xlsx` | `recon_labeled_packets_ALL.csv` | `879,225` | `14` | `0` | `0` (`row_index` unique `0..879,224`) |
| `recon_sequences_ALL.csv.xlsx` | `recon_sequences_ALL.csv` | `175,800` | `13` | `0` | `0` (`sequence_id` unique `0..175,799`) |
| `attack_events_mapped.xlsx` | `attack_events_mapped` | `158` | `12` | `0` | `0` |

---

## 2. Verification of Proposal Claims vs. Actual Dataset Reality

| Proposal Claim | Empirical Finding | Status |
| :--- | :--- | :--- |
| **`175,800` sequence windows of shape `(20, 7)`** | `recon_sequences_ALL.csv.xlsx` has exactly `175,800` rows, each encoding `20` semicolon-separated values across `7` feature columns: `['unit_id', 'func_code', 'modbus_len', 'register_start', 'quantity', 'packet_size', 'time_delta']`. | **Verified (`100%` match)** |
| **`13` distinct sessions (`session_id`)** | `recon_sequences_ALL.csv.xlsx` has `13` distinct `session_id`s (`s0001..s0013`). However, `recon_labeled_packets_ALL.csv.xlsx` has **`17` distinct `session_id`s** because `attached_recon_flows.csv` adds `4` tiny sessions (`s0014..s0017`) with `2–4` packets each (`14` rows total, $<20$ packets so excluded from 20-packet windowing). | **Discrepancy Recorded (`13` in sequences vs. `17` in packets)** |
| **`75%` window overlap (stride `5`)** | Within each of the 13 sessions in `recon_labeled_packets_ALL`, sliding a 20-packet window with stride `5` in raw row order yields $\sum_{s=1}^{13} \lfloor (N_s - 20)/5 + 1 \rfloor = 175,800$ windows, matching `recon_sequences_ALL` on `175,800 / 175,800` (`100.0%`) rows. | **Verified (`100%` match)** |
| **Window label rule** | Every window in `recon_sequences_ALL` satisfies `window_label = 1` iff at least 1 of its 20 constituent packets has `label == 1` (`any_positive` rule: `175,800 / 175,800` = `100.0%` match; `18,338` positive windows, `157,462` negative windows). By contrast, majority rule (`>=10/20`) matches `89.66%` and `all_positive` matches `89.57%`. | **Verified (`any_positive` rule)** |
| **`unit_id` as an informative feature** | `unit_id == 1` in all `879,225` packets (`std = 0.0`) and all `175,800 x 20` sequence positions. It carries zero bits of information. | **Refuted (Constant column)** |

---

## 3. Five Critical Data & Chronology Flaws Discovered in the As-Provided Dataset

### Flaw 1: `session_id` Is a Long-Lived Host-Pair Identifier, Not an Isolated Capture Session
In `recon_labeled_packets_ALL`, `session_id` is formatted as `<src_ip>_<dst_ip>_u1_sXXXX`. Each of the 13 main `session_id`s spans **2 to 9 distinct `.pcap` files** across **up to `57.66` days** (`2023-01-22` to `2023-03-20` or `2023-03-23`).

### Flaw 2: Out-of-Order File Concatenation & Cross-File Windowing in `recon_sequences_ALL`
Because `recon_labeled_packets_ALL` concatenated `.pcap` files in non-chronological order (e.g., March 2023 substation captures interleaved with January/February 2023 virtual-interface captures) and sorted/indexed `sequence_position` in raw table order rather than by timestamp:
- Within `session_id` in `recon_labeled_packets_ALL`, there are **`126,643` negative timestamp jumps** (up to `-57.66` days).
- Because `recon_sequences_ALL` was generated in raw row order without sorting by timestamp or respecting `.pcap` file boundaries:
  - **`174,708 / 175,800` (`99.38%`)** of the as-provided sequences contain at least one backward jump in time;
  - **`67,489 / 175,800` (`38.39%`)** have `window_start_time > window_end_time` (mean signed duration `-2.29` days; mean span `40.00` days);
  - **`171,080 / 175,800` (`97.32%`)** mix packets from `2` to `7` different `.pcap` files inside a single 20-packet window!

### Flaw 3: Corrupted As-Provided `time_delta` Column
In `recon_labeled_packets_ALL`, **`595,213 / 879,225` (`67.70%`)** of `time_delta` values are `0.0`, and `time_delta` agrees with the actual chronological inter-packet gap within `(file_source, session_id)` on only **`0.094%`** of packets. Consequently, using the as-provided `time_delta` column cannot validly test `RQ2`.

### Flaw 4: Simultaneous Multi-Interface Duplicate Captures on `2023-02-01`
Five virtual-interface `.pcap` files (`veth5bbeaa2-0.pcap` [`216,466` rows], `veth4edc015-0.pcap` [`137,543` rows, `50` positives], `vethd9e14c0-0.pcap` [`72,574` rows], `veth8bc3408-0.pcap` [`72,018` rows], and `veth665f3cf-0.pcap` [`65,610` rows, `50` positives]) were recorded simultaneously on `2023-02-01 11:02:13–12:02:13 UTC`:
- Every single packet of the **`282,076` secondary-view rows** (including all `50` positive packets in `veth665f3cf-0.pcap`, which duplicate `veth4edc015-0.pcap` in session `185.175.0.7_185.175.0.4_u1_s0007`) has a `100.0%` content-and-label match within $\le 1\text{ ms}$ (median timestamp offset $7\ \mu\text{s}$) in the primary interface capture for that session.

### Flaw 5: `attached_recon_flows.csv` Malformed Timestamps & Non-Substation Subnet
The `14` rows from `file_source == "attached_recon_flows.csv"` (`12` positive, `2` negative) use time-of-day strings (`00:31:01.700000`) with **no calendar date**, belong to multicast/broadcast IPs (`192.168.10.112 -> 255.255.255.255` / `224.0.0.251`), and contain only `2–4` packets per session (`s0014..s0017`).

---

## 4. Ground-Truth Label Audit & Positive Signature Breakdown

Auditing all `8,699` positive packets (`artifacts/label_audit.json`) and `158` mapped attack log entries (`attack_events_mapped.xlsx`) reveals four mutually exclusive positive packet categories:

| Category | Raw Packets (`879,225`) | Rebuilt Packets (`597,135`) | Protocol Signature & Origin |
| :--- | ---: | ---: | :--- |
| **1. `fc5_len3` Slave Response Signature** | `8,400` (`96.56%`) | `8,400` (`97.26%`) | `func_code == 5, modbus_len == 3, register_start == 0, quantity == 0, packet_size == 75` (`8,384` in `s0004` (`185.175.0.5 -> 185.175.0.3`) across `substation-1, 4, 10, 14`; `16` in `substation-2`). |
| **2. `other_len3` Frame Signature** | `13` (`0.15%`) | `13` (`0.15%`) | `func_code in {1,2,3,4}, modbus_len == 3, packet_size == 75` in `substation-2.pcap`. |
| **3. `qty_scan` Multi-Register Scan Requests** | `155` (`1.78%`) | `93` (`1.08%`) | `modbus_len == 6, quantity in {2, 4, 5, 9, 20, 125, 2000, 65535}` (`50` in `veth4edc015-0`, `50` duplicate in `veth665f3cf-0`, `43` in `substation-2`, `12` in `attached_recon_flows`). |
| **4. `event_mapped` Normal-Format Packets** | `131` (`1.51%`) | `131` (`1.52%`) | Routine `func_code in {1..4}, modbus_len in {9,10,11}, register_start == 0, quantity in {0,1}` packets in `substation-2` (`80` pkts) and `substation-10` (`51` pkts) labelled via timestamp matching to `attack_events_mapped.xlsx` (where packet-minus-log clock offsets vary from `-210.0` min to `+141.5` min). |
| **Total Positive Packets** | **`8,699`** | **`8,637`** | — |

Crucially, **every single packet in the entire dataset with `modbus_len == 3` (`8,413 / 8,413`, all of which also have `packet_size == 75`) is labelled `1` (`100.0%` precision)**.

---

## 5. Chronological Sequence Reconstruction (`data/rebuilt_sequences/`)

To enable a scientifically defensible test of `RQ1` and `RQ2`, `src/rebuild_sequences.py` constructs the clean Rebuilt dataset while keeping the As-Provided dataset for comparison:
1. **Exclusions (`282,090` packets logged in `packet_exclusions.csv`)**:
   - `14` rows from `attached_recon_flows.csv` (`no_date_in_timestamp_and_session_len_lt_20`);
   - `282,076` duplicate secondary virtual-interface rows on `2023-02-01` (`duplicate_simultaneous_veth_capture_2023-02-01`).
2. **Stream Ordering & Causal Timing (`597,135` kept packets)**:
   - Grouped into **`10` independent capture episodes (`G01`..`G10`)** and directional `session_id` (`77` `(capture_group, session_id)` streams), sorted strictly by `(timestamp, row_index)`, with causal inter-packet intervals `dt_s` recomputed within each stream (`0` negative intervals).
3. **Windowing (`119,237` windows of length `20`, stride `5`)**:
   - `1,878` positive windows (`1.575%`) and `117,359` normal windows (`98.425%`).
   - `0` windows cross `session_id` or `capture_group` boundaries; `0` windows contain negative time steps.

| Capture Group | Source `.pcap` File(s) | Capture Date (UTC) | Kept Packets | Positive Packets | Windows ($L=20, S=5$) | Positive Windows |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: |
| `G01_0122_normal4` | `veth4edc015-normal-4.pcap` | `2023-01-22` | `35,000` | `0` | `6,994` | `0` |
| `G02_0123_normal13` | `veth5bbeaa2-normal-13.pcap` | `2023-01-23` | `35,000` | `0` | `6,980` | `0` |
| `G03_0201_veth` | `veth5bbeaa2-0` + `veth4edc015-0` (deduped) | `2023-02-01` | `282,135` | `50` | `56,403` | `10` |
| `G04_0315_sub1` | `substation-1.pcap` | `2023-03-15 15:02` | `35,000` | `2,001` | `6,983` | `415` |
| `G05_0315_sub2` | `substation-2.pcap` | `2023-03-15 17:19` | `35,000` | `136` | `6,979` | `86` |
| `G06_0316_sub4` | `substation-4.pcap` | `2023-03-16` | `35,000` | `2,140` | `6,980` | `454` |
| `G07_0319_sub10` | `substation-10.pcap` | `2023-03-19` | `35,000` | `2,185` | `6,979` | `470` |
| `G08_0320_sub14` | `substation-14.pcap` | `2023-03-20` | `35,000` | `2,125` | `6,981` | `443` |
| `G09_0323_veth3e0` | `veth3efd353-0.pcap` | `2023-03-23 11:15` | `35,000` | `0` | `6,978` | `0` |
| `G10_0323_veth3e1` | `veth3efd353-1.pcap` | `2023-03-23 14:43` | `35,000` | `0` | `6,980` | `0` |
| **Total** | **10 Independent Capture Episodes** | — | **`597,135`** | **`8,637`** | **`119,237`** | **`1,878`** |
