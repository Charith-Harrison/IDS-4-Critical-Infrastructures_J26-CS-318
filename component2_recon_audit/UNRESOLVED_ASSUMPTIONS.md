# Unresolved Assumptions & External Provenance Boundaries

**Project:** J26-CS-318 — Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis  
**Component 2 (RP2):** Reconnaissance Attack Detection Using Temporal Behavior Analysis  
**Student:** Charith H. / Harry (`IT23269002`)  
**Audit Scope:** Forensic Dataset & Label Provenance Audit (`component2_recon_audit/`)

---

## Purpose of This Document

In accordance with strict forensic audit discipline, this document explicitly separates **empirically verified facts** (reproducible directly from the repository datasets in [`Dataset/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset) and [`Pre-processed/rebuilt_sequences/`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences)) from **unresolved upstream facts** that cannot be proved from the files present on disk without external raw captures or upstream extraction scripts.

---

## 1. Absence of Raw `.pcap` Binary Captures on Disk (`[EXTERNAL SOURCE REQUIRED]`)

### What is verified locally
- The raw packet dataset ([`Dataset/recon_labeled_packets_ALL.csv.xlsx`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset/recon_labeled_packets_ALL.csv.xlsx)) contains `879,225` rows referencing 15 distinct `file_source` names (`14` CIC Modbus 2023 `.pcap` filenames across 10 capture groups `G01_0122_normal4` through `G10_0323_veth3e1`, plus `attached_recon_flows.csv`).
- The rebuilt dataset ([`Pre-processed/rebuilt_sequences/packets_rebuilt.csv`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Pre-processed/rebuilt_sequences/packets_rebuilt.csv)) retains `597,135` rows across 10 capture groups (`10` retained `.pcap` source files after deduplicating 4 simultaneous Docker `veth` interface views in `G03_0201_veth` and excluding the 14-row `attached_recon_flows.csv` snippet).
- Parsed Modbus/TCP header fields (`timestamp`, `src_ip`, `dst_ip`, `unit_id`, `func_code`, `register_start`, `quantity`, `modbus_len`, `packet_size`) are present for every row.

### What cannot be verified without the original `.pcap` binaries
1. **Raw Payload Bytes of `func_code == 5, modbus_len == 3, packet_size == 75` Frames:**
   - In standard Modbus/TCP (Modbus Application Protocol Specification V1.1b3), a normal **Function Code 5 (`Write Single Coil`)** request or normal echo response contains a 5-byte PDU (`1B func_code [0x05] + 2B output_address + 2B output_value`), yielding `modbus_len == 6` (`1B unit_id + 5B PDU`, total frame size `78` bytes in this capture environment).
   - A Modbus/TCP frame with `modbus_len == 3` (`1B unit_id + 2B PDU`, total frame size `75` bytes = `78 - 3` bytes) sent from the IED slave (`185.175.0.5`, `185.175.0.4`, or `185.175.0.8`) back to the SCADA master (`185.175.0.3`) matches the exact byte length of either:
     - a **Modbus Exception Response** (`1B unit_id + 1B exception_function_code [0x85 = 0x05 | 0x80] + 1B exception_code`), where the upstream packet parser masked `func_code & 0x7F -> 5` and defaulted the absent `register_start` and `quantity` fields to `0`, or
     - an implementation-specific truncated/short 2-byte response PDU from the simulated IED in CICModbus2023 when handling `FC5` coil writes.
   - Because the raw `.pcap` binary files are not stored in the workspace, we cannot inspect the raw hex byte at PDU offset 0 (`0x85` vs `0x05`) or the 1-byte code at PDU offset 1, nor can we inspect why the upstream parser did not export a separate `is_exception` or `exception_code` column.
2. **TCP Port Numbers (`src_port`, `dst_port`), Sequence/ACK Numbers, and TCP Handshakes:**
   - Neither `recon_labeled_packets_ALL.csv.xlsx` nor `packets_rebuilt.csv` contains `src_port`, `dst_port`, TCP flags (`SYN`, `FIN`, `RST`), or TCP stream indices.
   - Therefore, while we can prove with 100% certainty that `session_id` is a deterministic mapping of `(src_ip, dst_ip, unit_id)`, we cannot determine from the CSV alone whether a given `(capture_group, session_id)` stream used a single long-lived TCP connection on port 502 or opened multiple ephemeral TCP connections across the capture.

---

## 2. Missing Upstream Script That Generated `recon_labeled_packets_ALL.csv.xlsx` (`[UNPROVED UPSTREAM EXTRACTION LOGIC]`)

### What is verified locally
- Every single one of the `8,699` raw positive packets (`8,637` retained in `packets_rebuilt.csv`) is accounted for by four mutually exclusive empirical rules:
  1. **`fc5_len3_response` (`8,400` raw / `8,400` retained, `97.26%` of retained positives):** Every slave-to-master packet with `func_code == 5` and `modbus_len == 3` (`packet_size == 75`, `register_start == 0`, `quantity == 0`) in `substation-1.pcap`, `substation-2.pcap`, `substation-4.pcap`, `substation-10.pcap`, and `substation-14.pcap`.
  2. **`event_mapped` (`158` raw / `158` retained, `1.83%` of retained positives):** Exactly the 158 rows listed in [`Dataset/attack_events_mapped.xlsx`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset/attack_events_mapped.xlsx) (`107` in `substation-2.pcap` and `51` in `substation-10.pcap`), matched by `(timestamp, src_ip, dst_ip)`.
  3. **`nonroutine_quantity_read` (`116` raw / `66` retained, `0.76%` of retained positives):** Multi-register read requests (`func_code in {1, 2, 3, 4}` with non-routine `quantity > 1`, such as `quantity == 204` in `G03_0201_veth` [`50` kept + `50` duplicate view dropped] and `16` additional `quantity > 1` reads in `substation-2.pcap` and `substation-10.pcap`).
  4. **`len3_response_fc1_4` (`13` raw / `13` retained, `0.15%` of retained positives):** 3-byte slave-to-master responses (`modbus_len == 3, packet_size == 75`) for `func_code in {1, 2, 3, 4}` (`12` in `substation-2.pcap`, `1` in `substation-10.pcap`).
  5. **`external_attached_flow_no_date` (`12` raw / `0` retained):** 12 positive rows in the 14-row external snippet `attached_recon_flows.csv` (intentionally excluded in `packets_rebuilt.csv`).

### What remains unresolved without the upstream preprocessing script
1. **Why Only Slave-to-Master `FC5 + len3` Responses Were Labelled `1` While Preceding `FC5 + len6` Master Requests Were Labelled `0`:**
   - Across the five substation captures, the SCADA master (`185.175.0.3`) sends `8,400+` `func_code == 5, modbus_len == 6, packet_size == 78` `Write Single Coil` requests to the IEDs (`185.175.0.5`, `185.175.0.4`, `185.175.0.8`), and within `~1.5 ms` the IED replies with a `func_code == 5, modbus_len == 3, packet_size == 75` response.
   - **100% of the master's `FC5, modbus_len == 6` request packets are labelled `0` (Normal)**, while **100% of the slave's `FC5, modbus_len == 3` response packets are labelled `1` (Reconnaissance)**.
   - Without the upstream Python/ notebook script that generated `recon_labeled_packets_ALL.csv.xlsx`, we cannot prove whether the upstream author applied a heuristic rule (`if modbus_len == 3: label = 1`) or mis-mapped the direction/signature when labeling the PCAPs.
2. **Why `FC5` (`Write Single Coil`) Traffic Was Labelled as Reconnaissance:**
   - `attack_events_mapped.xlsx` contains zero rows for `substation-1.pcap`, `substation-4.pcap`, and `substation-14.pcap` (which together contain `6,266` `FC5 + len3` positive packets), and its `158` rows for `substation-2.pcap` and `substation-10.pcap` contain only `func_code in {1, 2, 3, 4}` (`Recon. Complete` and `Recon. Range: 2000`).
   - Why `FC5` coil-write response traffic in `substation-1, 2, 4, 10, 14` was assigned `label = 1` in a reconnaissance dataset is undocumented in the supplied files and cannot be verified without the original CICModbus2023 full attack logs for `03-15-2023`, `03-16-2023`, `03-19-2023`, and `03-20-2023`.

---

## 3. Non-Constant Clock Offsets in `attack_events_mapped.xlsx` (`[UNPROVED LOG-TO-PACKET MAPPING PROCEDURE]`)

### What is verified locally
- [`Dataset/attack_events_mapped.xlsx`](file:///d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/Dataset/attack_events_mapped.xlsx) maps `158` individual packets in `substation-2.pcap` (`107` packets) and `substation-10.pcap` (`51` packets) to `8` distinct `(file_source, log_attack, log_timestamp)` entries from CIC attack logs (`attack\compromised-scada\attack logs\03-15-2023\03-15-2023-1.csv` and `attack\compromised-scada\attack logs\03-19-2023\03-19-2023-1.csv`).
- However, the time difference (`packet_timestamp_utc - log_timestamp`) is **not a constant timezone offset** across the 8 log entries:
  - In `substation-10.pcap`, the two log entries have offsets of **`-191.07` minutes** and **`-209.98` minutes** (~19 minutes apart in relative drift).
  - In `substation-2.pcap`, the six log entries have offsets of **`+141.48` min**, **`+130.05` min**, **`+95.56` min**, **`+60.54` min**, **`+34.60` min**, and **`-13.26` min**.
- Furthermore, `147` of the `158` `event_mapped` packets have routine single-register polling parameters (`func_code in {1, 2, 3, 4}`, `quantity == 1` for requests or `quantity == 0` for responses, `modbus_len == 6` for requests or `4/5` for responses) that are indistinguishable at the packet and sequence level from normal background polling.

### What remains unresolved
- Because the upstream script that created `attack_events_mapped.xlsx` is not present in the repository, the exact matching algorithm used to link those 158 packets to log timestamps separated by variable offsets (`-210` min to `+141.5` min) cannot be independently verified.

---

## 4. Provenance of the 14 Excluded `attached_recon_flows.csv` Rows (`[EXTERNAL LAB ARTIFACT]`)

### What is verified locally
- `recon_labeled_packets_ALL.csv.xlsx` contains 14 rows (`row_index` `879,211 .. 879,224`, of which 12 have `label == 1` and 2 have `label == 0`) with `file_source == "attached_recon_flows.csv"`.
- These rows have time-of-day-only strings (`00:31:01.700000 .. 00:32:18.900000`) with no calendar date, use `192.168.10.x` IP addresses (`192.168.10.50 -> 192.168.10.10/11/12`, whereas all CIC captures use `185.175.0.x`), and consist of tiny 2–4 packet sessions (`s0001..s0005`, all `< 20` packets).
- All 14 rows are excluded in `Pre-processed/rebuilt_sequences/packet_exclusions.csv` with `reason = "excluded_file"`.

### What remains unresolved
- The origin of `attached_recon_flows.csv` is undocumented in `Dataset/`. Its exclusion during sequence rebuilding is mandatory because timestamps lack a date and no stream reaches the 20-packet window length.
