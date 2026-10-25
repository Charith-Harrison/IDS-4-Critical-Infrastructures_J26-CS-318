# CIC raw-source inventory

Source: `G:\modbus cic 2023\Modbus Dataset`

Read-only inspection. No full capture decoding, dataset extraction, label assignment, split, model preprocessing or training was performed. No MSU or external dataset was inspected.

- Files: **207**
- Directories below root: **78**
- Total file bytes: **15,761,969,012** (15.762 GB; 14.679 GiB)
- AGENTS.md files in source/ancestors: **0**

## File types

| Extension | Files | Bytes |
|---|---:|---:|
| `.csv` | 34 | 109,651,156 |
| `.md` | 1 | 5,950 |
| `.pcap` | 170 | 15,650,015,783 |
| `.png` | 1 | 99,562 |
| `.xlsx` | 1 | 2,196,561 |

## Capture series and bounded timestamp endpoints

First timestamps come directly from the first record header. Last timestamps come from a bounded, structurally valid multi-record suffix ending at EOF. The unread middle is not validated, and a timestamp endpoint is not a known recording independence boundary. All times below are UTC; CSV log time zones remain unverified.

| Candidate series | PCAPs | Suffixes | First UTC | Last UTC (tail-derived) |
|---|---:|---|---|---|
| `attack/compromised-ied/central-agent/central-agent-network-captures` | 5 | 0, 1, 2, 3, 4 | 2023-03-23T02:09:46.409187Z | 2023-03-29T16:29:01.683995Z |
| `attack/compromised-ied/ied1a/ied1a-network-captures` | 6 | 0, 1, 2, 3, 4, 5 | 2023-03-23T02:12:00.885261Z | 2023-03-29T16:29:01.684000Z |
| `attack/compromised-ied/ied1b/ied1b-network-captures` | 6 | 0, 1, 2, 3, 4, 5 | 2023-03-23T02:12:00.885255Z | 2023-03-29T16:29:01.683998Z |
| `attack/compromised-ied/ied4c/ied4c-network-captures` | 6 | 0, 1, 2, 3, 4, 5 | 2023-03-23T02:12:00.885242Z | 2023-03-29T16:22:55.030348Z |
| `attack/compromised-ied/trust-scada-hmi/trust-scada-network-captures` | 20 | 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 | 2023-03-23T02:12:00.885271Z | 2023-03-29T16:29:01.684005Z |
| `attack/compromised-scada/central-agent/central-agent-network-captures` | 2 | 0, 1 | 2023-03-15T02:01:00.182176Z | 2023-03-22T03:56:18.985309Z |
| `attack/compromised-scada/ied1a/ied1a-network-captures` | 6 | 0, 1, 2, 3, 4, 5 | 2023-03-15T02:01:05.333343Z | 2023-03-22T03:56:19.241237Z |
| `attack/compromised-scada/ied1b/ied1b-network-captures` | 8 | 0, 1, 2, 3, 4, 5, 6, 7 | 2023-03-15T02:01:06.081371Z | 2023-03-22T03:56:14.633222Z |
| `attack/compromised-scada/ied4c/ied4c-network-captures` | 6 | 0, 1, 2, 3, 4, 5 | 2023-03-15T02:00:57.969356Z | 2023-03-22T03:56:19.501225Z |
| `attack/compromised-scada/scada-hmi/scada-hmi-network-capture` | 17 | 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 | 2023-03-15T02:01:08.009340Z | 2023-03-22T03:56:19.501223Z |
| `attack/compromised-scada/substation-wide-capture` | 18 | 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 | 2023-03-15T08:53:28.842227Z | 2023-03-23T02:15:43.529226Z |
| `attack/external/central-agent/central-agent-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921377Z | 2023-02-01T14:02:04.979890Z |
| `attack/external/external-attacker/external-attacker-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921372Z | 2023-02-01T14:01:59.915864Z |
| `attack/external/ied1a/ied1a-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921383Z | 2023-02-01T14:02:04.979889Z |
| `attack/external/ied1b/ied1b-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921397Z | 2023-02-01T14:01:59.915881Z |
| `attack/external/ied4c/ied4c-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921366Z | 2023-02-01T14:02:00.210127Z |
| `attack/external/network-wide` | 2 | 0, 1 | 2023-02-01T03:48:39.921403Z | 2023-02-01T14:02:04.979891Z |
| `attack/external/scada-hmi/scada-hmi-network-capture` | 1 | 0 | 2023-02-01T03:48:39.921314Z | 2023-02-01T14:02:00.226216Z |
| `benign/central-agent/central-agent-network-capture` | 1 | no numeric suffix | 2023-01-17T06:29:00.344402Z | 2023-01-31T16:31:59.801454Z |
| `benign/ied1a/ied1a-network-capture` | 8 | 4, 5, 6, 7, 8, 9, 10, 11 | 2023-01-22T04:10:36.642504Z | 2023-01-31T16:29:02.040466Z |
| `benign/ied1b/ied1b-network-capture` | 7 | 4, 5, 6, 7, 8, 9, 10 | 2023-01-23T10:02:58.561337Z | 2023-01-31T16:29:02.040468Z |
| `benign/ied4c/ied4c-network-capture` | 8 | 4, 5, 6, 7, 8, 9, 10, 11 | 2023-01-22T04:00:30.273571Z | 2023-01-31T16:29:02.040462Z |
| `benign/network-wide-pcap-capture/network-wide` | 19 | 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 | 2023-01-23T20:52:05.777284Z | 2023-01-31T16:29:02.040459Z |
| `benign/scada-hmi/scada-hmi-network-capture` | 19 | 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 | 2023-01-23T13:52:04.004077Z | 2023-01-31T16:29:02.040469Z |

## What the source establishes

- The supplied README describes device NIC and Docker bridge viewpoints, 100 MB sequential capture chunks, and timestamped attack logs. Device and bridge copies may observe the same traffic. Treat capture files as source fragments rather than independent experimental samples.
- Attack parent folders are `external`, `compromised-scada`, and `compromised-ied`. Those folder labels establish scenario provenance, not per-message attack ground truth.
- Benign chunk series include nonzero starting suffixes. Their absence before the observed minimum is recorded as a source-boundary limitation, not assumed corruption. Any unexpected internal suffix gaps are listed in the JSON.
- The single XLSX sits alongside an `original.csv` of the same date. They must be compared as possible versions of one log, not automatically appended as separate attack events.
- PCAP link type, timestamp precision, exact relative paths, byte counts, CSV headers, and each file's bounded timestamps are in `source_inventory.json`.

## Remaining checks before extraction/splitting on the owner's machine

1. Confirm scenario clocks and CSV log time zones against packet evidence; do not assume displayed clock strings are UTC.
2. Establish continuity across numbered chunks and run identity across views using time, TCP state, packet duplication and log provenance.
3. Identify overlapping views before choosing a canonical capture source or deduplicating observations. Keep all views of an event in one partition.
4. Verify request/response mechanism and event-level labels from sufficient packet/log evidence. A response to an injected request is not automatically response injection.
5. Count independently supported groups for each class before promising train/validation/test coverage. Continuous runs or scenarios may provide too few independent groups.
6. Preserve raw bytes, precise timestamps and packet/source offsets in later extraction. Do not infer decoded process values from empty exports.

## Immediate source-specific limitations

- All 170 captures have classic-PCAP Ethernet link type 1 and microsecond timestamp precision. Every bounded suffix passed the structural chain check. This does not establish whole-capture integrity.
- Six external attack CSVs have only `Timestamp,Attack`; they lack the `TargetIP` and `TransactionID` fields present in the other 28 logs. The README's richer log dictionary does not apply to every file.
- External packet endpoints cover February 1, 2023, whereas external log filenames also name December 29–30, January 1–2 and January 17. Log-to-capture coverage must be established using actual contents and clock alignment; unmatched historical logs cannot create observed packet examples.
- Compromised-SCADA device captures begin March 15, while its log filenames include March 12–14. Those older logs must not be assumed to have corresponding packet coverage.
- **Numeric order is wrong for one apparent series.** `attack/compromised-scada/substation-wide-capture/substation-0.pcap` is only 20,006 bytes and spans March 23, 02:12:00.885275–02:15:43.529226 UTC. `substation-1.pcap` starts March 15, 08:53:28.842227 UTC. Moving numerically from 0 to 1 jumps backwards 667,334.687 seconds. Files 1–17 cover March 15–22. Do not concatenate file 0 with 1–17 as a normal sequential run; resolve its recording origin.
- That March 23 `substation-0.pcap` overlaps the compromised-IED capture start at approximately 02:09–02:12 UTC. Packet-level checks must establish whether these include duplicated traffic, a scenario transition or different run boundaries before splitting by folder.
- The other 145 numeric adjacent file boundaries have nonnegative gaps no larger than 4.973 seconds, supporting apparent chunk continuity while leaving TCP/run checks outstanding.
- No internal numeric chunk gaps were found within each observed suffix range. Nonzero starts remain recorded source-boundary caveats.

No row split is declared valid by this inventory.
