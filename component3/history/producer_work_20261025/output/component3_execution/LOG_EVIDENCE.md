# Original CIC log evidence audit

This audit reads the original README and attack CSV logs. It does not scan full PCAPs, extract a dataset, create ground-truth labels, or split data.

Source: `G:\modbus cic 2023\Modbus Dataset`

Found **34 CSVs**, **1,420,042 rows**, totaling **109,651,156 bytes**.

Log rows are tool events, not necessarily individual network messages. Completion rows, ranges, duplicates, malformed timestamps and oversized transaction IDs prevent a direct one-to-one label join.

## Evidence and limits for component 3

- The supplied README lists reconnaissance, query flooding, payload loading, response delay, length manipulation, false-data injection, stacked frames, brute-force writes and replay. It does not provide per-packet labels or attack implementation code.
- The seven compromised-IED CSVs contain 676 events, all targeting `185.175.0.2`, the secure HMI according to the README. These include 54 literal `False Data Injection Attack` events on March 23–29, 2023, plus 50 delay-start and 50 response-send events. Their 16-bit transaction IDs and full naive millisecond timestamps make them strong candidates for targeted capture verification. A candidate is not yet a verified response-injection label.
- The compromised-SCADA logs contain brute-force/specific-coil events and payload/length/stacking/replay activity directed at IEDs. These are candidates for command-side analysis, but attack names alone do not prove message direction or mechanism.
- All six external attacker CSVs have only `Timestamp,Attack`. They lack `TargetIP` and `TransactionID`, despite the README's four-column dictionary. Missing values cannot be filled from documentation without packet evidence.
- All CSV times are timezone-naive. Apparent fractional widths of one/two/three digits are literal decimal representations, often consistent with omitted trailing zeros; they do not themselves establish different clock accuracy. Never add a guessed UTC offset.
- Folder dates are not always event dates: `03-12-2023-2.csv` and `03-12-2023-3.csv` contain March 13 events, overlapping the date in other log folders. Determine recording overlap from actual timestamps and packets, never folder names alone.
- The March 21 CSV contains 8,306 rows for target `.8` with truncated `mm:ss.0` time strings. Its companion XLSX retains numeric date/hour/millisecond values, and additionally contains `.4` and `.5` sheets. Do not discard the day before checking the workbook; do not double-count overlapping CSV/workbook records.
- There are 806,142 excess exact event signatures across the CSVs. Repeated same-millisecond tool-loop events may be real log behavior. This audit reports them; it does not remove them or assume each row is an independent packet.
- Many completed reconnaissance/payload/length/stacking/flooding events have `TransactionID=1048575`, larger than a Modbus 16-bit transaction identifier. Such values cannot be joined as literal wire transaction IDs or silently reduced modulo 65536. Treat their semantics as unverified tool metadata until source code or packet evidence explains them.
- `Baseline Replay: In position` is a state/event annotation, not proof that a replayed message was emitted at exactly that instant. Genuine PLC replies following injected writes also must not be relabelled response injection.
- No source `.py` files or additional local attack implementation documentation were found under the dataset root during the initial metadata search. Mechanism confirmation requires captures or additional original code.

## Safe next inspection on her machine

1. Index capture headers/ranges and device viewpoints, preserving source paths and original timestamp precision.
2. Check a few exact compromised-IED false-data/delay events against corresponding captures using target, direction, connection, transaction ID, time and bytes together. Establish clock alignment rather than using a broad blanket attack window.
3. Check brute-force/specific-coil events against command requests and genuine acknowledgements, preserving the distinction.
4. Create evidence records with matched/ambiguous/unmatched status. Only verified matches may become mechanism labels; unknown records remain unknown.
5. Reconstruct recording/duplicate-viewpoint/dependency groups before selecting partitions. This audit itself creates no extraction, labels, partitions or model preprocessing.

## Per-log inventory

| Log | Rows | Timestamp shape | Missing/out-of-range TID | Exact duplicate excess |
|---|---:|---|---|---:|
| `attack\compromised-ied\attack logs\03-23-2023\03-23-2023-1.csv` | 66 | {'full_naive_datetime': 66} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-24-2023\03-24-2023-1.csv` | 113 | {'full_naive_datetime': 113} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-25-2023\03-25-2023-1.csv` | 102 | {'full_naive_datetime': 102} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-26-2023\03-26-2023-1.csv` | 109 | {'full_naive_datetime': 109} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-27-2023\03-27-2023-1.csv` | 109 | {'full_naive_datetime': 109} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-28-2023\03-28-2023-1.csv` | 106 | {'full_naive_datetime': 106} | 0 | 0 |
| `attack\compromised-ied\attack logs\03-29-2023\03-29-2023-1.csv` | 71 | {'full_naive_datetime': 71} | 0 | 0 |
| `attack\compromised-scada\attack logs\03-12-2023\03-12-2023-1.csv` | 107,770 | {'full_naive_datetime': 107770} | integer_outside_uint16=172 | 68,285 |
| `attack\compromised-scada\attack logs\03-12-2023\03-12-2023-2.csv` | 33,566 | {'full_naive_datetime': 33566} | integer_outside_uint16=96 | 22,275 |
| `attack\compromised-scada\attack logs\03-12-2023\03-12-2023-3.csv` | 41,618 | {'full_naive_datetime': 41618} | integer_outside_uint16=112 | 28,257 |
| `attack\compromised-scada\attack logs\03-13-2023\03-13-2023-1.csv` | 106,092 | {'full_naive_datetime': 106092} | integer_outside_uint16=300 | 62,662 |
| `attack\compromised-scada\attack logs\03-13-2023\03-13-2023-2.csv` | 49,776 | {'full_naive_datetime': 49776} | integer_outside_uint16=111 | 33,244 |
| `attack\compromised-scada\attack logs\03-14-2023\03-14-2023-1.csv` | 141,042 | {'full_naive_datetime': 141042} | integer_outside_uint16=300 | 85,031 |
| `attack\compromised-scada\attack logs\03-14-2023\03-14-2023-2.csv` | 99,536 | {'full_naive_datetime': 99536} | integer_outside_uint16=172 | 52,741 |
| `attack\compromised-scada\attack logs\03-14-2023\03-14-2023-3.csv` | 30,888 | {'full_naive_datetime': 30888} | integer_outside_uint16=36 | 19,279 |
| `attack\compromised-scada\attack logs\03-15-2023\03-15-2023-1.csv` | 101,863 | {'full_naive_datetime': 101863} | integer_outside_uint16=217 | 62,814 |
| `attack\compromised-scada\attack logs\03-15-2023\03-15-2023-2.csv` | 74,794 | {'full_naive_datetime': 74794} | integer_outside_uint16=200 | 42,516 |
| `attack\compromised-scada\attack logs\03-15-2023\03-15-2023-3.csv` | 14,784 | {'full_naive_datetime': 14784} | integer_outside_uint16=56 | 6,561 |
| `attack\compromised-scada\attack logs\03-16-2023\03-16-2023-1.csv` | 51,786 | {'full_naive_datetime': 51786} | integer_outside_uint16=226 | 33,429 |
| `attack\compromised-scada\attack logs\03-16-2023\03-16-2023-2.csv` | 33,555 | {'full_naive_datetime': 33555} | integer_outside_uint16=211 | 21,352 |
| `attack\compromised-scada\attack logs\03-16-2023\03-16-2023-3.csv` | 66,536 | {'full_naive_datetime': 66536} | integer_outside_uint16=188 | 29,818 |
| `attack\compromised-scada\attack logs\03-17-2023\03-17-2023-1.csv` | 21,134 | {'full_naive_datetime': 21134} | integer_outside_uint16=48 | 14,133 |
| `attack\compromised-scada\attack logs\03-17-2023\03-17-2023-2.csv` | 8,878 | {'full_naive_datetime': 8878} | integer_outside_uint16=20 | 6,053 |
| `attack\compromised-scada\attack logs\03-18-2023\03-18-2023-1.csv` | 74,754 | {'full_naive_datetime': 74754} | integer_outside_uint16=180 | 42,085 |
| `attack\compromised-scada\attack logs\03-19-2023\03-19-2023-1.csv` | 138,314 | {'full_naive_datetime': 138314} | integer_outside_uint16=432 | 80,221 |
| `attack\compromised-scada\attack logs\03-20-2023\03-20-2023-1.csv` | 74,829 | {'full_naive_datetime': 74829} | integer_outside_uint16=239 | 43,615 |
| `attack\compromised-scada\attack logs\03-21-2023\03-21-2023-1-original.csv` | 8,306 | {'truncated_mm_ss_or_unknown': 8306} | integer_outside_uint16=20 | 8,217 |
| `attack\compromised-scada\attack logs\03-22-2023\03-22-2023-1.csv` | 8,338 | {'full_naive_datetime': 8338} | integer_outside_uint16=28 | 4,480 |
| `attack\external\external-attacker\attacker logs\01-01-2023\01-01-2023-1.csv` | 1 | {'full_naive_datetime': 1} | missing=1 | 0 |
| `attack\external\external-attacker\attacker logs\01-02-2023\01-02-2023-1.csv` | 2 | {'full_naive_datetime': 2} | missing=2 | 0 |
| `attack\external\external-attacker\attacker logs\01-17-2023\01-17-2023-1.csv` | 6 | {'full_naive_datetime': 6} | missing=6 | 0 |
| `attack\external\external-attacker\attacker logs\02-01-2023\02-01-2023-1.csv` | 131,187 | {'full_naive_datetime': 131187} | missing=131187 | 39,074 |
| `attack\external\external-attacker\attacker logs\12-29-2022\12-29-2022-1.csv` | 1 | {'full_naive_datetime': 1} | missing=1 | 0 |
| `attack\external\external-attacker\attacker logs\12-30-2022\12-30-2022-1.csv` | 10 | {'full_naive_datetime': 10} | missing=10 | 0 |

## Attack family counts

These families group literal tool-event names for auditing only; they are not attack-mechanism labels.

| Literal family | Log rows |
|---|---:|
| baseline_replay | 1,965 |
| loading_payloads | 1,420 |
| delay_response | 100 |
| false_data_injection | 54 |
| query_flooding | 1,475 |
| length_manipulation | 1,456 |
| stacking_frames | 1,542 |
| brute_force_or_specific_coil | 1,410,633 |
| reconnaissance | 1,397 |

## Literal attack names

| Attack text | Rows |
|---|---:|
| `Baseline Replay: In position` | 83 |
| `Starting Payload Injection... ` | 45 |
| `Payload Injection.. Complete` | 45 |
| `Delay Response Attack: Delaying response by 8267 milliseconds` | 1 |
| `Delay response: Sending response to client` | 50 |
| `False Data Injection Attack` | 54 |
| `Starting Query flooding.. ` | 63 |
| `Starting Length manipulation... ` | 71 |
| `Length manipulation.. Complete` | 71 |
| `Delay Response Attack: Delaying response by 7734 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9390 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5439 milliseconds` | 2 |
| `Query flooding.. Complete` | 28 |
| `Starting Frame Stacking... ` | 58 |
| `Frame Stacking... Complete` | 58 |
| `Delay Response Attack: Delaying response by 7481 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6610 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5928 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5077 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9242 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7564 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6104 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5305 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9300 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8633 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9645 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6713 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8280 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5245 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8890 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5508 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6865 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9702 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9017 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9525 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7038 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8344 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9478 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7101 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5421 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7288 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9755 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5561 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6146 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9190 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8332 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7209 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6291 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5149 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6438 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6743 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7056 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 7167 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9609 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6203 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8622 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 8634 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 5665 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 6210 milliseconds` | 1 |
| `Delay Response Attack: Delaying response by 9461 milliseconds` | 1 |
| `Brute force or specific coil. Address: 13` | 189 |
| `Brute force or specific - Complete` | 705,315 |
| `Brute force or specific coil. Address: 14` | 188 |
| `Brute force or specific coil. Address: 8` | 188 |
| `Replay` | 941 |
| `Replay - Complete` | 941 |
| `Query Flooding` | 712 |
| `Query flooding. Complete` | 672 |
| `Stacked Modbus Frames` | 713 |
| `Stacked Modbus Frames - Complete` | 713 |
| `Brute force or specific coil. Address: 1` | 639,195 |
| `Length manipulation` | 657 |
| `Length manipulation - Complete` | 657 |
| `Payload injection` | 665 |
| `Payload injection - Complete` | 665 |
| `Recon. Range: 2000` | 331 |
| `Recon. Complete` | 693 |
| `Recon. Range: 125` | 330 |
| `Recon. Range: 65535` | 12 |
| `Brute force or specific coil. Address: 0` | 65,558 |
| `Recon. Range: 5` | 4 |
| `Recon. Range: 2` | 1 |
| `Recon. Range: 9` | 1 |
| `Recon. Range: 20` | 1 |
| `Recon. Range: 4` | 21 |
| `Recon. Range: 1` | 3 |

## Representative verbatim events

### baseline_replay

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-23 05:09:22.829",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "1"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 3,
    "Timestamp": "2023-03-23 05:30:24.984",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "1238"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 4,
    "Timestamp": "2023-03-23 05:51:26.274",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "2479"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 32,
    "Timestamp": "2023-03-24 06:36:29.91",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "57509"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 10,
    "Timestamp": "2023-03-25 02:15:39.463",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "61512"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 4,
    "Timestamp": "2023-03-26 00:33:30.785",
    "TargetIP": "185.175.0.2",
    "Attack": "Baseline Replay: In position",
    "TransactionID": "9537"
  }
]
```

### loading_payloads

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 29,
    "Timestamp": "2023-03-23 15:14:43.534",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Payload Injection... ",
    "TransactionID": "3241"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 30,
    "Timestamp": "2023-03-23 15:14:43.534",
    "TargetIP": "185.175.0.2",
    "Attack": "Payload Injection.. Complete",
    "TransactionID": "3241"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 31,
    "Timestamp": "2023-03-23 15:31:44.009",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Payload Injection... ",
    "TransactionID": "4244"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-24 00:02:42.164",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Payload Injection... ",
    "TransactionID": "34313"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 30,
    "Timestamp": "2023-03-25 07:56:16.875",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Payload Injection... ",
    "TransactionID": "16106"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 10,
    "Timestamp": "2023-03-26 02:21:39.341",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Payload Injection... ",
    "TransactionID": "16194"
  }
]
```

### delay_response

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 33,
    "Timestamp": "2023-03-23 15:59:47.182",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay Response Attack: Delaying response by 8267 milliseconds",
    "TransactionID": "5895"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 34,
    "Timestamp": "2023-03-23 15:59:55.45",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay response: Sending response to client",
    "TransactionID": "5895"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 40,
    "Timestamp": "2023-03-23 17:50:56.35",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay Response Attack: Delaying response by 7734 milliseconds",
    "TransactionID": "12426"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 4,
    "Timestamp": "2023-03-24 00:24:42.861",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay Response Attack: Delaying response by 7481 milliseconds",
    "TransactionID": "35612"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 25,
    "Timestamp": "2023-03-25 06:23:04.447",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay Response Attack: Delaying response by 8633 milliseconds",
    "TransactionID": "10632"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 6,
    "Timestamp": "2023-03-26 01:28:35.81",
    "TargetIP": "185.175.0.2",
    "Attack": "Delay Response Attack: Delaying response by 5508 milliseconds",
    "TransactionID": "12839"
  }
]
```

### false_data_injection

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 35,
    "Timestamp": "2023-03-23 16:26:51.793",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "7485"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 46,
    "Timestamp": "2023-03-23 19:04:08.729",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "16712"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 13,
    "Timestamp": "2023-03-24 02:03:56.153",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "41435"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 4,
    "Timestamp": "2023-03-25 00:35:31.738",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "55640"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 5,
    "Timestamp": "2023-03-26 00:59:31.278",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "11129"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-27-2023\\03-27-2023-1.csv",
    "line": 22,
    "Timestamp": "2023-03-27 03:58:28.401",
    "TargetIP": "185.175.0.2",
    "Attack": "False Data Injection Attack",
    "TransactionID": "41136"
  }
]
```

### query_flooding

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 36,
    "Timestamp": "2023-03-23 16:52:52.009",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "9015"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 39,
    "Timestamp": "2023-03-23 17:28:54.872",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "11130"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 47,
    "Timestamp": "2023-03-23 19:28:12.29",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "18125"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 6,
    "Timestamp": "2023-03-24 00:40:46.831",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "36552"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 5,
    "Timestamp": "2023-03-25 00:57:32.625",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "56933"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-26 00:13:27.217",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Query flooding.. ",
    "TransactionID": "8356"
  }
]
```

### length_manipulation

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 37,
    "Timestamp": "2023-03-23 17:10:53.728",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Length manipulation... ",
    "TransactionID": "10076"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 38,
    "Timestamp": "2023-03-23 17:10:53.729",
    "TargetIP": "185.175.0.2",
    "Attack": "Length manipulation.. Complete",
    "TransactionID": "10076"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 42,
    "Timestamp": "2023-03-23 18:09:59.174",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Length manipulation... ",
    "TransactionID": "13540"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 11,
    "Timestamp": "2023-03-24 01:34:51.832",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Length manipulation... ",
    "TransactionID": "39730"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 6,
    "Timestamp": "2023-03-25 01:26:37.622",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Length manipulation... ",
    "TransactionID": "58645"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 8,
    "Timestamp": "2023-03-26 01:54:36.719",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Length manipulation... ",
    "TransactionID": "14528"
  }
]
```

### stacking_frames

```json
[
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 58,
    "Timestamp": "2023-03-23 21:53:24.972",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Frame Stacking... ",
    "TransactionID": "26657"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 59,
    "Timestamp": "2023-03-23 21:53:24.972",
    "TargetIP": "185.175.0.2",
    "Attack": "Frame Stacking... Complete",
    "TransactionID": "26657"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-23-2023\\03-23-2023-1.csv",
    "line": 62,
    "Timestamp": "2023-03-23 23:02:31.3",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Frame Stacking... ",
    "TransactionID": "30773"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-24-2023\\03-24-2023-1.csv",
    "line": 7,
    "Timestamp": "2023-03-24 00:57:47.177",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Frame Stacking... ",
    "TransactionID": "37552"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-25-2023\\03-25-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-25 00:08:29.948",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Frame Stacking... ",
    "TransactionID": "54048"
  },
  {
    "file": "attack\\compromised-ied\\attack logs\\03-26-2023\\03-26-2023-1.csv",
    "line": 17,
    "Timestamp": "2023-03-26 03:35:48.741",
    "TargetIP": "185.175.0.2",
    "Attack": "Starting Frame Stacking... ",
    "TransactionID": "20548"
  }
]
```

### brute_force_or_specific_coil

```json
[
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-12 16:12:27.761",
    "TargetIP": "185.175.0.4",
    "Attack": "Brute force or specific coil. Address: 13",
    "TransactionID": "5"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 3,
    "Timestamp": "2023-03-12 16:12:27.773",
    "TargetIP": "185.175.0.4",
    "Attack": "Brute force or specific - Complete",
    "TransactionID": "65535"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 4,
    "Timestamp": "2023-03-12 16:12:27.774",
    "TargetIP": "185.175.0.4",
    "Attack": "Brute force or specific coil. Address: 14",
    "TransactionID": "5"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-2.csv",
    "line": 10,
    "Timestamp": "2023-03-13 00:28:48.885",
    "TargetIP": "185.175.0.4",
    "Attack": "Brute force or specific coil. Address: 1",
    "TransactionID": "5"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-3.csv",
    "line": 10,
    "Timestamp": "2023-03-13 00:39:07.545",
    "TargetIP": "185.175.0.8",
    "Attack": "Brute force or specific coil. Address: 13",
    "TransactionID": "5"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-13-2023\\03-13-2023-1.csv",
    "line": 18,
    "Timestamp": "2023-03-13 01:09:18.061",
    "TargetIP": "185.175.0.5",
    "Attack": "Brute force or specific coil. Address: 1",
    "TransactionID": "5"
  }
]
```

### reconnaissance

```json
[
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 33106,
    "Timestamp": "2023-03-12 17:46:58.006",
    "TargetIP": "185.175.0.8",
    "Attack": "Recon. Range: 2000",
    "TransactionID": "0"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 33107,
    "Timestamp": "2023-03-12 17:46:58.011",
    "TargetIP": "185.175.0.8",
    "Attack": "Recon. Complete",
    "TransactionID": "1048575"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-1.csv",
    "line": 33108,
    "Timestamp": "2023-03-12 17:46:58.011",
    "TargetIP": "185.175.0.8",
    "Attack": "Recon. Range: 2000",
    "TransactionID": "0"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-2.csv",
    "line": 8284,
    "Timestamp": "2023-03-13 01:59:14.54",
    "TargetIP": "185.175.0.4",
    "Attack": "Recon. Range: 2000",
    "TransactionID": "0"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-12-2023\\03-12-2023-3.csv",
    "line": 2,
    "Timestamp": "2023-03-13 00:19:07.516",
    "TargetIP": "185.175.0.8",
    "Attack": "Recon. Range: 2000",
    "TransactionID": "0"
  },
  {
    "file": "attack\\compromised-scada\\attack logs\\03-13-2023\\03-13-2023-1.csv",
    "line": 2,
    "Timestamp": "2023-03-13 00:21:18.041",
    "TargetIP": "185.175.0.5",
    "Attack": "Recon. Range: 2000",
    "TransactionID": "0"
  }
]
```

## Original workbook recovery evidence

The XLSX file is inspected as zipped XML, without formulas, macros or edits. It retains numeric serial timestamps. The CSV's truncated display is therefore not proof that this day's date/hour precision is lost from all originals.

```json
[
  {
    "path": "attack\\compromised-scada\\attack logs\\03-21-2023\\03-21-2023-1-formatted.xlsx",
    "bytes": 2196561,
    "date1904": false,
    "excel_epoch": "1899-12-30",
    "sheets": [
      {
        "sheet": "To IED4C",
        "member": "xl/worksheets/sheet1.xml",
        "rows": 8306,
        "timestamp_cell_types": {
          "numeric_excel_serial_timestamp": 8306
        },
        "date_counts": {
          "2023-03-21": 8306
        },
        "datetime_min_naive": "2023-03-21 03:07:40.517000",
        "datetime_max_naive": "2023-03-21 05:13:52.814000",
        "target_counts": {
          "185.175.0.8": 8306
        },
        "attack_counts": {
          "Recon. Range: 2000": 2,
          "Recon. Complete": 4,
          "Recon. Range: 125": 2,
          "Brute force or specific coil. Address: 1": 4125,
          "Brute force or specific - Complete": 4128,
          "Query Flooding": 4,
          "Query flooding. Complete": 4,
          "Length manipulation": 4,
          "Length manipulation - Complete": 4,
          "Payload injection": 4,
          "Payload injection - Complete": 4,
          "Stacked Modbus Frames": 4,
          "Stacked Modbus Frames - Complete": 4,
          "Replay": 5,
          "Replay - Complete": 5,
          "Brute force or specific coil. Address: 13": 1,
          "Brute force or specific coil. Address: 14": 1,
          "Brute force or specific coil. Address: 8": 1
        },
        "duplicate_raw_serial_event_excess": 4729,
        "companion_csv_rowwise_content_matches": 8306,
        "companion_csv_rowwise_mm_ss_tenth_matches": 8267,
        "companion_csv_rows": 8306,
        "companion_csv_time_render_mismatch_examples": [
          {
            "row": 917,
            "serial": "45006.142140625001",
            "converted_naive": "2023-03-21 03:24:40.950000",
            "csv_time": "24:40.9",
            "diagnostic_render": "24:41.0"
          },
          {
            "row": 918,
            "serial": "45006.142140625001",
            "converted_naive": "2023-03-21 03:24:40.950000",
            "csv_time": "24:40.9",
            "diagnostic_render": "24:41.0"
          },
          {
            "row": 919,
            "serial": "45006.142140625001",
            "converted_naive": "2023-03-21 03:24:40.950000",
            "csv_time": "24:40.9",
            "diagnostic_render": "24:41.0"
          },
          {
            "row": 920,
            "serial": "45006.142140625001",
            "converted_naive": "2023-03-21 03:24:40.950000",
            "csv_time": "24:40.9",
            "diagnostic_render": "24:41.0"
          },
          {
            "row": 1140,
            "serial": "45006.142141782409",
            "converted_naive": "2023-03-21 03:24:41.050000",
            "csv_time": "24:41.0",
            "diagnostic_render": "24:41.1"
          }
        ],
        "samples": [
          {
            "cell": "A2",
            "raw_value": "45006.130330057873",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 03:07:40.517000",
            "numFmtId": "47",
            "target": "185.175.0.8",
            "attack": "Recon. Range: 2000",
            "transaction_id": "0"
          },
          {
            "cell": "A3",
            "raw_value": "45006.130330231485",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 03:07:40.532000",
            "numFmtId": "47",
            "target": "185.175.0.8",
            "attack": "Recon. Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A4",
            "raw_value": "45006.130330243053",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 03:07:40.533000",
            "numFmtId": "47",
            "target": "185.175.0.8",
            "attack": "Recon. Range: 2000",
            "transaction_id": "0"
          },
          {
            "cell": "A5",
            "raw_value": "45006.130330243053",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 03:07:40.533000",
            "numFmtId": "47",
            "target": "185.175.0.8",
            "attack": "Recon. Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A6",
            "raw_value": "45006.130330254629",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 03:07:40.534000",
            "numFmtId": "47",
            "target": "185.175.0.8",
            "attack": "Recon. Range: 125",
            "transaction_id": "0"
          }
        ]
      },
      {
        "sheet": "To IED1A",
        "member": "xl/worksheets/sheet2.xml",
        "rows": 8306,
        "timestamp_cell_types": {
          "numeric_excel_serial_timestamp": 8306
        },
        "date_counts": {
          "2023-03-21": 8306
        },
        "datetime_min_naive": "2023-03-21 12:14:58.761000",
        "datetime_max_naive": "2023-03-21 14:37:17.030000",
        "target_counts": {
          "185.175.0.4": 8306
        },
        "attack_counts": {
          "Recon. Range: 2000": 2,
          "Recon. Complete": 4,
          "Recon. Range: 125": 2,
          "Brute force or specific coil. Address: 1": 4125,
          "Brute force or specific - Complete": 4128,
          "Query Flooding": 4,
          "Query flooding. Complete": 4,
          "Length manipulation": 4,
          "Length manipulation - Complete": 4,
          "Payload injection": 4,
          "Payload injection - Complete": 4,
          "Stacked Modbus Frames": 4,
          "Stacked Modbus Frames - Complete": 4,
          "Replay": 5,
          "Replay - Complete": 5,
          "Brute force or specific coil. Address: 13": 1,
          "Brute force or specific coil. Address: 14": 1,
          "Brute force or specific coil. Address: 8": 1
        },
        "duplicate_raw_serial_event_excess": 4541,
        "companion_csv_rowwise_content_matches": 0,
        "companion_csv_rowwise_mm_ss_tenth_matches": 0,
        "companion_csv_rows": 8306,
        "companion_csv_time_render_mismatch_examples": [],
        "samples": [
          {
            "cell": "A2",
            "raw_value": "45006.510402326392",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 12:14:58.761000",
            "numFmtId": "47",
            "target": "185.175.0.4",
            "attack": "Recon. Range: 2000",
            "transaction_id": "0"
          },
          {
            "cell": "A3",
            "raw_value": "45006.510402546293",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 12:14:58.780000",
            "numFmtId": "47",
            "target": "185.175.0.4",
            "attack": "Recon. Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A4",
            "raw_value": "45006.510402557869",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 12:14:58.781000",
            "numFmtId": "47",
            "target": "185.175.0.4",
            "attack": "Recon. Range: 2000",
            "transaction_id": "0"
          },
          {
            "cell": "A5",
            "raw_value": "45006.510402581021",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 12:14:58.783000",
            "numFmtId": "47",
            "target": "185.175.0.4",
            "attack": "Recon. Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A6",
            "raw_value": "45006.510402650463",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 12:14:58.789000",
            "numFmtId": "47",
            "target": "185.175.0.4",
            "attack": "Recon. Range: 125",
            "transaction_id": "0"
          }
        ]
      },
      {
        "sheet": "To IED1B",
        "member": "xl/worksheets/sheet3.xml",
        "rows": 99472,
        "timestamp_cell_types": {
          "numeric_excel_serial_timestamp": 99472
        },
        "date_counts": {
          "2023-03-21": 99472
        },
        "datetime_min_naive": "2023-03-21 00:13:43.050000",
        "datetime_max_naive": "2023-03-21 23:58:39.452000",
        "target_counts": {
          "185.175.0.5": 99472
        },
        "attack_counts": {
          "Stacked Modbus Frames": 44,
          "Stacked Modbus Frames - Complete": 44,
          "Recon. Range: 2000": 10,
          "Recon. Complete": 20,
          "Recon. Range: 125": 10,
          "Brute force or specific coil. Address: 1": 49500,
          "Brute force or specific - Complete": 49527,
          "Query Flooding": 36,
          "Query flooding. Complete": 36,
          "Payload injection": 32,
          "Payload injection - Complete": 32,
          "Length manipulation": 32,
          "Length manipulation - Complete": 32,
          "Brute force or specific coil. Address: 13": 9,
          "Brute force or specific coil. Address: 14": 9,
          "Brute force or specific coil. Address: 8": 9,
          "Replay": 45,
          "Replay - Complete": 45
        },
        "duplicate_raw_serial_event_excess": 56213,
        "companion_csv_rowwise_content_matches": 0,
        "companion_csv_rowwise_mm_ss_tenth_matches": 0,
        "companion_csv_rows": 8306,
        "companion_csv_time_render_mismatch_examples": [],
        "samples": [
          {
            "cell": "A2",
            "raw_value": "45006.009526041664",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 00:13:43.050000",
            "numFmtId": "47",
            "target": "185.175.0.5",
            "attack": "Stacked Modbus Frames",
            "transaction_id": "0"
          },
          {
            "cell": "A3",
            "raw_value": "45006.009526064816",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 00:13:43.052000",
            "numFmtId": "47",
            "target": "185.175.0.5",
            "attack": "Stacked Modbus Frames - Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A4",
            "raw_value": "45006.009526076392",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 00:13:43.053000",
            "numFmtId": "47",
            "target": "185.175.0.5",
            "attack": "Stacked Modbus Frames",
            "transaction_id": "0"
          },
          {
            "cell": "A5",
            "raw_value": "45006.009526076392",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 00:13:43.053000",
            "numFmtId": "47",
            "target": "185.175.0.5",
            "attack": "Stacked Modbus Frames - Complete",
            "transaction_id": "1048575"
          },
          {
            "cell": "A6",
            "raw_value": "45006.009526076392",
            "style_index": "1",
            "cell_type": "numeric",
            "converted_naive_datetime": "2023-03-21 00:13:43.053000",
            "numFmtId": "47",
            "target": "185.175.0.5",
            "attack": "Stacked Modbus Frames",
            "transaction_id": "0"
          }
        ]
      }
    ],
    "interpretation": "Workbook retains numeric serial date+hour+subsecond values absent from CSV display strings. These are naive wall-clock timestamps; timezone alignment still requires capture evidence. Different sheets and CSV overlap must not be counted as independent events."
  }
]
```
