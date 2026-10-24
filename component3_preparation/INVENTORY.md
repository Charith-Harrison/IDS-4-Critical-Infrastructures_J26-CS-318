# Verified CIC source inventory

Local source: `C:\Users\ASUS\Desktop\Github_Kavisha_Harshangi\IDS-4-Critical-Infrastructures_J26-CS-318\data\raw\Modbus Dataset`. Reference pack: `references/component3_reference/`. Identification agrees with the supplied README and the [publisher's CICModbusDataset2023 description](https://www.unb.ca/cic/datasets/modbus-2023.html). This establishes local collection identity; no publisher checksum/archive completeness certificate was available.

There are **207 files / 15,761,969,012 bytes**: 170 classic PCAPs, 34 original CSV logs, one XLSX, README and setup image. Full local file SHA256 values are in `output/inventory.json`; capture headers/record boundaries were scanned, not just filename endpoints. Source preservation was checked again after extraction: **True**. All observed captures use Ethernet and microsecond classic-PCAP timestamps. Unsupported formats are not silently converted.

The log table preserves **1,536,126 source rows** (1,420,042 CSV and 116,084 workbook). The March21 workbook's three sheets retain raw numeric serials and decimal time conversion; the shortened CSV is retained as a superseded version. Its 8,306 non-time rows agree with IED4C; 39 display rounding differences remain visible. Completion ID1048575 is not a wire ID and is never wrapped. Six external-attacker CSVs lack target/TID; external means an original CIC attack scenario, not an additional dataset.

## Selected extraction scope

| Canonical view | Capture chunks | Frames | ADUs | Extraction seconds |
|---|---:|---:|---:|---:|
| benign_ied1b | 7 | 7,023,161 | 1,404,306 | 360.81 |
| external_bridge | 2 | 1,710,508 | 282,100 | 91.42 |
| ied_ied1b | 6 | 6,125,628 | 1,116,805 | 261.14 |
| scada_ied1a | 6 | 6,064,388 | 964,683 | 282.05 |

**21 original captures / 1,815,936,064 bytes** were decoded, producing **3,767,894 ADUs** and **3,768,287 total application/candidate records** from **20,923,685 frames**. Selection uses full available endpoint chains, not attack-only packets. Benign/compromised-IED use IED1b(.5); compromised-SCADA uses IED1a(.4); the external scenario uses its bridge. Other endpoints and views remain inventoried but outside the selected row cohort. The selected source manifest lists every capture/hash/chunk; checkpoints link source chunks to event frame offsets.

All rotations and simultaneous views belong to four broad capture campaigns. They do not establish independent physical testbeds or one independent episode per day. `substation-0.pcap` under compromised-SCADA is March23 and is conservatively grouped with compromised-IED using time and cross-view frame evidence; it is not concatenated before March15 chunks1–17. Copy audit: 595 time-linked sampled mirror clusters, 0 cross-group clusters. Absence of sampled duplicates is not proof of complete uniqueness; one canonical view per group avoids importing simultaneous copies as independent rows.

Original derivatives, original parser modules, PDFs, existing models/application and other components were preserved. No external dataset or old derivative supplied extracted records.
