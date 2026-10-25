# External documentation cross-check

Checked 25 October 2026. These references support interpretation; they do not replace direct PCAP/log verification.

- [CIC's original dataset page](https://www.unb.ca/cic/datasets/modbus-2023.html) identifies endpoint roles and three attack-origin scenarios. It describes sequential 100 MB chunks, NIC/bridge views, UTC logger timestamps, and a display-time adjustment for captures. PCAP record timestamps are epoch values: this audit compares those values directly, rather than adding a second display-time offset. Match quality must establish whether a given logger behaves consistently.
- [Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf), sections 6.5 and 7, defines FC5 as Write Single Coil. A normal FC5 request/echo has address and value fields; an exception has the high-bit function code and one exception byte. Length 3 alone cannot establish the initiating attack mechanism. Exact bytes are needed.
- [Independent processing author's project](https://github.com/AliDMazloum/ICS_Data_Processing) reports that response-template novelty detects some recon-associated exceptions while read-based reconnaissance can require address/timing context. This is a lead for comparison, not independent verification of Harry's labels. Its reported performance is not imported into this audit.
- [CIC download endpoint](https://cicresearch.ca/CICDataset/CICModbusDataset2023/) returned a download form/server error during this audit. The user subsequently provided the complete local distribution at `G:\modbus cic 2023\Modbus Dataset`; it is inventoried directly.

The local README states scenario, endpoint, chunk and mirror facts. It does not precisely describe every attack generator's scan algorithm. That detail must be reconstructed from original logs and bytes. No external repository instruction was executed as an instruction for this task.
