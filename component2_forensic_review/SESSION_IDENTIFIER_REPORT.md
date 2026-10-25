# Identifier semantics

This review derives facts directly from 879,225 worksheet packet rows. Exact creation code for original `session_id` and `sequence_position` is absent. Visible repo code only loads these supplied fields.

| Identifier | Verified construction / meaning | Independence consequence |
|---|---|---|
| `session_id` | Every one of 17 IDs maps to exactly one directional `(src_ip,dst_ip,unit_id)` tuple. Names embed these values and an arbitrary `_sNNNN` suffix. Original creation procedure is unavailable. | Static endpoint/unit identity, **not proven TCP session**. Main IDs span several files and up to 57.657254 days. |
| `sequence_position` | Equals zero-based row counter within each supplied session (see per-session CSV); assigned to existing mixed, unsorted row order. | Derived ordinal, no chronology proof. |
| `file_source` | Supplied basename of putative PCAP or `attached_recon_flows.csv`; no frame or byte reference. | Source-file reference only. Basenames are not immutable source identities or independent experiments. |
| `row_index` | New zero-based position in extracted packet worksheet, exactly as `io_data.load_packets` inserts. | Audit provenance to a worksheet row; never model predictor. |
| `capture_group` | Configured filename lookup in `configs/default.yaml`; all five Feb-1 interface files map to one group. Other listed files each get their own group. | Capture group hypothesis, **not independently proven campaign/run identity**. |
| rebuilt stream | `(capture_group,session_id)`, sorted by `(ts_ns,row_index)`. | Capture-local directional logical stream, not real TCP connection; inactivity never splits it. |
| `dt_s` | Consecutive timestamps in that rebuilt stream, in seconds; first row missing. | Derived causal gap. First window timestep may depend on an outside packet unless reset by feature builder. |
| `window_id` / `window_in_stream` | Enumerated 20-row slices, stride 5, within configured stream. | Derived overlapping samples share 15 packets; cannot be split independently. |

The available packet fields contain no source/destination TCP ports, TCP sequence/acknowledgment values, flags, transaction IDs, connection generations or source frame numbers. No actual TCP boundaries can be audited from these processed fields alone. See the separate raw-source reconstruction for PCAP evidence. Treating static IDs or separate filenames as independent sessions/campaigns exceeds the evidence.

See `evidence/identifier_profiles.csv`, `evidence/legacy_session_profiles.csv`, and `evidence/diagnostic_stream_profiles.csv` for every ID and span.
