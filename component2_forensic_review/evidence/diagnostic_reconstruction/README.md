# New diagnostic reconstruction

These files are newly derived during the 2026-10-25 forensic review from the attached processed packet workbook. They follow the visible historical filename grouping, largest-interface-view selection, chronological sorting and 20-packet/stride-5 window rules.

They are **not** copies of the missing historical rebuilt files. Matching historical summary counts does not establish file equality or ground-truth label validity. Original `label` values are preserved solely to reproduce diagnostics. No source or historical output is overwritten.

`row_index` is the zero-based row position in the processed packet worksheet, not a PCAP frame number. All session, capture and window IDs are derived or supplied metadata. Their names do not prove TCP connection boundaries or campaign independence.

These outputs are not approved final training data. See `../../rebuilt_sequence_audit.json` (from the review root) and `../../WINDOW_INTEGRITY_REPORT.json` for audit limitations; source labels require separate provenance reconstruction.
