# Temporal reconnaissance evidence and normal lookalikes

This is descriptive source reconstruction. No LSTM was fitted, and no classification score is used as proof of temporal learning.

The raw recovery retained **468 request candidates**: **148 supported-contextual requests** and **320 ambiguous/other candidates**. Ambiguous candidates remain separate and are not treated as attack targets in the main comparison. The canonical documented-benign HMI view contains **2,042,925 read requests** across all its rotation chunks. All current-message shapes were counted. Causal contexts were sampled every100 requests per logical actor/target/unit stream; first-three shape exemplars are retained for traceability but excluded from the temporal distribution sample.

**0/148 candidates** have a benign counterpart sharing FC, quantity, MBAP length, frame length and unit. Exact requested-address overlap is separately tabulated below. Absence of a counterpart refers to this canonical benign view, not every possible legitimate deployment.

| func_code | quantity_value | modbus_len | packet_size | unit_id | candidate_requests | candidate_unique_addresses | benign_requests_same_shape | benign_requests_same_shape_and_candidate_address | matching_status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 5 | 6 | 78 | 1 | 3 | 2 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 1 | 20 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 1 | 2000 | 6 | 78 | 1 | 8 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 1 | 65535 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 2 | 2 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 2 | 4 | 6 | 78 | 1 | 20 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 2 | 2000 | 6 | 78 | 1 | 8 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 2 | 65535 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 3 | 9 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 3 | 125 | 6 | 78 | 1 | 50 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 3 | 65535 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 4 | 4 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 4 | 5 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 4 | 125 | 6 | 78 | 1 | 50 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |
| 4 | 65535 | 6 | 78 | 1 | 1 | 1 | 0 | 0 | no_match_in_all_canonical_benign_read_requests |

The feature distributions are in `temporal_signal_analysis.csv`; within-shape, full20-context comparisons are in `evidence/matched_shape_temporal_analysis.csv`. `evidence/temporal_candidate_examples.csv` gives source/frame/log references. The candidate-only sequence is a subsequence of all requests, so gaps between candidate rows must not be mistaken for the actual polling interval. The `previous_*` columns instead use all preceding parsed requests, causally, with a60s idle reset.

Unit IDs observed among candidates: **[1]**. Requested start-address counts: **{1: 139, 0: 4, 2: 3, 5: 2}**. Quantities: **{125: 100, 4: 21, 2000: 16, 65535: 4, 5: 4, 2: 1, 9: 1, 20: 1}**. A range read from one address is not evidence of a sequential sweep over start addresses. Multiple read functions or targets do not establish unit-ID enumeration when the unit is constant.

The figures show marginal distributions before matching; they must not be interpreted as a controlled temporal ablation. Where current-message shapes do not overlap, differences may already be explained by packet contents. Where they do overlap, causal histories can reveal observable timing or access-pattern differences, but source-family and repeated-episode dependencies remain. This audit establishes observations and limitations; it does not establish temporal generalization or an independent three-way experiment.

Raw controls taken from attack recordings are separately marked unlabeled and never called benign solely because no nearby recon log start was found. The documented-benign comparison above uses the explicit benign source scenario.
