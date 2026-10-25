# Transaction-ID audit

## Computation evidence

The original shared extractor that produced `trans_id_diff` is absent. Therefore its source code and exact pre-filter ordering cannot be certified. The currently checked-in pipeline does **not** use that stored column for its model: it recomputes `trans_id_raw_diff` and modulo delta on reconstructed requests, scoped to partition/capture/client IP/server IP/unit, **omitting both ports**. These are endpoint-channel features, not TCP-session features. Its first observation is incorrectly assigned a normal increment of 1.

For baseline rows, every comparable non-boundary row agrees exactly with global previous-message TID subtraction within observed segments: 149,990 / 149,990. Across all CSV rows it agrees on 149,994 / 149,999; source boundaries account for the five mismatches. This strongly identifies a global per-extraction diff, not a per-connection feature.

Replay agrees with direct global subtraction on only 7,319 / 9,493 comparable rows; no candidate scoped definition explains the rest. Retained rows are not sufficient to recover the exact producer. Several stored deltas imply preceding TIDs absent from the retained neighboring rows, consistent with calculation before filtering/selection. That is an inference, not recovered provenance.



## normal candidate comparisons

| Variant | Comparable rows | Equals stored diff | Negative | Zero | First/missing |
| --- | --- | --- | --- | --- | --- |
| global_csv_order | 149999 | 149994 | 7856 | 73251 | 1 |
| within_observed_segment | 149990 | 149990 | 7850 | 73251 | 10 |
| directed_ip_pair | 149960 | 61706 | 11 | 0 | 40 |
| directed_4tuple | 1 | 1 | 0 | 0 | 149999 |
| bidirectional_4tuple_proxy | 74994 | 73227 | 0 | 74993 | 75006 |
| request_only_ip_pair | 74982 | 61682 | 1 | 0 | 75018 |
| request_only_4tuple_proxy | 1 | 1 | 0 | 0 | 149999 |

## replay candidate comparisons

| Variant | Comparable rows | Equals stored diff | Negative | Zero | First/missing |
| --- | --- | --- | --- | --- | --- |
| global_csv_order | 9493 | 7319 | 1111 | 3585 | 1 |
| within_observed_segment | 9484 | 7319 | 1109 | 3585 | 10 |
| directed_ip_pair | 9450 | 2546 | 8 | 1 | 44 |
| directed_4tuple | 231 | 4 | 0 | 0 | 9263 |
| bidirectional_4tuple_proxy | 3861 | 3580 | 0 | 3668 | 5633 |
| request_only_ip_pair | 5728 | 2546 | 6 | 1 | 3766 |
| request_only_4tuple_proxy | 183 | 4 | 0 | 0 | 9311 |

## Interleaving reproduced

Replay CSV zero-based rows 5000-5003 contain requests to alternating servers:

| Row | Destination | Client port | TID | Stored diff | Endpoint-local previous-request diff |
| --- | --- | --- | --- | --- | --- |
| 5000 | 185.175.0.4 | 34590 | 15044 | -27056 | first / unavailable |
| 5001 | 185.175.0.5 | 40926 | 42101 | 27057 | first / unavailable |
| 5002 | 185.175.0.4 | 45466 | 15045 | -27060 | +1 |
| 5003 | 185.175.0.5 | 40966 | 42106 | 27061 | +5 |

The -27060 difference implies a previous TID of 42105, while the immediately preceding retained row is 42101. Both stream interleaving and omitted source rows matter. Baseline frames 29381 onward similarly switch from server .4 TID 11178 to server .8 TID 1, creating -11177 on **normal** traffic.

The endpoint-only normal request diff has only one negative value in ten observed segments, versus 7,854 negatives in the stored baseline column. This does not make the endpoint rule a replay detector: endpoints can reset, wrap or restart legitimately, and the channel spans many TCP ports. Almost all true four-tuple proxies have only one observed request, so their previous-request TID is **missing**, not zero or one. A verified TCP-connection/session-local candidate cannot be computed: handshake continuity, `tcp.stream`, TCP sequence/ACK numbers and omitted messages are unavailable. Four-tuple comparison is explicitly only a proxy.

## Corrected semantics

New `session_tid_diff` and modulo delta use requests only within the same observed four-tuple/lifetime proxy. `endpoint_tid_diff` is a separately named cross-port endpoint/unit hypothesis. Histories reset at observed segment and partition boundaries, use only preceding requests, and are bounded by both 100 requests and 60 seconds. First history remains NaN with an availability indicator. A 65535 to 0 wrap gives signed -65535 and modulo +1; a decrease alone does not imply replay. No old CSV or stored delta was overwritten.

## Shortcut audit

Each row below gives TP / FP / TN / FN followed by precision, recall, F1, FPR and accuracy. These are descriptive diagnostics, not a detector selected on a test set. Fixed simple rules are frozen without tuning. In-sample per-field majority probes in the JSON are explicitly overfit artifact probes, not held-out scores. The unrestricted signature rule is a table-order diagnostic, not a bounded online duplicate rule or payload hash.



### derivative

| Rule | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stored_tid_negative | 2213 | 31 | 7216 | 34 | 0.986185 | 0.984869 | 0.985527 | 0.004278 | 0.993154 |
| stored_tid_zero | 19 | 3567 | 3680 | 2228 | 0.005298 | 0.008456 | 0.006515 | 0.492204 | 0.389614 |
| stored_tid_abs_gt_1000 | 2210 | 1087 | 6160 | 37 | 0.670306 | 0.983534 | 0.797258 | 0.149993 | 0.881609 |
| earlier_observed_signature_in_table | 0 | 0 | 7247 | 2247 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.763324 |
| request_direction | 2074 | 3677 | 3570 | 173 | 0.360633 | 0.923008 | 0.518630 | 0.507382 | 0.594481 |
| function_3 | 2019 | 2957 | 4290 | 228 | 0.405748 | 0.898531 | 0.559047 | 0.408031 | 0.664525 |
| frame_length_78 | 2074 | 3678 | 3569 | 173 | 0.360570 | 0.923008 | 0.518565 | 0.507520 | 0.594375 |
| response_time_zero | 2074 | 3677 | 3570 | 173 | 0.360633 | 0.923008 | 0.518630 | 0.507382 | 0.594481 |
| iat_gt_1_second | 1508 | 1258 | 5989 | 739 | 0.545192 | 0.671117 | 0.601636 | 0.173589 | 0.789657 |

### full_normal_plus_replay_positives

| Rule | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stored_tid_negative | 2213 | 7854 | 142146 | 34 | 0.219827 | 0.984869 | 0.359428 | 0.052360 | 0.948189 |
| stored_tid_zero | 19 | 73257 | 76743 | 2228 | 0.000259 | 0.008456 | 0.000503 | 0.488380 | 0.504194 |
| stored_tid_abs_gt_1000 | 2210 | 31 | 149969 | 37 | 0.986167 | 0.983534 | 0.984848 | 0.000207 | 0.999553 |
| earlier_observed_signature_in_table | 0 | 0 | 150000 | 2247 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.985241 |
| request_direction | 2074 | 75002 | 74998 | 173 | 0.026909 | 0.923008 | 0.052293 | 0.500013 | 0.506230 |
| function_3 | 2019 | 30254 | 119746 | 228 | 0.062560 | 0.898531 | 0.116976 | 0.201693 | 0.799786 |
| frame_length_78 | 2074 | 75317 | 74683 | 173 | 0.026799 | 0.923008 | 0.052086 | 0.502113 | 0.504161 |
| response_time_zero | 2074 | 75007 | 74993 | 173 | 0.026907 | 0.923008 | 0.052289 | 0.500047 | 0.506197 |
| iat_gt_1_second | 1508 | 11900 | 138100 | 739 | 0.112470 | 0.671117 | 0.192654 | 0.079333 | 0.916984 |

For the negative-diff rule, the positive support is unchanged across comparisons. Precision collapses when the larger normal population is admitted; the derivative composition is a major shortcut. The full-normal experiment deliberately contains only baseline normals plus derivative positives, exactly as requested; it does not invent new packet chronology or recompute cross-file history.
