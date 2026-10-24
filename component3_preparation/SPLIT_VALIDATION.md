# Group and partition validation

**CANDIDATE_ONLY_UNSUPPORTED_INDEPENDENT_THREE_CLASS_EXPERIMENT**. These memberships are for inspection and future design; they are not a scoring-ready three-class dataset.

| Whole recording group | Candidate partition | All records | Normal | Command | Response |
|---|---|---:|---:|---:|---:|
| cic_benign_january | candidate_train | 1,404,306 | 1,404,306 | 0 | 0 |
| cic_external_february | candidate_validation | 282,101 | 0 | 0 | 0 |
| cic_compromised_ied_march | candidate_test | 1,116,921 | 0 | 0 | 54 |
| cic_compromised_scada_march | candidate_train | 964,959 | 0 | 100 | 0 |

Requested proportions were approximately 70/15/15 only if support permitted. Actual group fractions are 50/25/25 (two/one/one whole groups). Actual record fractions are 62.87% train / 7.49% validation / 29.64% test. Class completeness in every partition: **False**. Validation has no accepted targets and training has no response-injection targets. Do not use unavailable class metrics or manufacture coverage with row shuffling.

| Check | Result | Scope |
|---|---|---|
| Event and annotation membership | verified |Every canonical UID/sequence and one-to-one annotation validated |
| Group disjointness | verified |One fixed partition per entire campaign, including rotations/mirrored source views |
| Pair/candidate dependency containment | verified |1,982,133 relations, 0 partition crossings, 0 missing endpoint IDs |
| Known file/view copy containment | verified within audited evidence |Full-file hashes, source map and time-linked bounded frame samples; no payload-only deduplication |
| Partition-local chronology | verified |Membership manifests are externally sorted by completion epoch/view/event sequence; raw extraction keeps decoder emission order |
| Class-complete independent experiment | unsupported |Class-bearing groups shown below; same testbed and continuous campaigns do not create independent repetitions |

| Target | Accepted ADUs | Class-bearing groups | Groups |
|---|---:|---:|---|
| normal | 1,404,306 | 1 | cic_benign_january |
| command_injection | 100 | 1 | cic_compromised_scada_march |
| response_injection | 54 | 1 | cic_compromised_ied_march |

The membership Parquets contain event UID, source group/view, sequence, completion time and candidate partition. They select exact rows from the immutable extracted event Parquets; no X/y matrices or feature partitions exist. Source hashes, event-table hashes, annotation hashes and full chunk membership are in the manifest. Unlabelled/malformed/unsupported/out-of-scope background is retained.

Pairing carries outstanding transactions across verified same-view rotations, handles concurrent IDs/reuse and preserves ambiguity. Requests pending at connection end and capture end remain separate. The pairing audit has no learned or universal time expiry; it bounds outstanding requests at8192 per connection and reports capacity evictions. Matches over5/60/300seconds are sensitivity counts only. Connection idle handling uses the explicit300second extraction parameter; it is not a verified Modbus deadline. Cross-chunk pair counts are in `output/pair_report.json`.

Future context resets at recording/view/connection generations and observed gaps. Candidate lookbacks3/5/10 are documented only; no windows were built. A maximum time lookback/causal label horizon has not been chosen by the researcher. Whole campaigns share no partition history; any future within-run temporal split or horizon change requires a new purge/pair validation and answers a narrower question. No claim is made that these are unseen final research holdouts: the captures have been inspected for preparation.
