# Selected original-CIC scope and recording groups

The verified local raw inventory contains 207 files and 15,761,969,012 bytes: 170 PCAPs, 34 original CSV logs, one original XLSX, one README and one setup image. Every source has a path/format/byte-count/SHA256 inventory entry. Matching another machine's file count/size does not by itself establish byte identity with that copy.

The extraction deliberately selects complete available endpoint/interface chains rather than decoding all simultaneous mirrored views. Its **21 PCAP chunks contain 1,815,936,064 source bytes**. It retains the full ordered traffic of those chains, including background communication, legitimate writes, malformed/partial candidates and non-Modbus accounting. It is not a packet sample selected only around attacks, and it is not full-dataset endpoint coverage.

| Selected view | Parent recording group | Original source directory | Chunks | Source bytes |
|---|---|---|---:|---:|
| `benign_ied1b` | `cic_benign_january` | `benign/ied1b/ied1b-network-capture` | 7, suffixes 4-10 | 602,961,853 |
| `external_bridge` | `cic_external_february` | `attack/external/network-wide` | 2, suffixes 0-1 | 146,790,882 |
| `scada_ied1a` | `cic_compromised_scada_march` | `attack/compromised-scada/ied1a/ied1a-network-captures` | 6, suffixes 0-5 | 546,227,098 |
| `ied_ied1b` | `cic_compromised_ied_march` | `attack/compromised-ied/ied1b/ied1b-network-captures` | 6, suffixes 0-5 | 519,956,231 |

These are the aliases in `c3prep/run_extraction.py:VIEWS`, not original source filenames or independent experimental sessions. Exact paths, hashes and chunk order are recorded in each extraction checkpoint's `contract.sources`. Chronological rotation checks and connection generations support carrying reassembly state over chunks. The benign chain begins at the supplied suffix 4; absent earlier chunks remain an initial capture-coverage limitation rather than invented preceding traffic.

## Why these chains are useful and what they miss

IED1B provides a benign command/response stream and the compromised-IED response-side candidate observed in the earlier trust-HMI pilot. IED1A provides the compromised-SCADA endpoint stream without treating simultaneous HMI/bridge copies as new independent observations. The external bridge chain preserves that scenario's available network context; its sparse timestamp-only logs still do not automatically produce event-level injection labels.

`output/pilot/ied_endpoint_crossview.json` independently checks the specific TID 7485 request and malformed reply in both the trust-HMI source and the selected IED1B source. Endpoint frames 531105/531107 have identical TCP payloads to trust-HMI frames 833140/833142, with observed timestamp differences of roughly ten microseconds. This proves that specified transaction's shared observation, not full-recording equivalence. It supports retaining the selected endpoint chain as a source of that example without adding the mirrored pilot rows to final membership.

Other permitted CIC captures remain inventoried and preserved, but their application streams are not additional final extracted rows in this selected scope. A log attempt targeting an excluded endpoint can be outside the selected scope even when its source campaign is present. The label report distinguishes outside-selected-endpoint, outside-capture-interval, unmatched and ambiguous evidence. Do not interpret those states as proof that an attack is absent from the entire raw collection.

## Conservative parent groups

`output/group_sources.json` assigns every one of the 170 original capture files to one conservative whole-campaign group, preserving all simultaneous views and rotated chunks together. The group basis is temporally separated capture campaigns with source/topology/view relationships. The same simulated testbed is reused; these groups do not establish independent physical plants, independent protocol populations or independent per-day attack replications.

Days, numbered chunks, log rows, endpoint IPs and distinct attack occurrences cannot be promoted into independent groups just to satisfy train/validation/test class coverage. Each selected chain belongs wholly to its campaign. Pairing is additionally scoped by view, endpoint tuple and TCP connection generation. No pair dependency creates a cross-partition link when whole campaigns stay together.

The small file `attack/compromised-scada/substation-wide-capture/substation-0.pcap` is conservatively assigned to `cic_compromised_ied_march`: its actual March 23 interval overlaps that campaign, and time-linked identical frame samples establish the view relationship. Chunks 1-17 in the same folder cover March 15-22. Therefore lexical/numeric concatenation of 0,1,... would go backwards in time. This file is inventoried/grouped but is not appended to a selected endpoint chain.

## Duplicate-observation containment

The source map reports bounded first/last whole-frame samples with a declared one-millisecond inter-view timestamp tolerance. `output/duplicate_containment.json` checks source-group membership, full-file hash copies and time-linked sampled frame copies across groups. A repeated identical frame or PDU at a distant time is content recurrence, not by itself proof of duplicated observation. Absence of sampled overlap is not proof that all views are unique.

Final extraction uses one selected view per campaign. Proved TCP retransmissions are accounted separately from delivered stream bytes; suppressed/overlapping bytes and whether equality was verified remain in a lossless sidecar. Distinct legitimate polls/writes are preserved even when their payloads match. None of the source-level sample checks removes application records by payload equality.

## Candidate whole-group allocation

The fixed candidate assignment is:

| Membership | Whole parent groups |
|---|---|
| `candidate_train` | `cic_benign_january`, `cic_compromised_scada_march` |
| `candidate_validation` | `cic_external_february` |
| `candidate_test` | `cic_compromised_ied_march` |

This is a documented source-scenario candidate allocation, not an approximately 70/15/15 class-complete independent experiment. Group fractions are 50/25/25; actual event fractions and accepted class-bearing group counts come from `output/split_manifest.json`. It was fixed without training or model-score selection. The names deliberately retain `candidate_`.

Insufficient accepted labels or independent class-bearing groups make a three-class experiment unsupported. A dense logged command burst can still be ambiguous under the frozen exact-target/TID/time policy; failure to assign unique command labels does not establish that the raw source lacks command attacks. Likewise a supported malformed response in one group cannot be divided into independent response-class training, validation and test replicates.

Membership manifests retain exact event IDs and source-table/annotation hashes rather than generating predictor matrices. The audit checks every canonical event UID in each contiguous view domain, every pair/candidate endpoint against that exact domain and its recording/view/partition, and one annotation per event. Their completion-time order is explicit because decoder emission can be delayed by buffered reassembly. Unknown, ambiguous and out-of-scope records remain attributed instead of being silently relabelled normal or stitched into artificial adjacency.

## Later context boundaries

No context features or windows are generated. Later history must reset at recording/view/connection generations and declared stream gaps. The proposed event lookbacks 3/5/10 are planning candidates, not executed windows. A deployment time/label horizon is not yet selected. If the researcher later introduces temporal subdivision or changes horizons, pair dependencies, warm-up and purge checks must be rerun before scoring. A temporal slice from one run answers a narrower question than an independently held-out run.
