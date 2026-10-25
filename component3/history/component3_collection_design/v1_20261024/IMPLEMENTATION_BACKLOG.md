# Concrete implementation backlog

This backlog is prospective. The current pilot and its recorded sources are v0.1; none of the items below is represented as already implemented or collected.

| Item | New implementation requirement | Acceptance evidence before collection |
|---|---|---|
| B01: version boundary | Separate generator/validator version and output root; preserve v0.1 and all CIC artifacts | Existing protected hashes unchanged; source, image, policy and design identities recorded |
| B02: public object map | Parameterize mode/setpoint/coil roles for M0/M1/M2 throughout protocol/state and both decoders | Legal reads/writes and reply associations validated for every map; no implicit address-zero missingness |
| B03: normal families | Implement inhibited idle, legitimate updates, repeats and visible mode transitions in addition to existing controls | Normal examples verified against declared policy in both modes; repeated genuine messages kept |
| B04: intervention families | Retain direct unauthorized ON and both directions of changed readback under the same policy | Actual changed bytes plus private intervention/state truth; acknowledgement/request associations retain correct labels |
| B05: scheduler | Implement S1/S2 without hidden state, label-specific timing or fixed target positions | Dependency ledger proves earlier visible anchors; at most six intervening ADUs during qualification; no future evidence used |
| B06: independent validator | Extend capture/stream/object/policy and normal-overlap checks for new maps/families/schedules | Fail-closed offline and actual-capture checks, including malformed, no-op mutation, missing anchor, mismatched acknowledgement, duplicate and byte-gap cases |
| B07: bounded launcher | Consume an explicit planned run; preserve network-none isolation and unique outputs; reject unsupported profiles | Check-only path does no collection; run ledger saves exact config/source/image hashes and failures |
| B08: qualification | Execute Q01–Q04 only after required code support is verified | All eight scenario families, reciprocal forgeries, normal PDU controls, zero recorded drops and complete byte/state reconciliation |
| B09: freeze main design | Review yield/cost and held-out conditions; freeze amended roster before main collection or test inspection | Written methodology decision, final design hash, role ledger, access policy and recorded amendments |
| B10: later research work | Student-owned preprocessing and matched-cohort protocol/rule/RF comparisons | Separate authorization and inspectable implementation; no transformations or models in collection code |

## Implementation constraints

- Extend the process and validator together. A map must not be changed only in message generation while the private state or verifier still assumes registers 0/1.
- The original policy only restricts pump ON. Do not invent a new setpoint-write prohibition and then mix old and new labels.
- Place any additional polling before the causal anchor, or observe the anchor again before the target. Randomization must not destroy the declared information available to the detector.
- One outstanding request per connection is sufficient for this study version. Do not silently claim multi-client/concurrent transaction or industrial-network realism.
- Use the original PCAP plus stream positions and exact bytes to identify repeated occurrences. Do not join by TID alone or delete equal PDU values.
- Retain the private oracle as ground truth and expose only actual wire observations to future detectors. The generator's knowledge of the next scenario is not causal context.
- Do not add a new algorithm to compensate for inadequate controls, or choose scenarios because a model scores well. Collection acceptance is based on protocol/evidence/observability requirements.

The immediate engineering deliverable is B01–B07 plus four unscored qualification captures. This design does not authorize claiming the draft 48-run roster has been collected, that changing seeds creates new industrial campaigns, or that ML must outperform rules.
