# Proposed evidence policy v2.0 — NOT ADOPTED

Decision: **NO_TIMING_TOLERANCE_CHANGE_JUSTIFIED_BY_AVAILABLE_CLOCK_AND_IDENTITY_EVIDENCE**. Baseline v1 and all 154 accepted injection labels remain frozen. This document does not authorize activating new labels.

| Window(us), diagnostic only | Unique candidates | Parser-ok | Malformed | Existing100 retained | New candidate only |
|---|---:|---:|---:|---:|---:|
| 0 | 82 | 34 | 48 | 0 | 82 |
| 1,000 | 400 | 63 | 337 | 97 | 303 |
| 5,000 | 187 | 10 | 177 | 100 | 87 |
| 25,000 | 100 | 2 | 98 | 100 | 0 |

This table is a before/after *candidate* comparison; accepted counts after this run remain 1,404,306 / 100 / 54 at every row. Exact-time excludes all 100 currently accepted commands yet proposes 82 different candidates; 1 ms retains 97, withholds 3 old candidates and introduces 303 new ones. No change is scientifically justified by those counts alone.

Required rationale and activation gates:

1. Preserve v1 accepted labels separately and retain all original log rows/serials.
2. Establish original logger serialization/call order and independently justified clock uncertainty, scoped by family/source/day/device; otherwise retain ambiguous timing intervals.
3. Reconcile connection generations, target/unit/function/address and literal TID behavior in a complete justified canonical view; keep all candidate edges.
4. Require mechanism-specific support independent of malformedness or direction; record injection attempt, pair outcome and physical impact separately.
5. Publish event-level before/after dispositions with source/log/frame/byte lineage and explicit reasons for every promotion/rejection, then obtain approval before replacing the baseline.

No global offset, clock precision or transaction-range semantics is invented. Independent logger/clock evidence is absent, and current matching residuals are selection-conditioned. A future revision must retain the current version and publish exact accepted/rejected event/log lineage before seeking authorization.
