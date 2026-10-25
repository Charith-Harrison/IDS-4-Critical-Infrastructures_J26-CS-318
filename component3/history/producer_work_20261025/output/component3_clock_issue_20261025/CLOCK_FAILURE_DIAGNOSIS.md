# Recurring collector clock failure —25 October2026

The collection is stopped with87 accepted completion receipts. MX086(first attempt), MX087(first attempt), and MX088 were rejected because an application response wall-clock timestamp was earlier than its request. Reported capture drops were0 in each case. These are recorded timing-order failures, not proof that the real TCP response travelled backwards in time.

| Failed planned run | Backward timestamp jump |
|---|---:|
| MX086 |1.251897ms|
| MX087 |1.292246ms|
| MX088 |0.702820ms|

The generator records send/receive observations using `time.time_ns()` in runtime/collector.py. The validator requires those values to be nondecreasing in engine/c3qual/validation.py. The actual runtime reports `CLOCK_REALTIME` as adjustable and non-monotonic, while `CLOCK_MONOTONIC` is nonadjustable. This is a collector clock-design vulnerability: calendar timestamps are not a guaranteed stopwatch. It should have been caught during engineering qualification with an injected clock-step software test.

The exact mechanism causing the real clock reversals is not established. WSL/Hyper-V synchronization is a plausible contributor, not a proved explanation for this PC. The Windows Time service was stopped when queried. No clock, service, VM, Docker or Windows setting has been changed during this diagnosis.

## Corrective design

A separately versioned collector should preserve original UTC/wall-clock values for provenance and also record a monotonic nanosecond value at each observation. It should validate application ordering/durations using that actual monotonic evidence, independently validate captured TCP/frame order, and report wall-clock discontinuities without fabricating corrected timestamps. It must still reject reversed monotonic evidence, missing bytes, bad pairs, invalid controls and packet loss.

Test the correction with forward/backward calendar-clock changes, real monotonic-order violations, and existing byte/pair/state/label failures. Qualify the changed metadata path separately before any new main capture. Include a bounded retry for transient progress-file replacement errors only if separately versioned and tested; do not hide that change in the frozen image.

Do not edit or refreeze the current collector in place. Do not backfill monotonic readings for earlier runs. Existing87 accepted recordings remain preserved; whether a new continuation can be combined with them needs an explicit compatibility and timing-feature decision, not an automatic claim. Full recollection is not assumed merely from this diagnosis.

Sources: https://docs.python.org/3.13/library/time.html#time.monotonic ; https://docs.python.org/3.13/library/time.html#time.time ; https://ubuntu.com/wsl/docs/stable/explanation/time-sync/ . External WSL reports explain plausibility, not the proven cause on this host.


## Operational recommendation clarified after checking the frozen retry contract

The earlier blanket recommendation to stop until a new collector version was too strong. The unchanged frozen protocol already permits explicit preserved fresh attempts, up to three attempts per planned ID. On checking the current records, MX086 and MX087 each passed their second attempt; MX088 has only one failed attempt,87 accepted slots remain preserved and17 are still to complete.

Finishing the current collection under those unchanged checks is defensible. Every new attempt must pass the same evidence/clock/drop/pair/control requirements; failed attempts remain excluded and preserved. No acceptance threshold, timestamp, seed, source or frozen image is changed. A code/clock-instrumentation change requires separate versioning, but a predeclared technical retry does not. Stop if a planned ID exhausts its attempt cap or substantive data contradictions appear. Clock-order acceptance does not certify absolute timing accuracy; acquisition failures and retry selection must be disclosed in the later dataset documentation.
