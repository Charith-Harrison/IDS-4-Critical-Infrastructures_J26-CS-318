# Pilot design iterations

Gates and thresholds in `PILOT_PROTOCOL.md` are unchanged across iterations. Every collected iteration is kept with
its raw evidence; a failed design is not deleted or re-labelled.

## v1 (`configs/pilot_v1.json`, `c2tb/scenarios.py`, collection `pilot_v1_20261025`)

Collected 20/20 runs; **20/20 passed run acceptance** (capture, tshark, ledger join, pairing).
Collection-level gates: **G1 FAIL** (address-per-FC/unit coverage 0.705 < 0.95), **G2 FAIL** (joint shape in other
runs' normal 0.476 < 0.90), G3 pass (max current-message AUC 0.567, balanced accuracy 0.636).

Diagnosis:
* 64-address tables × four quantities gave ~1,440 shapes; normal tag lists covered too few of them. Recon shapes
  were therefore mostly *never seen* in normal traffic. Supervised current-message models could not exploit this
  (unseen values fall back to the prior), which is why G3 passed. A post-hoc "shape unseen in training-fold normal"
  rule also scored only AUC 0.505, because held-out *normal* requests were equally often unseen. So v1 is not shown
  to contain an exploitable static shortcut at this scale; it fails because the matched-shape premise was not
  achieved (recon and normal simply did not share most shapes), which G2 is designed to catch and G3 alone would not.
  At larger scale, normal coverage would grow faster than recon novelty and the novelty rule would likely strengthen.
* Informative history check: minimum inter-request interval alone gave AUC 0.994. Recon was paced steadily at
  50–400 ms while every normal poll cycle has 4–30 ms back-to-back gaps — an attack-unique *timing* shape, against
  the audit rule that attacks must not be uniquely fast or slow.

Decision written **before** v2 collection on 25 October 2026: v1 rejected as a design; redesign and repeat the pilot.

## v2 (`configs/pilot_v2.json`, `c2tb/scenarios_v2.py`)

* Fixed site envelope: each (unit, table) has a read granularity in {1, 2, 4}, shared by legitimate masters and the
  actor (threat-model assumption: a stealthy actor mimics the legitimate request shapes it can observe).
  All runs share this site configuration, so the pilot does **not** test generalisation across sites.
* 32-address tables; background HMI polls 40–80 % of every table each 2–4 s cycle.
* Recon timing: half of the R1/R2/R3/R5/R6 runs use poll-mimicking batches (4–12 requests at 4–15 ms, then
  0.5–3 s pauses); R4 stays slow (0.6–2.5 s).
* Scan breadth widened slightly (more tables per sweep) to give each recon run enough requests.
* Plan-level simulation (no traffic) predicted v2 joint-shape coverage of 1.0 versus 0.457 for v1.

Outcome (collection `pilot_v2_20261025`): 19/20 runs accepted (r09 rejected by the same-clock check). G1, G2 and G3
pass. Remaining weakness found by the hard-negative history check: recon is separable mainly because it never
revisits targets, while every legitimate pilot workload does. See `PILOT_RESULTS.md` §5 and the v3 recommendation.

## v3 (`configs/pilot_v3.json`, `c2tb/scenarios_v3.py`, collection `pilot_v3_20261025`)

Added before collection (PILOT_PROTOCOL.md Amendment A): legitimate one-pass coverage workloads N5–N8 mirroring the
recon patterns (same lead-in, same timing distributions); sites A and B (different read granularities); a 10 ms VM
clock monitor with step-corrected derived timestamps (the v3 smoke run showed ~1–3 ms wall-clock steps every ~30 s).
Recon-family plans are byte-identical to v2's for the same site and seed.

Found during processing: a backward clock step between a request and its response broke wall-clock-ordered response
pairing in one run; pairing now uses capture frame order (v1/v2 acceptance unchanged after reprocessing).

Outcome: 28/28 runs accepted; G1, G2, G3 pass (G3 nearest its limits through the raw TID value, a small-sample
counter artifact). History separates recon from revisiting normal work (within-fold AUC 0.987) but not from
legitimate one-pass coverage work (single statistics ≤ 0.56; trained models invert between mirrored scenario pairs).
See `PILOT_RESULTS.md`.
