# Component 2 controlled Modbus/TCP pilot: pre-specified protocol

Written 25 October 2026 **before collection**. Thresholds below were fixed before any pilot data existed and must
not be relaxed after inspecting results. Threat model: `THREAT_MODEL.md`.

## Purpose and non-goals

The pilot validates the *methodology*: real traffic, immutable capture, ledger-derived ground truth, lineage-preserving
parsing, and above all that **normal and recon requests overlap on current-message fields**. It is not the final
dataset, does not fix a final run count, and does not train or evaluate the LSTM.

## Relationship to existing material

* **CIC remains a secondary case study.** No CIC capture, recovered request, inherited label, log ID or audit
  confidence field enters this collection. CIC informed the out-of-scope list (bulk quantities from address 1).
* **MSU is not used**, although the proposal (p13) lists it as a secondary source.
* **Proposal conflicts flagged, not forced:** the proposal names ICSSIM and port mirroring (p13). The pilot uses a
  pymodbus server and passive capture in the target's namespace, which is equivalent observational evidence with
  fewer moving parts. The proposal's "175,800 windows from an initial testbed run" is CIC-derived per the audit and
  is not reused. The proposal requests a naive random-split contrast; random row/window splitting is not used here.
* Existing `C2_Reconnaissance_Detection/` code is not modified. The PCAP reader is reused read-only from
  `component2_forensic_review/scripts/pcapio.py`.

## Unit of independence

A **run** is a separately initialised acquisition: fresh isolated network, fresh server process with its own seeded
state, fresh capture process, fresh client processes and TCP connections, an independent seeded schedule and random
client IPs. Runs are executed in a seeded random order so scenario family is not confounded with time. A run is the
grouping unit for every held-out evaluation. Windows/requests within a run are never treated as independent.

## Scenario matrix (pilot v1)

Every run contains a **background HMI poller** (normal) plus one **actor** host:

| ID | Family | Actor behaviour |
|---|---|---|
| N1 | normal | fixed-period cyclic polling of its own tag list |
| N2 | normal | polling whose period drifts between operating modes, plus fast operator-screen bursts over contiguous blocks |
| N3 | normal | maintenance: contiguous block reads (multi-register or address-by-address, ascending or configured order), revisits, think pauses |
| N4 | normal | trend watch: repeated fast reads of a few important tags |
| R1 | recon | sequential sweep of 1–2 tables |
| R2 | recon | sparse/strided sweep over 2–3 tables |
| R3 | recon | randomised sweep (permutation) of 1–2 tables |
| R4 | recon | slow jittered sweep with intervals drawn from the normal polling range |
| R5 | recon | function-code probing (FC1–4 at each address) |
| R6 | recon | unit probing (units 1–3 at each address) |

Recon runs begin with a legitimate maintenance lead-in by the actor (labelled normal). All request shapes are drawn
from one shared envelope: units {1,2,3}; FC {1,2,3,4} with the same table weights; quantities {1,2,4,8} with the same
weights; start addresses aligned to the quantity inside 0–63. Pilot size: **2 replicates × 10 scenarios = 20 runs**,
~75 s each. This is a feasibility size, not a power-justified sample.

## Collection and lineage requirements

Per run: run manifest (IDs, seed, configuration, scenario parameters including selected units/functions/addresses,
client/target IPs, start/end, software versions, git commit, code hashes), immutable PCAP with SHA-256, tcpdump
drop statistics, per-client action ledgers with SHA-256, completion state and failure reason.
Per parsed ADU: run ID, PCAP file, frame number, ADU offset in TCP payload, capture timestamp (ns), TCP endpoints,
transaction ID, unit ID, wire function code, direction/role, address and quantity only where semantically valid
(requests FC1–4), exception flag/code, exact ADU hex. Responses are paired causally to the earlier request on the
reversed connection with the same TID/unit/base function. Response fields are never used as request addresses.

## Run acceptance (all must hold, else the run is rejected and kept with its reason)

1. Capture readable; tcpdump reports 0 packets dropped by kernel/interface.
2. Every ledger action with a sent request is matched to exactly one on-wire request; every on-wire request from a
   client is matched to exactly one ledger action (1:1 by client IP, client port, TID and exact ADU bytes).
3. Every request has exactly one paired response; no unintended exception responses; no client timeouts.
4. Parser output agrees with tshark on every Modbus ADU (frame, TID, unit, FC, address, quantity).
5. No TCP retransmission or out-of-order payload affecting a Modbus ADU (or it is explicitly resolved).
6. The run's scenario completed (recon plan executed without truncation beyond the configured cap).

## Matched-current-message gates (collection level, pre-specified)

Evaluated on requests from accepted runs, label from ledger. Current-message fields: wire FC, unit, address,
quantity, MBAP length, request frame length, transaction ID.

* **G1 value coverage:** 100% of recon requests have FC, unit, quantity, MBAP length and frame length values that
  occur among normal requests; ≥ 95% have an address value (per FC/unit) that occurs among normal requests.
* **G2 joint-shape coverage:** ≥ 90% of recon requests have their exact joint shape
  (FC, unit, address, quantity, MBAP length, frame length) present among normal requests of **other runs**.
* **G3 no current-message solution:** with run-grouped 5-fold cross-validation, every current-message model
  (single-field lookups, joint-shape lookup, depth-6 decision tree, logistic regression, random forest) must have
  pooled out-of-fold ROC-AUC ≤ 0.80 **and** oracle-threshold balanced accuracy ≤ 0.75.
  Exceeding either value in any model ⇒ **stop and redesign scenarios before scaling.**

Identity fields (client IP/port) and response-side fields are reported separately as diagnostics; they are not
removed to pass a gate.

## History-signal diagnostic (informative only, not a gate, not a model result)

Causal contexts are built **only after** run acceptance and label join: per (run, client IP, server IP) stream,
ordered by capture time, the last 20 requests ending at the target request (never crossing runs; streams whose
history is shorter are reported as partial). Pre-specified summary statistics (unique-target fraction, first-seen
novelty, ascending-step fraction, mean absolute address delta, FC/unit transitions, interval mean/CV/min, revisit
fraction) are fed to an untuned depth-4 tree and random forest with the same run-grouped folds. This shows whether
history carries signal and which scenarios are hard; it is not evidence for or against the LSTM.

## What a pass does and does not mean

A pass means the methodology can produce matched-shape data with clean lineage and that scaling is worthwhile.
It does not establish temporal detection performance, a final run count or any LSTM advantage.

## Amendment A (25 October 2026, before v3 collection)

Gates G1–G3, their thresholds and the history-check definition are unchanged. Added for v3:

* **Scenarios:** legitimate one-pass coverage workloads N5–N8 (`c2tb/scenarios_v3.py`) and a second site
  configuration (sites A and B, one run per scenario per site).
* **Hard-negative reporting:** the actor-only history check is also reported for recon vs. one-pass workloads only,
  per recon/one-pass scenario pair, and with leave-one-site-out evaluation.
* **VM clock monitoring:** a sidecar samples wall and monotonic clocks every 10 ms. The v3 smoke run showed the
  Docker Desktop VM wall clock running ~50–60 ppm fast and being stepped back by 1.2–1.9 ms about every 30 s (this
  also explains the v2 r09 rejection). Raw PCAP/ledger timestamps are never modified. Derived timestamps
  `ts_corr_ns` remove the measured steps (piecewise offset from the clock log); requests inside a sampling interval
  that contains a step are flagged `clock_ambiguous` and reported. Run acceptance requires: clock log covering the
  run; capture-after-send on corrected timestamps for all non-ambiguous requests; ambiguous requests ≤ 1 %. A
  wall-clock step is not by itself a rejection reason. All history timing features use corrected timestamps.
