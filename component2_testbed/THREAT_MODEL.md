# Component 2 controlled testbed: threat model

Project J26-CS-318, RP2 (Reconnaissance Attack Detection Using Temporal Behavior Analysis), Charith H. / Harry.
Written 25 October 2026, **before** any pilot traffic was collected.

## Research question this testbed serves

> Given Modbus/TCP requests that are individually legitimate-looking and overlap normal traffic in their
> current-message fields, can recent observable command history distinguish reconnaissance from normal operation?

The forensic CIC audit (`component2_forensic_review/FULL_FINDINGS_REPORT.md`) found that the inherited CIC labels
are dominated by exception responses from a coil-write mechanism, and that the recoverable genuine CIC recon
requests (FC1â€“4 from address 1 with quantities 125/2000/65535) share **no** current-message shape with the
documented benign HMI census (all quantity 1). CIC therefore cannot isolate the temporal question. This testbed is
built so that the current message is deliberately *not* sufficient.

## Assets and environment

| Element | Pilot realisation |
|---|---|
| Target | One Modbus/TCP server (pymodbus 3.6.9) on TCP/502 hosting **three unit IDs (1, 2, 3)**, each with coils, discrete inputs, holding registers and input registers at addresses 0â€“63. Process values evolve over time from a per-run seed. |
| Legitimate masters | An HMI-like background poller present in every run, plus a second client host whose activity is either a normal workload or (after a legitimate lead-in) reconnaissance. |
| Network | An isolated, per-run, `--internal` Docker bridge network (no route off-host). Client IPs are drawn at random per run, so an IP address carries no class information across runs. |
| Observation point | Passive `tcpdump` in the target's network namespace (one canonical interface). |

## Adversary

* **Position:** an actor on a host that already has legitimate Modbus/TCP reachability to the target, e.g. a
  compromised engineering workstation or HMI. It uses the ordinary protocol stack: real TCP connections from its
  own address. **No spoofing, no malformed frames, no writes.**
* **Capability:** issues well-formed read requests (FC1 coils, FC2 discrete inputs, FC3 holding registers, FC4
  input registers) with valid unit IDs, addresses and quantities that legitimate masters also use.
* **Goal:** map which units, tables and addresses exist and what they contain, before any later attack.
* **Constraint (stealth):** the actor deliberately stays inside the target's valid address map and the
  function/quantity/unit envelope used by legitimate masters, so that no single request is anomalous. It does
  not trigger exception responses in the pilot.
* **Behaviours modelled:** sequential address sweep, sparse/strided sweep, randomised sweep, slow jittered sweep
  with rates inside the normal polling range, function-code probing across FC1â€“4, and unit probing across the
  three configured units.
* **Prior legitimate activity:** in recon runs the same host first performs ordinary maintenance-style reads (the
  *lead-in*); those actions are labelled normal in the ledger because they are not reconnaissance actions.

## Deliberately out of scope for the matched pilot

These recon behaviours exist in practice but **necessarily create current-message novelty** (a value no legitimate
master sends), so they cannot test the temporal hypothesis and would recreate the CIC shortcut. They are excluded
from the matched pilot and listed for a separate, explicitly labelled "unmatched" study:

* probing non-existent unit IDs (e.g. 4â€“247) or out-of-map addresses that produce exception responses;
* diagnostic/identification functions never used by legitimate masters (FC8, FC17, FC43/14);
* bulk quantities such as 125/2000/65535 seen in CIC;
* writes, malformed ADUs, spoofed sources, connection-per-probe scanning (TCP-level signal).

## Ground truth

Each client writes its own action ledger (intent, role, phase, scenario, unit, function, address, quantity,
scheduled/actual time, transaction ID, local TCP port, exact request/response bytes). Labels are assigned by
joining on-wire requests to ledger actions by **identity** (client IP, client port, transaction ID, exact ADU bytes),
never from packet feature values. The ledger and scenario plan are written independently of capture.

## Known residual limitations

* Software-only testbed in one Docker VM: no PLC scan-cycle latency, no real field devices, shared kernel clock.
* The proposal names ICSSIM; this pilot uses a smaller pymodbus server for transparency (see `PILOT_PROTOCOL.md`).
* A legitimate full-map "configuration backup" read is behaviourally identical to a sequential sweep. v1/v2 did not
  include such workloads; v3 adds them (N5–N8) and measures the ambiguity: with these hard negatives, recon is not
  separable from legitimate one-pass coverage reads on observable history (`PILOT_RESULTS.md` §4).
* The Docker VM wall clock is stepped by ~1–3 ms about every 30 s; v3 measures and corrects this (`clock.jsonl`).
