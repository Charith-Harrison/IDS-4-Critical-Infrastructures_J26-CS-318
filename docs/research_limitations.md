# Research status and interpretation

This is the approximately 70% preliminary implementation, not completed research.
Random Forest was selected because it is suitable for structured contextual
features; performance is evaluated experimentally. No claim is made that it is
the most accurate algorithm.

## Labels and scope

Current targets are exactly Normal and Command_Response_Injection. The original
CSV labels are preserved, including attack-labelled response rows. Labels have
not been independently verified against original packet evidence. The attack
subtypes are Coil_Brute_Force and Length_Manipulation, not separate verified
command/response labels. The final three-class workflow is implemented and
software-tested using synthetic fixtures, but no final research model exists.

## Evaluation limits

Six normal-file capture names are provided. The attack file has no capture IDs;
six provisional segments are inferred from frame/time resets. These may not
represent independent captures or scenarios. Network-wide and interface-specific
normal captures could contain correlated traffic. Exact observation duplicates
are checked, but this cannot eliminate all mirrored or correlated observations.

The deterministic allocation keeps groups disjoint and checks class coverage.
It does not optimize class balance or test performance. Validation contains only
98 attack rows, making model selection fragile. Report partition counts and all
per-class metrics; do not interpret a single score as deployment readiness.

The source files were evaluated by the legacy implementation. The new holdout
is internal preliminary evaluation, not a pristine final research test. Final
claims require newly acquired independent data. Evaluation is cached against
artifact/data hashes and retraining is blocked when an evaluation already
exists for the same configuration, to discourage accidental tuning against this
test set. Changing configuration or source data automatically archives the old
experiment before inspection/preprocessing. This preserves provenance and allows
the three-class transition; it does not restore test independence.

Protocol fields can still proxy dataset scenarios even after obvious target
columns are blocked. Function code is strongly associated with these labels.
High accuracy can reflect dataset construction. No label-informed normal
register profile is used. No synthetic observations or oversampling are added
to measured results.

## Event and feature semantics

Each valid structured record is an event, including requests and responses.
Context uses a bidirectional endpoint/port session within a capture/segment and
resets after a configured idle gap. Missing endpoints isolate rows unless a
logical session identifier is supplied. Short-lived connections therefore have
little context; this is visible through missingness rather than invented history.

Pairing uses earlier requests with the same transaction in the same session,
within the timeout. Multiple eligible requests are ambiguous. Function and unit
consistency are exposed only for unambiguous partial matches. This is partial CSV
reconstruction, not verified PCAP reconstruction. A pending request is not called
a missing response before the future is observed. Expired-request counts concern
the transaction key encountered at the current event, not all session timeouts.

Sequence and value features refer to preceding protocol events in the session,
not exclusively preceding commands. Windows contain at most 3, 5 or 10 preceding
events and exclude the current observation. Inter-arrival time uses the current
arrival and previous observation. Response timing is available only upon response.
`repeated_write_count_N` counts writes in the preceding N events, not a consecutive
run. `repeated_access_count_N` counts prior adjacent repeated accesses. Value
deltas are adjacent-event exported values, not verified physical-process changes.

The exporter may encode absent response register/value fields as zero. Zero is
retained rather than reinterpreted without packet evidence. Exporter-precomputed
response time, packet rate, inter-arrival and transaction differences are not
used. Absolute timestamps, raw transaction IDs, IPs, ports, filenames, frame
numbers, labels, and row IDs are never model inputs.

Sensitive-register permission maps and defensible role mappings are unavailable;
no risk rule or permission violation is fabricated. Complete PCAP-based role,
pair, value and session reconstruction remains future work.

## Explanations and latency

The dashboard reports observed feature evidence and impurity-based global RF
importance. These are not SHAP or causal local explanations. Reference quantiles
use training rows only, without labels. Vote fractions are not calibrated attack
probabilities. Batch and single-event latency are measured model-only; end-to-end
CSV inference reports elapsed time separately. This is a batch prototype, not a
live stateful traffic sensor.

## Pending research

- Verified three-class dataset and packet-backed Command_Injection/Response_Injection labels.
- Final three-class Random Forest and complete CIC PCAP/log reconstruction.
- Independent external MSU validation and evidence-backed numeric label mapping.
- Full feature ablation, expanded hyperparameter experiments, calibration and uncertainty.
- Fusion/integration with other research components and final conclusions.
