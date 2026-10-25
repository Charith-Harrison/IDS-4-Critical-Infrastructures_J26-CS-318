# Independent sequence findings

## Legacy files: FAIL

Direct exhaustive audit of supplied XLSX values gives 879,225 packet rows and 175,800 sequence windows. All 175,800 windows reproduce 20 successive packet rows within the supplied `session_id` order at stride 5. Window label `any(packet label == 1)` matches 175,800 windows. This validates reproduction, not ground truth.

There are 126,643 backward packet timestamp transitions within supplied session order. 174,708 windows contain at least one backward transition; 67,489 end before they start; 171,080 mix source files; 144,180 mix configured capture groups. Actual min-to-max window span exceeds one minute in 164,701, five minutes in 148,845, and one hour in 146,243. Zero windows cross the supplied session ID because grouping uses that ID, which itself spans captures/days.

**Established failure mechanism:** window construction consumes the already mixed packet table in supplied row order and groups only by static directional endpoint/unit identity. `sequence_position` follows that order. Timestamp chronology and capture boundaries are not enforced. Consequently, windows combine unrelated temporal contexts. The original extraction/merge code that created the mixed order is absent; its exact earlier implementation cannot be proven. The visible `audit_sequences.py` only diagnoses it. See exact bad examples in `evidence/legacy_bad_window_examples.json`. Claims that a particular unavailable preprocessing program caused a specific merge/sort error remain unverified.

## Supplied historical rebuilt files: NOT AVAILABLE

The requested rebuilt CSV/NPY files were absent locally. Historical JSON/Markdown reports are source claims and were not used as evidence of current data integrity. Original file equality and their original ID membership cannot be verified.

## New independent diagnostic reconstruction

Using the visible configuration policies creates 597,135 retained packets, 282,090 exclusions and 119,237 windows, saved only under this review. All original worksheet IDs are accounted exactly once across new retained/excluded sets. All 282,076 secondary interface exclusions have equal **available processed fields** within 1 ms in the selected retained view, with 0 label disagreements. The processed fields lack bytes and TCP identity, so feature/timestamp correspondence alone does not prove exact duplicate packets. Raw-source evidence is evaluated separately.

All new windows pass the mechanical 20-row/stride-5/group/chronology/start/end/count/any-positive checks. First missing `dt_s` is expected in all 56 configured streams. Chronology remains scientifically conditional: these are endpoint streams, do not enforce TCP generations, and do not split inactivity. 509 windows exceed one minute, 88 exceed five minutes, and 11 exceed one hour. 11 windows contain an internal gap over one hour. Mechanical timestamp order alone is insufficient to establish coherent behavioral sessions.

Historical summary comparison is explicitly segregated in `rebuilt_sequence_audit.json`. Reproducing summary counts does not validate absent original files or their labels. Capture groups are not independently established campaigns.


### Submicrosecond timing precision

The historical `groupby(...).ts_ns.diff()` expression promotes epoch nanoseconds to floating point during shifting in this pandas runtime. Independent comparison with integer subtraction finds 579064 gaps differing by more than 1 ns, with maximum absolute error 256.0000007534313 ns. The new diagnostic file uses integer subtraction before conversion to seconds and validates 0 differences above 1 ns after CSV reload. This small numerical issue does not explain the severe legacy chronology failure. The historical files are missing, so their actual stored rounding cannot be independently inspected.
