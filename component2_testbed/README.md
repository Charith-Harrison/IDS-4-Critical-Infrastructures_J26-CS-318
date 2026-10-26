# Component 2 controlled Modbus/TCP testbed (pilot)

Primary, controlled data source for RP2 (reconnaissance detection via temporal behaviour). It is **separate** from
the CIC material: CIC stays a secondary case study (`component2_forensic_review/`), and no CIC capture, label, log or
audit field is merged here. Component 3 data is not used.

| Document | Content |
|---|---|
| `THREAT_MODEL.md` | Adversary, assets, what is in and out of scope, ground-truth principle |
| `PILOT_PROTOCOL.md` | Pre-specified design, run definition, acceptance checks and stop/redesign gates (written before collection) |
| `DESIGN_ITERATIONS.md` | Why v1 was rejected, what v2 and v3 changed, and each outcome |
| `PILOT_RESULTS.md` | What the pilot actually produced, gate outcomes, limitations and next step |
| `MODELLING_PLAN.md` | Frozen modelling plan (representations, selection, operating point, test sealing) |
| `FINAL_RESULTS.md` | **Final H1/H2/H3 results** across validation, in-site test and Site C |
| `FINAL_COLLECTION_PROTOCOL.md` | **Frozen** final-collection protocol (strata, TID treatment, context, Site C, gates, splits, run count, execution) |

## Layout

```
component2_testbed/
  docker/            Dockerfile + pinned requirements (one image for every role)
  configs/           pilot_v1/v2/v3.json (scenario design, sites, replicates, durations, network)
  c2tb/              testbed code
    wire.py          Modbus/TCP FC1-4 encode/decode (client side)
    server.py        pymodbus target, units 1-3, seeded evolving process image
    scenarios.py     v1 plans (kept for reproducibility of the rejected v1 collection)
    scenarios_v2.py  v2 site envelope: per-table read granularity, broad background polling
    scenarios_v3.py  v3: adds one-pass legitimate coverage workloads N5-N8 (hard negatives)
    clockmon.py      VM wall/monotonic clock sampler (v3)
    client.py        executes a plan, writes the ground-truth action ledger
    parse_pcap.py    TCP reassembly + ADU extraction with frame/offset lineage, causal response pairing
    process_run.py   tshark cross-check, ledger identity join, per-run acceptance
    diagnostics.py   acceptance manifest, overlap, gates, causal contexts, history-signal check
  run_pilot.py       host orchestrator (stdlib only): one isolated Docker acquisition per run
  data/<collection>/
    collection_manifest.json
    runs/<run_id>/   RAW, write-protected: capture.pcap, ledger_*.jsonl, plan.json, clock.jsonl (v3), run_manifest.json, logs
    derived/<run_id>/ adus.parquet, requests_labeled.parquet, tshark_check.json, acceptance.json
    analysis/        acceptance_manifest.csv, overlap/model/history tables, causal_context_index.parquet, pilot_summary.json
```

`*.pcap` is ignored by the repository `.gitignore`; captures stay local unless a storage decision is made.

## Reproduce

```bash
docker build -f component2_testbed/docker/Dockerfile -t c2-recon-testbed:0.1.0 component2_testbed
```

```bash
python component2_testbed/run_pilot.py --config configs/pilot_v3.json --collection-id pilot_v3_20261025
```

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/repo" -w /repo/component2_testbed -e PYTHONPATH=/repo/component2_testbed:/repo/component2_forensic_review/scripts c2-recon-testbed:0.1.0 python -m c2tb.process_run --collection-dir data/pilot_v3_20261025
```

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/repo" -w /repo/component2_testbed -e PYTHONPATH=/repo/component2_testbed:/repo/component2_forensic_review/scripts c2-recon-testbed:0.1.0 python -m c2tb.diagnostics --collection-dir data/pilot_v3_20261025
```

(`$(pwd -W)` and `MSYS_NO_PATHCONV` are for Git Bash on Windows, run from the repository root; use `$(pwd)` on Linux/macOS.)

## Labels and predictors

Labels (`gt_*`) come only from the client ledgers via an identity join (client IP, client port, transaction ID,
exact request bytes). `gt_*`, `ledger_*`, run/scenario/collection IDs, file names, frame numbers, IPs and ports are
never model predictors; they exist for lineage and grouping.
