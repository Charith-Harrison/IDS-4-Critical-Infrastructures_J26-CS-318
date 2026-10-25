# Component 3 — start here

Command and response injection detection in Modbus/TCP using earlier observable context.

**Research status:** the completed experiment is a controlled software-testbed study. It is not the originally proposed CIC-primary experiment, and supervisor acceptance of that amendment is **NOT_RECORDED**. The causal rules solve all supported final cases; the contextual Random Forest misses one ordering-holdout response. There is no demonstrated ML advantage over the rules.

## Read and run

- [Decision and issue report](docs/AUDIT.md): findings, independently checked results, remaining limits.
- [Requirements traceability](docs/TRACEABILITY.md): all proposal requirements, individual/group boundaries and the actual PP1 rubric.
- [Setup and demonstration](docs/SETUP.md): safe commands, portable paths and output contract.
- [Viva guide](docs/VIVA.md): exactly what the preprocessing, features, models and scores mean.
- [Methodology amendment for review](docs/METHODOLOGY_AMENDMENT.md): proposed change, not approval.
- [Migration record](docs/MIGRATION.md): old/new paths, preservation and historical commands.

From the repository root, using the existing environment:

```powershell
.\.venv\Scripts\python.exe -B c3.py check
.\.venv\Scripts\python.exe -B c3.py test
.\.venv\Scripts\python.exe -B c3.py demo --run MX001
```

`check` verifies the expected lock/model hashes and loads four saved models. It is not a full raw-data check. `audit` independently verifies the complete accepted collection and recounts **saved** final predictions; it never generates final predictions or trains. `demo` accepts training/validation runs only. See SETUP before running other commands.

## One layout

```text
c3.py                         safe entry point at repository root
component3/
  runtime.py, cli.py           new v2 label-free inference adapter and commands
  tests/, tools/              synthetic tests, audit and preservation utilities
  docs/                       requirements, setup, viva, amendment, migration
  reports/                    small tracked evidence and audit results
  locked/v1_20261025/          original experiment, internally unchanged
    artifacts/                original processed data/models/results (local, ignored)
  data/collection/             ONE canonical completed raw collection (local, ignored)
  local/                      new demos and repeat audit outputs (local, ignored)
  history/                    intact previous designs, captures, CIC work and import
```

Collection `40ae7a846cce48fc8e3c52ebfca7e2cd`: **104 accepted runs**, 107 attempt folders, **250,066 ADUs** (247,906 normal / 720 command / 1,440 response). Only `data/collection/collection_complete.json` decides which attempts are admitted. Never combine folders by globbing.

The original lock remains `f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9`. Frozen instructions retain their historical paths and commands; they are evidence, not the active workflow. Do not run their `prepare`, `train`, `freeze` or `evaluate-final` commands against the locked artifacts. Current commands do not expose those operations.

The root `app/`, `src/` and other group components are unchanged. The legacy binary CSV application's metrics do not establish performance of this three-class testbed component.
