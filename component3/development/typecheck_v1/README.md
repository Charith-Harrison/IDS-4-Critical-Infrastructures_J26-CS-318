# Type-checking proposal

Subsequent update: the production source-lock mismatch recorded during this proposal was repaired by recovering the exact original source bytes. See [inference recovery](../../reports/locked_source_recovery_v1/README.md). This development proposal and its original verification records remain preserved separately.

This is a development copy for review. The dashboard and command-line runtime still use their existing imports. No frozen source, model, collection file, lock or official result is replaced by this proposal.

Open `c3model/experiment.py` and `c3model/records.py` **in this directory** to inspect the corrected code in VS Code. Diagnostics on the original frozen files will remain: clearing them there would require changing those files or hiding diagnostics, both outside the requested scope.

## Errors and corrections

| Location in current frozen source | Cause | Development correction |
|---|---|---|
| `experiment.py:82–83` | The installed sklearn stub describes metric outputs as scalar-or-array, and support as array-or-None. The actual call uses default `average=None`, so it returns per-class arrays. | Cast the existing return tuple to three float arrays and one integer support array. No array conversion, averaging or new check is introduced. |
| `experiment.py:237` | Ordinary mixed-value dictionaries do not tell the checker which keyword has which type. Unpacking them makes even unrelated RF keyword parameters appear to accept integers. | Add `RFCandidate` and `RFFixed` TypedDict definitions. Keep every value, candidate order and combination. Equivalent dictionary literals retain the exact runtime keys/values. |
| `records.py:211–212` | The checker cannot infer that the separately computed `available` boolean proves the corresponding anchor exists. | Describe connection/anchor/pending-request shapes and cast the selected anchor at the existing lookup. No new state checks or branches are added. |
| `records.py:226` and `:233` | Both public and paired object roles can be None, but the inferred role-code dictionary accepts only string keys. | Annotate the existing dictionary as accepting `str | None` keys. Its three entries and the default-zero lookup stay unchanged. No None entry is inserted. |

`typing.cast` returns its argument unchanged. The casts document existing guarantees rather than changing detector behavior. The proposal does not introduce broad `Any` casts, diagnostic suppression or `type: ignore` comments.

## Preservation issue found before editing

Both current source files already differed from the experiment lock when this task started:

| File | SHA-256 at task start (preserved) | SHA-256 in original lock |
|---|---|---|
| experiment.py | `dd601ff0fd5452cd18ed0063c7c4bc41e7c8a9bc1c6e6b85919fda83b312110e` | `8012e15e2a10922e31c77d2d2aa8537d800149d456a4fa4372cc09a96c58936c` |
| records.py | `304b7c35f10a658b25582a36bc12f234c6592576555058118f560dcf106fb7c8` | `adb2ac4fed42e09490ac7415bc7d59d19bb448654924b4c3d5007395f6f8a189` |

These differences are pre-existing and were not repaired or normalized here. Do not update the original lock to make it accept changed source. Its mismatch needs a separate provenance review against an authenticated original bundle. In particular, the production model loader's original-code identity check can reject the current source bytes; this proposal does not weaken that check.

The verification helper hashes saved model files against the unchanged lock before read-only loading for isolated regression comparisons. That helper does not alter or replace the production loader.

## Verification

See [verification/report.json](verification/report.json), [the review patch](typecheck.patch), and the before/after Pyright diagnostics in `verification/`.

Syntax is checked using `compile` and `ast.parse`, without writing bytecode into the frozen directory. The checker is Pyright 1.1.414, basic mode, using the installed Pylance 2026.4.1 sklearn/pandas stubs and the existing Python environment. No diagnostic rules are disabled. This is a scoped check of the two requested files, not a strict-mode audit of the entire repository or a live VS Code screenshot.

Regression checks replay every accepted training/validation run through both copies. They compare complete prepared rows, the 9 CURRENT / 5 CONTEXT / 5 WIRE names and order, all four method schemas, RF parameter/candidate values, predictions, abstentions, out-of-scope status and metric dictionaries. Probability comparison allows absolute difference `1e-12` for parallel floating-point summation.

The same 17 existing non-training tests run against each package. The existing eighteenth test explicitly fits toy models and is omitted to keep this verification entirely free of fitting. No official final evaluation is repeated.

To repeat the read-only regression check from the repository root after generating the recorded type-check diagnostics:

```powershell
.\.venv\Scripts\python.exe -B component3/development/typecheck_v1/verify.py
```

The local checker configurations and exact logs are in `component3/local/typecheck_v1/`. Pyright is installed only in the ignored `component3/local/typecheck_tools/` directory; the project environment and VS Code settings were not changed. The recorded checker invocations use:

```text
node component3/local/typecheck_tools/pyright/dist/index.js --project component3/local/typecheck_v1/baseline.json --outputjson
node component3/local/typecheck_tools/pyright/dist/index.js --project component3/local/typecheck_v1/proposal.json --outputjson
```

The generated configurations contain this laptop's environment/stub paths. Another laptop must select its own Python environment and installed Pylance stubs rather than reusing those absolute paths.

Do not run `prepare`, `train`, `freeze` or final evaluation from this development copy against the original artifacts. Code identity intentionally differs; this copy is not a replacement for the locked experiment.
