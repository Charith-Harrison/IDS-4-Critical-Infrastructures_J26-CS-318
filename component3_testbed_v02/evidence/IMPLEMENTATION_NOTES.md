# Qualification implementation history

The first measured Q01 attempt, `Q01-20261024T180347Z-35f1f35c`, stopped before
the first application message: the vendored ledger-writer definition needed
`json` in the new module's import header. No verified labels were emitted.
The folder, PCAP, original failure manifest, image identity and failed execution
ledger are preserved. This is an implementation failure, not a failed attack
or a usable qualification recording.

The header import was corrected and an actual `JsonLines` flush/exclusive-create
test was added. The vendored class definitions remain unchanged. A new image
and source hashes distinguish the corrected version. `-RetryFailed` allows a
fresh Q01 without replacing the failed attempt. Subsequent capture outcomes
are reported separately in `qualification_summary.json`.

After all four captures passed, the original reporting helper encountered Windows
PowerShell 5's `{value:[...],Count:1}` wrapper around the image-inspect array. The
post-capture `evidence/build_report.py` adapter unwraps it in memory. Captured
host records, collection sources, image identities and accepted labels remain
unchanged. The adapter has a separate recorded hash in the generated summary.
