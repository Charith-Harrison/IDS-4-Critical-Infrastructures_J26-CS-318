# Exact engineering handover

Keep the repository-relative layout of `component3_testbed_v03` and
`component3_collection_runs/engineering-v03`. Retain all files in each EQ recording,
including private intervention/state audits and host metadata. Raw recordings, transcripts,
the preservation snapshot and runtime archive may be ignored by Git; they remain part of
the local handover. Do not substitute a Git checkout alone for these evidence files.

`handover_manifest.json` records source/configuration and report hashes, original PCAP /
annotation / private-audit / validation hashes, actual collection-machine and image IDs,
and the exact runtime archive checksum. Paths are portable relative references; original
absolute execution paths remain in historical argv as provenance only.

The cached v0.1/v0.2/v0.3 Docker images were exported together to
`runtime-images-v03.tar`, with shared layers retained once. The archive is local and
ignored by Git. Verify its SHA256 against the manifest/checksum file before loading it.
On another Docker Linux-container machine it can be loaded without rebuilding:

```powershell
docker load --input .\component3_testbed_v03\evidence\runtime-images-v03.tar
```

Loading an image is not collection. A new collection still requires the launcher and
the adopted engineering scope; accepted recordings are protected against accidental rerun.
The 104 proposed main runs remain disabled. Existing evidence can be read with local Python
without Docker. The preservation checker expects the previous repository roots on the
original complete repository; individual captured-byte/state checks need only the v0.3
source/design and its corresponding recordings.

The separate post-capture audit independently reconstructed all 33,970 annotated ADUs,
replayed 16,985 transactions and checked the 324 direct target lineages/anchors/controls.
All 108 targets in literal-5 cells have a same-cell normal observation with an identical
complete current ADU. Its timing/position/length summaries are audit diagnostics, not model
features or detector performance. Finite generator cues can remain; no model was trained.

All engineering recordings remain excluded from fitting, tuning, feature/threshold
selection and scored evaluation. These are one simulator's replications, not independent
industrial campaigns. Machine/clock identity is self-reported; supervisor approval of the
testbed-primary academic amendment is not recorded.
