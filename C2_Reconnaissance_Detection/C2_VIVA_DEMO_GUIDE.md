# C2 viva demo — quick guide

## What you need

* **The repository:** branch `branch-ghost`, cloned or pulled.
* **`C2_handoff_package.zip`:** sent separately. It holds the Git-ignored models, results, demo data and evidence
  (see `C2_HANDOFF.md`).
* **Python 3.10–3.13** from python.org. Python 3.14 will not work.

Docker, Node.js and Wireshark are not needed.

## One-time setup (internet needed once)

1. Extract `C2_handoff_package.zip` into the **repository root**, the folder that contains
   `C2_Reconnaissance_Detection`. `HANDOFF_MANIFEST.json` should appear there.
2. Keep the repository at a short path, for example `C:\C2\IDS-4-Critical-Infrastructures_J26-CS-318`.
3. In PowerShell, in `C2_Reconnaissance_Detection`, run:

   ```
   powershell -ExecutionPolicy Bypass -File .\setup_c2_demo.ps1
   ```

Setup checks every package file against its SHA-256, creates `demo\.venv`, installs the pinned packages, and runs a
self-test. The self-test re-scores all samples and prepared runs with the frozen models and compares them with the
saved held-out predictions. It must end with `SELF-TEST PASS`.

## Start

```
powershell -ExecutionPolicy Bypass -File .\start_c2_demo.ps1
```

The browser opens <http://127.0.0.1:8020/>. After setup it works offline.

## Demo sequence

1. **Overview:** the research question, final held-out results and the one-pass limitation.
2. **Metrics:** choose test set, legitimate workload, history length and model. Show precision, recall, F1, accuracy, ROC-AUC, false-positive rate and exact TP/FP/TN/FN counts. Change from revisiting normal to legitimate one-pass work. These are saved-prediction summaries, not newly fitted or rescored tests. The page explains request-pooled versus scenario-balanced recall.
3. **Traffic replay** (the default run is a sequential scan):
   1. Press **Play**.
   2. Watch Current Message, Model Prediction, Temporal Context and Recent 20 Requests.
   3. Switch the run to **Configuration backup** (a legitimate one-pass read, which is flagged: the known limitation).
   4. Switch to **Fixed polling** (revisiting normal traffic, which stays quiet).
   5. Switch to **Unit probe · Site C** (an unseen site).
   6. At the bottom, press **Verify with frozen models**. It re-scores the run live and should show 0 disagreements.
4. **Compare:** recon scan vs one-pass read vs normal polling.
5. **Walkthrough:** plain-language presentation notes, model explanations, metric formulas and changes from the CIC prototype. A printable version is in `FRONTEND_WALKTHROUGH.md`.
6. **Data checks:** runs, split, gates G1–G3, tshark and ledger checks, the rejected run.
7. **CIC audit:** why the inherited labels and old scores are historical evidence rather than the current result.
8. **Score a file:**
   1. Choose a file from `C2_Reconnaissance_Detection\demo_bundle\samples\`, CSV or Parquet, e.g.
      `recon_sequential_scan_siteA.parquet`. The files can also be downloaded from the links on the page.
   2. The page shows alert counts per model and a **Reference check** against the saved held-out scores, which
      should show 0 disagreements.

## Optional: Wireshark proof

* Each prepared run's capture is at `component2_testbed\data\final_v1\runs\<run>\capture.pcap`. The path is shown
  under "Reproduce predictions".
* Open it in Wireshark with the filter `mbtcp`; the frame numbers match the replay.
* Its SHA-256 is in the run's `run_manifest.json` next to it.

## Stop

Press **Ctrl+C** in the PowerShell window, or run:

```
powershell -ExecutionPolicy Bypass -File .\stop_c2_demo.ps1
```
