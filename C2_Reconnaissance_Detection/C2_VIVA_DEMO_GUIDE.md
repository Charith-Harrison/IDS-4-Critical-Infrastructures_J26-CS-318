# C2 viva demo — quick guide

## What to copy

Copy **`C2_viva_demo_package.zip`** to the laptop. It contains the demo app, the built frontend, the frozen models,
eight held-out test runs and their PCAPs.

Extract it either:

* **over the repository**, so that `C2_Reconnaissance_Detection\demo_bundle\` exists; or
* **into an empty folder** (it runs on its own).

Keep the path short, for example `C:\C2demo`. Very long folder paths hit the Windows path-length limit.

## One-time setup (with internet, before the viva)

* Install Python 3.10–3.13 from python.org. Python 3.14 will not work.
* Then run the startup command below once. It creates `demo\.venv` and installs the pinned packages (~2 min).
* Docker, Node.js and Wireshark are not needed.

## Start

Open PowerShell in `C2_Reconnaissance_Detection`:

```
powershell -ExecutionPolicy Bypass -File .\start_c2_demo.ps1
```

The browser opens at <http://127.0.0.1:8020/>. After setup it works offline.

## Demo sequence

1. **Overview:** final results on the held-out tests, model comparison and the known limitation.
2. **Traffic Replay:** the default run is a sequential scan.
   1. Press **Play**.
   2. Watch the current message, the model predictions, the Temporal Context panel and the Recent 20 Requests.
   3. Switch the run to **Configuration backup** (a one-pass legitimate read, which is flagged: the known limitation).
   4. Switch to **Fixed polling** (revisiting normal traffic, which stays quiet).
   5. Switch to **Unit probe · Site C** (an unseen site).
3. **Verify with frozen models** (bottom of Traffic Replay) re-scores the run live and shows 0 disagreements.
4. **Compare:** recon scan vs one-pass read vs normal polling, side by side.
5. **Validation:** runs, split, gates G1–G3, tshark and ledger checks, the rejected run.
6. **Why the dataset changed:** the CIC audit summary.
7. *Optional:* **Score a file.** Download a sample input from the page and upload it back.

## Optional: Wireshark proof

The PCAP for each prepared run is in the package under `component2_testbed\data\final_v1\runs\<run>\capture.pcap`.
Its path is shown under "Reproduce predictions". Open it in Wireshark with the display filter `mbtcp`; the frame
numbers match the replay.

## Stop

Press **Ctrl+C** in the PowerShell window, or run:

```
powershell -ExecutionPolicy Bypass -File .\stop_c2_demo.ps1
```
