# Commands for this PC

Run in PowerShell. These paths select the verified bundled Python and isolated dependencies installed for this run. For another PC use README's virtual-environment instructions.

```powershell
$c3Python = 'C:\Users\Thithira\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$c3Project = 'D:\VSCode\Github-Other\Github-Kavisha\IDS-4-Critical-Infrastructures_J26-CS-318'
$env:PYTHONPATH = 'D:\VSCode\GitHub\4th Year Cyber\output\c3_ml_deps;' + "$c3Project\component3_model_pipeline\v1_20261025"
Set-Location -LiteralPath $c3Project
& $c3Python -B -m unittest discover -s component3_model_pipeline\v1_20261025\tests -v
& $c3Python -B -m c3model verify
```

The original experiment is already complete and locked. Read existing artifacts/reports rather than rerunning final evaluation. To demonstrate preprocessing again, use a NEW output location:

```powershell
& $c3Python -B -m c3model prepare --artifacts component3_model_pipeline/v1_20261025/artifacts/viva_demo
```

This repeats development preprocessing only and preserves the locked results. Any new modelling choices after final inspection are exploratory, even if the code runs successfully. The all-ADU CSV is gzip compressed; Python `pandas.read_csv(path)` handles `.csv.gz`, and `pandas.read_parquet(path)` retains typed timestamps.
