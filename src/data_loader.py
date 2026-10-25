# Read source CSVs and describe their columns without changing the source files.
"""Read-only CSV ingestion and machine-readable schema discovery."""

from __future__ import annotations

import pandas as pd

from src.utils import ROOT, checksum, now, project_path, save_json


# Read a CSV using the configured input rules.
def load_csv(path) -> pd.DataFrame:
    path = project_path(path)
    if path.suffix.lower() != ".csv":
        raise ValueError("Expected a CSV file")
    return pd.read_csv(path, low_memory=False)


# Record available files, columns, and sample information for input inspection.
def inspect_datasets(cfg: dict) -> dict:
    from src.experiments import archive_if_changed

    archive_if_changed(cfg)
    reports = []
    for source in cfg["dataset"]["files"]:
        path = project_path(source)
        data = load_csv(path)
        counts = data.nunique(dropna=False)
        top_share = {c: float(data[c].value_counts(dropna=False, normalize=True).iloc[0]) for c in data}
        labels = {
            c: {str(k): int(v) for k, v in data[c].value_counts(dropna=False).items()}
            for c in data
            if any(x in c.lower() for x in ["label", "attack", "category"])
        }
        reports.append(
            {
                "filename": source,
                "sha256": checksum(path),
                "rows": len(data),
                "columns": len(data.columns),
                "column_names": list(data),
                "dtypes": data.dtypes.astype(str).to_dict(),
                "missing_values": data.isna().sum().to_dict(),
                "duplicate_rows": int(data.duplicated().sum()),
                "unique_counts": counts.to_dict(),
                "label_distributions": labels,
                "constant_columns": counts[counts <= 1].index.tolist(),
                "near_constant_columns": {c: v for c, v in top_share.items() if 0.99 <= v < 1},
                "suspicious_identifiers": [
                    c
                    for c in data
                    if any(
                        x in c.lower()
                        for x in [
                            "ip",
                            "port",
                            "trans_id",
                            "frame_number",
                            "source",
                            "timestamp",
                            "scenario",
                            "capture",
                        ]
                    )
                ],
                "categorical_columns": data.select_dtypes(exclude="number").columns.tolist(),
                "numeric_columns": data.select_dtypes(include="number").columns.tolist(),
                "timestamp_columns": [c for c in data if "time" in c.lower()],
                "modbus_columns": [c for c in data if "modbus" in c or "mbtcp" in c],
                "frame_resets": int((data.frame_number.diff() < 0).sum()) if "frame_number" in data else None,
                "timestamp_resets": (
                    int((data.timestamp.diff() < 0).sum())
                    if "timestamp" in data and pd.api.types.is_numeric_dtype(data.timestamp)
                    else None
                ),
            }
        )
    report = {
        "created_at": now(),
        "grain": "CSV protocol record; causal event construction retains each valid record",
        "datasets": reports,
        "limitations": [
            "Supplied binary labels are not independently packet-verified.",
            "No command/response target separation is inferred from direction.",
            "Reset-inferred groups are not verified capture identifiers.",
            "Exporter-provided timing and value semantics require original PCAP confirmation.",
        ],
    }
    save_json(ROOT / "results/metrics/dataset_audit.json", report)
    lines = ["# Dataset inspection", "", "Original CSVs are read only.", ""]
    for item in reports:
        lines += [
            f"## {item['filename']}",
            f"Rows: {item['rows']:,}; columns: {item['columns']}; duplicates: {item['duplicate_rows']}.",
            f"Labels: {item['label_distributions']}",
            f"Constant fields: {', '.join(item['constant_columns'])}",
            "",
        ]
    lines += [
        "## Interpretation",
        *report["limitations"],
        "High risk: attack-category and subtype fields reveal targets and are forbidden as features.",
        "High risk: capture identity and traffic function mix may confound validation; grouped splitting cannot establish external validity.",
    ]
    (ROOT / "results/metrics/dataset_audit.md").write_text("\n\n".join(lines), encoding="utf-8")
    return report
