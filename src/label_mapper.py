"""Targets come exclusively from supplied labels, never from protocol direction."""

from __future__ import annotations

import pandas as pd

CLASSES = {
    "temporary_binary": ["Normal", "Command_Response_Injection"],
    "final_three_class": ["Normal", "Command_Injection", "Response_Injection"],
}
MSU_MAPPING = {
    "0": "Normal",
    "1": "Response_Injection",
    "2": "Response_Injection",
    "3": "Command_Injection",
    "4": "Command_Injection",
    "5": "Command_Injection",
}


def class_names(cfg: dict) -> list[str]:
    return CLASSES[cfg["model_mode"]].copy()


def map_labels(frame: pd.DataFrame, cfg: dict, required: bool = True) -> pd.DataFrame:
    """Reject unknown labels; explicitly exclude MSU 6/7, retaining their audit rows."""
    out = frame.copy()
    column = cfg["dataset"]["label_column"]
    if column not in out:
        if required:
            raise ValueError(f"Missing configured label column: {column}")
        out["target"] = None
        out["label_status"] = "unlabelled"
        return out
    labels = out[column].astype("string").str.strip()
    scheme = cfg["dataset"].get("label_scheme", "canonical")
    if scheme == "msu_numeric":
        if cfg["model_mode"] != "final_three_class":
            raise ValueError("MSU mapping is supported only in verified final_three_class mode")
        labels = labels.str.replace(r"\.0$", "", regex=True)
        excluded = labels.isin(["6", "7"])
        mapped = labels.map(MSU_MAPPING)
    elif scheme == "canonical":
        excluded = pd.Series(False, index=out.index)
        mapped = labels.where(labels.isin(class_names(cfg)))
    else:
        raise ValueError(f"Unknown label scheme: {scheme}")
    unknown = mapped.isna() & ~excluded
    if unknown.any():
        raise ValueError(f"Unmapped or missing labels: {labels[unknown].value_counts(dropna=False).to_dict()}")
    out["target"] = mapped
    out["label_status"] = excluded.map({True: "excluded_out_of_scope", False: "supplied_label"})
    # Audit auxiliary flags only. They never replace the authoritative category.
    if cfg["model_mode"] == "temporary_binary" and "is_attack" in out:
        flag = pd.to_numeric(out["is_attack"], errors="coerce")
        conflict = flag.notna() & (flag != (mapped != "Normal").astype(int))
        if conflict.any():
            raise ValueError(f"{int(conflict.sum())} labels conflict with is_attack; resolve source evidence")
    return out
