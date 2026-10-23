"""Capture-grouped 80/20 split (no row-level random splitting).

Whole captures go to either the development or the final-test partition.
Candidate test sets are enumerated deterministically and the one closest to
20% of labelled events (with both classes in both partitions) is chosen.
"""

from __future__ import annotations

from itertools import combinations

import pandas as pd

from src.utils.config import RANDOM_STATE


def choose_test_captures(events: pd.DataFrame, target: float = 0.20, min_class: int = 1000) -> dict:
    """Pick capture ids for the test partition from labelled request events."""
    lab = events[events["class_id"].notna()]
    table = lab.groupby(["capture_id", "class_id"]).size().unstack(fill_value=0)
    table.columns = ["normal", "attack"]
    total = int(table.values.sum())
    best, best_key = None, None
    caps = list(table.index)
    for size in (2, 3):
        for combo in combinations(caps, size):
            test = table.loc[list(combo)]
            train = table.drop(list(combo))
            share = test.values.sum() / total
            ok = (
                test["attack"].sum() >= min_class
                and test["normal"].sum() >= min_class
                and (train["attack"] > 0).sum() >= 3
                and train["attack"].sum() >= 0.5 * table["attack"].sum()
            )
            if not ok:
                continue
            key = (round(abs(share - target), 6), size, combo)
            if best_key is None or key < best_key:
                best, best_key = combo, key
    if best is None:
        raise RuntimeError("No valid capture-grouped split satisfies the constraints.")
    test = table.loc[list(best)]
    return {
        "test_captures": list(best),
        "train_captures": [c for c in caps if c not in best],
        "labelled_event_share_test": float(test.values.sum() / total),
        "selection": "closest to 20% of labelled events; deterministic enumeration",
        "random_state": RANDOM_STATE,
        "per_capture_counts": table.reset_index().to_dict("records"),
    }
