"""Optional training-only reference summaries for explanations, never label rules."""

from __future__ import annotations

import pandas as pd


def fit_reference_profile(features: pd.DataFrame) -> dict:
    """Fit descriptive quantiles on training rows only, without reading targets."""
    profile = {}
    for name in features:
        values = features[name].dropna()
        if len(values):
            profile[name] = {
                "median": float(values.median()),
                "p01": float(values.quantile(0.01)),
                "p99": float(values.quantile(0.99)),
            }
    return profile
