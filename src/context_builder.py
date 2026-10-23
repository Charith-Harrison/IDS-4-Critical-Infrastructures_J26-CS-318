"""Past-only context; input must already be partitioned into capture/session groups."""

from __future__ import annotations

import numpy as np
import pandas as pd


def rolling_by_group(values: pd.Series, groups: pd.Series, window: int, operation: str) -> pd.Series:
    """Calculate a bounded rolling statistic on already-lagged values."""
    rolled = values.groupby(groups, sort=False).rolling(window, min_periods=1)
    if operation == "nunique":
        result = rolled.apply(lambda a: len(np.unique(a[~np.isnan(a)])), raw=True)
    else:
        result = getattr(rolled, operation)()
    return result.reset_index(level=0, drop=True).reindex(values.index)


def build_context(events: pd.DataFrame, static: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    result = pd.DataFrame(index=events.index)
    groups = events.context_id
    past = static.groupby(groups, sort=False).shift(1)
    result["previous_function_code"] = past.function_code
    result["previous_operation"] = past.is_write
    result["function_transition"] = past.function_code * 256 + static.function_code
    result["read_to_write_transition"] = past.is_read * static.is_write
    result["write_to_read_transition"] = past.is_write * static.is_read
    result["previous_register"] = past.address
    result["address_change"] = static.address - past.address
    result["repeated_access"] = (static.address == past.address).astype(float).where(past.address.notna())
    result["previous_value"] = past.value
    result["value_delta"] = static.value - past.value
    result["absolute_value_delta"] = result.value_delta.abs()
    result["value_direction"] = np.sign(result.value_delta)
    result["repeated_same_value"] = (static.value == past.value).astype(float).where(past.value.notna())
    result["inter_arrival_time"] = events.groupby(groups, sort=False).timestamp.diff()
    result["previous_inter_arrival_time"] = result.inter_arrival_time.groupby(groups, sort=False).shift(1)
    prior_delta = result.absolute_value_delta.groupby(groups, sort=False).shift(1)
    for window in cfg["features"]["windows"]:
        result[f"recent_write_ratio_{window}"] = rolling_by_group(past.is_write, groups, window, "mean")
        result[f"repeated_write_count_{window}"] = rolling_by_group(past.is_write, groups, window, "sum")
        result[f"function_diversity_{window}"] = rolling_by_group(past.function_code, groups, window, "nunique")
        result[f"distinct_registers_{window}"] = rolling_by_group(past.address, groups, window, "nunique")
        result[f"repeated_access_count_{window}"] = rolling_by_group(
            result.repeated_access.groupby(groups).shift(1), groups, window, "sum"
        )
        result[f"rolling_mean_inter_arrival_{window}"] = rolling_by_group(
            result.previous_inter_arrival_time, groups, window, "mean"
        )
        result[f"rolling_std_inter_arrival_{window}"] = rolling_by_group(
            result.previous_inter_arrival_time, groups, window, "std"
        )
        result[f"rolling_value_change_{window}"] = rolling_by_group(prior_delta, groups, window, "mean")
    return result
