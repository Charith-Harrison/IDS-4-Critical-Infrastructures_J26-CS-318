# Check schema behavior using software fixtures and existing evidence.
import numpy as np
import pytest

from src.preprocessing import preprocess_frame
from src.schema_validator import normalize_columns


# Check that required column.
def test_required_column(raw):
    with pytest.raises(ValueError, match="modbus_func_code"):
        normalize_columns(raw.drop(columns="modbus_func_code"))


# Check that column aliases.
def test_column_aliases(raw):
    renamed = raw.rename(columns={"modbus_func_code": "Function Code"})
    assert "modbus_func_code" in normalize_columns(renamed, {"Function Code": "modbus_func_code"})


# Check that normalization collision.
def test_normalization_collision(raw):
    raw[" MODBUS FUNC CODE "] = 3
    with pytest.raises(ValueError, match="duplicate"):
        normalize_columns(raw)


# Check that invalid range is quarantined.
@pytest.mark.parametrize(
    "column,value",
    [("modbus_func_code", 999), ("is_request", 3), ("mbtcp_trans_id", -1), ("modbus_ref_num", 1.5), ("timestamp", -1)],
)
def test_invalid_range_is_quarantined(raw, cfg, column, value):
    raw[column] = raw[column].astype(float)
    raw.loc[0, column] = value
    result = preprocess_frame(raw, cfg, "fixture")
    assert result.loc[0, "processing_status"] == "malformed"
    assert column in result.loc[0, "invalid_reason"]


# Check that missing optional values are explicit.
def test_missing_optional_values_are_explicit(raw, cfg):
    raw["modbus_val"] = np.nan
    result = preprocess_frame(raw, cfg, "fixture")
    assert result.processing_status.eq("valid").all()
    assert result.modbus_val.isna().all()


# Check that unknown label fails.
def test_unknown_label_fails(raw, cfg):
    raw.loc[0, "attack_category"] = "invented_label"
    with pytest.raises(ValueError, match="Unmapped"):
        preprocess_frame(raw, cfg, "fixture")
