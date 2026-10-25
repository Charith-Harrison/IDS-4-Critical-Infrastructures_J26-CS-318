# Check label mapping behavior using software fixtures and existing evidence.
import pandas as pd
import pytest

from src.label_mapper import class_names, map_labels


# Check that binary direction does not define target.
def test_binary_direction_does_not_define_target(raw, cfg):
    raw.loc[:3, "attack_category"] = "Command_Response_Injection"
    result = map_labels(raw, cfg)
    assert result.loc[:3, "target"].eq("Command_Response_Injection").all()
    assert set(result.target) == set(class_names(cfg))


# Check that binary rejects final labels.
def test_binary_rejects_final_labels(raw, cfg):
    raw.loc[0, "attack_category"] = "Command_Injection"
    with pytest.raises(ValueError):
        map_labels(raw, cfg)


# Check that final canonical mapping.
def test_final_canonical_mapping(cfg):
    cfg["model_mode"] = "final_three_class"
    expected = class_names(cfg)
    result = map_labels(pd.DataFrame({"attack_category": expected}), cfg)
    assert result.target.tolist() == expected


# Check that msu explicit mapping and exclusions.
def test_msu_explicit_mapping_and_exclusions(cfg):
    cfg["model_mode"] = "final_three_class"
    cfg["dataset"]["label_scheme"] = "msu_numeric"
    result = map_labels(pd.DataFrame({"attack_category": list(range(8))}), cfg)
    assert result.target.tolist()[:6] == [
        "Normal",
        "Response_Injection",
        "Response_Injection",
        "Command_Injection",
        "Command_Injection",
        "Command_Injection",
    ]
    assert result.loc[6:, "label_status"].eq("excluded_out_of_scope").all()


# Check that auxiliary label conflict fails.
def test_auxiliary_label_conflict_fails(raw, cfg):
    raw["is_attack"] = 0
    with pytest.raises(ValueError, match="conflict"):
        map_labels(raw, cfg)
