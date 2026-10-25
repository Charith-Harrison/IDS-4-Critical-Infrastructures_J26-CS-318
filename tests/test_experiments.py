# Check experiments behavior using software fixtures and existing evidence.
from src.experiments import archive_if_changed
from src.utils import checksum, config_digest, save_json


# Check that dataset switch archives outputs but preserves raw and docs.
def test_dataset_switch_archives_outputs_but_preserves_raw_and_docs(cfg, tmp_path):
    raw = tmp_path / "data/raw/original.csv"
    raw.parent.mkdir(parents=True)
    raw.write_text("original data")
    document = tmp_path / "docs/research.md"
    document.parent.mkdir()
    document.write_text("research evidence")
    model = tmp_path / "models/contextual/model.joblib"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"old model fixture")
    save_json(
        tmp_path / "data/manifests/preprocessing.json",
        {
            "configuration_hash": config_digest(cfg),
            "configuration": cfg,
            "inputs": [{"input_file": "data/raw/original.csv", "sha256": checksum(raw)}],
        },
    )
    assert archive_if_changed(cfg, tmp_path) is None
    cfg["model_mode"] = "final_three_class"
    archived = archive_if_changed(cfg, tmp_path)
    assert archived is not None
    assert (archived / "models/contextual/model.joblib").read_bytes() == b"old model fixture"
    assert raw.read_text() == "original data"
    assert document.read_text() == "research evidence"
    assert not model.exists()
