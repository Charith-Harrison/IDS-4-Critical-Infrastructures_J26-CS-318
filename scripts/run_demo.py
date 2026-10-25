# Run the older saved model on a small validation batch.
"""Load a saved model and produce predictions on a small validation batch."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd

from src.inference import load_model, predict_events, prediction_records
from src.utils import ROOT, load_config, save_json


# Load an existing older model and predict a small validation batch.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["baseline", "contextual"], default="contextual")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    artifact = load_model(args.model, load_config())
    data = pd.read_parquet(ROOT / "data/processed/events.parquet")
    sample = (
        data[data.partition.eq("validation")]
        .sort_values(["group_id", "timestamp", "source_row"])
        .head(args.limit)
        .reset_index(drop=True)
    )
    predicted = predict_events(sample, artifact)
    destination = ROOT / "results/predictions/demo.json"
    save_json(destination, prediction_records(predicted))
    print(f"{len(predicted)} predictions written to {destination}")


if __name__ == "__main__":
    main()
