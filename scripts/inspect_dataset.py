# Inspect the older workflow's configured input files without training.
"""Run inspect_datasets from any working directory."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data_loader import inspect_datasets
from src.utils import load_config


# Inspect the configured input paths and report their schema.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()
    result = inspect_datasets(load_config(args.config))
    print("inspect_datasets completed. See data/manifests, models, and results/metrics for outputs.")
    return result


if __name__ == "__main__":
    main()
