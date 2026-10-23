"""Run train_models from any working directory."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.training import train_models
from src.utils import load_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()
    result = train_models(load_config(args.config))
    print("train_models completed. See data/manifests, models, and results/metrics for outputs.")
    return result


if __name__ == "__main__":
    main()
