# Run preparation for the older configurable CSV workflow.
"""Run prepare_data from any working directory."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.preprocessing import prepare_data
from src.utils import load_config


# Load the older configuration and invoke its data preparation command.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()
    result = prepare_data(load_config(args.config))
    print("prepare_data completed. See data/manifests, models, and results/metrics for outputs.")
    return result


if __name__ == "__main__":
    main()
