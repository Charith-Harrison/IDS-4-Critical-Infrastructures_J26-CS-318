"""Run the pipeline from the command line.

Usage: python run_pipeline.py [prep | train | verify | audit | compare | evaluate | all]

  prep    audit the CSVs, preprocess, pair requests/responses, split by capture
  train   grouped cross-validation, then fit and save both Random Forests
  verify  reload the saved models and check them
  audit   write the feature audit files (needs the trained models)
  compare compare candidate algorithms and contextual features on dev data
  evaluate run development-only leakage, FC5, importance and ablation diagnostics
  all     everything above, in order
"""

import sys


def run_prep() -> None:
    from src.data.pipeline_prep import run_preprocess_and_split

    run_preprocess_and_split()


def run_train() -> None:
    from src.models.train import train_all

    train_all()


def run_verify() -> None:
    from src.models.train import verify_models

    print(verify_models())


def run_audit() -> None:
    from src.features.audit import evidence_matrix, run_feature_audit
    from src.features.profile import apply_profile
    from src.models.train import load_dev_features
    from src.utils.config import MODELS_DIR
    from src.utils.io import read_json

    # Only the development partition is used here.
    feats = load_dev_features()
    stats = read_json(MODELS_DIR / "contextual" / "feature_stats.json")
    names = read_json(MODELS_DIR / "contextual" / "feature_names.json")
    run_feature_audit(evidence_matrix(apply_profile(feats, stats), names))


def run_compare() -> None:
    from scripts.compare_models import run_comparison

    run_comparison()


def run_evaluate() -> None:
    from scripts.evaluate_diagnostics import run_evaluation_diagnostics

    run_evaluation_diagnostics()


STAGES = {
    "prep": run_prep,
    "train": run_train,
    "verify": run_verify,
    "audit": run_audit,
    "compare": run_compare,
    "evaluate": run_evaluate,
}


def main(argv: list[str]) -> int:
    stage = argv[1] if len(argv) > 1 else "all"
    if stage == "all":
        for run in STAGES.values():
            run()
    elif stage in STAGES:
        STAGES[stage]()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
