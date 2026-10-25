# Call the older shared trainer with current-message features only.
"""Isolated-event RF entry point; shares all fitting logic with the proposed RF."""

from src.training import fit_model


# Use the shared training code with the baseline feature set.
def train_baseline(train, validation, config, provenance=None):
    return fit_model(train, validation, config, "baseline", provenance)
