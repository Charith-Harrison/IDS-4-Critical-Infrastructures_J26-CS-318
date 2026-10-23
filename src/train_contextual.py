"""Context-aware RF entry point using the identical candidate search budget."""

from src.training import fit_model


def train_contextual(train, validation, config, provenance=None):
    return fit_model(train, validation, config, "contextual", provenance)
