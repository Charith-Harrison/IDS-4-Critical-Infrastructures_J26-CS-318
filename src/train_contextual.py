# Call the older shared trainer with context features enabled.
"""Context-aware RF entry point using the identical candidate search budget."""

from src.training import fit_model


# Use the same shared training code with context features enabled.
def train_contextual(train, validation, config, provenance=None):
    return fit_model(train, validation, config, "contextual", provenance)
