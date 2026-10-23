"""Isolated-event RF entry point; shares all fitting logic with the proposed RF."""

from src.training import fit_model


def train_baseline(train, validation, config, provenance=None):
    return fit_model(train, validation, config, "baseline", provenance)
