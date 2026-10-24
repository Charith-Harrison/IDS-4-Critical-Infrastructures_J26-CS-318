"""Deliberately unimplemented real-data stages, reserved for the student's viva.

Importing this file does not load data or fit anything. Every entry point stops.
These are interface placeholders, not an implementation of preprocessing.
"""


def prepare_real_observations(*args, **kwargs):
    raise NotImplementedError("WAIT: student implementation after collection acceptance")


def build_causal_context(*args, **kwargs):
    raise NotImplementedError("WAIT: causal context design only; no real features built")


def fit_training_transformations(*args, **kwargs):
    raise NotImplementedError("WAIT: training-only fitting requires later authorization")


def train_comparison_models(*args, **kwargs):
    raise NotImplementedError("WAIT: no model training authorized in this scaffold")


def evaluate_locked_models(*args, **kwargs):
    raise NotImplementedError("WAIT: final test access requires a later locked protocol")
