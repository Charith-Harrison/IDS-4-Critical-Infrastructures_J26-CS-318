"""Frozen model representations (MODELLING_PLAN.md section 3), without any PyTorch dependency.

Moved verbatim out of train_models.py so the offline demo can import the identical code; train_models re-imports
them, so training/evaluation behaviour is unchanged.
"""
from __future__ import annotations

import numpy as np

A_COLS = list(range(13))                 # FC(4) + unit(5) + address, log2 quantity, MBAP length, frame length
NUMERIC = [9, 10, 11, 12, 14, 17]        # address, log2q, mbap, frame, addr_step_q, log10_iat (LSTM scaling)


def seq(X, W, rows):
    w = W[rows]
    S = X[np.maximum(w, 0)]
    S[w < 0] = 0.0
    return S                                   # (n, 20, 19)


def rep(name, X, W, B3, rows):
    if name == "A":
        return X[rows][:, A_COLS]
    if name == "B1":
        return seq(X, W, rows).reshape(len(rows), -1)
    if name == "B3":
        return B3[rows]
    if name == "B2":
        S = seq(X, W, rows)
        m = S[:, :, 18:19]
        n = m.sum(1)
        mean = (S * m).sum(1) / n
        feats = [mean[:, 0:9]]
        for c in (9, 10):
            v = np.where(m[:, :, 0] > 0, S[:, :, c], np.nan)
            feats += [np.nanmean(v, 1, keepdims=True), np.nanstd(v, 1, keepdims=True),
                      np.nanmin(v, 1, keepdims=True), np.nanmax(v, 1, keepdims=True)]
        key = S[:, :, 0:4].argmax(2) * 1e6 + S[:, :, 4:9].argmax(2) * 1e5 + S[:, :, 9] * 10 + S[:, :, 10]
        key = np.where(m[:, :, 0] > 0, key, np.nan)
        uniq = np.array([len(set(k[~np.isnan(k)])) for k in key], float)[:, None] / n
        feats += [uniq, n]
        return np.hstack(feats).astype(np.float32)
    raise ValueError(name)


def scale(S, mu, sd):
    S = S.copy()
    real = S[:, :, 18:19] > 0
    S[:, :, NUMERIC] = np.where(real, (S[:, :, NUMERIC] - mu) / sd, 0.0)
    return S
