"""PyTorch LSTM sequence model (Model C) and timing ablation (Model D) for C2.

Architecture (faithful to approved TAF / proposal):
  Input: (batch, L=20, F)
  -> LSTM(input_size=F, hidden_size=64, batch_first=True) [returns full sequence (batch, L, 64)]
  -> Dropout(p=0.3)
  -> LSTM(input_size=64, hidden_size=32, batch_first=True) [takes final step (batch, 32)]
  -> Dropout(p=0.3)
  -> Linear(32, 16) + ReLU
  -> Linear(16, 1) -> Sigmoid score in [0, 1]

Strict leak-free protocol:
- `SequenceScaler` is fitted ONLY on `fit_groups` within each fold.
- Positive class weighting (`pos_weight = sqrt(n_neg_epoch / n_pos_fit)`) is derived ONLY from `fit_groups`.
- Early stopping and ReduceLROnPlateau monitor inner group-independent validation loss (`val_groups`).
- Operational decision threshold is selected ONLY on `val_groups` targeting validation FPR <= 0.05.
"""
from __future__ import annotations

import copy
import time
from typing import Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from baselines import _evaluate_precomputed_decisions
from common import ARTIFACTS, DATA_REBUILT, read_json, set_seeds, write_json
from evaluate import (
    evaluate_predictions,
    select_validation_threshold,
    summarize_fold_metrics,
)
from features import (
    SEQ_FEATURES,
    SEQ_FEATURES_NO_TIMING,
    SequenceScaler,
    packet_level_columns,
    sequence_tensor,
)


class ModbusReconLSTM(nn.Module):
    """Approved 2-layer LSTM architecture (64 -> 32 -> Dense 16 ReLU -> Dense 1 Sigmoid)."""

    def __init__(
        self,
        input_dim: int,
        hidden1: int = 64,
        hidden2: int = 32,
        dense_dim: int = 16,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.hidden1 = hidden1
        self.hidden2 = hidden2
        self.dense_dim = dense_dim
        self.dropout_p = dropout

        self.lstm1 = nn.LSTM(
            input_size=input_dim, hidden_size=hidden1, num_layers=1, batch_first=True
        )
        self.drop1 = nn.Dropout(p=dropout)
        self.lstm2 = nn.LSTM(
            input_size=hidden1, hidden_size=hidden2, num_layers=1, batch_first=True
        )
        self.drop2 = nn.Dropout(p=dropout)
        self.fc1 = nn.Linear(hidden2, dense_dim)
        self.act = nn.ReLU()
        self.fc_out = nn.Linear(dense_dim, 1)

    def forward_logits(self, x: torch.Tensor) -> torch.Tensor:
        out1, _ = self.lstm1(x)  # (B, L, 64)
        out1 = self.drop1(out1)
        out2, _ = self.lstm2(out1)  # (B, L, 32)
        last_h = out2[:, -1, :]  # (B, 32)
        last_h = self.drop2(last_h)
        z = self.act(self.fc1(last_h))  # (B, 16)
        logits = self.fc_out(z).squeeze(-1)  # (B,)
        return logits

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.forward_logits(x))


@torch.no_grad()
def predict_logits_lstm(
    model: ModbusReconLSTM, X: np.ndarray, batch_size: int = 4096
) -> np.ndarray:
    model.eval()
    t_x = torch.from_numpy(X.astype(np.float32))
    out_list = []
    for start in range(0, len(t_x), batch_size):
        batch = t_x[start : start + batch_size]
        logits = model.forward_logits(batch).cpu().numpy()
        out_list.append(logits)
    return np.concatenate(out_list, axis=0) if out_list else np.zeros(0, dtype=np.float64)


@torch.no_grad()
def predict_scores_lstm(
    model: ModbusReconLSTM, X: np.ndarray, batch_size: int = 4096
) -> np.ndarray:
    logits = predict_logits_lstm(model, X, batch_size=batch_size)
    return 1.0 / (1.0 + np.exp(-np.clip(logits, -40.0, 40.0)))


def train_one_fold_lstm(
    X_fit_raw: np.ndarray,
    y_fit: np.ndarray,
    X_val_raw: np.ndarray,
    y_val: np.ndarray,
    X_test_raw: np.ndarray,
    features: list[str],
    max_epochs: int = 12,
    batch_size: int = 512,
    lr: float = 1.5e-3,
    patience: int = 4,
    max_neg_per_epoch: int = 15000,
    seed: int = 42,
) -> tuple[ModbusReconLSTM, SequenceScaler, np.ndarray, np.ndarray, dict[str, Any]]:
    """Fit SequenceScaler and ModbusReconLSTM on (X_fit_raw, y_fit), validate on (X_val_raw, y_val)."""
    set_seeds(seed)
    scaler = SequenceScaler(features).fit(X_fit_raw)
    X_fit = scaler.transform(X_fit_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    pos_idx = np.where(y_fit == 1)[0]
    neg_idx = np.where(y_fit == 0)[0]
    n_pos = max(len(pos_idx), 1)
    n_neg_ep = min(len(neg_idx), max_neg_per_epoch)

    pos_weight_val = float(np.sqrt(max(n_neg_ep, 1) / n_pos))
    pos_weight = torch.tensor([pos_weight_val], dtype=torch.float32)

    model = ModbusReconLSTM(input_dim=len(features))
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=2
    )

    t_fit_x = torch.from_numpy(X_fit)
    t_fit_y = torch.from_numpy(y_fit.astype(np.float32))
    t_val_y = torch.from_numpy(y_val.astype(np.float32))

    rng = np.random.default_rng(seed)
    best_val_loss = float("inf")
    best_epoch = 0
    best_state = copy.deepcopy(model.state_dict())
    epochs_no_improve = 0
    history = []

    t0 = time.perf_counter()
    for epoch in range(1, max_epochs + 1):
        model.train()
        if len(neg_idx) > max_neg_per_epoch:
            sampled_neg = rng.choice(neg_idx, size=max_neg_per_epoch, replace=False)
        else:
            sampled_neg = neg_idx
        ep_indices = np.concatenate([pos_idx, sampled_neg])
        rng.shuffle(ep_indices)
        t_idx = torch.from_numpy(ep_indices)

        running_loss = 0.0
        n_seen = 0
        for start in range(0, len(t_idx), batch_size):
            b_idx = t_idx[start : start + batch_size]
            bx = t_fit_x[b_idx]
            by = t_fit_y[b_idx]
            optimizer.zero_grad()
            logits = model.forward_logits(bx)
            loss = criterion(logits, by)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            running_loss += float(loss.item()) * len(by)
            n_seen += len(by)
        train_loss = running_loss / max(n_seen, 1)

        val_logits_np = predict_logits_lstm(model, X_val)
        val_logits_t = torch.from_numpy(val_logits_np.astype(np.float32))
        val_loss = float(criterion(val_logits_t, t_val_y).item())
        val_probs = 1.0 / (1.0 + np.exp(-np.clip(val_logits_np, -40.0, 40.0)))

        val_eval_05 = evaluate_predictions(y_val, val_probs, threshold=0.5)
        cur_lr = float(optimizer.param_groups[0]["lr"])
        scheduler.step(val_loss)

        history.append(
            {
                "epoch": epoch,
                "train_loss": train_loss,
                "val_loss": val_loss,
                "val_f1_at_0_5": val_eval_05["f1"],
                "val_pr_auc": val_eval_05["pr_auc"],
                "lr": cur_lr,
            }
        )

        if val_loss < best_val_loss - 1e-4:
            best_val_loss = val_loss
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                break

    train_wall_s = time.perf_counter() - t0
    model.load_state_dict(best_state)
    val_scores = predict_scores_lstm(model, X_val)
    test_scores = predict_scores_lstm(model, X_test)

    train_meta = {
        "pos_weight": pos_weight_val,
        "max_neg_per_epoch": max_neg_per_epoch,
        "best_epoch": best_epoch,
        "best_val_loss": best_val_loss,
        "epochs_ran": len(history),
        "train_wall_seconds": train_wall_s,
        "epochs": history,
    }
    return model, scaler, val_scores, test_scores, train_meta


def run_lstm_cv(
    r: pd.DataFrame,
    W: pd.DataFrame,
    idx_mat: np.ndarray,
    folds: list[dict[str, Any]],
    features: list[str] = SEQ_FEATURES,
    max_epochs: int = 12,
    batch_size: int = 512,
    lr: float = 1.5e-3,
    patience: int = 4,
    max_neg_per_epoch: int = 15000,
    seed: int = 42,
    save_artifact_prefix: str | None = None,
) -> dict[str, Any]:
    """Run group-independent cross-validation for the PyTorch LSTM."""
    X_seq_all = sequence_tensor(r, idx_mat, features=features)
    y_all = W["label"].to_numpy(dtype=np.int64)
    win_groups = W["capture_group"].to_numpy()

    oof_scores = np.zeros(len(W), dtype=np.float64)
    oof_val_thresholds = np.full(len(W), 0.5, dtype=np.float64)
    oof_pred_val_thr = np.zeros(len(W), dtype=np.int64)
    fold_reports = []
    histories = {}

    representative_model = None
    representative_scaler = None
    representative_thr = 0.5

    for f in folds:
        fold_id = f["fold_id"]
        fit_m = np.isin(win_groups, list(f["fit_groups"]))
        val_m = np.isin(win_groups, list(f["val_groups"]))
        test_m = np.isin(win_groups, list(f["test_groups"]))

        model, scaler, val_scores, test_scores, train_meta = train_one_fold_lstm(
            X_fit_raw=X_seq_all[fit_m],
            y_fit=y_all[fit_m],
            X_val_raw=X_seq_all[val_m],
            y_val=y_all[val_m],
            X_test_raw=X_seq_all[test_m],
            features=features,
            max_epochs=max_epochs,
            batch_size=batch_size,
            lr=lr,
            patience=patience,
            max_neg_per_epoch=max_neg_per_epoch,
            seed=seed + f["fold_index"],
        )

        thr_info = select_validation_threshold(y_all[val_m], val_scores, max_fpr=0.05)
        thr = thr_info["threshold"]

        oof_scores[test_m] = test_scores
        oof_val_thresholds[test_m] = thr
        oof_pred_val_thr[test_m] = (test_scores >= thr).astype(np.int64)

        eval_05 = evaluate_predictions(y_all[test_m], test_scores, threshold=0.5)
        eval_vt = evaluate_predictions(y_all[test_m], test_scores, threshold=thr)

        print(
            f"    [{fold_id}] ep={train_meta['best_epoch']}/{train_meta['epochs_ran']} "
            f"({train_meta['train_wall_seconds']:.1f}s) | val_thr={thr:.3f} | "
            f"test_F1@val={eval_vt['f1']} | test_FPR@val={eval_vt['fpr']:.4f}",
            flush=True,
        )

        fold_reports.append(
            {
                "fold_id": fold_id,
                "test_groups": f["test_groups"],
                "val_groups": f["val_groups"],
                "threshold_selection": thr_info,
                "training_summary": {
                    k: v for k, v in train_meta.items() if k != "epochs"
                },
                "at_0_5": eval_05,
                "at_val_threshold": eval_vt,
            }
        )
        histories[fold_id] = train_meta

        if "G08_0320_sub14" in f["test_groups"] or representative_model is None:
            representative_model = model
            representative_scaler = scaler
            representative_thr = thr

    if save_artifact_prefix is not None and representative_model is not None:
        models_dir = ARTIFACTS / "models"
        prep_dir = ARTIFACTS / "preprocessing"
        models_dir.mkdir(parents=True, exist_ok=True)
        prep_dir.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state_dict": representative_model.state_dict(),
                "input_dim": len(features),
                "features": list(features),
                "hidden1": representative_model.hidden1,
                "hidden2": representative_model.hidden2,
                "dense_dim": representative_model.dense_dim,
                "dropout": representative_model.dropout_p,
                "operational_threshold": float(representative_thr),
            },
            models_dir / f"{save_artifact_prefix}.pt",
        )
        write_json(
            representative_scaler.state(),
            prep_dir / f"{save_artifact_prefix}_scaler.json",
        )

    pooled_05 = evaluate_predictions(y_all, oof_scores, threshold=0.5)
    pooled_vt = _evaluate_precomputed_decisions(y_all, oof_scores, oof_pred_val_thr)

    return {
        "features": list(features),
        "n_features": len(features),
        "architecture": {
            "type": "PyTorch 2-Layer LSTM",
            "layers": [
                f"LSTM({len(features)} -> 64, return_sequences=True)",
                "Dropout(0.3)",
                "LSTM(64 -> 32, return_sequences=False)",
                "Dropout(0.3)",
                "Linear(32 -> 16) + ReLU",
                "Linear(16 -> 1) + Sigmoid",
            ],
            "optimizer": f"Adam(lr={lr}, weight_decay=1e-4)",
            "batch_size": batch_size,
            "max_epochs": max_epochs,
            "early_stopping_patience": patience,
        },
        "per_fold": fold_reports,
        "summary_at_0_5": summarize_fold_metrics(fold_reports, key="at_0_5"),
        "summary_at_val_threshold": summarize_fold_metrics(
            fold_reports, key="at_val_threshold"
        ),
        "pooled_oof_at_0_5": pooled_05,
        "pooled_oof_at_val_threshold": pooled_vt,
        "training_histories": histories,
        "oof_scores": oof_scores,
        "oof_val_thresholds": oof_val_thresholds,
    }


def main() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    r = packet_level_columns(r)
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    folds_art = read_json(ARTIFACTS / "folds.json")
    locgo_folds = folds_art["locgo_10fold"]["folds"]
    sgkf5_folds = folds_art["sgkf_5fold"]["folds"]

    print("Training Model C (LSTM with Timing, 19 features) on LOCGO-10...", flush=True)
    c_locgo = run_lstm_cv(
        r,
        W,
        idx_mat,
        locgo_folds,
        features=SEQ_FEATURES,
        save_artifact_prefix="model_c_lstm_full",
    )
    print("Training Model C (LSTM with Timing, 19 features) on SGKF-5...", flush=True)
    c_sgkf5 = run_lstm_cv(
        r, W, idx_mat, sgkf5_folds, features=SEQ_FEATURES
    )

    print("Training Model D (LSTM without Timing, 17 features, RQ2 ablation) on LOCGO-10...", flush=True)
    d_locgo = run_lstm_cv(
        r,
        W,
        idx_mat,
        locgo_folds,
        features=SEQ_FEATURES_NO_TIMING,
        save_artifact_prefix="model_d_lstm_no_timing",
    )
    print("Training Model D (LSTM without Timing, 17 features, RQ2 ablation) on SGKF-5...", flush=True)
    d_sgkf5 = run_lstm_cv(
        r, W, idx_mat, sgkf5_folds, features=SEQ_FEATURES_NO_TIMING
    )

    training_history = {
        "Model_C_LSTM_Full": {
            "locgo_10fold": c_locgo["training_histories"],
            "sgkf_5fold": c_sgkf5["training_histories"],
        },
        "Model_D_LSTM_NoTiming": {
            "locgo_10fold": d_locgo["training_histories"],
            "sgkf_5fold": d_sgkf5["training_histories"],
        },
    }
    write_json(training_history, ARTIFACTS / "training_history.json")

    pred_df = W[["window_id", "capture_group", "session_id", "label"]].copy()
    pred_df["score_model_c_lstm"] = c_locgo["oof_scores"]
    pred_df["thr_model_c_lstm"] = c_locgo["oof_val_thresholds"]
    pred_df["score_model_d_lstm_no_timing"] = d_locgo["oof_scores"]
    pred_df["thr_model_d_lstm_no_timing"] = d_locgo["oof_val_thresholds"]
    pred_df.to_csv(ARTIFACTS / "lstm_oof_predictions.csv", index=False)

    def _strip(res: dict[str, Any]) -> dict[str, Any]:
        return {
            k: v
            for k, v in res.items()
            if not k.startswith("oof_") and k != "training_histories"
        }

    lstm_out = {
        "Model_C_LSTM_Full": {
            "locgo_10fold": _strip(c_locgo),
            "sgkf_5fold": _strip(c_sgkf5),
        },
        "Model_D_LSTM_NoTiming": {
            "locgo_10fold": _strip(d_locgo),
            "sgkf_5fold": _strip(d_sgkf5),
        },
    }
    write_json(lstm_out, ARTIFACTS / "lstm_metrics.json")
    print("Saved artifacts/lstm_metrics.json, artifacts/training_history.json, and artifacts/lstm_oof_predictions.csv", flush=True)
    for name, res in lstm_out.items():
        p05 = res["locgo_10fold"]["pooled_oof_at_0_5"]
        pvt = res["locgo_10fold"]["pooled_oof_at_val_threshold"]
        s5 = res["sgkf_5fold"]["summary_at_val_threshold"]["metrics"]["f1"]["mean"]
        print(
            f"  {name}: LOCGO Pooled F1@0.5={p05['f1']:.4f}, F1@val_thr={pvt['f1']:.4f} "
            f"(FPR={pvt['fpr']:.4f}, PR-AUC={p05['pr_auc']:.4f}); SGKF5 mean F1@val_thr={s5:.4f}",
            flush=True,
        )


if __name__ == "__main__":
    main()
