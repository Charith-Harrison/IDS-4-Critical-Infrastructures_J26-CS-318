"""C2 Integration Contract and Runtime Inference Engine (Section 23).

Produces the standardized C2 output contract for downstream decision fusion / dashboarding,
with explicit distinction between uncalibrated sigmoid scores (`score_type="raw_sigmoid_score"`,
`calibrated=False`) and calibrated probabilities, plus gradient-based feature/timestep
attribution and behavioural indicator extraction.
"""
from __future__ import annotations

import time
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch

from common import ARTIFACTS, read_json
from features import (
    PACKET_FEATURES,
    SEQ_FEATURES,
    SEQ_FEATURES_NO_TIMING,
    WINDOW_FEATURES,
    SequenceScaler,
    extract_single_window_from_packets,
)
from train_lstm import ModbusReconLSTM


def derive_behavioural_indicators(
    pkt_df: pd.DataFrame,
    X_win: pd.DataFrame,
    top_grad_features: list[str] | None = None,
) -> list[str]:
    """Derive human-interpretable protocol & temporal indicators present in a 20-packet window."""
    indicators: list[str] = []
    ml = pkt_df["modbus_len"].to_numpy()
    qty = pkt_df["quantity"].to_numpy()
    fc = pkt_df["func_code"].to_numpy()
    w_row = X_win.iloc[0]

    if (ml == 3).any():
        indicators.append("modbus_len_eq_3_abnormal_frame_signature")
    if (~np.isin(qty, [0, 1])).any():
        max_q = int(qty.max())
        indicators.append(f"non_routine_register_quantity_request(max_qty={max_q})")
    if float(w_row["seq_step_ratio"]) >= 0.25:
        indicators.append(
            f"sequential_register_address_stepping(ratio={float(w_row['seq_step_ratio']):.2f})"
        )
    if int(w_row["n_unique_reg"]) >= 5:
        indicators.append(
            f"multi_register_address_probing(unique_regs={int(w_row['n_unique_reg'])})"
        )
    if float(w_row["write_ratio"]) > 0.0:
        indicators.append(
            f"write_function_code_activity(write_ratio={float(w_row['write_ratio']):.2f})"
        )
    if float(w_row["fc_change_ratio"]) >= 0.30:
        indicators.append(
            f"frequent_function_code_transitions(ratio={float(w_row['fc_change_ratio']):.2f})"
        )
    if float(w_row["req_rate"]) >= 20.0:
        indicators.append(
            f"elevated_request_rate(rate={float(w_row['req_rate']):.1f}_pkt_per_s)"
        )
    if float(w_row["dt_cv"]) >= 1.5:
        indicators.append(
            f"irregular_inter_packet_timing(dt_cv={float(w_row['dt_cv']):.2f})"
        )

    if top_grad_features:
        for gf in top_grad_features[:2]:
            tag = f"top_gradient_feature:{gf}"
            if tag not in indicators:
                indicators.append(tag)

    if not indicators:
        indicators.append("routine_polling_profile")
    return indicators[:5]


def severity_from_score(score: float, threshold: float, prediction: int) -> str:
    if prediction == 0:
        return "NORMAL"
    margin = (score - threshold) / max(1.0 - threshold, 1e-6)
    if score >= 0.90 or margin >= 0.60:
        return "HIGH"
    if score >= 0.70 or margin >= 0.25:
        return "MEDIUM"
    return "LOW"


class C2InferenceEngine:
    """Self-contained runtime inference wrapper for C2 models (LSTM C/D and Baseline B/A)."""

    def __init__(self) -> None:
        self.models_loaded = False
        self.lstm_c: ModbusReconLSTM | None = None
        self.sc_c: SequenceScaler | None = None
        self.thr_c: float = 0.5

        self.lstm_d: ModbusReconLSTM | None = None
        self.sc_d: SequenceScaler | None = None
        self.thr_d: float = 0.5

        self.rf_b: Any = None
        self.sc_b: Any = None
        self.thr_b: float = 0.5

        self.lr_a: Any = None
        self.sc_a: Any = None
        self.thr_a: float = 0.5

    def load(self) -> "C2InferenceEngine":
        ckpt_c = torch.load(
            ARTIFACTS / "models" / "model_c_lstm_full.pt",
            map_location="cpu",
            weights_only=False,
        )
        self.lstm_c = ModbusReconLSTM(
            input_dim=ckpt_c["input_dim"],
            hidden1=ckpt_c["hidden1"],
            hidden2=ckpt_c["hidden2"],
            dense_dim=ckpt_c["dense_dim"],
            dropout=ckpt_c["dropout"],
        )
        self.lstm_c.load_state_dict(ckpt_c["model_state_dict"])
        self.lstm_c.eval()
        self.sc_c = SequenceScaler.from_state(
            read_json(ARTIFACTS / "preprocessing" / "model_c_lstm_full_scaler.json")
        )
        self.thr_c = float(ckpt_c.get("operational_threshold", 0.5))

        ckpt_d = torch.load(
            ARTIFACTS / "models" / "model_d_lstm_no_timing.pt",
            map_location="cpu",
            weights_only=False,
        )
        self.lstm_d = ModbusReconLSTM(
            input_dim=ckpt_d["input_dim"],
            hidden1=ckpt_d["hidden1"],
            hidden2=ckpt_d["hidden2"],
            dense_dim=ckpt_d["dense_dim"],
            dropout=ckpt_d["dropout"],
        )
        self.lstm_d.load_state_dict(ckpt_d["model_state_dict"])
        self.lstm_d.eval()
        self.sc_d = SequenceScaler.from_state(
            read_json(ARTIFACTS / "preprocessing" / "model_d_lstm_no_timing_scaler.json")
        )
        self.thr_d = float(ckpt_d.get("operational_threshold", 0.5))

        self.rf_b = joblib.load(ARTIFACTS / "models" / "model_b_window_rf.joblib")
        self.rf_b.n_jobs = 1
        self.sc_b = joblib.load(
            ARTIFACTS / "preprocessing" / "model_b_window_rf_scaler.joblib"
        )
        self.lr_a = joblib.load(ARTIFACTS / "models" / "model_a_packet_logreg.joblib")
        self.sc_a = joblib.load(
            ARTIFACTS / "preprocessing" / "model_a_packet_logreg_scaler.joblib"
        )
        self.models_loaded = True
        return self

    def score_window(
        self,
        packets: list[dict[str, Any]] | pd.DataFrame,
        session_id: str = "runtime_session",
        model_choice: str = "c2-lstm-v1",
        include_attribution: bool = True,
    ) -> dict[str, Any]:
        if not self.models_loaded:
            self.load()
        t0 = time.perf_counter()
        pkt_df = (
            packets.copy().reset_index(drop=True)
            if isinstance(packets, pd.DataFrame)
            else pd.DataFrame(packets)
        )
        if len(pkt_df) == 0:
            raise ValueError("Packet sequence cannot be empty.")

        X_seq_c, X_win, X_pkt = extract_single_window_from_packets(
            pkt_df, seq_features=SEQ_FEATURES
        )
        Z_c = self.sc_c.transform(X_seq_c)

        # Gradient * Input attribution for Model C LSTM
        t_z = torch.from_numpy(Z_c).requires_grad_(include_attribution)
        logits_c = self.lstm_c.forward_logits(t_z)
        score_c = float(torch.sigmoid(logits_c).item())

        timestep_salience = None
        top_grad_features: list[str] = []
        feature_salience_dict: dict[str, float] = {}
        if include_attribution:
            self.lstm_c.zero_grad()
            logits_c.backward()
            grad_input = (t_z.grad[0].detach().numpy() * Z_c[0])  # (L, F)
            abs_gi = np.abs(grad_input)
            ts_sal = abs_gi.sum(axis=1)
            if ts_sal.sum() > 0:
                ts_sal = ts_sal / ts_sal.sum()
            timestep_salience = [float(x) for x in ts_sal]

            feat_sal = abs_gi.sum(axis=0)
            if feat_sal.sum() > 0:
                feat_sal = feat_sal / feat_sal.sum()
            order = np.argsort(feat_sal)[::-1]
            top_grad_features = [SEQ_FEATURES[i] for i in order[:5]]
            feature_salience_dict = {
                SEQ_FEATURES[i]: float(feat_sal[i]) for i in order[:8]
            }

        # Also compute baseline & ablation scores for comparative diagnostics
        Z_win = self.sc_b.transform(X_win[WINDOW_FEATURES].to_numpy(dtype=np.float32))
        score_b_rf = float(self.rf_b.predict_proba(Z_win)[0, 1])

        Z_pkt = self.sc_a.transform(X_pkt)
        score_a_lr = float(self.lr_a.predict_proba(Z_pkt)[:, 1].max())

        idx_d = [SEQ_FEATURES.index(f) for f in SEQ_FEATURES_NO_TIMING]
        Z_d = self.sc_d.transform(X_seq_c[:, :, idx_d])
        with torch.no_grad():
            score_d = float(
                torch.sigmoid(self.lstm_d.forward_logits(torch.from_numpy(Z_d))).item()
            )

        if model_choice == "c2-rf-baseline-v1":
            primary_score = score_b_rf
            primary_thr = self.thr_b
            score_type = "rf_vote_fraction"
        elif model_choice == "c2-lstm-notiming-v1":
            primary_score = score_d
            primary_thr = self.thr_d
            score_type = "raw_sigmoid_score"
        else:
            model_choice = "c2-lstm-v1"
            primary_score = score_c
            primary_thr = self.thr_c
            score_type = "raw_sigmoid_score"

        pred = int(primary_score >= primary_thr)
        severity = severity_from_score(primary_score, primary_thr, pred)
        indicators = derive_behavioural_indicators(pkt_df, X_win, top_grad_features)

        w_start = (
            str(pkt_df["timestamp"].iloc[0])
            if "timestamp" in pkt_df.columns
            else "0"
        )
        w_end = (
            str(pkt_df["timestamp"].iloc[-1])
            if "timestamp" in pkt_df.columns
            else str(float(X_win["duration_s"].iloc[0]))
        )
        if "session_id" in pkt_df.columns and session_id == "runtime_session":
            session_id = str(pkt_df["session_id"].iloc[0])

        latency_ms = float((time.perf_counter() - t0) * 1000.0)

        return {
            "module": "C2_RECON_DETECTION",
            "attack_type": "Reconnaissance",
            "window_start": w_start,
            "window_end": w_end,
            "session_id": session_id,
            "sequence_length": int(len(pkt_df)),
            "prediction": pred,
            "score": float(primary_score),
            "score_type": score_type,
            "calibrated": False,
            "threshold": float(primary_thr),
            "severity": severity,
            "top_indicators": indicators,
            "model_version": model_choice,
            "latency_ms": latency_ms,
            "comparative_scores": {
                "Model_A_Packet_LogReg": score_a_lr,
                "Model_B_Window_RF": score_b_rf,
                "Model_C_LSTM_Full": score_c,
                "Model_D_LSTM_NoTiming": score_d,
            },
            "attribution": {
                "timestep_salience": timestep_salience,
                "top_sequence_features": feature_salience_dict,
            }
            if include_attribution
            else None,
        }
