"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/baseline.py

Purpose:
    Implements a transparent, rule-based detection baseline using protocol consistency
    heuristics (transaction ID recurrence, non-sequential deltas, and response timeouts).

Viva Explanation:
    - Why do we have a rule baseline?
      In academic research, comparing machine learning against a transparent,
      deterministic rule baseline demonstrates whether an ML model adds genuine value
      or merely replicates trivial thresholds.
    - The rule baseline triggers an alert if ANY of these protocol anomalies occur:
        1. Direct TID Reuse: The Transaction ID was already observed in recent channel history (tid_previously_seen == 1).
        2. Non-Sequential Repeated Command: The TID delta violates the standard +1 increment
           WHILE repeating a previously observed command fingerprint.
        3. Missing-Response Disruption: A request timed out without a server reply AND exhibited
           an irregular TID delta.
    - Critical research safeguards:
        * Rule thresholds are fixed a priori, NOT tuned using test set results.
        * Rules provide comparative performance evidence and NEVER establish ground truth.
        * Rule outputs are strictly NEVER used as training labels for XGBoost.
"""

from typing import Dict, Any, Optional
import numpy as np
import pandas as pd


class ProtocolRuleBaseline:
    """
    Transparent protocol consistency rule baseline for Modbus/TCP replay detection.
    """

    def __init__(
        self,
        require_tid_previously_seen: bool = True,
        enable_non_sequential_repeated_cmd: bool = True,
        enable_timeout_rule: bool = True,
        normal_tid_increment: float = 1.0
    ):
        self.require_tid_previously_seen = require_tid_previously_seen
        self.enable_non_sequential_repeated_cmd = enable_non_sequential_repeated_cmd
        self.enable_timeout_rule = enable_timeout_rule
        self.normal_tid_increment = normal_tid_increment

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Generates binary replay predictions (0=Normal, 1=Replay) using fixed heuristic rules.

        Parameters:
            X: DataFrame containing protocol-aware consistency features

        Returns:
            np.ndarray of binary predictions (0 or 1)
        """
        condition_flags = np.zeros(len(X), dtype=bool)

        # Rule 1: Direct transaction ID reuse in recent history window
        if self.require_tid_previously_seen and "tid_previously_seen" in X.columns:
            r1 = (X["tid_previously_seen"] == 1.0)
            condition_flags |= r1

        # Rule 2: Non-sequential TID delta combined with repeated command fingerprint
        if self.enable_non_sequential_repeated_cmd and "trans_id_delta" in X.columns and "is_repeated_command" in X.columns:
            r2 = (X["trans_id_delta"] != self.normal_tid_increment) & (X["is_repeated_command"] == 1.0)
            condition_flags |= r2

        # Rule 3: Transaction timeout combined with non-sequential TID
        if self.enable_timeout_rule and "is_timeout" in X.columns and "trans_id_delta" in X.columns:
            r3 = (X["is_timeout"] == 1.0) & (X["trans_id_delta"] != self.normal_tid_increment)
            condition_flags |= r3

        return condition_flags.astype(int)

    def describe_rules(self) -> Dict[str, Any]:
        """
        Returns textual documentation of the rule baseline logic for viva presentation.
        """
        return {
            "name": "Protocol Consistency Heuristic Baseline",
            "type": "Transparent deterministic rules (fixed thresholds)",
            "rules": [
                "Rule 1: Flag replay if Transaction ID was seen previously in the recent channel history (tid_previously_seen == 1).",
                f"Rule 2: Flag replay if Transaction ID delta != {self.normal_tid_increment} AND command is a duplicate of a previously seen command.",
                f"Rule 3: Flag replay if transaction timed out without response AND Transaction ID delta != {self.normal_tid_increment}."
            ],
            "methodology_disclaimer": (
                "Rules serve as an interpretable comparative baseline. "
                "Rule decisions are never used to generate ground truth labels, "
                "and thresholds are fixed without test-set optimization."
            )
        }
