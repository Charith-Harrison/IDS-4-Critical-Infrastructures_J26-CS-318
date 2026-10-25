"""All examples below are invented in memory; no dataset is read or written."""
import unittest

from contracts import (ContractError, ToyEvent, ToyMembership, check_earlier_evidence,
                       check_predictor_names, check_toy_fit_intent, check_toy_memberships)
import stages


def event(n, connection="SYNTHETIC-connection", recording="SYNTHETIC-recording"):
    return ToyEvent(recording, connection, n, 5)


def member(n, group, role, stream=None):
    return ToyMembership(f"SYNTHETIC-r{n}", f"SYNTHETIC-g{group}", role,
                         f"SYNTHETIC-stream{n if stream is None else stream}")


class EvidenceBoundaryTests(unittest.TestCase):
    def test_reused_tid_does_not_collapse_distinct_positions(self):
        self.assertEqual(event(1).tid, event(2).tid)
        self.assertNotEqual(event(1).identity, event(2).identity)

    def test_future_or_current_message_cannot_be_history(self):
        for n in (2, 3):
            with self.subTest(n=n), self.assertRaises(ContractError):
                check_earlier_evidence(event(2), event(n))
        self.assertEqual(check_earlier_evidence(event(2), event(1)),
                         "EARLIER_EVIDENCE_ONLY_NOT_A_CLASSIFICATION")

    def test_missing_gap_and_new_connection_require_abstention(self):
        for anchor, gap in ((None, False), (event(1), True),
                            (event(1, connection="SYNTHETIC-new"), False),
                            (event(1, recording="SYNTHETIC-another"), False)):
            with self.subTest(anchor=anchor, gap=gap):
                self.assertEqual(check_earlier_evidence(event(2), anchor, gap), "ABSTAIN")

    def test_real_recording_names_are_refused(self):
        for name in ("MX001", "EQ01", "cic_benign_january"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                event(1, recording=name)


class LeakageTests(unittest.TestCase):
    def test_private_unknown_and_context_fields_refused_by_current_baseline(self):
        for name in ("label", "scenario", "private_state", "run_id", "surprise_column",
                     "paired_request_object_role", "earlier_observed_mode"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                check_predictor_names(["current_function", name], "B", "request")

    def test_fc3_response_is_not_given_a_wire_address(self):
        for method in ("B", "D", "B-wire", "D-wire"):
            with self.subTest(method=method), self.assertRaises(ContractError):
                check_predictor_names(["current_wire_address"], method, "response")
        check_predictor_names(["paired_request_object_role"], "D", "response")

    def test_wire_headers_are_available_equally_only_in_companion(self):
        for method in ("B-wire", "D-wire"):
            check_predictor_names(["current_numeric_tid", "current_source_port"], method, "request")
        for method in ("B", "D"):
            with self.subTest(method=method), self.assertRaises(ContractError):
                check_predictor_names(["current_numeric_tid"], method, "request")

    def test_mirrors_related_groups_and_same_recording_cannot_cross_roles(self):
        pairs = [
            [member(1, 1, "train"), member(2, 1, "final")],
            [member(1, 1, "train"), member(2, 2, "final", stream=1)],
            [member(1, 1, "train"), member(1, 2, "validation", stream=2)],
        ]
        for rows in pairs:
            with self.subTest(rows=rows), self.assertRaises(ContractError):
                check_toy_memberships(rows)

    def test_fresh_groups_can_be_reserved_without_splitting_payload_rows(self):
        check_toy_memberships([member(1, 1, "train"), member(2, 2, "validation"),
                               member(3, 3, "final")])
        # This contract compares ordered-stream identity, never individual payload equality.

    def test_validation_and_final_cannot_fit_a_transform(self):
        check_toy_fit_intent(member(1, 1, "train"))
        for role in ("validation", "final"):
            with self.subTest(role=role), self.assertRaises(ContractError):
                check_toy_fit_intent(member(2, 2, role))


class DeferredStageTests(unittest.TestCase):
    def test_every_real_stage_stops_before_work(self):
        functions = (stages.prepare_real_observations, stages.build_causal_context,
                     stages.fit_training_transformations, stages.train_comparison_models,
                     stages.evaluate_locked_models)
        for function in functions:
            with self.subTest(function=function.__name__), self.assertRaises(NotImplementedError):
                function()


if __name__ == "__main__":
    unittest.main(verbosity=2)
