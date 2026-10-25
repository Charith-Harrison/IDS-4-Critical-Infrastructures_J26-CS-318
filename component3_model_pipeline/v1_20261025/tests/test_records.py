"""Synthetic wire-message contract tests; no real final-test observations read.

Fixtures encode Modbus directly rather than calling the new adapter/generator.
They are invented software tests, not captured research examples.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

import pandas as pd

from c3model.records import CURRENT, WIRE, CONTEXT, build_run, decode


PUBLIC_MAPS = [{"id": "M0", "mode_register": 0, "setpoint_register": 1, "pump_coil": 1}]
MEMBERSHIP = {"planned_run_id": "SYNTHETIC-MX001", "map": "M0",
              "related_group": "SYNTHETIC-GROUP", "evaluation_role": "train",
              "recording_mode": "mixed"}


def adu(tid, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


class WireFixture:
    """Small independent state/byte fixture with one outstanding transaction."""

    def __init__(self):
        self.rows = []
        self.truth = []
        self.mode, self.setpoint, self.coil = 0, 50, 0
        self.connection = "SYNTHETIC-CONNECTION-0"
        self.transaction_index = 0
        self.offsets = {"request": 0, "response": 0}
        self.episode = "SYNTHETIC-EPISODE-A"

    def new_connection(self):
        self.connection = "SYNTHETIC-CONNECTION-1"
        self.transaction_index = 0
        self.offsets = {"request": 0, "response": 0}

    def exchange(self, fc, address, value, *, tid=5, forged_word=None,
                 request_label="normal", response_label="normal"):
        request = struct.pack("!BHH", fc, address, value)
        if fc == 3:
            expected = self.mode if address == 0 else self.setpoint
            response = bytes((3, 2)) + struct.pack("!H", expected if forged_word is None else forged_word)
        elif fc == 1:
            response = bytes((1, 1, self.coil))
        elif fc == 5:
            self.coil = int(value == 0xFF00)
            response = request
        elif fc == 6:
            if address == 0:
                self.mode = value
            else:
                self.setpoint = value
            response = request
        else:
            raise AssertionError("Unsupported test-fixture operation")
        indices = []
        for role, pdu, label in (("request", request, request_label), ("response", response, response_label)):
            index = len(self.rows)
            raw = adu(tid, pdu)
            row = {"event_id": f"SYNTHETIC-RUN:e{index}", "run_id": "SYNTHETIC-RUN",
                   "connection_id": self.connection, "transaction_index": self.transaction_index,
                   "role": role, "direction": "client_to_server" if role == "request" else "server_to_client",
                   "tid": tid, "unit": 1, "adu_hex": raw.hex(), "pdu_hex": pdu.hex(),
                   "stream_offset": self.offsets[role], "observed_at_ns": 1_000_000_000 + index * 1_000_000,
                   "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                   "source_port": 41000 if role == "request" else 15020,
                   "destination_port": 15020 if role == "request" else 41000,
                   "episode_id": self.episode, "scenario": "SYNTHETIC-PRIVATE-SCENARIO",
                   "label": label, "step": "SYNTHETIC-PRIVATE-STEP"}
            self.rows.append(row)
            self.truth.append({"event_id": row["event_id"], "label": label})
            self.offsets[role] += len(raw)
            indices.append(index)
        self.transaction_index += 1
        return tuple(indices)

    def mode_anchor(self, value):
        self.exchange(6, 0, value)
        return self.exchange(3, 0, 1)

    def write(self, folder):
        folder.mkdir(parents=True, exist_ok=True)
        for name, rows in (("application_ledger.jsonl", self.rows), ("verified_labels.jsonl", self.truth)):
            (folder / name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


class RecordsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c3model-SYNTHETIC-records-")
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, fixture, suffix="case"):
        folder = self.base / suffix
        fixture.write(folder)
        return build_run(folder, MEMBERSHIP, PUBLIC_MAPS)

    def test_fc3_response_has_no_current_wire_address_or_quantity(self):
        parsed = decode(adu(5, bytes.fromhex("03020034")), False)
        self.assertIsNone(parsed["address"])
        self.assertIsNone(parsed["quantity"])
        self.assertEqual(parsed["word"], 52)
        f = WireFixture()
        f.exchange(6, 1, 52)
        _, target = f.exchange(3, 1, 1)
        frame = self.build(f)
        self.assertTrue(pd.isna(frame.iloc[target]["current_wire_address"]))
        self.assertTrue(pd.isna(frame.iloc[target]["current_wire_quantity"]))
        self.assertEqual(frame.iloc[target]["current_wire_word"], 52)

    def test_future_ack_does_not_backfill_current_request_or_ack_features(self):
        f = WireFixture()
        f.exchange(6, 1, 50)
        request, acknowledgement = f.exchange(6, 1, 80)
        _, readback = f.exchange(3, 1, 1)
        frame = self.build(f)
        self.assertEqual(frame.iloc[request]["earlier_acknowledged_setpoint"], 50)
        # Pending writes may invalidate old knowledge, but current ACK must not
        # appear as an earlier acknowledged value at its own decision point.
        at_ack = frame.iloc[acknowledgement]["earlier_acknowledged_setpoint"]
        self.assertTrue(pd.isna(at_ack) or at_ack == 50)
        self.assertEqual(frame.iloc[readback]["earlier_acknowledged_setpoint"], 80)

    def test_zero_mode_and_zero_setpoint_are_values_not_missing_anchors(self):
        f = WireFixture()
        f.mode_anchor(0)
        f.exchange(6, 1, 0)
        _, readback = f.exchange(3, 1, 1)
        command, _ = f.exchange(5, 1, 0xFF00, request_label="command_injection")
        frame = self.build(f)
        self.assertEqual(frame.iloc[readback]["current_wire_word"], 0)
        self.assertEqual(frame.iloc[readback]["earlier_acknowledged_setpoint"], 0)
        self.assertTrue(bool(frame.iloc[readback]["eligible"]))
        self.assertEqual(frame.iloc[readback]["rule_prediction"], "normal")
        self.assertEqual(frame.iloc[command]["earlier_observed_mode"], 0)
        self.assertTrue(bool(frame.iloc[command]["eligible"]))
        self.assertEqual(frame.iloc[command]["rule_prediction"], "command_injection")

    def test_future_message_mutation_cannot_change_past_features(self):
        f = WireFixture()
        f.mode_anchor(1)
        f.exchange(5, 1, 0xFF00)
        cutoff = len(f.rows)
        f.exchange(6, 1, 70)
        f.exchange(3, 1, 1)
        before = self.build(f, "before")
        # Mutate complete future request/reply bytes together, preserving structure.
        for index in (cutoff, cutoff + 1):
            f.rows[index]["adu_hex"] = adu(5, bytes.fromhex("0600010063")).hex()
            f.rows[index]["pdu_hex"] = "0600010063"
        f.rows[cutoff + 3]["adu_hex"] = adu(5, bytes.fromhex("03020063")).hex()
        f.rows[cutoff + 3]["pdu_hex"] = "03020063"
        after = self.build(f, "after")
        pd.testing.assert_frame_equal(before.iloc[:cutoff][CURRENT + WIRE + CONTEXT],
                                      after.iloc[:cutoff][CURRENT + WIRE + CONTEXT])

    def test_mode_write_invalidates_old_read_and_ack_does_not_restore_it(self):
        f = WireFixture()
        f.mode_anchor(1)
        _, mode_ack = f.exchange(6, 0, 0)
        target, _ = f.exchange(5, 1, 0xFF00, request_label="command_injection")
        frame = self.build(f)
        self.assertTrue(pd.isna(frame.iloc[mode_ack]["earlier_observed_mode"]))
        self.assertTrue(bool(frame.iloc[target]["eligible"]))
        self.assertFalse(bool(frame.iloc[target]["context_available"]))
        self.assertEqual(frame.iloc[target]["rule_prediction"], "abstain")

    def test_missing_mode_anchor_abstains_despite_attack_label(self):
        f = WireFixture()
        target, _ = f.exchange(5, 1, 0xFF00, request_label="command_injection")
        frame = self.build(f)
        self.assertFalse(bool(frame.iloc[target]["context_available"]))
        self.assertTrue(bool(frame.iloc[target]["eligible"]))
        self.assertEqual(frame.iloc[target]["rule_prediction"], "abstain")

    def test_six_intervening_adus_allowed_eight_are_stale(self):
        for filler_count, expected in ((3, True), (4, False)):
            with self.subTest(filler_transactions=filler_count):
                f = WireFixture()
                f.mode_anchor(1)
                for _ in range(filler_count):
                    f.exchange(1, 1, 1)
                target, _ = f.exchange(5, 1, 0xFF00)
                frame = self.build(f, f"staleness-{filler_count}")
                self.assertTrue(bool(frame.iloc[target]["eligible"]))
                self.assertEqual(bool(frame.iloc[target]["context_available"]), expected)
                self.assertEqual(frame.iloc[target]["rule_prediction"], "normal" if expected else "abstain")

    def test_reply_uses_earlier_acknowledged_word_not_private_truth(self):
        f = WireFixture()
        f.exchange(6, 1, 86)
        _, target = f.exchange(3, 1, 1, forged_word=52, response_label="response_injection")
        frame = self.build(f)
        self.assertEqual(frame.iloc[target]["earlier_acknowledged_setpoint"], 86)
        self.assertEqual(frame.iloc[target]["current_wire_word"], 52)
        self.assertEqual(frame.iloc[target]["response_minus_acknowledged_setpoint"], -34)
        self.assertEqual(frame.iloc[target]["rule_prediction"], "response_injection")

    def test_response_anchor_expires_by_reply_decision(self):
        for filler_count, expected in ((2, True), (3, False)):
            with self.subTest(filler_transactions=filler_count):
                f = WireFixture()
                f.exchange(6, 1, 86)
                for _ in range(filler_count):
                    f.exchange(1, 1, 1)
                _, target = f.exchange(3, 1, 1, forged_word=52, response_label="response_injection")
                frame = self.build(f, f"reply-staleness-{filler_count}")
                self.assertTrue(bool(frame.iloc[target]["eligible"]))
                self.assertEqual(bool(frame.iloc[target]["context_available"]), expected)
                self.assertEqual(frame.iloc[target]["rule_prediction"], "response_injection" if expected else "abstain")

    def test_new_connection_resets_context_without_using_private_episode(self):
        f = WireFixture()
        f.mode_anchor(1)
        f.new_connection()
        target, _ = f.exchange(5, 1, 0xFF00)
        frame = self.build(f)
        self.assertTrue(bool(frame.iloc[target]["eligible"]))
        self.assertFalse(bool(frame.iloc[target]["context_available"]))
        self.assertTrue(pd.isna(frame.iloc[target]["earlier_observed_mode"]))

    def test_private_episode_boundary_does_not_reset_observable_history(self):
        f = WireFixture()
        f.mode_anchor(1)
        f.episode = "SYNTHETIC-EPISODE-B"
        target, _ = f.exchange(5, 1, 0xFF00)
        frame = self.build(f)
        self.assertTrue(bool(frame.iloc[target]["eligible"]))
        self.assertEqual(frame.iloc[target]["earlier_observed_mode"], 1)

    def test_private_metadata_and_truth_changes_cannot_change_features(self):
        f = WireFixture()
        f.mode_anchor(1)
        target, _ = f.exchange(5, 1, 0xFF00)
        before = self.build(f, "private-before")
        for row in f.rows:
            row.update(scenario="SYNTHETIC-CHANGED", step="SECRET-ATTACK-HINT", episode_id="CHANGED",
                       block=999, tid_profile="PRIVATE", anchor_poll_count=999,
                       private_state={"mode": 0, "setpoint": 999}, label="response_injection",
                       pair_state="FAKE", object_role="FAKE")
        f.truth[target]["label"] = "command_injection"
        after = self.build(f, "private-after")
        pd.testing.assert_frame_equal(before[CURRENT + WIRE + CONTEXT], after[CURRENT + WIRE + CONTEXT])
        self.assertEqual(after.iloc[target]["rule_prediction"], "normal")

    def test_tid_reuse_and_equal_pdus_preserve_distinct_occurrences(self):
        f = WireFixture()
        f.mode_anchor(1)
        first, _ = f.exchange(5, 1, 0xFF00, tid=5)
        second, _ = f.exchange(5, 1, 0xFF00, tid=5)
        frame = self.build(f)
        self.assertEqual(len(frame), len(f.rows))
        self.assertEqual(f.rows[first]["adu_hex"], f.rows[second]["adu_hex"])
        self.assertEqual(frame.iloc[first]["rule_prediction"], "normal")
        self.assertEqual(frame.iloc[second]["rule_prediction"], "normal")
        self.assertTrue(bool(frame.iloc[first]["eligible"]))
        self.assertTrue(bool(frame.iloc[second]["eligible"]))

    def test_missing_truth_record_cannot_be_silently_relabelled_normal(self):
        f = WireFixture()
        f.mode_anchor(0)
        target, _ = f.exchange(5, 1, 0xFF00, request_label="command_injection")
        f.truth = [row for row in f.truth if row['event_id'] != f.rows[target]['event_id']]
        with self.assertRaises(ValueError):
            self.build(f)

    def test_supplied_public_map_routes_roles_without_private_object_metadata(self):
        f = WireFixture()
        f.mode_anchor(0)
        target, _ = f.exchange(5, 1, 0xFF00, request_label="command_injection")
        alternate = {"id": "M1", "mode_register": 10, "setpoint_register": 11, "pump_coil": 7}
        for row in f.rows:
            raw = bytes.fromhex(row['adu_hex'])
            pdu = raw[7:]
            fc = pdu[0]
            if row['role'] == 'request' or fc in (5, 6):
                _, address, value = struct.unpack('!BHH', pdu)
                address = 7 if fc in (1, 5) else 10 if address == 0 else 11
                pdu = struct.pack('!BHH', fc, address, value)
                row['pdu_hex'] = pdu.hex()
                row['adu_hex'] = adu(row['tid'], pdu).hex()
            row['object_role'] = 'WRONG_PRIVATE_ROLE'
        folder = self.base/'alternate-map'
        f.write(folder)
        membership = dict(MEMBERSHIP, map='M1')
        by_list = build_run(folder, membership, [PUBLIC_MAPS[0], alternate])
        by_dict = build_run(folder, membership, {'M0':PUBLIC_MAPS[0], 'M1':alternate})
        self.assertEqual(by_list.iloc[target]['current_wire_address'], 7)
        self.assertEqual(by_list.iloc[target]['current_request_object_role'], 3)
        self.assertEqual(by_list.iloc[target]['rule_prediction'], 'command_injection')
        pd.testing.assert_frame_equal(by_list[CURRENT+WIRE+CONTEXT], by_dict[CURRENT+WIRE+CONTEXT])


if __name__ == "__main__":
    unittest.main()
