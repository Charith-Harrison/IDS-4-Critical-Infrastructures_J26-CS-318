"""Adversarial SYNTHETIC fixtures, never research traffic or training data."""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from c3lab.capture_validation import validate_capture


CLIENT_PORT = 41000
SERVER_PORT = 15020


def adu(tid, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def packet(source, destination, sequence, payload=b"", flags=16, linktype=1, fragment=0):
    ip = bytes((0x45, 0)) + struct.pack("!HHH", 40 + len(payload), 1, fragment) + bytes((64, 6)) + b"\0\0" + b"\x7f\0\0\x01" * 2
    tcp = struct.pack("!HHIIBBHHH", source, destination, sequence & 0xFFFFFFFF, 0, 0x50, flags, 65535, 0, 0)
    if linktype == 1:
        header = b"\0" * 12 + b"\x08\0"
    elif linktype == 113:
        header = b"\0" * 14 + b"\x08\0"
    else:
        header = b"\x08\0" + b"\0" * 18
    return header + ip + tcp + payload


def write_pcap(path, frames, linktype=1, endian="<", nanoseconds=False, truncate=False):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    with path.open("wb") as stream:
        stream.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
        for number, frame in enumerate(frames):
            stream.write(struct.pack(endian + "IIII", 1, number * 100, len(frame), len(frame) + int(truncate)))
            stream.write(frame)


def jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def fixture(folder, segments=None, linktype=1, endian="<", nanoseconds=False,
            client_base=10001, server_base=20001, truncate=False):
    """Four fake-fixture transactions covering normal and both interventions."""
    state = {"mode": 0, "setpoint": 50, "coil": 0}
    ledger, audit = [], []
    offsets = {"client_to_server": 0, "server_to_client": 0}
    operations = [(6, 0, 0), (5, 1, 0xFF00), (6, 1, 80), (3, 1, 1)]
    for tid, (fc, address, value) in enumerate(operations, 1):
        pdu = struct.pack("!BHH", fc, address, value)
        request = adu(tid, pdu)
        before = dict(state)
        if fc == 5:
            state["coil"] = 1
        if fc == 6:
            state["mode" if address == 0 else "setpoint"] = value
        genuine = adu(tid, b"\x03\x02\x00\x50" if fc == 3 else pdu)
        response = adu(tid, b"\x03\x02\x00\x14") if fc == 3 else genuine
        audit.append({"tid": tid, "unit": 1, "request_adu_hex": request.hex(),
                      "expected_response_adu_hex": genuine.hex(), "wire_response_adu_hex": response.hex(),
                      "response_overridden": fc == 3,
                      **{key + "_before": val for key, val in before.items()},
                      **{key + "_after": val for key, val in state.items()}})
        for role, direction, raw in (("request", "client_to_server", request), ("response", "server_to_client", response)):
            label = "command_injection" if role == "request" and fc == 5 else \
                    "response_injection" if role == "response" and fc == 3 else "normal"
            ledger.append({"event_id": "fixture-" + str(len(ledger)), "run_id": "SYNTHETIC_TEST_ONLY",
                           "episode_id": "fixture", "scenario": "synthetic_test_fixture", "label": label,
                           "role": role, "tid": tid, "unit": 1, "adu_hex": raw.hex(), "pdu_hex": raw[7:].hex(),
                           "direction": direction, "stream_offset": offsets[direction],
                           "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                           "source_port": CLIENT_PORT if role == "request" else SERVER_PORT,
                           "destination_port": SERVER_PORT if role == "request" else CLIENT_PORT,
                           "observed_at_ns": len(ledger)})
            offsets[direction] += len(raw)
    jsonl(folder / "application_ledger.jsonl", ledger)
    jsonl(folder / "server_audit.jsonl", audit)
    (folder / "run_manifest.json").write_text(json.dumps({"status": "CAPTURE_COLLECTED", "capture_required": True,
                                                         "capture_exit_code": 0, "run_id": "SYNTHETIC_TEST_ONLY",
                                                         "purpose": "FEASIBILITY_PILOT_NOT_TRAINING_DATASET"}), encoding="utf-8")
    (folder / "capture.log").write_text("tcpdump test fixture\n0 packets dropped by kernel\n", encoding="utf-8")
    streams = {direction: b"".join(bytes.fromhex(row["adu_hex"]) for row in ledger if row["direction"] == direction)
               for direction in offsets}
    if segments is None:
        segments = [("client_to_server", 0, streams["client_to_server"]),
                    ("server_to_client", 0, streams["server_to_client"])]
    elif callable(segments):
        segments = segments(streams)
    frames = [packet(CLIENT_PORT, SERVER_PORT, client_base - 1, flags=2, linktype=linktype),
              packet(SERVER_PORT, CLIENT_PORT, server_base - 1, flags=18, linktype=linktype)]
    for direction, offset, data in segments:
        source, destination, base = (CLIENT_PORT, SERVER_PORT, client_base) if direction == "client_to_server" else \
                                     (SERVER_PORT, CLIENT_PORT, server_base)
        frames.append(packet(source, destination, base + offset, data, linktype=linktype))
    write_pcap(folder / "capture.pcap", frames, linktype, endian, nanoseconds, truncate)
    return ledger, audit, streams, frames


class CaptureValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c3-synthetic-capture-tests-")
        self.folder = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def assertFailed(self, report):
        self.assertEqual(report["status"], "FAILED", report)
        self.assertFalse((self.folder / "verified_labels.jsonl").exists())
        self.assertTrue((self.folder / "validation_report.json").exists())

    def test_exact_capture_all_labels_and_byte_lineage(self):
        fixture(self.folder)
        report = validate_capture(self.folder)
        self.assertEqual(report["status"], "PASSED", report)
        self.assertEqual(report["label_counts"], {"normal": 6, "command_injection": 1, "response_injection": 1})
        rows = [json.loads(line) for line in (self.folder / "verified_labels.jsonl").read_text().splitlines()]
        capture = (self.folder / "capture.pcap").read_bytes()
        for row in rows:
            raw = bytes.fromhex(row["adu_hex"])
            recovered = bytearray(len(raw))
            for ref in row["frame_byte_references"]:
                start, length = ref["pcap_file_byte_offset"], ref["length"]
                recovered[ref["message_byte_offset"]:ref["message_byte_offset"] + length] = capture[start:start + length]
            self.assertEqual(bytes(recovered), raw)

    def test_segmentation_out_of_order_coalescing_and_exact_retransmission(self):
        def segments(streams):
            client, server = streams.values()
            return [("client_to_server", 5, client[5:]), ("server_to_client", 0, server),
                    ("client_to_server", 0, client[:5]), ("client_to_server", 0, client[:8])]
        fixture(self.folder, segments)
        report = validate_capture(self.folder)
        self.assertEqual(report["status"], "PASSED", report)
        self.assertEqual(report["capture_statistics"]["retransmitted_payload_bytes"], 8)

    def test_sequence_wraparound(self):
        fixture(self.folder, client_base=0xFFFFFFFA, server_base=0xFFFFFFF0)
        self.assertEqual(validate_capture(self.folder)["status"], "PASSED")

    def test_supported_linktypes_endianness_and_nanoseconds(self):
        for linktype, endian, nanoseconds in ((113, ">", False), (276, "<", True)):
            with self.subTest(linktype=linktype):
                fixture(self.folder, linktype=linktype, endian=endian, nanoseconds=nanoseconds)
                self.assertEqual(validate_capture(self.folder)["status"], "PASSED")

    def test_gap_rejects(self):
        fixture(self.folder, lambda streams: [(direction, 1, raw[1:]) for direction, raw in streams.items()])
        self.assertFailed(validate_capture(self.folder))

    def test_conflicting_overlap_rejects(self):
        def segments(streams):
            rows = [(direction, 0, raw) for direction, raw in streams.items()]
            rows.append(("client_to_server", 0, bytes((streams["client_to_server"][0] ^ 1,))))
            return rows
        fixture(self.folder, segments)
        self.assertFailed(validate_capture(self.folder))

    def test_extra_unlogged_bytes_reject(self):
        fixture(self.folder, lambda streams: [(direction, 0, raw + b"\x00") for direction, raw in streams.items()])
        self.assertFailed(validate_capture(self.folder))

    def test_truncated_packet_rejects(self):
        fixture(self.folder, truncate=True)
        self.assertFailed(validate_capture(self.folder))

    def test_missing_syn_rejects(self):
        _, _, _, frames = fixture(self.folder)
        write_pcap(self.folder / "capture.pcap", frames[1:])
        self.assertFailed(validate_capture(self.folder))

    def test_nonzero_kernel_drops_rejects(self):
        fixture(self.folder)
        (self.folder / "capture.log").write_text("1 packets dropped by kernel\n")
        self.assertFailed(validate_capture(self.folder))

    def test_fragmentation_rejects(self):
        _, _, _, frames = fixture(self.folder)
        frames[-1] = packet(SERVER_PORT, CLIENT_PORT, 20001, b"x", fragment=0x2000)
        write_pcap(self.folder / "capture.pcap", frames)
        self.assertFailed(validate_capture(self.folder))

    def test_incomplete_pcap_record_rejects(self):
        fixture(self.folder)
        path = self.folder / "capture.pcap"
        path.write_bytes(path.read_bytes()[:-1])
        self.assertFailed(validate_capture(self.folder))

    def test_missing_capture_rejects(self):
        fixture(self.folder)
        (self.folder / "capture.pcap").rename(self.folder / "capture.fixture-unavailable")
        self.assertFailed(validate_capture(self.folder))

    def test_intervention_flag_disagrees_with_wire_rejects(self):
        _, audit, _, _ = fixture(self.folder)
        audit[-1]["response_overridden"] = False
        jsonl(self.folder / "server_audit.jsonl", audit)
        self.assertFailed(validate_capture(self.folder))

    def test_false_attack_label_rejects(self):
        ledger, _, _, _ = fixture(self.folder)
        ledger[0]["label"] = "command_injection"
        jsonl(self.folder / "application_ledger.jsonl", ledger)
        self.assertFailed(validate_capture(self.folder))

    def test_false_oracle_state_rejects(self):
        _, audit, _, _ = fixture(self.folder)
        audit[1]["mode_before"] = 1
        jsonl(self.folder / "server_audit.jsonl", audit)
        self.assertFailed(validate_capture(self.folder))

    def test_mutated_payload_rejects(self):
        _, _, _, frames = fixture(self.folder)
        frames[-1] = frames[-1][:-1] + bytes((frames[-1][-1] ^ 1,))
        write_pcap(self.folder / "capture.pcap", frames)
        self.assertFailed(validate_capture(self.folder))

    def test_failed_revalidation_quarantines_prior_verified_labels(self):
        fixture(self.folder)
        self.assertEqual(validate_capture(self.folder)["status"], "PASSED")
        before = (self.folder / "verified_labels.jsonl").read_bytes()
        (self.folder / "capture.log").write_text("7 packets dropped by kernel\n")
        report = validate_capture(self.folder)
        self.assertFailed(report)
        self.assertEqual((self.folder / report["quarantined_previous_labels"]).read_bytes(), before)

    def test_smoke_manifest_cannot_produce_verified_labels(self):
        fixture(self.folder)
        (self.folder / "run_manifest.json").write_text(json.dumps({"status": "SMOKE_ONLY_NO_PCAP", "capture_required": False}))
        self.assertFailed(validate_capture(self.folder))


if __name__ == "__main__":
    unittest.main()
