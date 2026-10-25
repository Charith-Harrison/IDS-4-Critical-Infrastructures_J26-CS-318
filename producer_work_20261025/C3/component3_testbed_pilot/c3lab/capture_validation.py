"""Fail-closed verification of the pilot's actual TCP capture.

Synthetic PCAPs belong only in tests.  Research labels are emitted only after
the collected capture, client ledger, and server intervention audit agree.
This small decoder deliberately supports only this loopback feasibility pilot.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
from collections import Counter
from pathlib import Path


class ValidationError(ValueError):
    pass


def _check(condition, message):
    if not condition:
        raise ValidationError(message)


def _jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                row = json.loads(line)
                _check(isinstance(row, dict), f"{path.name}:{number}: expected object")
                rows.append(row)
    return rows


def _atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _bytes(value, name):
    _check(isinstance(value, str), f"{name}: expected hexadecimal string")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValidationError(f"{name}: invalid hexadecimal") from exc
    return result


def _adu(data, role):
    _check(8 <= len(data) <= 260, "ADU length outside supported limits")
    tid, protocol, length, unit = struct.unpack("!HHHB", data[:7])
    _check(protocol == 0, "nonzero MBAP protocol identifier")
    _check(unit == 1, "pilot supports unit 1 only")
    _check(2 <= length <= 254 and len(data) == length + 6, "MBAP length mismatch")
    pdu = data[7:]
    function = pdu[0]
    _check(function in (1, 3, 5, 6), "unsupported or exception function in pilot")
    if role == "request" or function in (5, 6):
        _check(len(pdu) == 5, "request/write-echo PDU must be five bytes")
        address, value = struct.unpack("!HH", pdu[1:])
        if function in (1, 3):
            _check(value == 1, "pilot only supports single-value reads")
        if function == 5:
            _check(value in (0, 0xFF00), "illegal FC5 coil word")
        _check(address == 1 if function in (1, 5) else address in (0, 1), "address outside declared pilot map")
        if function == 6 and address == 0:
            _check(value in (0, 1), "mode write outside declared policy")
    else:
        _check(len(pdu) >= 2 and pdu[1] == len(pdu) - 2, "response byte-count mismatch")
        if function == 1:
            _check(len(pdu) == 3 and pdu[1] == 1 and pdu[2] in (0, 1), "invalid single-coil reply")
        if function == 3:
            _check(len(pdu) == 4 and pdu[1] == 2, "invalid single-register reply")
    return {"tid": tid, "unit": unit, "function": function, "pdu": pdu}


def _pair(request, response):
    req, reply = _adu(request, "request"), _adu(response, "response")
    _check((req["tid"], req["unit"], req["function"]) ==
           (reply["tid"], reply["unit"], reply["function"]), "request/response identity mismatch")
    if req["function"] in (5, 6):
        _check(req["pdu"] == reply["pdu"], "write acknowledgement does not echo request")
    return req


def _read_pcap(path, port, client_port):
    """Return unique stream bytes and exact frame/file lineage, with no resync."""
    statistics = Counter()
    segments = {"client_to_server": [], "server_to_client": []}
    bases = {}
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    with path.open("rb") as stream:
        header = stream.read(24)
        _check(len(header) == 24 and header[:4] in magics, "missing/unsupported classic PCAP header")
        endian, scale = magics[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        _check((major, minor) == (2, 4), "unsupported PCAP version")
        _check(linktype in (1, 113, 276), "unsupported PCAP link type")
        while True:
            record_offset = stream.tell()
            record = stream.read(16)
            if not record:
                break
            _check(len(record) == 16, "truncated PCAP record header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            _check(captured <= snaplen and captured <= 16 * 1024 * 1024, "invalid captured frame size")
            _check(captured == original, "capture contains truncated packet")
            _check(fraction < (1_000_000 if scale == 1000 else 1_000_000_000), "invalid capture timestamp")
            frame = stream.read(captured)
            _check(len(frame) == captured, "truncated PCAP frame data")
            statistics["frames"] += 1
            number = statistics["frames"]
            if linktype == 1:
                _check(len(frame) >= 14, "short Ethernet header")
                network, offset = struct.unpack("!H", frame[12:14])[0], 14
                while network in (0x8100, 0x88A8):
                    _check(offset <= 22 and len(frame) >= offset + 4, "invalid VLAN header")
                    network = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
                    offset += 4
            elif linktype == 113:
                _check(len(frame) >= 16, "short Linux cooked header")
                network, offset = struct.unpack("!H", frame[14:16])[0], 16
            else:
                _check(len(frame) >= 20, "short Linux cooked v2 header")
                network, offset = struct.unpack("!H", frame[:2])[0], 20
            _check(network != 0x86DD, "IPv6 is outside this IPv4-only pilot")
            if network != 0x0800:
                statistics["non_ipv4_frames"] += 1
                continue
            _check(len(frame) >= offset + 20 and frame[offset] >> 4 == 4, "invalid IPv4 header")
            ihl = (frame[offset] & 15) * 4
            total = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            _check(ihl >= 20 and total >= ihl and len(frame) >= offset + total, "truncated IPv4 packet")
            fragment = struct.unpack("!H", frame[offset + 6:offset + 8])[0]
            _check((fragment & 0x3FFF) == 0, "fragmented IPv4 is unsupported")
            if frame[offset + 9] != 6:
                statistics["non_tcp_frames"] += 1
                continue
            source_ip = ".".join(str(x) for x in frame[offset + 12:offset + 16])
            destination_ip = ".".join(str(x) for x in frame[offset + 16:offset + 20])
            tcp = offset + ihl
            _check(total >= ihl + 20, "short TCP header")
            source, destination, sequence = struct.unpack("!HHI", frame[tcp:tcp + 8])
            tcp_length = (frame[tcp + 12] >> 4) * 4
            _check(tcp_length >= 20 and ihl + tcp_length <= total, "invalid TCP data offset")
            _check(source_ip == destination_ip == "127.0.0.1", "unexpected non-loopback endpoint")
            if (source, destination) == (client_port, port):
                direction = "client_to_server"
            elif (source, destination) == (port, client_port):
                direction = "server_to_client"
            else:
                raise ValidationError("capture contains another TCP connection")
            flags = frame[tcp + 13]
            _check(not flags & 4, "TCP connection was reset")
            if flags & 2:
                if direction == "client_to_server":
                    _check(not flags & 16, "unexpected client SYN+ACK")
                else:
                    _check(bool(flags & 16), "server SYN lacks ACK")
                base = (sequence + 1) & 0xFFFFFFFF
                _check(direction not in bases or bases[direction] == base, "multiple TCP connection generations")
                bases[direction] = base
            payload_offset = tcp + tcp_length
            payload = frame[payload_offset:offset + total]
            statistics["tcp_frames"] += 1
            statistics["observed_tcp_payload_bytes"] += len(payload)
            if payload:
                segments[direction].append({
                    "sequence": (sequence + bool(flags & 2)) & 0xFFFFFFFF,
                    "payload": payload, "frame_number": number,
                    "capture_timestamp_ns": seconds * 1_000_000_000 + fraction * scale,
                    "frame_byte_offset": payload_offset,
                    "pcap_file_byte_offset": record_offset + 16 + payload_offset,
                })
    _check(set(bases) == set(segments), "capture lacks both TCP SYN sequence bases")
    streams, lineage = {}, {}
    for direction, items in segments.items():
        values, refs = {}, {}
        for item in items:
            start = (item["sequence"] - bases[direction]) & 0xFFFFFFFF
            _check(start + len(item["payload"]) <= 16 * 1024 * 1024, "TCP stream span outside pilot limit")
            for index, byte in enumerate(item["payload"]):
                position = start + index
                if position in values:
                    _check(values[position] == byte, "conflicting TCP retransmission/overlap")
                    statistics["retransmitted_payload_bytes"] += 1
                values[position] = byte
                refs.setdefault(position, []).append((item, index))
        _check(values and len(values) == max(values) + 1, "gap or empty TCP stream")
        streams[direction] = bytes(values[index] for index in range(len(values)))
        lineage[direction] = refs
    statistics["unique_tcp_payload_bytes"] = sum(map(len, streams.values()))
    _check(statistics["observed_tcp_payload_bytes"] == statistics["unique_tcp_payload_bytes"] +
           statistics["retransmitted_payload_bytes"], "payload accounting failure")
    return streams, lineage, dict(statistics)


def _message_refs(lineage, start, length):
    """Coalesce per-byte source references, retaining duplicate observations."""
    spans = []
    by_frame = {}
    for relative in range(length):
        for item, index in lineage[start + relative]:
            by_frame.setdefault(item["frame_number"], []).append((relative, item, index))
    for number in sorted(by_frame):
        for relative, item, index in by_frame[number]:
            frame_offset = item["frame_byte_offset"] + index
            if spans and spans[-1]["frame_number"] == number and \
                    spans[-1]["message_byte_offset"] + spans[-1]["length"] == relative and \
                    spans[-1]["frame_byte_offset"] + spans[-1]["length"] == frame_offset:
                spans[-1]["length"] += 1
            else:
                spans.append({"frame_number": number, "capture_timestamp_ns": item["capture_timestamp_ns"],
                              "message_byte_offset": relative, "frame_byte_offset": frame_offset,
                              "pcap_file_byte_offset": item["pcap_file_byte_offset"] + index, "length": 1})
    return spans


def validate_capture(run_dir: Path, port: int = 15020) -> dict:
    """Validate one complete pilot run; emit labels only on full success.

    On any failure existing verified labels are quarantined by renaming within
    the same run directory. Raw inputs and the original manifest are unchanged.
    """
    run_dir = Path(run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": "FAILED", "accepted_labels": False,
              "purpose": "controlled_testbed_feasibility_only", "errors": [],
              "limitations": ["single IPv4 loopback TCP connection only", "single-value FC1/3/5/6 only",
                              "not an independent validation of the physical process or broad ML feasibility",
                              "TCP/IP checksums are not assessed; local capture offload can affect them"]}
    labels_path = run_dir / "verified_labels.jsonl"
    try:
        manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
        _check(manifest.get("status") in ("CAPTURE_AWAITING_VALIDATION", "CAPTURE_COLLECTED"),
               "manifest does not describe a completed capture awaiting validation")
        _check(manifest.get("capture_required") is True and manifest.get("capture_exit_code") == 0,
               "capture was not required or tcpdump did not exit successfully")
        _check(manifest.get("purpose") == "FEASIBILITY_PILOT_NOT_TRAINING_DATASET", "manifest purpose is not the feasibility pilot")
        capture_log = (run_dir / "capture.log").read_text(encoding="utf-8")
        drops = re.findall(r"(?m)^\s*(\d+) packets dropped by kernel\s*$", capture_log)
        _check(len(drops) == 1 and int(drops[0]) == 0, "missing or nonzero tcpdump kernel-drop footer")
        ledger = _jsonl(run_dir / "application_ledger.jsonl")
        audit = _jsonl(run_dir / "server_audit.jsonl")
        _check(ledger and len(ledger) % 2 == 0, "ledger must contain request/response pairs")
        _check(len({row["event_id"] for row in ledger}) == len(ledger), "duplicate event identifiers")
        _check(len({row["run_id"] for row in ledger}) == 1, "multiple ledger run identifiers")
        _check(manifest.get("run_id") == ledger[0]["run_id"], "manifest and ledger run identifiers differ")
        if "observed_application_messages" in manifest:
            _check(manifest["observed_application_messages"] == len(ledger), "manifest/ledger message count differs")
        client_ports = set()
        expected = {"client_to_server": bytearray(), "server_to_client": bytearray()}
        for row in ledger:
            role = row["role"]
            _check(role in ("request", "response"), "unknown ledger role")
            direction = "client_to_server" if role == "request" else "server_to_client"
            _check(row["direction"] == direction, "ledger role/direction disagreement")
            _check(row["source_ip"] == row["destination_ip"] == "127.0.0.1", "ledger endpoint is not loopback")
            client_port = row["source_port"] if role == "request" else row["destination_port"]
            server_port = row["destination_port"] if role == "request" else row["source_port"]
            _check(server_port == port and isinstance(client_port, int) and 0 < client_port < 65536,
                   "ledger endpoint ports disagree")
            client_ports.add(client_port)
            data = _bytes(row["adu_hex"], "ledger ADU")
            decoded = _adu(data, role)
            _check(data[7:] == _bytes(row["pdu_hex"], "ledger PDU"), "ledger PDU/ADU disagreement")
            _check((row["tid"], row["unit"]) == (decoded["tid"], decoded["unit"]), "ledger MBAP identity disagreement")
            _check(row["stream_offset"] == len(expected[direction]), "ledger offsets overlap, skip bytes, or are unordered")
            expected[direction].extend(data)
        _check(len(client_ports) == 1, "ledger contains more than one TCP connection")
        _check(len(audit) * 2 == len(ledger), "server-audit/ledger transaction count differs")
        audit_index = {}
        for row in audit:
            key = (row["tid"], row["unit"])
            _check(key not in audit_index, "server audit reuses transaction identity")
            audit_index[key] = row
        request_keys = set()
        counts = Counter()
        replay_state = {"mode": 0, "setpoint": 50, "coil": 0}
        for index in range(0, len(ledger), 2):
            request, response = ledger[index:index + 2]
            _check(request["role"] == "request" and response["role"] == "response", "ledger pair order is invalid")
            _check(request["episode_id"] == response["episode_id"] and request["scenario"] == response["scenario"],
                   "request/reply episode or scenario differs")
            _check(request["observed_at_ns"] <= response["observed_at_ns"], "reply precedes request in ledger")
            request_data, response_data = _bytes(request["adu_hex"], "request"), _bytes(response["adu_hex"], "response")
            decoded = _pair(request_data, response_data)
            key = (decoded["tid"], decoded["unit"])
            _check(key not in request_keys, "pilot ledger reuses transaction identity")
            request_keys.add(key)
            _check(key in audit_index, "request lacks server intervention audit")
            oracle = audit_index[key]
            _check(_bytes(oracle["request_adu_hex"], "audit request") == request_data, "server audit request differs")
            _check(_bytes(oracle["wire_response_adu_hex"], "audit reply") == response_data, "server audit wire reply differs")
            expected_reply = _bytes(oracle["expected_response_adu_hex"], "audit genuine reply")
            _pair(request_data, expected_reply)
            for field, value in replay_state.items():
                _check(oracle[field + "_before"] == value, "server audit before-state contradicts wire history")
            function, address, value = struct.unpack("!BHH", decoded["pdu"])
            if function == 1:
                genuine_pdu = bytes((1, 1, replay_state["coil"]))
            elif function == 3:
                genuine_pdu = bytes((3, 2)) + struct.pack("!H", replay_state["mode" if address == 0 else "setpoint"])
            else:
                replay_state["coil" if function == 5 else "mode" if address == 0 else "setpoint"] = \
                    int(value == 0xFF00) if function == 5 else value
                genuine_pdu = decoded["pdu"]
            genuine_reply = struct.pack("!HHHB", decoded["tid"], 0, len(genuine_pdu) + 1, decoded["unit"]) + genuine_pdu
            _check(expected_reply == genuine_reply, "server expected reply contradicts declared state machine")
            for field, value in replay_state.items():
                _check(oracle[field + "_after"] == value, "server audit after-state contradicts wire history")
            overridden = response_data != expected_reply
            _check(isinstance(oracle["response_overridden"], bool) and oracle["response_overridden"] == overridden,
                   "server response intervention flag disagrees with bytes")
            command = decoded["function"] == 5 and decoded["pdu"][3:] == b"\xff\x00" and oracle["mode_before"] == 0
            _check(not overridden or decoded["function"] == 3 and address == 1, "response override outside defined setpoint experiment")
            _check(request["label"] == ("command_injection" if command else "normal"), "request label contradicts audited policy")
            _check(response["label"] == ("response_injection" if overridden else "normal"), "response label contradicts audited intervention")
            for row in (request, response):
                counts[row["label"]] += 1
        _check(request_keys == set(audit_index), "unaccounted server-audit transaction")
        pcap_path = run_dir / "capture.pcap"
        streams, lineage, statistics = _read_pcap(pcap_path, port, next(iter(client_ports)))
        for direction in expected:
            _check(streams[direction] == bytes(expected[direction]), "captured stream does not exactly match full ledger: " + direction)
        capture_sha = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
        input_hashes = {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest() for name in
                        ("capture.pcap", "capture.log", "application_ledger.jsonl", "server_audit.jsonl", "run_manifest.json")}
        for name, value in manifest.get("output_sha256", {}).items():
            if name in input_hashes:
                _check(value == input_hashes[name], "recorded output hash differs: " + name)
        verified = []
        for row in ledger:
            result = dict(row)
            result["verification"] = "exact_capture_bytes_and_server_intervention_audit"
            result["capture_sha256"] = capture_sha
            result["capture_file"] = "capture.pcap"
            result["frame_byte_references"] = _message_refs(lineage[row["direction"]], row["stream_offset"],
                                                             len(_bytes(row["adu_hex"], "ADU")))
            verified.append(result)
        temporary = labels_path.with_name(labels_path.name + ".tmp-" + uuid.uuid4().hex)
        with temporary.open("w", encoding="utf-8") as stream:
            for row in verified:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        temporary.replace(labels_path)
        report.update(status="PASSED", accepted_labels=True, message_count=len(ledger),
                      transaction_count=len(audit), label_counts=dict(counts), capture_sha256=capture_sha,
                      capture_statistics=statistics, input_sha256=input_hashes, verified_labels_file=labels_path.name)
    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        if labels_path.exists():
            quarantine = labels_path.with_name("verified_labels.quarantined_" + uuid.uuid4().hex + ".jsonl")
            labels_path.replace(quarantine)
            report["quarantined_previous_labels"] = quarantine.name
    _atomic_json(run_dir / "validation_report.json", report)
    return report
