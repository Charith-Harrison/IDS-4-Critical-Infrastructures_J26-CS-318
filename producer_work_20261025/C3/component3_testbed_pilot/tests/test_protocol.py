import io
import struct
import unittest

from c3lab.protocol import PLCState, make_adu, parse_adu, recv_adu, request, validate_pdu
from c3lab.pilot import build_episodes


class ProtocolTests(unittest.TestCase):
    def test_roundtrip_and_mbap_length(self):
        pdu = request(5, 1, 0xFF00)
        adu = make_adu(65535, pdu)
        self.assertEqual(adu.hex(), 'ffff0000000601050001ff00')
        self.assertEqual(parse_adu(adu), (65535, 1, pdu))

    def test_invalid_output_words_rejected(self):
        for bad in (1, 8, 65535):
            with self.subTest(word=bad), self.assertRaises(ValueError):
                request(5, 1, bad)

    def test_real_zero_preserved_and_setpoint_readback(self):
        state = PLCState()
        state.handle(request(6, 1, 0))
        self.assertEqual(state.handle(request(3, 1, 1)), bytes.fromhex('03020000'))
        state.handle(request(6, 1, 91))
        self.assertEqual(state.handle(request(3, 1, 1)), bytes.fromhex('0302005b'))

    def test_protocol_valid_command_can_violate_declared_policy(self):
        state = PLCState(mode=0)
        pdu = request(5, 1, 0xFF00)
        self.assertEqual(state.handle(pdu), pdu)
        self.assertEqual(state.coil, 1)
        self.assertEqual(state.handle(request(1, 1, 1)), bytes.fromhex('010101'))

    def test_message_boundary_not_socket_recv_boundary(self):
        # Scripted recv fragmentation is a unit fixture, not captured traffic.
        one = make_adu(10, request(3, 1, 1))
        two = make_adu(11, request(5, 1, 0))
        class FragmentedSocket:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)
            def recv(self, size):
                return self.buffer.read(min(size, 2))
        stream = FragmentedSocket(one + two)
        self.assertEqual(recv_adu(stream), one)
        self.assertEqual(recv_adu(stream), two)

    def test_bad_header_and_partial_reply_rejected(self):
        good = make_adu(1, request(3, 1, 1))
        for bad in (good[:-1], good[:2] + b'\x00\x01' + good[4:], good + b'\x00'):
            with self.assertRaises(ValueError):
                parse_adu(bad)
        with self.assertRaises(ValueError):
            validate_pdu(bytes.fromhex('03abcd'), False)

    def test_matched_controls_reuse_target_value_distribution(self):
        episodes = build_episodes(4010, 2)
        self.assertEqual(len(episodes), 12)
        for group in range(2):
            rows = [r for r in episodes if r['group'] == group]
            normal = {r['reported_setpoint'] for r in rows if r['scenario'] == 'normal'}
            malicious = {r['reported_setpoint'] for r in rows if r['scenario'] == 'response_injection'}
            self.assertEqual(normal, malicious)
            self.assertTrue(all(r['actual_setpoint'] != r['reported_setpoint'] for r in rows if r['scenario'] == 'response_injection'))
        self.assertEqual(episodes, build_episodes(4010, 2))
        self.assertNotEqual(episodes, build_episodes(4011, 2))


if __name__ == '__main__':
    unittest.main()
