"""Bounded real-loopback integration check, without claiming a captured dataset."""
from collections import Counter
from pathlib import Path
import json
import tempfile
import unittest

from c3lab.pilot import run_pilot
from c3lab.protocol import parse_adu, validate_pdu
from c3lab.explain import explain_run


class PilotIntegrationTests(unittest.TestCase):
    def test_smoke_exercises_real_tcp_without_issuing_verified_labels(self):
        with tempfile.TemporaryDirectory(prefix='c3lab-smoke-') as tmp:
            folder = run_pilot(Path(tmp), seed=9, groups=1, captured=False, delay_range=(0, 0))
            manifest = json.loads((folder/'run_manifest.json').read_text(encoding='utf-8'))
            ledger = [json.loads(x) for x in (folder/'application_ledger.jsonl').read_text(encoding='utf-8').splitlines()]
            audit = [json.loads(x) for x in (folder/'server_audit.jsonl').read_text(encoding='utf-8').splitlines()]
            self.assertEqual(manifest['status'], 'SMOKE_ONLY_NO_PCAP')
            self.assertEqual(len(ledger), 108)
            self.assertEqual(len(audit), 54)
            self.assertEqual(Counter(r['label'] for r in ledger),
                             {'normal':104, 'command_injection':2, 'response_injection':2})
            self.assertFalse((folder/'capture.pcap').exists())
            self.assertFalse((folder/'verified_labels.jsonl').exists())
            for row in ledger:
                validate_pdu(parse_adu(bytes.fromhex(row['adu_hex']))[2], row['role'] == 'request')
            for index in range(0, len(ledger), 2):
                if ledger[index]['label'] == 'command_injection':
                    self.assertEqual(ledger[index+1]['label'], 'normal')
            normal_on = {r['pdu_hex'] for r in ledger if r['label'] == 'normal' and r['role']=='request' and r['pdu_hex']=='050001ff00'}
            attack_on = {r['pdu_hex'] for r in ledger if r['label'] == 'command_injection'}
            self.assertEqual(normal_on, attack_on)
            normal_replies = {r['pdu_hex'] for r in ledger if r['label']=='normal' and r['role']=='response'}
            self.assertTrue(all(r['pdu_hex'] in normal_replies for r in ledger if r['label']=='response_injection'))
            self.assertEqual(sum(r['response_overridden'] for r in audit), 2)
            with self.assertRaisesRegex(ValueError, 'not verified'):
                explain_run(folder)
            self.assertFalse((folder/'verified_labels.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
