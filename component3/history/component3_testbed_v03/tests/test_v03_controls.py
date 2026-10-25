"""Additional fail-closed checks for the adopted nuisance/control matrix."""
from pathlib import Path
import tempfile
import unittest
from c3qual.config import RUN_IDS,planned
from c3qual.scenarios import build
from c3qual.validation import validate
from test_qualification import fixture


class V03Controls(unittest.TestCase):
    def test_every_engineering_configuration_has_supported_wire_and_controls(self):
        for run_id in RUN_IDS:
            with self.subTest(run_id=run_id), tempfile.TemporaryDirectory(prefix='c3-v03-SYNTHETIC-') as name:
                path=Path(name)
                fixture(path,run_id=run_id)
                r=validate(path,write=False,allow_synthetic=True)
                self.assertEqual(r['status'],'SYNTHETIC_TEST_PASSED',r)
                self.assertFalse(r['accepted_labels'])
                normal_only=planned(run_id)['recording_mode']=='normal_only'
                self.assertEqual(r['label_counts']['command_injection'],0 if normal_only else 9)
                self.assertEqual(r['label_counts']['response_injection'],0 if normal_only else 18)
                if not normal_only:
                    full=[c for c in r['control_matches'] if c['tid_profile']=='DREUSE']
                    self.assertEqual(len(full),9)
                    self.assertTrue(all(c['full_adu_normal_event_ids'] for c in full))
                    ages={d['intervening_adus'] for d in r['causal_dependencies'] if d['event_id'] in
                          {c['event_id'] for c in r['control_matches']}}
                    self.assertEqual(ages,{0,1,2,3,4,5})

    def test_missing_declared_gap_rejects_even_if_bytes_and_oracle_agree(self):
        def change(episodes):
            ep=next(p for p in episodes if p['family']=='C_BLOCKED_ON' and p['anchor_poll_count']==2 and p['tid_profile']=='DREUSE')
            i=next(i for i,s in enumerate(ep['steps']) if s['step']=='pump_on')
            ep['steps'].pop(i-1)
        with tempfile.TemporaryDirectory(prefix='c3-v03-SYNTHETIC-') as name:
            path=Path(name)
            fixture(path,change_plan=change)
            r=validate(path,write=False,allow_synthetic=True)
            self.assertEqual(r['status'],'FAILED')
            self.assertIn('declared nuisance gap',' '.join(r['errors']))

    def test_missing_crossed_block_is_not_repaired_by_more_rows(self):
        with tempfile.TemporaryDirectory(prefix='c3-v03-SYNTHETIC-') as name:
            path=Path(name)
            fixture(path,change_plan=lambda ep:ep.__setitem__(slice(None),[p for p in ep if p['block']!=8]))
            r=validate(path,write=False,allow_synthetic=True)
            self.assertEqual(r['status'],'FAILED')
            self.assertIn('90 engineering',' '.join(r['errors']))

    def test_delay_bounds_and_separate_rng_channels(self):
        for run_id in RUN_IDS:
            config=planned(run_id)
            episodes=build(config)
            self.assertEqual(len(episodes),90)
            self.assertEqual(len({(p['tid_profile'],p['anchor_poll_count']) for p in episodes}),9)
            lo,hi={'T0':(.008,.015),'T1':(.03,.06),'T2':(.08,.16)}[config['timing']]
            self.assertTrue(all(lo<=s['sleep_seconds']<=hi for p in episodes for s in p['steps']))
            if config['recording_mode']=='normal_only':
                self.assertTrue(all(s['intervention']=='none' for p in episodes for s in p['steps']))

    def test_main_and_old_qualification_ids_are_rejected(self):
        for run_id in ('MX001','Q01','EQ15','../EQ01'):
            with self.assertRaises(ValueError): planned(run_id)
