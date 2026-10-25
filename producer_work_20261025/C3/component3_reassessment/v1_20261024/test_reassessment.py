"""Offline checks for bounded evidence diagnostics; no baseline writes."""
from collections import Counter
import struct
import unittest

from bounded_pilot import decode, near_header
from common import OUT, read


def frame(payload, seq=1):
    ethernet=b'\x00'*12+b'\x08\x00'
    ip=bytearray(20);ip[0]=0x45;ip[2:4]=(40+len(payload)).to_bytes(2,'big');ip[9]=6
    ip[12:16]=bytes([185,175,0,3]);ip[16:20]=bytes([185,175,0,4])
    tcp=struct.pack('!HHIIBBHHH',40000,502,seq,1,0x50,0x18,1024,0,0)
    return ethernet+ip+tcp+payload


class AuditTests(unittest.TestCase):
    def test_protocol_valid_zero_and_invalid_coil_stay_distinct(self):
        zero=bytes.fromhex('000500000006010500000000')
        invalid=bytes.fromhex('00050000000601050000ffff')
        result=decode(frame(zero+invalid))['adus']
        self.assertEqual(len(result),2)
        self.assertTrue(result[0]['fc5_value_spec_valid'])
        self.assertEqual(result[0]['address'],0)
        self.assertFalse(result[1]['fc5_value_spec_valid'])
        self.assertEqual(result[1]['word_or_quantity'],65535)

    def test_partial_adu_is_not_invented(self):
        r=decode(frame(bytes.fromhex('0005000000060105')))
        self.assertEqual(r['adus'],[])
        self.assertIn('noncomplete_or_unframed_remaining_hex',r)

    def test_read_reply_values_never_become_wire_address(self):
        data=frame(bytes.fromhex('00050000000701030400000009'))
        data=bytearray(data);data[34:38]=struct.pack('!HH',502,40000)
        a=decode(bytes(data))['adus'][0]
        self.assertNotIn('address',a)
        self.assertEqual(a['raw_register_words'],[0,9])

    def test_structural_seek_requires_three_valid_records(self):
        data=frame(bytes.fromhex('00050000000601050001ff00'))
        rec=struct.pack('<IIII',1678800000,500000,len(data),len(data))+data
        buf=b'X'*24+rec*3
        self.assertEqual(near_header(buf,24,1678799999,1678800001,'<'),24)
        self.assertIsNone(near_header(buf[:24+len(rec)],24,1678799999,1678800001,'<'))

    def test_widening_window_can_destroy_two_sided_uniqueness(self):
        edges=[('a','l1',0),('a','l2',500),('b','l1',600)]
        def unique(t):
            es=[r for r in edges if abs(r[2])<=t]
            a=Counter(r[0] for r in es);b=Counter(r[1] for r in es)
            return {(x,y) for x,y,d in es if a[x]==1 and b[y]==1}
        self.assertEqual(unique(0),{('a','l1')})
        self.assertEqual(unique(1000),set())

    def test_local_review_counts_agree_without_new_labels(self):
        r=read(OUT/'review_reproduction.json')
        self.assertTrue(r['all_checked_counts_agree'])
        c=read(OUT/'cohort_diagnostics.json')
        self.assertEqual([c['command_candidate_sensitivity'][str(t)]['two_sided_unique_candidates'] for t in (0,1000,5000,25000)],[82,400,187,100])
        self.assertEqual(c['views']['scada_ied1a']['labels']['command_injection'],100)

    def test_no_new_split_or_expanded_extraction(self):
        t=read(OUT/'temporal_feasibility.json')
        self.assertTrue(t['no_replacement_split_created'])
        p=read(OUT/'expanded_scope_plan.json')
        self.assertFalse(p['full_expanded_extraction_performed'])
        self.assertFalse(p['labels_transferred_or_changed'])

    def test_all_accepted_source_bytes_and_logs_checked(self):
        r=read(OUT/'identity_byte_log_examples.json')
        self.assertEqual(r['accepted_events_checked'],154)
        self.assertTrue(r['all_154_accepted_original_byte_and_log_checks_pass'])


if __name__=='__main__':
    unittest.main(verbosity=2)
