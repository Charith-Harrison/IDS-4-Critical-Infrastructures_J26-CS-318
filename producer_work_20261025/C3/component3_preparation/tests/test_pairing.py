from component3_preparation.c3prep.pairing import pair_connection


def ev(uid, role="request", tid=1, fc=3, ts=1, unit=1, **kwargs):
    d = dict(event_uid=uid, recording_id="fixture", view_id="fixture", conn_uid="fixture:c1",
             protocol_role=role, mbap_trans_id=tid, func_code=fc, unit_id=unit,
             record_kind="adu", is_exception=False, ts_complete_us=ts, address=0,
             quantity=1, byte_count=2 if role == "response" else None,
             single_value=0, and_mask=None, or_mask=None, parse_status="ok")
    d.update(kwargs)
    return d


def test_concurrent_out_of_order_replies_and_reuse():
    rows = [ev("a", tid=65535), ev("b", tid=0, ts=2),
            ev("c", "response", tid=0, ts=3), ev("d", "response", tid=65535, ts=4),
            ev("e", tid=65535, ts=5), ev("f", "response", tid=65535, ts=6)]
    result = list(pair_connection(rows))
    assert [(r["request_uid"], r["response_uid"]) for r in result] == [("b", "c"), ("a", "d"), ("e", "f")]
    assert result[-1]["transaction_generation"] == 2
    assert result[0]["request_address_audit_only"] == 0


def test_same_identity_outstanding_twice_is_ambiguous():
    result = list(pair_connection([ev("a"), ev("b", ts=2), ev("c", "response", ts=3)]))
    assert result[0]["status"] == "ambiguous_reused_transaction"
    assert result[0]["candidate_request_uids"] == ["a", "b"]
    assert sum(r["status"] == "pending_at_capture_end" for r in result) == 2


def test_mismatch_does_not_consume_legitimate_pending_request():
    result = list(pair_connection([ev("a"), ev("b", "response", fc=4, ts=2),
                                   ev("c", "response", ts=3, is_exception=True, byte_count=None)]))
    assert [r["status"] for r in result] == ["unit_or_function_mismatch", "matched_exception"]


def test_malformed_response_is_related_but_not_normalized():
    result = list(pair_connection([ev("a", fc=1), ev("b", "response", fc=1, ts=2,
                                   parse_status="malformed", byte_count=171)]))
    assert result[0]["status"] == "matched_inconsistent"
    assert "response_byte_count_vs_request_quantity" in result[0]["reasons"]


def test_no_arbitrary_time_cutoff_and_explicit_capacity():
    result = list(pair_connection([ev("a"), ev("b", "response", ts=1000000000)]))
    assert result[0]["status"] == "matched"
    result = list(pair_connection([ev("a"), ev("b", tid=2, ts=2)], max_pending=1, capture_end=False))
    assert [r["status"] for r in result] == ["pending_evicted_capacity", "pending_at_connection_end"]


def test_orphan_and_repeated_response_never_imply_injection():
    result = list(pair_connection([ev("a", "response"), ev("b", ts=2),
                                   ev("c", "response", ts=3), ev("d", "response", ts=4)]))
    assert [r["status"] for r in result] == ["orphan_response", "matched", "late_or_duplicate_response_candidate"]


def test_unpairable_request_retains_request_role():
    result = list(pair_connection([ev("a", record_kind="incomplete", mbap_trans_id=None)]))
    assert result[0]["request_uid"] == "a" and result[0]["response_uid"] is None


def test_mask_echo_values_are_checked():
    result = list(pair_connection([ev("a", fc=22, and_mask=0, or_mask=65535),
                                  ev("b", "response", fc=22, ts=2, and_mask=0, or_mask=0)]))
    assert "write_echo_mask_mismatch" in result[0]["reasons"]
