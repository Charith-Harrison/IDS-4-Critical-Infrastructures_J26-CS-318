"""Small offline software fixtures; these are never research dataset rows."""
from datetime import datetime, timedelta
import json

import pyarrow as pa
import pyarrow.parquet as pq

from component3_preparation.c3prep.labels import run_labels
from component3_preparation.c3prep.logs import SCHEMA, make_row, reconcile_workbook_versions


def test_original_tid_sentinel_is_not_wrapped_and_zero_is_valid():
    rel = "attack/compromised-ied/attack logs/example.csv"
    values = {"Timestamp": "2023-03-23 16:26:51.793", "TargetIP": "185.175.0.2",
              "Attack": "False Data Injection Attack", "TransactionID": "1048575"}
    row = make_row(rel, "source-hash", values, 2)
    assert row["transaction_id"] == 1048575
    assert row["transaction_id_original"] == "1048575"
    assert not row["wire_tid_valid"]
    values["TransactionID"] = "0"
    row = make_row(rel, "source-hash", values, 3)
    assert row["wire_tid_valid"] and row["transaction_id"] == 0
    assert "unknown" in row["timestamp_timezone"]
    assert row["timestamp_original"] == "2023-03-23 16:26:51.793"


def test_xlsx_csv_version_overlap_preserves_full_serial(tmp_path):
    base = "attack/compromised-scada/attack logs/03-21-2023/"
    values = {"Timestamp": "07:40.5", "TargetIP": "185.175.0.8", "Attack": "Recon. Range: 2000", "TransactionID": "0"}
    short = make_row(base + "03-21-2023-1-original.csv", "short-hash", values, 2,
                     eligibility="superseded_time_damaged_csv_version")
    serial = "45006.130330057873"
    rich = make_row(base + "03-21-2023-1-formatted.xlsx", "rich-hash", values, 2,
                    sheet="To IED4C", serial=serial)
    pq.write_table(pa.Table.from_pylist([short, rich], schema=SCHEMA), tmp_path / "logs.parquet")
    result = reconcile_workbook_versions(tmp_path)
    assert result["status"] == "verified_version_overlap"
    assert result["rowwise_non_time_fields_matching"] == 1
    assert short["timestamp_us"] is None
    assert rich["excel_serial_original"] == serial
    assert rich["timestamp_us"] is not None
    assert rich["excel_epoch_us_decimal"] is not None


def test_ambiguous_log_to_multiple_responses_does_not_create_target(tmp_path):
    output = tmp_path
    directory = output / "extraction" / "fixture_ied"
    directory.mkdir(parents=True)
    (directory / "checkpoint.json").write_text(json.dumps({"reconciliation_passed": True}))
    logs, events, pairs = [], [], []
    base = datetime(2023, 3, 23, 16, 0)
    rec = "cic_compromised_ied_march"
    for i in range(1, 5):
        values = {"Timestamp": (base + timedelta(seconds=i)).isoformat(sep=" ", timespec="milliseconds"),
                  "TargetIP": "185.175.0.2", "Attack": "False Data Injection Attack", "TransactionID": str(i)}
        log = make_row("attack/compromised-ied/attack logs/fixture.csv", "hash", values, i+1)
        logs.append(log)
        ts = log["timestamp_us"]
        common = dict(recording_id=rec, view_id="fixture_ied", conn_uid="fixture_connection", record_kind="adu",
                      client_ip="185.175.0.2", server_ip="185.175.0.5", mbap_trans_id=i, func_code=1,
                      address=None, single_value=None, parse_status="ok", reasm_after_gap=False)
        req = dict(common, event_uid=f"req{i}", protocol_role="request", ts_first_us=ts-100_000, ts_complete_us=ts-100_000)
        rsp = dict(common, event_uid=f"rsp{i}", protocol_role="response", ts_first_us=ts+500, ts_complete_us=ts+500)
        events.extend([req, rsp])
        pairs.append(dict(request_uid=req["event_uid"], response_uid=rsp["event_uid"], status="matched", reasons=[]))
        if i == 4:
            events.append(dict(rsp, event_uid="ambiguous_rsp4", ts_first_us=ts+1000, ts_complete_us=ts+1000))
    pq.write_table(pa.Table.from_pylist(logs, schema=SCHEMA), output / "logs.parquet")
    pq.write_table(pa.Table.from_pylist(events), directory / "events.parquet")
    pq.write_table(pa.Table.from_pylist(pairs), directory / "pairs.parquet")
    conn_schema = pa.schema([("conn_uid", pa.string()), ("retrans_conflicts", pa.int32()), ("unverified_retrans_segments", pa.int32())])
    pq.write_table(pa.Table.from_pylist([], schema=conn_schema), directory / "connections.parquet")
    result = run_labels(output)
    annotations = {r["event_uid"]: r for r in pq.read_table(directory / "annotations.parquet").to_pylist()}
    assert sum(r["component_label"] == "response_injection" for r in annotations.values()) == 3
    assert annotations["rsp4"]["component_label"] is None
    assert annotations["ambiguous_rsp4"]["component_label"] is None
    assert annotations["rsp4"]["annotation_state"] == "unknown_or_ambiguous"
    assert result["views"]["fixture_ied"]["counts"]["events"] == len(events)
    assert result["signature_match_states"]["accepted_core_mechanism_event_evidence"] == 3
