"""Read-only viva demonstration of original-CIC event, pair, label and membership."""
import json
from pathlib import Path

import pyarrow.parquet as pq


def first_matching(path, predicate, columns=None):
    for batch in pq.ParquetFile(path).iter_batches(batch_size=20000, columns=columns):
        for row in batch.to_pylist():
            if predicate(row):
                return row
    return None


def printable(value):
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(type(value).__name__)


def main():
    output = Path(__file__).resolve().parents[1] / "output"
    normal = first_matching(output / "pilot/benign/events.parquet", lambda r: r["first_frame"] == 5)
    response = first_matching(output / "extraction/ied_ied1b/events.parquet",
                              lambda r: r["mbap_trans_id"] == 7485 and r["first_frame"] == 531107 and r["first_chunk"] == 0)
    assert normal["reg_values"] == [9] and normal["pdu_bytes"] == bytes.fromhex("03020009")
    assert response["pdu_bytes"] == bytes.fromhex("01abcd")
    uid = response["event_uid"]
    annotation = first_matching(output / "extraction/ied_ied1b/annotations.parquet", lambda r: r["event_uid"] == uid)
    pair = first_matching(output / "extraction/ied_ied1b/pairs.parquet", lambda r: r["response_uid"] == uid)
    membership = first_matching(output / "partitions/candidate_test_membership.parquet", lambda r: r["event_uid"] == uid)
    assert annotation and pair and membership
    assert membership["recording_id"] == response["recording_id"] == pair["recording_id"]
    record_fields = ["event_uid", "recording_id", "view_id", "conn_uid", "first_chunk", "first_frame", "segment_refs",
                     "ts_first_us", "ts_complete_us", "mbap_trans_id", "func_raw", "address", "quantity", "reg_values", "byte_count", "pdu_bytes", "parse_status"]
    result = {
        "stage": "read_only_extraction_evidence_demonstration",
        "normal_value_example": {k: normal[k] for k in record_fields},
        "response_example": {k: response[k] for k in record_fields},
        "pair_audit_only": pair, "evidence_annotation": annotation, "candidate_membership": membership,
        "claims": "Payload value9 is preserved; read response wire address remains null; log-linked malformed reply retains rawbytes. Candidate membership is not a class-complete independent experiment. No model preprocessing executed.",
    }
    (output / "demonstration.json").write_text(json.dumps(result, indent=2, default=printable) + "\n", encoding="utf8")
    print(json.dumps(result, indent=2, default=printable))


if __name__ == "__main__":
    main()
