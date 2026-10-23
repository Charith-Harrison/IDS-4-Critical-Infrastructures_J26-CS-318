# Shared test helpers. Small hand-written packet frames are UNIT-TEST inputs
# only (to exercise edge cases deterministically); they are never written to
# data/ and never used for training. Integration tests use real dev records.
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.loader import REQUIRED_COLUMNS  # noqa: E402


def mk_row(ts, frame, is_req, tid, fc, ref=1, val=1, src="10.0.0.1", dst="10.0.0.2", sport=40000, exc=0):
    """Build one raw packet row with every required column."""
    a, b = (src, dst) if is_req else (dst, src)
    row = {c: 0 for c in REQUIRED_COLUMNS}
    row.update(
        frame_number=frame,
        timestamp=ts,
        frame_len=78,
        src_ip=a,
        dst_ip=b,
        src_port=sport if is_req else 502,
        dst_port=502 if is_req else sport,
        payload_len=12,
        is_request=is_req,
        mbtcp_trans_id=tid,
        mbtcp_len=6,
        mbtcp_unit_id=1,
        modbus_func_code=fc,
        modbus_ref_num=ref,
        modbus_val=val,
        is_exception=exc,
        tcp_flags_ack=1,
        tcp_flags_psh=1,
    )
    return row


@pytest.fixture
def raw_pairs() -> pd.DataFrame:
    """Three requests: one answered, one unanswered, plus one orphan response."""
    rows = [
        mk_row(1000.0, 1, 1, 1, 3, 5),
        mk_row(1000.1, 2, 0, 1, 3, 5),
        mk_row(1001.0, 3, 1, 2, 6, 9, 7),  # request with no response
        mk_row(1002.0, 4, 0, 99, 3, 5),  # orphan response
    ]
    return pd.DataFrame(rows)
