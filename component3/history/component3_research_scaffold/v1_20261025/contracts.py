"""Synthetic-only design checks. No capture reader, feature builder or learner.

These contracts exercise boundaries before the student implements preprocessing.
They are not a real-data admission mechanism or a security sandbox.
"""
from dataclasses import dataclass


class ContractError(ValueError):
    pass


def synthetic(value: str) -> None:
    if not isinstance(value, str) or not value.startswith("SYNTHETIC-"):
        raise ContractError("Only invented SYNTHETIC- identifiers are supported here")


@dataclass(frozen=True)
class ToyEvent:
    recording: str
    connection: str
    ordinal: int
    tid: int

    def __post_init__(self):
        synthetic(self.recording)
        synthetic(self.connection)
        if self.ordinal < 0 or not 0 <= self.tid <= 65535:
            raise ContractError("Invalid toy ordinal or TID")

    @property
    def identity(self):
        # Literal TID 5 may occur many times at different real stream positions.
        return self.recording, self.connection, self.ordinal


def check_earlier_evidence(current: ToyEvent, earlier: ToyEvent | None,
                           unresolved_gap: bool = False) -> str:
    """Check time/connection availability only; infer no process state or label."""
    if unresolved_gap or earlier is None:
        return "ABSTAIN"
    if current.identity[:2] != earlier.identity[:2]:
        return "ABSTAIN"
    if earlier.ordinal >= current.ordinal:
        raise ContractError("Current/future evidence cannot be earlier context")
    return "EARLIER_EVIDENCE_ONLY_NOT_A_CLASSIFICATION"


# Names are explicit contracts, not a feature selection or a produced matrix.
CURRENT_FIELDS = frozenset({
    "current_function", "current_unit", "current_direction", "current_pdu_length",
    "current_wire_address", "current_wire_word", "current_wire_quantity",
})
WIRE_COMPANION_FIELDS = frozenset({
    "current_numeric_tid", "current_source_ip", "current_destination_ip",
    "current_source_port", "current_destination_port",
})
CONTEXT_FIELDS = frozenset({
    "earlier_observed_mode", "earlier_acknowledged_setpoint",
    "paired_request_object_role", "context_available",
})
FORBIDDEN_FIELDS = frozenset({
    "label", "scenario", "step", "episode_id", "run_id", "seed", "block",
    "tid_profile", "anchor_poll_count", "source", "partition", "capture_sha256",
    "private_state", "intervention_flag", "planned_role", "observed_at_ns",
    "event_id", "connection_id", "transaction_index", "stream_offset",
})


def check_predictor_names(names, method: str, role: str) -> None:
    """Reject unknown names as well as known metadata. Do not process values."""
    if method not in {"B", "D", "B-wire", "D-wire"}:
        raise ContractError("Unknown proposed comparison")
    if role not in {"request", "response"}:
        raise ContractError("Unknown observation role")
    allowed = set(CURRENT_FIELDS)
    if method.startswith("D"):
        allowed.update(CONTEXT_FIELDS)
    if method.endswith("-wire"):
        allowed.update(WIRE_COMPANION_FIELDS)
    if role == "response":
        # FC3 reply has no address; FC5/6 echo replies are a separate task.
        allowed.discard("current_wire_address")
        allowed.discard("current_wire_quantity")
    bad = set(names) - allowed
    if bad:
        raise ContractError("Unavailable/metadata/undeclared predictors: " + ", ".join(sorted(bad)))


@dataclass(frozen=True)
class ToyMembership:
    recording: str
    related_group: str
    role: str
    ordered_stream_identity: str

    def __post_init__(self):
        for value in (self.recording, self.related_group, self.ordered_stream_identity):
            synthetic(value)
        if self.role not in {"train", "validation", "final"}:
            raise ContractError("Unknown toy role")


def check_toy_memberships(rows) -> None:
    """Check invented memberships; never allocate an actual recording."""
    recordings, groups, streams = {}, {}, {}
    for row in rows:
        for index, key in ((recordings, row.recording), (groups, row.related_group),
                           (streams, row.ordered_stream_identity)):
            if key in index and index[key] != row.role:
                raise ContractError("Related or copied history crosses roles")
            index[key] = row.role


def check_toy_fit_intent(row: ToyMembership) -> None:
    if row.role != "train":
        raise ContractError("Only training data may fit a future transformation")
