"""v1.5 evidence -- execute() confirms execution (E7).

Before this, a native "allowed" record was a grant of permission and nothing
else: an action that was authorized and never ran, one that ran and failed, and
one that ran and succeeded were indistinguishable in the log.  A reconstruction
could state what the gate permitted and never what the agent actually did, which
is usually the question that matters in an incident involving a successful
attack.

The invariant these tests enforce, in the strongest form available: a backend
that throws on every write, on the attempt only, or on the completion only, must
not break, block, or alter the tool call.  The tool runs, it returns its value,
the caller sees no exception, and the failure to observe is counted rather than
discarded.  An evidence layer that can break the thing it observes is not worth
deploying.
"""

from __future__ import annotations

import pytest

from agentlock import AgentLockPermissions, AuthorizationGate
from agentlock.audit import AuditRecord, InMemoryAuditBackend
from agentlock.exceptions import TokenReplayedError


class ThrowOnActions:
    """A backend that fails writes for the given actions, and records the rest.

    ``fail_actions`` is mutable, so a test can let the AUTHORIZE path write
    normally and then take the backend down before execution.  That is not a
    convenience: the non-fatal invariant is scoped to the EXECUTION path on
    purpose.  On the authorize path a backend failure propagates and no token is
    issued, so the call FAILS CLOSED.  That is the correct polarity and it stays:
    an unrecordable decision should not become an unrecorded permission.  On the
    execution path the decision is already made and the tool is already running
    or has run, so a failure to observe can only ever be a failure to observe.
    """

    def __init__(self, *actions: str) -> None:
        self.fail_actions = set(actions)
        self.records: list[AuditRecord] = []
        self.failed = 0

    def write(self, record: AuditRecord) -> None:
        if "*" in self.fail_actions or record.action in self.fail_actions:
            self.failed += 1
            raise RuntimeError(f"audit backend is down ({record.action})")
        self.records.append(record)

    def query(self, **kwargs: object) -> list[AuditRecord]:
        return list(self.records)


def _perms() -> AgentLockPermissions:
    return AgentLockPermissions(
        risk_level="high", requires_auth=False, allowed_roles=["user"]
    )


def _gate(backend=None):
    backend = backend or InMemoryAuditBackend()
    gate = AuthorizationGate(audit_backend=backend)
    gate.register_tool("send_email", _perms())
    return gate, backend


def _executions(records):
    return [
        r
        for r in records
        if r.action in ("execution_attempted", "execution_completed")
    ]


class TestTheThreeOutcomesAreDistinguishable:
    def test_ran_and_succeeded(self):
        gate, backend = _gate()
        auth = gate.authorize(
            "send_email", user_id="u", role="user", parameters={"to": "bob"}
        )
        result = gate.execute(
            "send_email",
            lambda **p: f"sent to {p['to']}",
            token=auth.token,
            parameters={"to": "bob"},
        )
        assert result == "sent to bob"

        attempt, completed = _executions(backend.records)
        assert attempt.action == "execution_attempted"
        assert attempt.token_id == auth.token.token_id
        assert completed.metadata["status"] == "succeeded"
        assert completed.metadata["attempt_audit_id"] == attempt.audit_id
        assert completed.duration_ms >= 0

    def test_ran_and_failed(self):
        """A failed execution is a THIRD fact, not an absence."""
        gate, backend = _gate()
        auth = gate.authorize("send_email", user_id="u", role="user")

        def boom(**_):
            raise TimeoutError("smtp timeout")

        with pytest.raises(TimeoutError):
            gate.execute("send_email", boom, token=auth.token)

        attempt, completed = _executions(backend.records)
        assert attempt.action == "execution_attempted"
        assert completed.metadata["status"] == "failed"
        assert completed.metadata["error_type"] == "TimeoutError"
        assert completed.metadata["attempt_audit_id"] == attempt.audit_id

    def test_authorized_and_never_attempted(self):
        """The grant exists and no execution record does.  That is now a
        readable fact rather than an ambiguity."""
        gate, backend = _gate()
        gate.authorize("send_email", user_id="u", role="user")

        assert [r.action for r in backend.records] == ["allowed"]
        assert _executions(backend.records) == []

    def test_attempted_and_never_returned_leaves_an_orphan_attempt(self):
        """The crash case, simulated: the attempt record is durable BEFORE the
        tool runs, so a call that never returns still leaves its trace.  This is
        the whole reason the writer is synchronous by default."""
        gate, backend = _gate()
        auth = gate.authorize("send_email", user_id="u", role="user")

        class ProcessDied(BaseException):
            """Not an Exception: stands in for a kill that unwinds the stack."""

        def never_returns(**_):
            raise ProcessDied()

        with pytest.raises(ProcessDied):
            gate.execute("send_email", never_returns, token=auth.token)

        # The attempt was recorded before control left the gate.
        actions = [r.action for r in backend.records]
        assert "execution_attempted" in actions

    def test_a_rejected_token_writes_no_attempt_record(self):
        """Nothing was attempted, so nothing claims it was."""
        gate, backend = _gate()
        auth = gate.authorize("send_email", user_id="u", role="user")
        gate.execute("send_email", lambda **_: "ok", token=auth.token)
        before = len(_executions(backend.records))

        with pytest.raises(TokenReplayedError):
            gate.execute("send_email", lambda **_: "ok", token=auth.token)

        assert len(_executions(backend.records)) == before


class TestTheEvidencePathCannotBreakTheToolCall:
    """Never break, never alter.  Absolute, and enforced here."""

    def _run(self, *fail_actions: str):
        """Authorize with a healthy backend, then take it down before the tool
        runs.  The backend dying mid-flight is the realistic case, and it is the
        one the invariant is about."""
        backend = ThrowOnActions()
        gate = AuthorizationGate(audit_backend=backend)
        gate.register_tool("send_email", _perms())
        auth = gate.authorize(
            "send_email", user_id="u", role="user", parameters={"to": "bob"}
        )
        assert auth.allowed is True

        backend.fail_actions = set(fail_actions)
        result = gate.execute(
            "send_email",
            lambda **p: f"sent to {p['to']}",
            token=auth.token,
            parameters={"to": "bob"},
        )
        return gate, backend, result

    def test_backend_throwing_on_every_write(self):
        gate, backend, result = self._run("*")

        assert result == "sent to bob"
        assert backend.failed == 2  # the attempt and the completion
        assert gate.evidence_write_failures == 2

    def test_backend_throwing_on_the_attempt_write_only(self):
        gate, backend, result = self._run("execution_attempted")

        assert result == "sent to bob"
        assert gate.evidence_write_failures == 1
        # The completion still lands, and honestly cites no attempt id, because
        # there is no attempt record to cite.
        completed = [r for r in backend.records if r.action == "execution_completed"]
        assert len(completed) == 1
        assert completed[0].metadata.get("attempt_audit_id", "") == ""

    def test_backend_throwing_on_the_completion_write_only(self):
        gate, backend, result = self._run("execution_completed")

        assert result == "sent to bob"
        assert gate.evidence_write_failures == 1
        assert [r.action for r in backend.records if r.action.startswith("execution")] == [
            "execution_attempted"
        ]

    def test_a_failing_tool_still_raises_its_own_error_when_audit_is_down(self):
        """The evidence path must not swap out the caller's exception."""
        backend = ThrowOnActions()
        gate = AuthorizationGate(audit_backend=backend)
        gate.register_tool("send_email", _perms())
        auth = gate.authorize("send_email", user_id="u", role="user")
        backend.fail_actions = {"*"}

        def boom(**_):
            raise ValueError("the tool's own error")

        with pytest.raises(ValueError, match="the tool's own error"):
            gate.execute("send_email", boom, token=auth.token)

    def test_the_authorize_path_still_fails_closed_when_audit_is_down(self):
        """Scope check, deliberately asserted.  The non-fatal rule covers the
        EXECUTION path only.  If the backend cannot record a DECISION, the
        decision does not quietly proceed unrecorded: it raises, and no token is
        issued. An unrecordable decision must not become an unrecorded
        permission, and this milestone does not weaken that."""
        backend = ThrowOnActions("*")
        gate = AuthorizationGate(audit_backend=backend)
        gate.register_tool("send_email", _perms())

        with pytest.raises(RuntimeError):
            gate.authorize("send_email", user_id="u", role="user")
