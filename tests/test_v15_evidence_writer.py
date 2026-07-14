"""v1.5 evidence -- the execution writer, and the invariant that governs it.

Never break and never alter are ABSOLUTE, and these tests enforce them: an
evidence layer must never be able to break, or change the result of, the thing
it observes.  A backend that throws must not propagate, and the failure must be
counted and reported out of band rather than swallowed quietly, because a blind
evidence layer that says nothing is worse than one that admits it is blind.

Never block is NOT a property of the gate.  It is a property of the backend a
deployment chooses.  Synchronous is the default because a record that cannot
survive a crash cannot describe one.  The optional async backend does not block,
loses queued records when the process dies, and stamps that weaker semantics
into every record it writes, so a reconstruction reads the limitation out of the
log rather than out of a config file it does not have.
"""

from __future__ import annotations

import logging

from agentlock.audit import (
    AsyncAuditBackend,
    AuditLogger,
    AuditRecord,
    InMemoryAuditBackend,
)


class ThrowingBackend:
    """A backend that fails every write."""

    def __init__(self) -> None:
        self.attempts = 0

    def write(self, record: AuditRecord) -> None:
        self.attempts += 1
        raise RuntimeError("audit backend is down")

    def query(self, **kwargs: object) -> list[AuditRecord]:
        return []


class TestWriterNeverBreaksItsCaller:
    def test_a_throwing_backend_does_not_propagate(self):
        backend = ThrowingBackend()
        audit = AuditLogger(backend=backend)

        result = audit.log_best_effort(tool_name="send_email", action="allowed")

        assert result is None
        assert backend.attempts == 1

    def test_the_failure_is_counted_not_swallowed(self):
        audit = AuditLogger(backend=ThrowingBackend())

        audit.log_execution_attempt(tool_name="send_email")
        audit.log_execution_completion(tool_name="send_email", status="succeeded")

        # A non-zero counter is the deployment's signal that the log is
        # incomplete.  Silent loss is the failure mode this exists to prevent.
        assert audit.evidence_write_failures == 2

    def test_the_failure_is_reported_out_of_band(self, caplog):
        audit = AuditLogger(backend=ThrowingBackend())
        with caplog.at_level(logging.ERROR, logger="agentlock.audit"):
            audit.log_execution_attempt(tool_name="send_email")

        assert any(
            "EVIDENCE WRITE FAILED" in record.message for record in caplog.records
        )

    def test_a_healthy_backend_records_no_failures(self):
        audit = AuditLogger(backend=InMemoryAuditBackend())
        audit.log_execution_attempt(tool_name="send_email")
        assert audit.evidence_write_failures == 0


class TestExecutionRecords:
    def _audit(self):
        backend = InMemoryAuditBackend()
        return AuditLogger(backend=backend), backend

    def test_attempt_and_completion_join_by_id(self):
        audit, backend = self._audit()

        attempt = audit.log_execution_attempt(
            tool_name="send_email", token_id="atk_1", session_id="s1"
        )
        assert attempt is not None
        audit.log_execution_completion(
            tool_name="send_email",
            status="succeeded",
            token_id="atk_1",
            session_id="s1",
            attempt_audit_id=attempt.audit_id,
            duration_ms=12.5,
        )

        started, completed = backend.records
        assert started.action == "execution_attempted"
        assert completed.action == "execution_completed"
        assert completed.metadata["attempt_audit_id"] == attempt.audit_id
        assert completed.metadata["status"] == "succeeded"
        assert completed.token_id == started.token_id == "atk_1"

    def test_failure_is_a_first_class_outcome(self):
        audit, backend = self._audit()
        audit.log_execution_completion(
            tool_name="send_email", status="failed", error_type="TimeoutError"
        )

        record = backend.records[-1]
        assert record.metadata["status"] == "failed"
        assert record.metadata["error_type"] == "TimeoutError"
        assert record.reason == "failed"

    def test_records_stamp_the_writer_mode(self):
        """A reconstruction reads the absence semantics out of the log."""
        audit, backend = self._audit()
        audit.log_execution_attempt(tool_name="send_email")

        record = backend.records[-1]
        assert record.metadata["writer_mode"] == "sync"
        assert record.metadata["durable_before_execution"] is True

    def test_execution_records_carry_no_asserted_classes(self):
        """``tally_observations()`` counts records carrying asserted_classes.
        An execution is not a caller assertion and must not move that tally."""
        audit, backend = self._audit()
        audit.log_execution_attempt(tool_name="send_email")
        audit.log_execution_completion(tool_name="send_email", status="succeeded")

        assert all(
            "asserted_classes" not in (r.metadata or {}) for r in backend.records
        )


class TestAsyncBackendStampsItsWeakerSemantics:
    def test_async_records_say_they_are_not_durable(self):
        inner = InMemoryAuditBackend()
        audit = AuditLogger(backend=AsyncAuditBackend(inner))

        assert audit.writer_mode == "async"
        audit.log_execution_attempt(tool_name="send_email")
        assert audit.backend.flush() is True

        record = inner.records[-1]
        assert record.metadata["writer_mode"] == "async"
        # The honest statement: under this backend, "no attempt record" does
        # NOT mean the action was not attempted.
        assert record.metadata["durable_before_execution"] is False

    def test_a_full_queue_drops_loudly_and_never_raises(self, caplog):
        inner = InMemoryAuditBackend()
        backend = AsyncAuditBackend(inner, max_queue=1)
        # Stall the drain thread so the queue genuinely fills.
        backend._queue.put(AuditRecord(tool_name="filler"))

        with caplog.at_level(logging.ERROR, logger="agentlock.audit"):
            for _ in range(5):
                backend.write(AuditRecord(tool_name="send_email"))

        assert backend.dropped >= 1
        assert any("DROPPED" in r.message for r in caplog.records)

    def test_a_throwing_inner_backend_does_not_kill_the_writer(self):
        backend = AsyncAuditBackend(ThrowingBackend())
        backend.write(AuditRecord(tool_name="send_email"))
        assert backend.flush() is True
        # The worker survived, so the next write is still accepted.
        backend.write(AuditRecord(tool_name="send_email"))
        assert backend.flush() is True
