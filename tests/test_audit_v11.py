"""Tests for v1.1 audit record extensions — trust degradation, memory ops, context provenance."""

from __future__ import annotations

from agentlock.audit import (
    AuditLogger,
    AuditRecord,
    InMemoryAuditBackend,
)

# ---- AuditRecord v1.1 defaults -------------------------------------------


class TestAuditRecordV11Defaults:
    def test_v11_fields_have_correct_defaults(self):
        r = AuditRecord()
        assert r.trust_ceiling is None
        assert r.is_trust_degraded is False
        assert r.degradation_effects is None
        assert r.context_provenance_ids is None
        assert r.memory_operation is None
        assert r.memory_entry_id is None

    def test_v11_fields_set_correctly(self):
        r = AuditRecord(
            tool_name="read_file",
            action="allowed",
            trust_ceiling="medium",
            is_trust_degraded=True,
            degradation_effects=["tools_restricted", "requires_confirmation"],
            context_provenance_ids=["ctx-001", "ctx-002"],
            memory_operation="write",
            memory_entry_id="mem-abc-123",
        )
        assert r.trust_ceiling == "medium"
        assert r.is_trust_degraded is True
        assert r.degradation_effects == ["tools_restricted", "requires_confirmation"]
        assert r.context_provenance_ids == ["ctx-001", "ctx-002"]
        assert r.memory_operation == "write"
        assert r.memory_entry_id == "mem-abc-123"


# ---- AuditRecord.to_dict v1.1 serialization ------------------------------


class TestAuditRecordV11ToDict:
    def test_to_dict_omits_none_v11_fields(self):
        r = AuditRecord()
        d = r.to_dict()
        assert "trust_ceiling" not in d
        assert "is_trust_degraded" not in d
        assert "degradation_effects" not in d
        assert "context_provenance_ids" not in d
        assert "memory_operation" not in d
        assert "memory_entry_id" not in d

    def test_to_dict_includes_v11_fields_when_set(self):
        r = AuditRecord(
            trust_ceiling="high",
            is_trust_degraded=True,
            degradation_effects=["tools_restricted"],
            context_provenance_ids=["ctx-001"],
            memory_operation="write",
            memory_entry_id="mem-xyz",
        )
        d = r.to_dict()
        assert d["trust_ceiling"] == "high"
        assert d["is_trust_degraded"] is True
        assert d["degradation_effects"] == ["tools_restricted"]
        assert d["context_provenance_ids"] == ["ctx-001"]
        assert d["memory_operation"] == "write"
        assert d["memory_entry_id"] == "mem-xyz"

    def test_to_dict_omits_is_trust_degraded_when_false(self):
        r = AuditRecord(
            trust_ceiling="low",
            is_trust_degraded=False,
        )
        d = r.to_dict()
        assert d["trust_ceiling"] == "low"
        assert "is_trust_degraded" not in d


# ---- AuditLogger v1.1 fields ---------------------------------------------


class TestAuditLoggerV11:
    def test_log_accepts_and_stores_v11_fields(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="send_email",
            action="allowed",
            trust_ceiling="medium",
            is_trust_degraded=True,
            degradation_effects=["tools_restricted", "scope_limited"],
            context_provenance_ids=["ctx-100", "ctx-200"],
            memory_operation="read",
            memory_entry_id="mem-456",
        )
        assert record.trust_ceiling == "medium"
        assert record.is_trust_degraded is True
        assert record.degradation_effects == ["tools_restricted", "scope_limited"]
        assert record.context_provenance_ids == ["ctx-100", "ctx-200"]
        assert record.memory_operation == "read"
        assert record.memory_entry_id == "mem-456"
        assert len(backend.records) == 1
        assert backend.records[0] is record

    def test_log_trust_degraded_action(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="run_command",
            action="trust_degraded",
            trust_ceiling="low",
            is_trust_degraded=True,
            degradation_effects=["tools_restricted"],
            reason="Untrusted context detected",
        )
        assert record.action == "trust_degraded"
        assert record.trust_ceiling == "low"
        assert record.is_trust_degraded is True
        assert record.degradation_effects == ["tools_restricted"]
        assert record.reason == "Untrusted context detected"

    def test_log_memory_write_action(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="memory_store",
            action="memory_write",
            memory_operation="write",
            memory_entry_id="mem-new-001",
        )
        assert record.action == "memory_write"
        assert record.memory_operation == "write"
        assert record.memory_entry_id == "mem-new-001"

    def test_log_memory_write_denied_action(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="memory_store",
            action="memory_write_denied",
            memory_operation="write",
            reason="Insufficient trust level for memory writes",
        )
        assert record.action == "memory_write_denied"
        assert record.memory_operation == "write"
        assert record.reason == "Insufficient trust level for memory writes"

    def test_log_memory_read_action(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="memory_recall",
            action="memory_read",
            memory_operation="read",
            memory_entry_id="mem-existing-999",
        )
        assert record.action == "memory_read"
        assert record.memory_operation == "read"
        assert record.memory_entry_id == "mem-existing-999"

    def test_log_context_rejected_action(self):
        backend = InMemoryAuditBackend()
        audit_logger = AuditLogger(backend=backend)
        record = audit_logger.log(
            tool_name="context_loader",
            action="context_rejected",
            context_provenance_ids=["ctx-bad-001"],
            reason="Context failed provenance verification",
        )
        assert record.action == "context_rejected"
        assert record.context_provenance_ids == ["ctx-bad-001"]
        assert record.reason == "Context failed provenance verification"


# ---- Backward compatibility -----------------------------------------------


class TestAuditV11BackwardCompat:
    def test_old_records_without_v11_fields_work_with_in_memory_backend(self):
        backend = InMemoryAuditBackend()
        # Simulate a v1.0 record with no v1.1 fields
        old_record = AuditRecord(
            tool_name="legacy_tool",
            user_id="bob",
            action="allowed",
            risk_level="low",
        )
        backend.write(old_record)

        # Write a v1.1 record alongside it
        new_record = AuditRecord(
            tool_name="new_tool",
            user_id="alice",
            action="trust_degraded",
            trust_ceiling="medium",
            is_trust_degraded=True,
        )
        backend.write(new_record)

        # Both records queryable
        all_records = backend.query()
        assert len(all_records) == 2

        # Old record retains defaults
        legacy = backend.query(tool_name="legacy_tool")[0]
        assert legacy.trust_ceiling is None
        assert legacy.is_trust_degraded is False
        assert legacy.degradation_effects is None
        assert legacy.context_provenance_ids is None
        assert legacy.memory_operation is None
        assert legacy.memory_entry_id is None

        # New record has v1.1 fields
        modern = backend.query(tool_name="new_tool")[0]
        assert modern.trust_ceiling == "medium"
        assert modern.is_trust_degraded is True
