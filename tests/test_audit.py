"""Tests for agentlock.audit — AuditLogger, backends, and log level filtering."""

from __future__ import annotations

import json
import time

from agentlock.audit import (
    AuditLogger,
    AuditRecord,
    FileAuditBackend,
    InMemoryAuditBackend,
)
from agentlock.types import AuditLogLevel

# ---- AuditRecord ---------------------------------------------------------

class TestAuditRecord:
    def test_defaults(self):
        r = AuditRecord()
        assert r.audit_id.startswith("agentlock-")
        assert r.timestamp > 0
        assert r.tool_name == ""
        assert r.action == ""
        assert r.parameters is None
        assert r.metadata == {}

    def test_fields_set(self):
        r = AuditRecord(
            tool_name="send_email",
            user_id="alice",
            role="admin",
            action="allowed",
            risk_level="high",
        )
        assert r.tool_name == "send_email"
        assert r.user_id == "alice"
        assert r.action == "allowed"

    def test_to_dict_excludes_none_parameters(self):
        r = AuditRecord(parameters=None)
        d = r.to_dict()
        assert "parameters" not in d

    def test_to_dict_includes_parameters_when_set(self):
        r = AuditRecord(parameters={"key": "value"})
        d = r.to_dict()
        assert d["parameters"] == {"key": "value"}

    def test_unique_audit_ids(self):
        r1 = AuditRecord()
        r2 = AuditRecord()
        assert r1.audit_id != r2.audit_id


# ---- InMemoryAuditBackend ------------------------------------------------

class TestInMemoryAuditBackend:
    def test_write_and_query(self):
        backend = InMemoryAuditBackend()
        r = AuditRecord(tool_name="tool_a", user_id="alice", action="allowed")
        backend.write(r)
        results = backend.query()
        assert len(results) == 1
        assert results[0].tool_name == "tool_a"

    def test_query_by_tool_name(self):
        backend = InMemoryAuditBackend()
        backend.write(AuditRecord(tool_name="a", action="allowed"))
        backend.write(AuditRecord(tool_name="b", action="allowed"))
        results = backend.query(tool_name="a")
        assert len(results) == 1
        assert results[0].tool_name == "a"

    def test_query_by_user_id(self):
        backend = InMemoryAuditBackend()
        backend.write(AuditRecord(user_id="alice", action="allowed"))
        backend.write(AuditRecord(user_id="bob", action="denied"))
        results = backend.query(user_id="bob")
        assert len(results) == 1
        assert results[0].user_id == "bob"

    def test_query_by_since(self):
        backend = InMemoryAuditBackend()
        now = time.time()
        backend.write(AuditRecord(timestamp=now - 100, action="old"))
        backend.write(AuditRecord(timestamp=now, action="new"))
        results = backend.query(since=now - 50)
        assert len(results) == 1
        assert results[0].action == "new"

    def test_query_limit(self):
        backend = InMemoryAuditBackend()
        for i in range(10):
            backend.write(AuditRecord(tool_name=f"t{i}"))
        results = backend.query(limit=3)
        assert len(results) == 3

    def test_query_empty(self):
        backend = InMemoryAuditBackend()
        assert backend.query() == []


# ---- FileAuditBackend ----------------------------------------------------

class TestFileAuditBackend:
    def test_write_and_query(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        r = AuditRecord(tool_name="tool_x", user_id="alice", action="allowed")
        backend.write(r)

        results = backend.query()
        assert len(results) == 1
        assert results[0].tool_name == "tool_x"

    def test_file_created(self, tmp_path):
        path = tmp_path / "sub" / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        backend.write(AuditRecord(action="test"))
        assert path.exists()

    def test_query_by_tool_name(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        backend.write(AuditRecord(tool_name="a"))
        backend.write(AuditRecord(tool_name="b"))
        results = backend.query(tool_name="b")
        assert len(results) == 1

    def test_query_by_user_id(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        backend.write(AuditRecord(user_id="alice"))
        backend.write(AuditRecord(user_id="bob"))
        results = backend.query(user_id="alice")
        assert len(results) == 1

    def test_query_empty_file(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        # File does not exist yet
        backend = FileAuditBackend(path=path)
        assert backend.query() == []

    def test_query_limit(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        for i in range(10):
            backend.write(AuditRecord(tool_name=f"t{i}"))
        results = backend.query(limit=5)
        assert len(results) == 5

    def test_append_mode(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        backend.write(AuditRecord(tool_name="first"))
        backend.write(AuditRecord(tool_name="second"))
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_jsonl_format(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = FileAuditBackend(path=path)
        backend.write(AuditRecord(tool_name="check", action="allowed"))
        line = path.read_text().strip()
        data = json.loads(line)
        assert data["tool_name"] == "check"
        assert data["action"] == "allowed"


# ---- AuditLogger log level filtering -------------------------------------

class TestAuditLoggerLevels:
    def test_minimal_strips_identity_and_params(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(
            tool_name="tool",
            user_id="alice",
            role="admin",
            action="allowed",
            parameters={"key": "value"},
            response_summary="some output",
            log_level=AuditLogLevel.MINIMAL,
        )
        assert record.user_id == ""
        assert record.role == ""
        assert record.parameters is None
        assert record.response_summary == ""

    def test_standard_strips_params_but_keeps_identity(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(
            tool_name="tool",
            user_id="alice",
            role="admin",
            action="allowed",
            parameters={"key": "value"},
            response_summary="some output",
            log_level=AuditLogLevel.STANDARD,
        )
        assert record.user_id == "alice"
        assert record.role == "admin"
        assert record.parameters is None
        assert record.response_summary == ""

    def test_full_includes_everything(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(
            tool_name="tool",
            user_id="alice",
            role="admin",
            action="allowed",
            parameters={"key": "value"},
            response_summary="some output",
            log_level=AuditLogLevel.FULL,
            include_parameters=True,
        )
        assert record.user_id == "alice"
        assert record.role == "admin"
        assert record.parameters == {"key": "value"}
        assert record.response_summary == "some output"

    def test_full_without_include_params_omits_params(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(
            tool_name="tool",
            user_id="alice",
            role="admin",
            action="allowed",
            parameters={"key": "value"},
            log_level=AuditLogLevel.FULL,
            include_parameters=False,
        )
        # When include_parameters is False, params not set
        assert record.parameters is None

    def test_log_returns_record(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(tool_name="t", action="allowed")
        assert record.audit_id.startswith("agentlock-")
        assert record.tool_name == "t"

    def test_log_writes_to_backend(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        logger.log(tool_name="t", action="allowed")
        assert len(backend.records) == 1

    def test_query_delegates_to_backend(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        logger.log(tool_name="a", action="allowed")
        logger.log(tool_name="b", action="denied")
        results = logger.query(tool_name="a")
        assert len(results) == 1

    def test_backend_property(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        assert logger.backend is backend

    def test_metadata_included(self):
        backend = InMemoryAuditBackend()
        logger = AuditLogger(backend=backend)
        record = logger.log(
            tool_name="t",
            action="allowed",
            metadata={"source": "test"},
        )
        assert record.metadata == {"source": "test"}
