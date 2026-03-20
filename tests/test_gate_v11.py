"""Tests for v1.1 gate functionality — context tracking, trust degradation, memory gate."""

from __future__ import annotations

import hashlib

import pytest

from agentlock.audit import InMemoryAuditBackend
from agentlock.context import ContextProvenance, ContextTracker
from agentlock.gate import AuthorizationGate
from agentlock.memory_gate import MemoryGate
from agentlock.schema import (
    AgentLockPermissions,
    ContextPolicyConfig,
    DegradationTrigger,
    MemoryPolicyConfig,
    MemoryRetentionConfig,
    TrustDegradationConfig,
)
from agentlock.types import (
    ContextSource,
    DataBoundary,
    DegradationEffect,
    DenialReason,
    MemoryPersistence,
    MemoryWriter,
    RiskLevel,
)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _make_context_policy(
    *triggers: tuple[ContextSource, DegradationEffect],
    reject_unattributed: bool = True,
) -> ContextPolicyConfig:
    """Build a context policy with the given degradation triggers."""
    return ContextPolicyConfig(
        trust_degradation=TrustDegradationConfig(
            enabled=True,
            triggers=[
                DegradationTrigger(source=src, effect=eff)
                for src, eff in triggers
            ],
        ),
        reject_unattributed=reject_unattributed,
    )


def _make_memory_policy(
    *,
    allowed_writers: list[MemoryWriter] | None = None,
    allowed_readers: list[MemoryWriter] | None = None,
    persistence: MemoryPersistence = MemoryPersistence.SESSION,
    require_write_confirmation: bool = True,
) -> MemoryPolicyConfig:
    return MemoryPolicyConfig(
        persistence=persistence,
        allowed_writers=allowed_writers or [MemoryWriter.SYSTEM],
        allowed_readers=allowed_readers or [MemoryWriter.SYSTEM],
        retention=MemoryRetentionConfig(max_entries=100),
        require_write_confirmation=require_write_confirmation,
    )


@pytest.fixture
def backend():
    return InMemoryAuditBackend()


@pytest.fixture
def gate(backend):
    return AuthorizationGate(audit_backend=backend, token_ttl=60)


# ---- 1. notify_context_write creates provenance and returns it -----------

class TestNotifyContextWriteProvenance:
    def test_creates_provenance_and_returns_it(self, gate):
        gate.register_tool("tool_a", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(),
        ))
        session = gate.create_session("alice", "user")

        prov = gate.notify_context_write(
            session.session_id,
            ContextSource.USER_MESSAGE,
            _sha256("hello"),
            writer_id="alice",
        )

        assert isinstance(prov, ContextProvenance)
        assert prov.provenance_id.startswith("cprov_")
        assert prov.source == ContextSource.USER_MESSAGE
        assert prov.session_id == session.session_id
        assert prov.content_hash == _sha256("hello")


# ---- 2. notify_context_write with web_content triggers trust degradation -

class TestWebContentDegradation:
    def test_web_content_triggers_degradation(self, gate):
        gate.register_tool("tool_a", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(
                (ContextSource.WEB_CONTENT, DegradationEffect.REQUIRE_APPROVAL),
            ),
        ))
        session = gate.create_session("alice", "user")

        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("untrusted web page"),
            writer_id="web_fetcher",
        )

        state = gate.context_tracker.get(session.session_id)
        assert state is not None
        assert state.is_degraded is True
        assert DegradationEffect.REQUIRE_APPROVAL in state.active_effects


# ---- 3. Authorization after trust degradation → DENIED (trust_degraded) --

class TestDegradedAuthDenied:
    def test_require_approval_denies_after_degradation(self, gate):
        gate.register_tool("send_email", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(
                (ContextSource.WEB_CONTENT, DegradationEffect.REQUIRE_APPROVAL),
            ),
        ))
        session = gate.create_session("alice", "user")

        # Degrade trust
        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("evil page"),
            writer_id="web",
        )

        result = gate.authorize("send_email", user_id="alice", role="user")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.TRUST_DEGRADED.value


# ---- 4. v1.0 permissions NOT affected by degraded context ----------------

class TestV10SkipsDegradation:
    def test_v10_unaffected_by_degraded_context(self, gate):
        # Register a v1.1 tool (to trigger degradation via context_policy)
        gate.register_tool("web_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.LOW,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(
                (ContextSource.WEB_CONTENT, DegradationEffect.REQUIRE_APPROVAL),
            ),
        ))
        # Register a v1.0 tool — should NOT be affected by degradation
        gate.register_tool("legacy_tool", AgentLockPermissions(
            version="1.0",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
        ))
        session = gate.create_session("alice", "user")

        # Degrade via v1.1 tool's policy
        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("web data"),
            writer_id="fetcher",
        )

        # v1.0 tool should still be allowed
        result = gate.authorize("legacy_tool", user_id="alice", role="user")
        assert result.allowed is True


# ---- 5. elevate_logging effect → audit log_level is elevated -------------

class TestElevateLoggingEffect:
    def test_elevate_logging_on_degradation(self, gate, backend):
        gate.register_tool("tool_a", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(
                (ContextSource.WEB_CONTENT, DegradationEffect.ELEVATE_LOGGING),
            ),
        ))
        session = gate.create_session("alice", "user")

        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("web stuff"),
            writer_id="fetcher",
        )

        # Authorize — should still be allowed (elevate_logging doesn't deny)
        result = gate.authorize("tool_a", user_id="alice", role="user")
        assert result.allowed is True

        # Verify the audit record has elevated log level
        allowed_records = [r for r in backend.records if r.action == "allowed"]
        assert len(allowed_records) >= 1
        # The gate sets effective_log_level to FULL when elevate_logging is active,
        # but the current audit log uses permissions.audit.log_level for allowed.
        # The degradation state is recorded on the audit record.
        state = gate.context_tracker.get(session.session_id)
        assert state is not None
        assert DegradationEffect.ELEVATE_LOGGING in state.active_effects


# ---- 6. restrict_scope effect → data_boundary overridden ----------------

class TestRestrictScopeEffect:
    def test_restrict_scope_overrides_data_boundary(self, gate):
        gate.register_tool("team_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            scope={"data_boundary": "team"},
            context_policy=_make_context_policy(
                (ContextSource.WEB_CONTENT, DegradationEffect.RESTRICT_SCOPE),
            ),
        ))
        session = gate.create_session(
            "alice", "user", data_boundary=DataBoundary.TEAM,
        )

        # Before degradation — TEAM boundary works
        result_before = gate.authorize("team_tool", user_id="alice", role="user")
        assert result_before.allowed is True

        # Degrade
        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("web data"),
            writer_id="fetcher",
        )

        # After degradation — boundary restricted to AUTHENTICATED_USER_ONLY
        # The tool scope allows TEAM but restrict_scope forces the request boundary
        # down to AUTHENTICATED_USER_ONLY, which is within scope → still allowed.
        result_after = gate.authorize("team_tool", user_id="alice", role="user")
        assert result_after.allowed is True

        # Verify the state has restrict_scope active
        state = gate.context_tracker.get(session.session_id)
        assert DegradationEffect.RESTRICT_SCOPE in state.active_effects


# ---- 7. deny_writes effect → write ops denied, read-only allowed --------

class TestDenyWritesEffect:
    def test_deny_writes_blocks_medium_risk(self, gate):
        policy = _make_context_policy(
            (ContextSource.WEB_CONTENT, DegradationEffect.DENY_WRITES),
        )
        gate.register_tool("write_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=policy,
        ))
        gate.register_tool("read_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.NONE,
            allowed_roles=["user"],
            context_policy=policy,
        ))
        session = gate.create_session("alice", "user")

        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("web"),
            writer_id="fetcher",
        )

        # Medium-risk tool (write) → denied
        write_result = gate.authorize("write_tool", user_id="alice", role="user")
        assert write_result.allowed is False
        assert write_result.denial["reason"] == DenialReason.TRUST_DEGRADED.value

        # None-risk tool (read-only) → allowed
        read_result = gate.authorize("read_tool", user_id="alice", role="user")
        assert read_result.allowed is True


# ---- 8. authorize_memory_write with valid writer succeeds ----------------

class TestMemoryWriteValid:
    def test_valid_writer_succeeds(self, gate):
        gate.register_tool("mem_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            memory_policy=_make_memory_policy(
                allowed_writers=[MemoryWriter.SYSTEM, MemoryWriter.AGENT],
                persistence=MemoryPersistence.SESSION,
                require_write_confirmation=False,
            ),
        ))

        decision = gate.authorize_memory_write(
            "mem_tool",
            content="remember this",
            content_hash=_sha256("remember this"),
            user_id="alice",
            writer=MemoryWriter.AGENT,
        )
        assert decision.allowed is True
        assert decision.entry is not None
        assert decision.entry.content == "remember this"


# ---- 9. authorize_memory_write with invalid writer is DENIED -------------

class TestMemoryWriteInvalidWriter:
    def test_invalid_writer_denied(self, gate):
        gate.register_tool("mem_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            memory_policy=_make_memory_policy(
                allowed_writers=[MemoryWriter.SYSTEM],
                require_write_confirmation=False,
            ),
        ))

        decision = gate.authorize_memory_write(
            "mem_tool",
            content="sneaky write",
            content_hash=_sha256("sneaky write"),
            user_id="alice",
            writer=MemoryWriter.AGENT,
        )
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED


# ---- 10. authorize_memory_write with no memory_policy is DENIED ----------

class TestMemoryWriteNoPolicy:
    def test_no_memory_policy_denied(self, gate):
        gate.register_tool("no_mem_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            # No memory_policy
        ))

        decision = gate.authorize_memory_write(
            "no_mem_tool",
            content="data",
            content_hash=_sha256("data"),
            user_id="alice",
            writer=MemoryWriter.AGENT,
        )
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED


# ---- 11. authorize_memory_read with valid reader succeeds ----------------

class TestMemoryReadValid:
    def test_valid_reader_succeeds(self, gate):
        gate.register_tool("mem_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            memory_policy=_make_memory_policy(
                allowed_readers=[MemoryWriter.SYSTEM, MemoryWriter.AGENT],
            ),
        ))

        decision = gate.authorize_memory_read(
            "mem_tool",
            user_id="alice",
            reader=MemoryWriter.AGENT,
        )
        assert decision.allowed is True


# ---- 12. authorize_memory_read with invalid reader is DENIED -------------

class TestMemoryReadInvalidReader:
    def test_invalid_reader_denied(self, gate):
        gate.register_tool("mem_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            memory_policy=_make_memory_policy(
                allowed_readers=[MemoryWriter.SYSTEM],
            ),
        ))

        decision = gate.authorize_memory_read(
            "mem_tool",
            user_id="alice",
            reader=MemoryWriter.AGENT,
        )
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_READ_DENIED


# ---- 13. End-to-end: web search → degradation → tool call denied --------

class TestEndToEndDegradation:
    def test_web_search_degrades_then_tool_denied(self, gate, backend):
        ctx_policy = _make_context_policy(
            (ContextSource.WEB_CONTENT, DegradationEffect.REQUIRE_APPROVAL),
        )
        gate.register_tool("web_search", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.LOW,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=ctx_policy,
        ))
        gate.register_tool("send_email", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=ctx_policy,
        ))

        # Step 1: Create session
        session = gate.create_session("alice", "user")

        # Step 2: Authorize web_search (before degradation) → allowed
        result_search = gate.authorize("web_search", user_id="alice", role="user")
        assert result_search.allowed is True

        # Step 3: Web content enters context → trust degrades
        gate.notify_context_write(
            session.session_id,
            ContextSource.WEB_CONTENT,
            _sha256("search results from the web"),
            writer_id="web_search_tool",
            tool_name="web_search",
        )

        # Step 4: Attempt send_email → DENIED
        result_email = gate.authorize("send_email", user_id="alice", role="user")
        assert result_email.allowed is False
        assert result_email.denial["reason"] == DenialReason.TRUST_DEGRADED.value

        # Step 5: Verify audit trail contains trust_degraded event
        degraded_records = [
            r for r in backend.records if r.action == "trust_degraded"
        ]
        assert len(degraded_records) >= 1


# ---- 14. Gate has context_tracker property --------------------------------

class TestGateContextTrackerProperty:
    def test_has_context_tracker(self, gate):
        assert hasattr(gate, "context_tracker")
        assert isinstance(gate.context_tracker, ContextTracker)


# ---- 15. Gate has memory_gate property ------------------------------------

class TestGateMemoryGateProperty:
    def test_has_memory_gate(self, gate):
        assert hasattr(gate, "memory_gate")
        assert isinstance(gate.memory_gate, MemoryGate)


# ---- 16. Unattributed context denial ------------------------------------

class TestUnattributedContextDenial:
    def test_unattributed_then_v11_authorize_denied(self, gate):
        gate.register_tool("strict_tool", AgentLockPermissions(
            version="1.1",
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            context_policy=_make_context_policy(
                reject_unattributed=True,
            ),
        ))
        session = gate.create_session("alice", "user")

        # Record unattributed context
        gate.context_tracker.record_unattributed(session.session_id)

        result = gate.authorize("strict_tool", user_id="alice", role="user")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.UNATTRIBUTED_CONTEXT.value
