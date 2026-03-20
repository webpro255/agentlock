"""Tests for v1.0 backward compatibility with v1.1."""

from __future__ import annotations

from agentlock.gate import AuthorizationGate
from agentlock.schema import (
    SCHEMA_VERSION,
    AgentLockPermissions,
    ContextPolicyConfig,
    MemoryPolicyConfig,
    ToolDefinition,
)
from agentlock.types import (
    ContextAuthority,
    ContextSource,
    DegradationEffect,
    DenialReason,
    MemoryPersistence,
    MemoryWriter,
    RiskLevel,
)

# ---- Helpers ----------------------------------------------------------------

def _v10_permissions(**overrides) -> AgentLockPermissions:
    """Build a v1.0-style permissions block (no context_policy, no memory_policy)."""
    defaults = {
        "version": "1.0",
        "risk_level": "medium",
        "requires_auth": True,
        "allowed_roles": ["user"],
    }
    defaults.update(overrides)
    return AgentLockPermissions(**defaults)


# ---- v1.0 document parsing --------------------------------------------------

class TestV10Parsing:
    def test_v10_document_parses_successfully(self):
        """A v1.0 document (version='1.0', no context/memory policy) parses."""
        perms = AgentLockPermissions(
            version="1.0",
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        )
        assert perms.version == "1.0"
        assert perms.risk_level == RiskLevel.MEDIUM
        assert perms.allowed_roles == ["admin"]

    def test_v10_document_has_none_context_policy(self):
        """v1.0 documents have context_policy=None."""
        perms = _v10_permissions()
        assert perms.context_policy is None

    def test_v10_document_has_none_memory_policy(self):
        """v1.0 documents have memory_policy=None."""
        perms = _v10_permissions()
        assert perms.memory_policy is None


# ---- v1.1 defaults ----------------------------------------------------------

class TestV11Defaults:
    def test_schema_version_default_is_1_1(self):
        """Schema version defaults to '1.1'."""
        assert SCHEMA_VERSION == "1.1"
        perms = AgentLockPermissions(allowed_roles=["user"])
        assert perms.version == "1.1"

    def test_v11_permissions_no_context_policy_defaults_none(self):
        """v1.1 permissions without explicit context_policy default to None."""
        perms = AgentLockPermissions(
            risk_level="low",
            allowed_roles=["viewer"],
        )
        assert perms.version == "1.1"
        assert perms.context_policy is None

    def test_v11_permissions_no_memory_policy_defaults_none(self):
        """v1.1 permissions without explicit memory_policy default to None."""
        perms = AgentLockPermissions(
            risk_level="low",
            allowed_roles=["viewer"],
        )
        assert perms.memory_policy is None


# ---- v1.0 deny-by-default ---------------------------------------------------

class TestV10DenyByDefault:
    def test_v10_empty_roles_deny_by_default(self):
        """v1.0 permissions with empty allowed_roles still deny by default."""
        perms = AgentLockPermissions(version="1.0")
        assert perms.allowed_roles == []
        assert perms.risk_level == RiskLevel.HIGH

    def test_v10_risk_none_auto_allows(self):
        """v1.0 permissions with risk_level='none' still auto-allow."""
        perms = AgentLockPermissions(version="1.0", risk_level="none")
        assert perms.risk_level == RiskLevel.NONE
        assert perms.allowed_roles == []


# ---- Gate with v1.0 permissions ----------------------------------------------

class TestGateV10Compat:
    def test_gate_v10_skips_v11_checks(self):
        """v1.1 gate with v1.0 permissions skips v1.1-specific checks."""
        gate = AuthorizationGate()
        perms = _v10_permissions(allowed_roles=["admin"])
        gate.register_tool("read_data", perms)

        result = gate.authorize("read_data", user_id="alice", role="admin")
        assert result.allowed is True
        assert result.token is not None

    def test_gate_v10_role_denial_works(self):
        """v1.0 permissions deny wrong role the same as before."""
        gate = AuthorizationGate()
        perms = _v10_permissions(allowed_roles=["admin"])
        gate.register_tool("read_data", perms)

        result = gate.authorize("read_data", user_id="bob", role="viewer")
        assert result.allowed is False
        assert result.denial is not None
        assert result.denial["reason"] == DenialReason.INSUFFICIENT_ROLE.value

    def test_gate_v10_no_context_state_works_normally(self):
        """Gate authorize with v1.0 permissions and no context state works."""
        gate = AuthorizationGate()
        perms = _v10_permissions(
            risk_level="low",
            allowed_roles=["user"],
        )
        gate.register_tool("list_items", perms)

        result = gate.authorize("list_items", user_id="alice", role="user")
        assert result.allowed is True
        assert result.token is not None
        assert result.denial is None

    def test_gate_v10_risk_none_auto_allows(self):
        """Gate with v1.0 risk_level='none' auto-allows without auth."""
        gate = AuthorizationGate()
        perms = AgentLockPermissions(version="1.0", risk_level="none")
        gate.register_tool("ping", perms)

        result = gate.authorize("ping")
        assert result.allowed is True

    def test_gate_v10_auth_required_denies_unauthenticated(self):
        """v1.0 permissions still deny unauthenticated calls."""
        gate = AuthorizationGate()
        perms = _v10_permissions(allowed_roles=["user"])
        gate.register_tool("secret", perms)

        result = gate.authorize("secret")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.NOT_AUTHENTICATED.value


# ---- New v1.1 enums exist ---------------------------------------------------

class TestV11EnumsExist:
    def test_denial_reason_trust_degraded(self):
        assert DenialReason.TRUST_DEGRADED == "trust_degraded"

    def test_denial_reason_memory_write_denied(self):
        assert DenialReason.MEMORY_WRITE_DENIED == "memory_write_denied"

    def test_denial_reason_memory_read_denied(self):
        assert DenialReason.MEMORY_READ_DENIED == "memory_read_denied"

    def test_denial_reason_unattributed_context(self):
        assert DenialReason.UNATTRIBUTED_CONTEXT == "unattributed_context"

    def test_context_source_values(self):
        expected = {
            "user_message",
            "system_prompt",
            "tool_output",
            "retrieved_document",
            "web_content",
            "agent_memory",
            "peer_agent",
        }
        actual = {member.value for member in ContextSource}
        assert expected.issubset(actual)

    def test_context_authority_values(self):
        assert ContextAuthority.AUTHORITATIVE == "authoritative"
        assert ContextAuthority.DERIVED == "derived"
        assert ContextAuthority.UNTRUSTED == "untrusted"

    def test_degradation_effect_values(self):
        assert DegradationEffect.REQUIRE_APPROVAL == "require_approval"
        assert DegradationEffect.ELEVATE_LOGGING == "elevate_logging"
        assert DegradationEffect.RESTRICT_SCOPE == "restrict_scope"
        assert DegradationEffect.DENY_WRITES == "deny_writes"

    def test_memory_persistence_values(self):
        assert MemoryPersistence.NONE == "none"
        assert MemoryPersistence.SESSION == "session"
        assert MemoryPersistence.CROSS_SESSION == "cross_session"

    def test_memory_writer_values(self):
        assert MemoryWriter.SYSTEM == "system"
        assert MemoryWriter.USER == "user"
        assert MemoryWriter.AGENT == "agent"
        assert MemoryWriter.TOOL == "tool"


# ---- ToolDefinition with v1.1 block -----------------------------------------

class TestToolDefinitionV11:
    def test_tool_definition_with_context_and_memory_policy(self):
        """ToolDefinition with v1.1 agentlock block validates correctly."""
        tool = ToolDefinition(
            name="smart_search",
            description="Search with context awareness",
            parameters={"query": {"type": "string"}},
            agentlock=AgentLockPermissions(
                version="1.1",
                risk_level="medium",
                requires_auth=True,
                allowed_roles=["user", "admin"],
                context_policy=ContextPolicyConfig(
                    reject_unattributed=True,
                ),
                memory_policy=MemoryPolicyConfig(
                    persistence="session",
                    allowed_writers=[MemoryWriter.SYSTEM, MemoryWriter.AGENT],
                    require_write_confirmation=True,
                ),
            ),
        )
        assert tool.name == "smart_search"
        assert tool.agentlock.version == "1.1"
        assert tool.agentlock.context_policy is not None
        assert tool.agentlock.context_policy.reject_unattributed is True
        assert tool.agentlock.memory_policy is not None
        assert tool.agentlock.memory_policy.persistence == MemoryPersistence.SESSION
        assert MemoryWriter.AGENT in tool.agentlock.memory_policy.allowed_writers

    def test_tool_definition_v10_agentlock_block(self):
        """ToolDefinition with v1.0 agentlock block (no new policies) validates."""
        tool = ToolDefinition(
            name="legacy_tool",
            description="A v1.0 tool",
            agentlock=AgentLockPermissions(
                version="1.0",
                risk_level="low",
                allowed_roles=["user"],
            ),
        )
        assert tool.agentlock.version == "1.0"
        assert tool.agentlock.context_policy is None
        assert tool.agentlock.memory_policy is None

    def test_tool_definition_default_agentlock(self):
        """ToolDefinition with default agentlock uses v1.1."""
        tool = ToolDefinition(name="default_tool")
        assert tool.agentlock.version == "1.1"
