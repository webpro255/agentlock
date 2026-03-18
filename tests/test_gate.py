"""Tests for agentlock.gate — AuthorizationGate (integration)."""

from __future__ import annotations

import pytest

from agentlock.audit import InMemoryAuditBackend
from agentlock.exceptions import DeniedError, TokenReplayedError
from agentlock.gate import AuthorizationGate
from agentlock.schema import (
    AgentLockPermissions,
    DataPolicyConfig,
    RateLimitConfig,
    ScopeConfig,
)
from agentlock.types import (
    DataBoundary,
    DataClassification,
    DenialReason,
    RedactionMode,
    RiskLevel,
)


@pytest.fixture
def backend():
    return InMemoryAuditBackend()


@pytest.fixture
def gate(backend):
    return AuthorizationGate(audit_backend=backend, token_ttl=60)


def _register_basic_tool(gate, name="test_tool", roles=None):
    """Helper to register a simple tool."""
    if roles is None:
        roles = ["user", "admin"]
    gate.register_tool(name, AgentLockPermissions(
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=roles,
    ))


# ---- Unregistered tool denied ---------------------------------------------

class TestUnregisteredTool:
    def test_unregistered_tool_denied(self, gate):
        result = gate.authorize("nonexistent_tool", user_id="alice", role="admin")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.NO_PERMISSIONS.value

    def test_unregistered_tool_has_audit_id(self, gate):
        result = gate.authorize("nonexistent_tool", user_id="alice", role="admin")
        assert result.audit_id != ""


# ---- Registered tool with matching role -----------------------------------

class TestRegisteredTool:
    def test_matching_role_allowed(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        assert result.allowed is True

    def test_token_issued_on_allow(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        assert result.token is not None
        assert result.token.tool_name == "test_tool"
        assert result.token.user_id == "alice"

    def test_wrong_role_denied(self, gate):
        _register_basic_tool(gate, roles=["admin"])
        result = gate.authorize("test_tool", user_id="alice", role="user")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.INSUFFICIENT_ROLE.value


# ---- Token consumed on execute -------------------------------------------

class TestTokenConsumed:
    def test_execute_consumes_token(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        assert result.token is not None

        output = gate.execute(
            "test_tool",
            lambda **kw: "hello",
            token=result.token,
        )
        assert output == "hello"

    def test_execute_with_same_token_twice_raises(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        gate.execute("test_tool", lambda **kw: "ok", token=result.token)
        with pytest.raises(TokenReplayedError):
            gate.execute("test_tool", lambda **kw: "ok", token=result.token)


# ---- Rate limiting integrated correctly -----------------------------------

class TestRateLimitIntegration:
    def test_rate_limit_enforced(self, gate):
        gate.register_tool("limited_tool", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            rate_limit=RateLimitConfig(max_calls=2, window_seconds=60),
        ))
        gate.authorize("limited_tool", user_id="alice", role="user")
        gate.authorize("limited_tool", user_id="alice", role="user")
        result = gate.authorize("limited_tool", user_id="alice", role="user")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.RATE_LIMITED.value

    def test_rate_limit_per_user(self, gate):
        gate.register_tool("limited_tool", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            rate_limit=RateLimitConfig(max_calls=1, window_seconds=60),
        ))
        gate.authorize("limited_tool", user_id="alice", role="user")
        # alice is maxed
        result_alice = gate.authorize("limited_tool", user_id="alice", role="user")
        assert result_alice.allowed is False
        # bob is fine
        result_bob = gate.authorize("limited_tool", user_id="bob", role="user")
        assert result_bob.allowed is True


# ---- Session auto-resolves role ------------------------------------------

class TestSessionAutoResolve:
    def test_session_resolves_role(self, gate):
        _register_basic_tool(gate)
        gate.create_session("alice", "user")
        # Omit role — should be resolved from session
        result = gate.authorize("test_tool", user_id="alice")
        assert result.allowed is True
        assert result.token is not None
        assert result.token.role == "user"

    def test_session_resolves_data_boundary(self, gate):
        gate.register_tool("tool", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            scope=ScopeConfig(data_boundary=DataBoundary.TEAM),
        ))
        gate.create_session("alice", "user", data_boundary=DataBoundary.TEAM)
        result = gate.authorize("tool", user_id="alice")
        assert result.allowed is True

    def test_no_session_no_role_denied(self, gate):
        _register_basic_tool(gate)
        # No session, no role => empty role => denied
        result = gate.authorize("test_tool", user_id="alice")
        assert result.allowed is False


# ---- Redaction applied on execute ----------------------------------------

class TestRedactionOnExecute:
    def test_redaction_applied(self, gate):
        gate.register_tool("pii_tool", AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["admin"],
            data_policy=DataPolicyConfig(
                output_classification=DataClassification.MAY_CONTAIN_PII,
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.AUTO,
            ),
        ))
        result = gate.authorize("pii_tool", user_id="alice", role="admin")
        output = gate.execute(
            "pii_tool",
            lambda **kw: "SSN: 123-45-6789",
            token=result.token,
        )
        assert "123-45-6789" not in output
        assert "[REDACTED:ssn]" in output

    def test_no_redaction_when_not_configured(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        output = gate.execute(
            "test_tool",
            lambda **kw: "SSN: 123-45-6789",
            token=result.token,
        )
        # No redaction engine for this tool
        assert "123-45-6789" in output

    def test_redaction_audit_logged(self, gate, backend):
        gate.register_tool("pii_tool", AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["admin"],
            data_policy=DataPolicyConfig(
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.AUTO,
            ),
        ))
        result = gate.authorize("pii_tool", user_id="alice", role="admin")
        gate.execute(
            "pii_tool",
            lambda **kw: "SSN: 123-45-6789",
            token=result.token,
        )
        # Check that a "redacted" audit record was created
        redacted_records = [r for r in backend.records if r.action == "redacted"]
        assert len(redacted_records) == 1


# ---- call() combines authorize + execute ---------------------------------

class TestCall:
    def test_call_succeeds(self, gate):
        _register_basic_tool(gate)
        output = gate.call(
            "test_tool",
            lambda **kw: "result",
            user_id="alice",
            role="user",
        )
        assert output == "result"

    def test_call_denied_raises(self, gate):
        _register_basic_tool(gate, roles=["admin"])
        with pytest.raises(DeniedError):
            gate.call(
                "test_tool",
                lambda **kw: "result",
                user_id="alice",
                role="user",
            )

    def test_call_passes_parameters(self, gate):
        _register_basic_tool(gate)
        output = gate.call(
            "test_tool",
            lambda **kw: kw.get("msg", ""),
            user_id="alice",
            role="user",
            parameters={"msg": "hello"},
        )
        assert output == "hello"

    def test_call_unregistered_raises(self, gate):
        with pytest.raises(DeniedError):
            gate.call(
                "missing_tool",
                lambda **kw: "x",
                user_id="alice",
                role="admin",
            )


# ---- Full end-to-end flow ------------------------------------------------

class TestEndToEnd:
    def test_register_session_authorize_execute_audit(self, gate, backend):
        # 1. Register
        gate.register_tool("e2e_tool", AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["admin"],
            rate_limit=RateLimitConfig(max_calls=10, window_seconds=60),
            data_policy=DataPolicyConfig(
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.AUTO,
            ),
        ))

        # 2. Session
        session = gate.create_session("alice", "admin")
        assert session.user_id == "alice"

        # 3. Authorize
        result = gate.authorize("e2e_tool", user_id="alice")
        assert result.allowed is True
        assert result.token is not None

        # 4. Execute
        output = gate.execute(
            "e2e_tool",
            lambda **kw: "Patient SSN: 111-22-3333",
            token=result.token,
        )
        assert "111-22-3333" not in output
        assert "[REDACTED:ssn]" in output

        # 5. Audit records exist
        assert len(backend.records) >= 2  # allowed + redacted
        allowed = [r for r in backend.records if r.action == "allowed"]
        assert len(allowed) == 1
        assert allowed[0].tool_name == "e2e_tool"
        assert allowed[0].token_id == result.token.token_id


# ---- AuthResult.raise_if_denied ------------------------------------------

class TestAuthResultRaise:
    def test_raise_if_denied_raises_on_denial(self, gate):
        _register_basic_tool(gate, roles=["admin"])
        result = gate.authorize("test_tool", user_id="alice", role="user")
        assert result.allowed is False
        with pytest.raises(DeniedError) as exc_info:
            result.raise_if_denied()
        assert "insufficient_role" in str(exc_info.value)

    def test_raise_if_denied_noop_on_allow(self, gate):
        _register_basic_tool(gate)
        result = gate.authorize("test_tool", user_id="alice", role="user")
        result.raise_if_denied()  # should not raise


# ---- Introspection -------------------------------------------------------

class TestIntrospection:
    def test_registered_tools_list(self, gate):
        _register_basic_tool(gate, name="a")
        _register_basic_tool(gate, name="b")
        assert set(gate.registered_tools) == {"a", "b"}

    def test_get_permissions(self, gate):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.LOW,
            allowed_roles=["user"],
        )
        gate.register_tool("my_tool", perms)
        assert gate.get_permissions("my_tool") is not None
        assert gate.get_permissions("my_tool").risk_level == RiskLevel.LOW

    def test_get_permissions_unknown_returns_none(self, gate):
        assert gate.get_permissions("unknown") is None

    def test_register_from_dict(self, gate):
        gate.register_tool("dict_tool", {
            "risk_level": "low",
            "allowed_roles": ["user"],
        })
        assert gate.get_permissions("dict_tool") is not None
