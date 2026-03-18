"""Tests for agentlock.decorators — @agentlock decorator."""

from __future__ import annotations

import pytest

from agentlock.audit import InMemoryAuditBackend
from agentlock.decorators import agentlock
from agentlock.exceptions import DeniedError
from agentlock.gate import AuthorizationGate


@pytest.fixture
def gate():
    return AuthorizationGate(audit_backend=InMemoryAuditBackend())


# ---- Basic functionality --------------------------------------------------

class TestDecoratorBasics:
    def test_decorated_function_requires_user_id_and_role(self, gate):
        @agentlock(gate, allowed_roles=["user"])
        def my_tool(msg: str = "") -> str:
            return f"got {msg}"

        # Without _user_id / _role → denied (empty user = unauthenticated)
        with pytest.raises(DeniedError):
            my_tool(msg="hi")

    def test_denied_when_role_doesnt_match(self, gate):
        @agentlock(gate, allowed_roles=["admin"])
        def restricted_tool() -> str:
            return "secret"

        with pytest.raises(DeniedError):
            restricted_tool(_user_id="alice", _role="user")

    def test_allowed_when_role_matches(self, gate):
        @agentlock(gate, allowed_roles=["admin"])
        def admin_tool() -> str:
            return "admin_data"

        result = admin_tool(_user_id="alice", _role="admin")
        assert result == "admin_data"

    def test_parameters_forwarded(self, gate):
        @agentlock(gate, allowed_roles=["user"])
        def echo(x: int = 0, y: int = 0) -> int:
            return x + y

        result = echo(x=3, y=4, _user_id="alice", _role="user")
        assert result == 7


# ---- Rate limiting through decorator -------------------------------------

class TestDecoratorRateLimit:
    def test_rate_limiting_works(self, gate):
        @agentlock(
            gate,
            allowed_roles=["user"],
            rate_limit={"max_calls": 2, "window_seconds": 60},
        )
        def limited_fn() -> str:
            return "ok"

        assert limited_fn(_user_id="alice", _role="user") == "ok"
        assert limited_fn(_user_id="alice", _role="user") == "ok"
        with pytest.raises(DeniedError):
            limited_fn(_user_id="alice", _role="user")


# ---- functools.wraps preserves metadata -----------------------------------

class TestDecoratorMetadata:
    def test_preserves_function_name(self, gate):
        @agentlock(gate, allowed_roles=["user"])
        def my_special_tool() -> str:
            """My docstring."""
            return "ok"

        assert my_special_tool.__name__ == "my_special_tool"
        assert my_special_tool.__doc__ == "My docstring."

    def test_agentlock_attributes(self, gate):
        @agentlock(gate, allowed_roles=["user"], name="custom_name")
        def tool_fn() -> str:
            return "ok"

        assert tool_fn._agentlock_tool_name == "custom_name"
        assert tool_fn._agentlock_permissions is not None

    def test_tool_registered_with_gate(self, gate):
        @agentlock(gate, allowed_roles=["user"])
        def auto_registered() -> str:
            return "ok"

        assert "auto_registered" in gate.registered_tools

    def test_custom_name_registered(self, gate):
        @agentlock(gate, allowed_roles=["user"], name="overridden")
        def original_name() -> str:
            return "ok"

        assert "overridden" in gate.registered_tools
        assert "original_name" not in gate.registered_tools


# ---- Permissions object passthrough ---------------------------------------

class TestDecoratorPermissionsPassthrough:
    def test_pre_built_permissions(self, gate):
        from agentlock.schema import AgentLockPermissions
        from agentlock.types import RiskLevel

        perms = AgentLockPermissions(
            risk_level=RiskLevel.LOW,
            requires_auth=True,
            allowed_roles=["viewer"],
        )

        @agentlock(gate, permissions=perms)
        def view_tool() -> str:
            return "data"

        result = view_tool(_user_id="alice", _role="viewer")
        assert result == "data"

    def test_risk_level_none_allows_anonymous(self, gate):
        @agentlock(gate, risk_level="none", requires_auth=False)
        def public_tool() -> str:
            return "public"

        result = public_tool()
        assert result == "public"
