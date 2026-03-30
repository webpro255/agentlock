"""Tests for v1.2 gate integration — MODIFY decision type, DecisionType field."""

from __future__ import annotations

import pytest

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    DecisionType,
    RateLimitConfig,
)
from agentlock.hardening import HardeningConfig, HardeningSignal
from agentlock.schema import ModifyPolicyConfig, TransformationConfig


def _make_gate(
    hardening: bool = True,
    enforce: bool = False,
) -> AuthorizationGate:
    """Build a gate with standard test tools."""
    gate = AuthorizationGate(
        hardening_config=HardeningConfig(enabled=hardening, enforce_at_critical=enforce),
    )
    gate.register_tool("query_database", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin", "support"],
        modify_policy=ModifyPolicyConfig(
            enabled=True,
            transformations=[
                TransformationConfig(field="output", action="redact_pii"),
            ],
        ),
    ))
    gate.register_tool("send_email", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
        modify_policy=ModifyPolicyConfig(
            enabled=True,
            transformations=[
                TransformationConfig(
                    field="to",
                    action="restrict_domain",
                    config={"allowed_domains": ["company.com"]},
                ),
            ],
        ),
    ))
    gate.register_tool("read_file", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["admin", "support"],
        modify_policy=ModifyPolicyConfig(
            enabled=True,
            transformations=[
                TransformationConfig(
                    field="path",
                    action="whitelist_path",
                    config={"allowed_prefixes": ["/data/", "/public/"]},
                ),
            ],
        ),
    ))
    gate.register_tool("lookup_order", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["admin", "support"],
    ))
    return gate


class TestDecisionTypeField:
    """Test that AuthResult.decision is set correctly."""

    def test_allow_decision(self):
        gate = _make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed
        assert result.decision == DecisionType.ALLOW

    def test_deny_decision(self):
        gate = _make_gate()
        result = gate.authorize("lookup_order", user_id="", role="")
        assert not result.allowed
        assert result.decision == DecisionType.DENY

    def test_deny_no_permissions(self):
        gate = _make_gate()
        result = gate.authorize("nonexistent_tool", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.DENY

    def test_allowed_backward_compat(self):
        """AuthResult.allowed still works for existing code."""
        gate = _make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed is True  # backward compat
        assert result.decision == DecisionType.ALLOW


class TestModifyDecision:
    """Test MODIFY decision type in the gate pipeline."""

    def test_modify_decision_when_hardening_active(self):
        gate = _make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        # Push hardening to warning level
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed  # still allowed
        assert result.decision == DecisionType.MODIFY
        assert result.modify_output_fn is not None

    def test_allow_decision_when_no_hardening(self):
        """Without hardening signals, MODIFY doesn't activate (apply_when_hardening_active=True)."""
        gate = _make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed
        # No hardening signals → no modify
        assert result.decision == DecisionType.ALLOW
        assert result.modify_output_fn is None

    def test_modify_output_fn_redacts_pii(self):
        gate = _make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.modify_output_fn is not None

        output = "Email: jane@example.com, SSN: 123-45-6789"
        modified = result.modify_output_fn(output)
        assert "jane@example.com" not in modified
        assert "123-45-6789" not in modified

    def test_no_modify_on_tool_without_policy(self):
        gate = _make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed
        assert result.decision == DecisionType.ALLOW
        assert result.modify_output_fn is None


class TestModifyInExecute:
    """Test that execute() applies the modify_output_fn."""

    def test_execute_applies_modifier(self):
        gate = _make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.token is not None

        def mock_query_database(**kwargs):
            return (
                "Results: [{'name': 'Jane Doe', 'email': 'jane@example.com', "
                "'phone': '555-012-3456', 'ssn': '123-45-6789'}]"
            )

        output = gate.execute(
            "query_database",
            mock_query_database,
            token=result.token,
            modify_output_fn=result.modify_output_fn,
        )
        assert "jane@example.com" not in output
        assert "555-012-3456" not in output
        assert "123-45-6789" not in output
        assert "Jane Doe" in output  # name is not PII by default

    def test_execute_without_modifier_returns_raw(self):
        gate = _make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.token is not None

        def mock_query_database(**kwargs):
            return "Email: jane@example.com"

        output = gate.execute(
            "query_database",
            mock_query_database,
            token=result.token,
        )
        assert "jane@example.com" in output  # no modifier → raw output

    def test_execute_backward_compat_no_modifier_kwarg(self):
        """execute() still works without the modify_output_fn kwarg."""
        gate = _make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.token is not None

        def mock_lookup(**kwargs):
            return "Order #12345: laptop, shipped"

        output = gate.execute("lookup_order", mock_lookup, token=result.token)
        assert output == "Order #12345: laptop, shipped"


class TestModifyWithEnforcement:
    """Test MODIFY + hardening enforcement interaction."""

    def test_enforcement_blocks_before_modify(self):
        """At critical severity with enforcement, tool is blocked — MODIFY doesn't run."""
        gate = _make_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")
        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.DENY
        assert result.modify_output_fn is None


class TestModifyPolicyApplyWhenHardeningActive:
    """Test the apply_when_hardening_active flag."""

    def test_always_modify_when_flag_false(self):
        """When apply_when_hardening_active=False, MODIFY runs even without signals."""
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            modify_policy=ModifyPolicyConfig(
                enabled=True,
                apply_when_hardening_active=False,
                transformations=[
                    TransformationConfig(field="output", action="redact_pii"),
                ],
            ),
        ))
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed
        assert result.decision == DecisionType.MODIFY
        assert result.modify_output_fn is not None


class TestModifyAudit:
    """Test that MODIFY decisions are audited."""

    def test_modify_logged_as_modify_action(self):
        gate = _make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.decision == DecisionType.MODIFY

        records = gate.audit_logger.query(tool_name="query_database")
        modify_records = [r for r in records if r.action == "modify"]
        assert len(modify_records) >= 1


class TestSchemaVersion:
    """Test v1.2 schema version."""

    def test_schema_version_is_1_2(self):
        from agentlock.schema import SCHEMA_VERSION
        assert SCHEMA_VERSION == "1.2"

    def test_permissions_default_version_1_2(self):
        perms = AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        )
        assert perms.version == "1.2"

    def test_v11_permissions_still_valid(self):
        """v1.1 permissions block with explicit version still validates."""
        perms = AgentLockPermissions(
            version="1.1",
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["user"],
        )
        assert perms.version == "1.1"
        assert perms.modify_policy is None

    def test_v10_permissions_still_valid(self):
        """v1.0 permissions block still validates — deny by default."""
        perms = AgentLockPermissions(
            risk_level="low",
            requires_auth=False,
            allowed_roles=["viewer"],
        )
        assert perms.modify_policy is None


class TestDecisionTypeEnum:
    """Test the DecisionType enum."""

    def test_all_values(self):
        assert DecisionType.ALLOW.value == "allow"
        assert DecisionType.DENY.value == "deny"
        assert DecisionType.DEFER.value == "defer"
        assert DecisionType.STEP_UP.value == "step_up"
        assert DecisionType.MODIFY.value == "modify"

    def test_string_enum(self):
        assert str(DecisionType.ALLOW) == "DecisionType.ALLOW"
        assert DecisionType("allow") == DecisionType.ALLOW
