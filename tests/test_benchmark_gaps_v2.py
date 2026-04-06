"""Tests for benchmark gap fixes: first_call_any_risk + deny_on_block.

Phase 1: first_call_any_risk defer trigger (8 tests)
Phase 2: deny_on_block whitelist escalation (6 tests)
"""

from __future__ import annotations

from agentlock import AgentLockPermissions, AuthorizationGate, DecisionType
from agentlock.defer import DeferralManager
from agentlock.hardening import HardeningConfig
from agentlock.schema import (
    DeferPolicyConfig,
    ModifyPolicyConfig,
    TransformationConfig,
)

# ===========================================================================
# Phase 1: first_call_any_risk
# ===========================================================================


class TestFirstCallAnyRiskUnit:
    """Unit tests for DeferralManager.check_first_call_any_risk."""

    def test_fires_on_first_medium_risk_call(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_any_risk("s1", "lookup_order")
        assert result is not None
        assert result.trigger == "first_call_any_risk"

    def test_fires_on_first_low_risk_call(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_any_risk("s1", "search_contacts")
        assert result is not None
        assert result.trigger == "first_call_any_risk"

    def test_fires_on_first_high_risk_call(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_any_risk("s1", "query_database")
        assert result is not None

    def test_does_not_fire_on_second_call(self):
        mgr = DeferralManager()
        mgr.record_call("s1")
        result = mgr.check_first_call_any_risk("s1", "lookup_order")
        assert result is None

    def test_session_isolation(self):
        mgr = DeferralManager()
        mgr.record_call("s1")
        result = mgr.check_first_call_any_risk("s2", "lookup_order")
        assert result is not None

    def test_default_is_disabled_in_schema(self):
        policy = DeferPolicyConfig(enabled=True)
        assert policy.first_call_any_risk is False


class TestFirstCallAnyRiskGate:
    """Gate integration for first_call_any_risk."""

    def _make_gate(self):
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            defer_policy=DeferPolicyConfig(
                enabled=True,
                first_call_any_risk=True,
            ),
        ))
        return gate

    def test_lookup_order_deferred_on_first_call(self):
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.decision == DecisionType.DEFER
        assert result.denial["reason"] == "first_call_any_risk"

    def test_second_call_allowed(self):
        gate = self._make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        # First call defers
        gate.authorize("lookup_order", user_id="alice", role="admin")
        # Simulate resolution
        gate.deferral_manager.record_call(session.session_id)
        # Second call should succeed
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed


# ===========================================================================
# Phase 2: deny_on_block
# ===========================================================================


class TestDenyOnBlockUnit:
    """Unit tests for blocked_fields in ModifyResult."""

    def test_blocked_path_sets_blocked_fields(self):
        from agentlock.modify import ModifyEngine

        engine = ModifyEngine()
        transforms = [
            TransformationConfig(
                field="path",
                action="whitelist_path",
                config={"allowed_prefixes": ["/data/", "/public/"]},
            ),
        ]
        result = engine.apply_params("read_file", {"path": "./config.json"}, transforms)
        assert result.modified
        assert "path" in result.blocked_fields

    def test_allowed_path_no_blocked_fields(self):
        from agentlock.modify import ModifyEngine

        engine = ModifyEngine()
        transforms = [
            TransformationConfig(
                field="path",
                action="whitelist_path",
                config={"allowed_prefixes": ["/data/", "/public/"]},
            ),
        ]
        result = engine.apply_params("read_file", {"path": "/data/report.csv"}, transforms)
        assert not result.modified
        assert result.blocked_fields == []

    def test_multiple_fields_one_blocked(self):
        from agentlock.modify import ModifyEngine

        engine = ModifyEngine()
        transforms = [
            TransformationConfig(
                field="path",
                action="whitelist_path",
                config={"allowed_prefixes": ["/data/"]},
            ),
        ]
        result = engine.apply_params(
            "read_file",
            {"path": "/etc/passwd", "format": "text"},
            transforms,
        )
        assert "path" in result.blocked_fields

    def test_no_whitelist_no_block(self):
        from agentlock.modify import ModifyEngine

        engine = ModifyEngine()
        transforms = [
            TransformationConfig(field="output", action="redact_pii"),
        ]
        result = engine.apply_params("query_database", {"query": "SELECT *"}, transforms)
        assert result.blocked_fields == []


class TestDenyOnBlockGate:
    """Gate integration: blocked path → DENY instead of MODIFY."""

    def _make_gate(self):
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("read_file", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            modify_policy=ModifyPolicyConfig(
                enabled=True,
                apply_when_hardening_active=False,
                transformations=[
                    TransformationConfig(
                        field="path",
                        action="whitelist_path",
                        config={"allowed_prefixes": ["/data/", "/public/"]},
                    ),
                ],
            ),
        ))
        return gate

    def test_blocked_path_returns_deny(self):
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize(
            "read_file",
            user_id="alice",
            role="admin",
            parameters={"path": "./config.json"},
        )
        assert not result.allowed
        assert result.decision == DecisionType.DENY
        assert result.denial["reason"] == "parameter_blocked"
        assert "path" in result.denial["blocked_fields"]

    def test_allowed_path_returns_allow(self):
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize(
            "read_file",
            user_id="alice",
            role="admin",
            parameters={"path": "/data/report.csv"},
        )
        assert result.allowed
