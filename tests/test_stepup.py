"""Tests for the STEP_UP decision type."""

from __future__ import annotations

import time

import pytest

from agentlock.exceptions import StepUpRequiredError
from agentlock.stepup import StepUpManager, StepUpNotifier, StepUpRequest


class TestStepUpRequest:
    """Test StepUpRequest dataclass."""

    def test_create_request(self):
        r = StepUpRequest(tool_name="query_database", reason="test")
        assert r.request_id.startswith("stepup_")
        assert not r.is_resolved
        assert not r.is_expired

    def test_resolved_request(self):
        r = StepUpRequest(tool_name="query_database")
        r.resolution = "approved"
        assert r.is_resolved

    def test_expired_request(self):
        r = StepUpRequest(
            created_at=time.time() - 300,
            timeout_seconds=120,
        )
        assert r.is_expired


class TestHardeningElevatedHighRisk:
    """Test the hardening_elevated_high_risk trigger."""

    def test_fires_at_elevated_high_risk(self):
        mgr = StepUpManager()
        result = mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "elevated",
        )
        assert result is not None
        assert result.trigger == "hardening_elevated_high_risk"

    def test_fires_at_critical_severity(self):
        mgr = StepUpManager()
        result = mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "critical",
        )
        assert result is not None

    def test_does_not_fire_at_warning(self):
        mgr = StepUpManager()
        result = mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "warning",
        )
        assert result is None

    def test_does_not_fire_for_medium_risk(self):
        mgr = StepUpManager()
        result = mgr.check_hardening_elevated_high_risk(
            "s1", "lookup_order", "medium", "elevated",
        )
        assert result is None

    def test_fires_for_critical_risk_tool(self):
        mgr = StepUpManager()
        result = mgr.check_hardening_elevated_high_risk(
            "s1", "delete_records", "critical", "elevated",
        )
        assert result is not None


class TestMultiPiiToolSession:
    """Test the multi_pii_tool_session trigger."""

    def test_fires_after_threshold(self):
        mgr = StepUpManager()
        pii = ["query_database", "search_contacts", "check_balance"]
        mgr.record_pii_call("s1", "query_database", pii)
        mgr.record_pii_call("s1", "search_contacts", pii)
        result = mgr.check_multi_pii_tool_session("s1", "check_balance", pii)
        assert result is not None
        assert result.trigger == "multi_pii_tool_session"

    def test_does_not_fire_below_threshold(self):
        mgr = StepUpManager()
        pii = ["query_database", "search_contacts"]
        mgr.record_pii_call("s1", "query_database", pii)
        result = mgr.check_multi_pii_tool_session("s1", "search_contacts", pii)
        assert result is None

    def test_does_not_fire_for_non_pii_tool(self):
        mgr = StepUpManager()
        pii = ["query_database"]
        mgr.record_pii_call("s1", "query_database", pii)
        mgr.record_pii_call("s1", "query_database", pii)
        result = mgr.check_multi_pii_tool_session("s1", "lookup_order", pii)
        assert result is None

    def test_custom_threshold(self):
        mgr = StepUpManager()
        pii = ["query_database"]
        mgr.record_pii_call("s1", "query_database", pii)
        result = mgr.check_multi_pii_tool_session("s1", "query_database", pii, threshold=1)
        assert result is not None

    def test_session_isolation(self):
        mgr = StepUpManager()
        pii = ["query_database"]
        mgr.record_pii_call("s1", "query_database", pii)
        mgr.record_pii_call("s1", "query_database", pii)
        result = mgr.check_multi_pii_tool_session("s2", "query_database", pii)
        assert result is None


class TestPostDenialRetry:
    """Test the post_denial_retry trigger."""

    def test_fires_after_denial_different_tool(self):
        mgr = StepUpManager()
        mgr.record_denial("s1", "send_email")
        result = mgr.check_post_denial_retry("s1", "query_database", "high")
        assert result is not None
        assert result.trigger == "post_denial_retry"
        assert "send_email" in result.reason

    def test_does_not_fire_same_tool(self):
        mgr = StepUpManager()
        mgr.record_denial("s1", "query_database")
        result = mgr.check_post_denial_retry("s1", "query_database", "high")
        assert result is None

    def test_does_not_fire_no_denials(self):
        mgr = StepUpManager()
        result = mgr.check_post_denial_retry("s1", "query_database", "high")
        assert result is None

    def test_does_not_fire_medium_risk(self):
        mgr = StepUpManager()
        mgr.record_denial("s1", "send_email")
        result = mgr.check_post_denial_retry("s1", "lookup_order", "medium")
        assert result is None


class TestStepUpResolution:
    """Test resolving step-up requests."""

    def test_resolve_approved(self):
        mgr = StepUpManager()
        req = mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "elevated",
        )
        resolved = mgr.resolve(req.request_id, "approved", "alice")
        assert resolved.resolution == "approved"
        assert resolved.resolved_by == "alice"

    def test_resolve_denied(self):
        mgr = StepUpManager()
        req = mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "elevated",
        )
        resolved = mgr.resolve(req.request_id, "denied")
        assert resolved.resolution == "denied"

    def test_resolve_unknown_id(self):
        mgr = StepUpManager()
        result = mgr.resolve("nonexistent", "denied")
        assert result is None

    def test_timeout_resolves_to_deny(self):
        mgr = StepUpManager()
        req = StepUpRequest(
            tool_name="query_database",
            created_at=time.time() - 300,
            timeout_seconds=120,
        )
        mgr._requests[req.request_id] = req
        timed_out = mgr.check_timeouts("deny")
        assert len(timed_out) == 1
        assert timed_out[0].resolution == "deny"


class TestStepUpNotifierProtocol:
    """Test the StepUpNotifier protocol."""

    def test_notifier_called(self):
        notifications = []

        class MockNotifier:
            def notify(self, request):
                notifications.append(request)
            def check_resolution(self, request_id):
                return None

        mgr = StepUpManager(notifier=MockNotifier())
        mgr.check_hardening_elevated_high_risk(
            "s1", "query_database", "high", "elevated",
        )
        assert len(notifications) == 1
        assert notifications[0].tool_name == "query_database"


class TestStepUpRequiredError:
    """Test the StepUpRequiredError exception."""

    def test_create_error(self):
        err = StepUpRequiredError(request_id="stepup_123", reason="test")
        assert err.request_id == "stepup_123"
        assert "stepup_123" in str(err)


class TestStepUpInGate:
    """Test STEP_UP integration in the gate pipeline."""

    def _make_gate(self):
        from agentlock import AuthorizationGate, AgentLockPermissions
        from agentlock.hardening import HardeningConfig, HardeningSignal
        from agentlock.schema import StepUpPolicyConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            stepup_policy=StepUpPolicyConfig(
                enabled=True,
                hardening_elevated_high_risk=True,
                multi_pii_tool_session=True,
                multi_pii_tool_threshold=2,
                post_denial_retry=True,
                pii_tool_names=["query_database", "search_contacts"],
            ),
        ))
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            stepup_policy=StepUpPolicyConfig(
                enabled=True,
                post_denial_retry=True,
            ),
        ))
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        return gate

    def test_hardening_elevated_triggers_stepup(self):
        from agentlock import DecisionType
        from agentlock.hardening import HardeningSignal
        gate = self._make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        # Push to elevated
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="trust_degraded", weight=4),
        )
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.STEP_UP
        assert result.stepup_request_id.startswith("stepup_")

    def test_multi_pii_triggers_stepup(self):
        from agentlock import DecisionType
        gate = self._make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        # Call PII tools twice — third should trigger step_up
        gate.authorize("query_database", user_id="alice", role="admin")
        gate.authorize("query_database", user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.STEP_UP
        assert "multi_pii_tool_session" in result.denial["reason"]

    def test_post_denial_retry_triggers_stepup(self):
        from agentlock import DecisionType
        gate = self._make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        # Create a denial by attempting unauthenticated
        deny_result = gate.authorize("send_email", user_id="", role="")
        assert not deny_result.allowed
        # Now retry with a different tool as admin
        result = gate.authorize("send_email", user_id="alice", role="admin")
        # post_denial_retry needs denial from the same session
        # Record denial manually for the correct session
        gate.stepup_manager.record_denial(session.session_id, "send_email")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.STEP_UP

    def test_no_stepup_when_disabled(self):
        from agentlock import AuthorizationGate, AgentLockPermissions
        gate = AuthorizationGate()
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed

    def test_no_stepup_for_medium_risk(self):
        from agentlock.hardening import HardeningSignal
        gate = self._make_gate()
        session = gate.create_session(user_id="alice", role="admin")
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="trust_degraded", weight=4),
        )
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed  # medium risk — no step_up
