"""Tests for the DEFER decision type."""

from __future__ import annotations

import time

from agentlock.defer import DeferralManager, DeferralRecord
from agentlock.exceptions import DeferredError


class TestDeferralRecord:
    """Test DeferralRecord dataclass."""

    def test_create_record(self):
        r = DeferralRecord(tool_name="query_database", reason="test")
        assert r.deferral_id.startswith("defer_")
        assert r.tool_name == "query_database"
        assert not r.is_resolved
        assert not r.is_expired

    def test_resolved_record(self):
        r = DeferralRecord(tool_name="query_database", reason="test")
        r.resolution = "denied"
        r.resolved_at = time.time()
        assert r.is_resolved
        assert not r.is_expired

    def test_expired_record(self):
        r = DeferralRecord(
            tool_name="query_database",
            reason="test",
            created_at=time.time() - 120,
            timeout_seconds=60,
        )
        assert r.is_expired

    def test_not_expired_within_timeout(self):
        r = DeferralRecord(
            tool_name="query_database",
            reason="test",
            timeout_seconds=60,
        )
        assert not r.is_expired


class TestFirstCallHighRisk:
    """Test the first_call_high_risk trigger."""

    def test_fires_on_first_high_risk_call(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_high_risk("s1", "query_database", "high")
        assert result is not None
        assert result.trigger == "first_call_high_risk"

    def test_fires_on_first_critical_risk_call(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_high_risk("s1", "delete_records", "critical")
        assert result is not None

    def test_does_not_fire_on_medium_risk(self):
        mgr = DeferralManager()
        result = mgr.check_first_call_high_risk("s1", "lookup_order", "medium")
        assert result is None

    def test_does_not_fire_on_second_call(self):
        mgr = DeferralManager()
        mgr.record_call("s1")
        result = mgr.check_first_call_high_risk("s1", "query_database", "high")
        assert result is None

    def test_session_isolation(self):
        mgr = DeferralManager()
        mgr.record_call("s1")
        result = mgr.check_first_call_high_risk("s2", "query_database", "high")
        assert result is not None  # s2 has no calls


class TestScanPlusTool:
    """Test the scan_plus_tool trigger."""

    def test_fires_with_scan_signals(self):
        mgr = DeferralManager()
        from agentlock.hardening import HardeningSignal
        signals = [HardeningSignal(signal_type="prompt_scan:injection", weight=4)]
        result = mgr.check_scan_plus_tool("s1", "query_database", signals)
        assert result is not None
        assert result.trigger == "scan_plus_tool"
        assert "injection" in result.reason

    def test_does_not_fire_without_signals(self):
        mgr = DeferralManager()
        result = mgr.check_scan_plus_tool("s1", "query_database", [])
        assert result is None

    def test_does_not_fire_with_none(self):
        mgr = DeferralManager()
        result = mgr.check_scan_plus_tool("s1", "query_database", None)
        assert result is None


class TestTrustBelowThreshold:
    """Test the trust_below_threshold trigger."""

    def test_fires_when_untrusted_and_high_risk(self):
        mgr = DeferralManager()
        result = mgr.check_trust_below_threshold(
            "s1", "query_database", "high", "untrusted",
        )
        assert result is not None
        assert result.trigger == "trust_below_threshold"

    def test_does_not_fire_at_derived(self):
        mgr = DeferralManager()
        result = mgr.check_trust_below_threshold(
            "s1", "query_database", "high", "derived",
        )
        assert result is None

    def test_does_not_fire_for_medium_risk(self):
        mgr = DeferralManager()
        result = mgr.check_trust_below_threshold(
            "s1", "lookup_order", "medium", "untrusted",
        )
        assert result is None


class TestDeferralResolution:
    """Test resolving deferred decisions."""

    def test_resolve_approved(self):
        mgr = DeferralManager()
        record = mgr.check_first_call_high_risk("s1", "query_database", "high")
        resolved = mgr.resolve(record.deferral_id, "approved", "alice")
        assert resolved.resolution == "approved"
        assert resolved.resolved_by == "alice"
        assert resolved.is_resolved

    def test_resolve_denied(self):
        mgr = DeferralManager()
        record = mgr.check_first_call_high_risk("s1", "query_database", "high")
        resolved = mgr.resolve(record.deferral_id, "denied", "alice")
        assert resolved.resolution == "denied"

    def test_resolve_unknown_id(self):
        mgr = DeferralManager()
        result = mgr.resolve("nonexistent", "denied")
        assert result is None

    def test_timeout_resolves_to_deny(self):
        mgr = DeferralManager()
        record = DeferralRecord(
            tool_name="query_database",
            reason="test",
            created_at=time.time() - 120,
            timeout_seconds=60,
        )
        mgr._deferrals[record.deferral_id] = record
        timed_out = mgr.check_timeouts("deny")
        assert len(timed_out) == 1
        assert timed_out[0].resolution == "deny"
        assert timed_out[0].resolved_by == "timeout"


class TestDeferredError:
    """Test the DeferredError exception."""

    def test_create_error(self):
        err = DeferredError(deferral_id="defer_123", reason="test", timeout_seconds=60)
        assert err.deferral_id == "defer_123"
        assert err.reason == "test"
        assert "defer_123" in str(err)


class TestDeferInGate:
    """Test DEFER integration in the gate pipeline."""

    def _make_gate(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig
        from agentlock.schema import DeferPolicyConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            defer_policy=DeferPolicyConfig(
                enabled=True,
                first_call_high_risk=True,
                scan_plus_tool=True,
                trust_below_threshold=True,
            ),
        ))
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            defer_policy=DeferPolicyConfig(
                enabled=True,
                first_call_high_risk=True,
            ),
        ))
        return gate

    def test_first_call_high_risk_defers(self):
        from agentlock import DecisionType
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.DEFER
        assert result.deferral_id.startswith("defer_")
        assert result.denial["reason"] == "first_call_high_risk"

    def test_medium_risk_first_call_not_deferred(self):
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed  # medium risk — first_call_high_risk doesn't fire

    def test_second_call_not_deferred(self):
        gate = self._make_gate()
        gate.create_session(user_id="alice", role="admin")
        # First call defers
        gate.authorize("query_database", user_id="alice", role="admin")
        # Simulate resolution by recording the call manually
        session = gate.get_session("alice")
        gate.deferral_manager.record_call(session.session_id)
        # Second call should not defer (has history now)
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed

    def test_no_defer_when_disabled(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        gate = AuthorizationGate()
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            # No defer_policy
        ))
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.allowed
