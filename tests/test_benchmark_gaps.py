"""Tests for v1.2.1 benchmark gap fixes.

Four fixes verified:
1. enforce_all_at_critical — blocks ALL tool risk levels at critical hardening
2. lookup_order combo pairs — new suspicious pair patterns
3. Sibling deferral — defer co-occurring tools when one is deferred
4. Prompt scan carry-forward — defer tools without defer_policy when scan fired
"""

from __future__ import annotations

import time

from agentlock import AgentLockPermissions, AuthorizationGate, DecisionType
from agentlock.defer import DeferralManager
from agentlock.hardening import HardeningConfig, HardeningSignal
from agentlock.schema import DeferPolicyConfig
from agentlock.signals.combos import DEFAULT_SUSPICIOUS_PAIRS, ComboDetector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gate_enforce_all() -> AuthorizationGate:
    """Gate with enforce_all_at_critical=True."""
    gate = AuthorizationGate(
        hardening_config=HardeningConfig(
            enabled=True,
            enforce_all_at_critical=True,
        ),
    )
    gate.register_tool("lookup_order", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["admin", "support"],
    ))
    gate.register_tool("read_file", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["admin", "support"],
    ))
    gate.register_tool("query_database", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin", "support"],
    ))
    gate.register_tool("send_email", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ))
    gate.register_tool("search_contacts", AgentLockPermissions(
        risk_level="low",
        requires_auth=True,
        allowed_roles=["admin", "support"],
    ))
    return gate


def _push_to_critical(gate: AuthorizationGate, session_id: str) -> None:
    """Push hardening score to critical (>= 10)."""
    for _ in range(4):
        gate.hardening_engine.record_signal(
            session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
    assert gate.hardening_engine.get_session_risk(session_id) >= 10


# ===========================================================================
# Fix 1: enforce_all_at_critical
# ===========================================================================


class TestEnforceAllAtCritical:
    """When enforce_all_at_critical=True, ALL tools blocked at critical."""

    def test_medium_risk_blocked_at_critical(self):
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert not result.allowed
        assert result.decision == DecisionType.DENY
        assert result.denial["reason"] == "hardening_enforced_global"

    def test_low_risk_blocked_at_critical(self):
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        result = gate.authorize("search_contacts", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial["reason"] == "hardening_enforced_global"

    def test_high_risk_blocked_at_critical(self):
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert not result.allowed

    def test_all_tools_blocked_at_critical(self):
        """Every registered tool should be blocked."""
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        for tool in gate.registered_tools:
            role = "admin"
            result = gate.authorize(tool, user_id="alice", role=role)
            assert not result.allowed, f"{tool} should be blocked at critical"

    def test_not_blocked_below_critical(self):
        """At elevated (not critical), tools should still be allowed."""
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        # Push to elevated (7), not critical (10)
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="trust_degraded", weight=4),
        )
        assert gate.hardening_engine.get_session_risk(session.session_id) == 7

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed

    def test_default_is_disabled(self):
        """enforce_all_at_critical defaults to False."""
        cfg = HardeningConfig()
        assert cfg.enforce_all_at_critical is False

    def test_original_enforce_at_critical_still_works(self):
        """The old enforce_at_critical still allows MEDIUM tools."""
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(
                enabled=True,
                enforce_at_critical=True,
                enforce_all_at_critical=False,
            ),
        )
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed  # old flag only blocks HIGH/CRITICAL

    def test_hardening_directive_returned_on_deny(self):
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.hardening is not None
        assert result.hardening.severity == "critical"

    def test_audit_record_created(self):
        gate = _make_gate_enforce_all()
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        gate.authorize("lookup_order", user_id="alice", role="admin")
        records = gate.audit_logger.query(tool_name="lookup_order")
        denied_records = [r for r in records if r.action == "denied"]
        assert len(denied_records) >= 1


# ===========================================================================
# Fix 2: lookup_order combo pairs
# ===========================================================================


class TestLookupOrderComboPairs:
    """New suspicious pairs involving lookup_order."""

    def test_lookup_order_query_database_pair_exists(self):
        assert ("lookup_order", "query_database") in DEFAULT_SUSPICIOUS_PAIRS

    def test_lookup_order_check_balance_pair_exists(self):
        assert ("lookup_order", "check_balance") in DEFAULT_SUSPICIOUS_PAIRS

    def test_lookup_order_search_contacts_pair_exists(self):
        assert ("lookup_order", "search_contacts") in DEFAULT_SUSPICIOUS_PAIRS

    def test_lookup_then_query_fires_signal(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "query_database")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4

    def test_lookup_then_check_balance_fires_signal(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "check_balance")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_lookup_then_search_contacts_fires_signal(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "search_contacts")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_reverse_order_also_fires(self):
        """Pair detection is order-independent."""
        det = ComboDetector()
        det.record_call("s1", "query_database")
        signals = det.record_call("s1", "lookup_order")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4

    def test_lookup_alone_no_signal(self):
        det = ComboDetector()
        signals = det.record_call("s1", "lookup_order")
        assert len(signals) == 0

    def test_lookup_query_fires_only_once(self):
        """Same pair doesn't fire twice in same session."""
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        det.record_call("s1", "query_database")
        signals = det.record_call("s1", "query_database")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 0  # already fired


# ===========================================================================
# Fix 3: Sibling deferral
# ===========================================================================


class TestSiblingDeferral:
    """When one tool is deferred, co-occurring tools are deferred too."""

    def test_check_sibling_within_window(self):
        mgr = DeferralManager(sibling_window_seconds=5.0)
        mgr.record_deferral("s1")
        result = mgr.check_sibling_deferral("s1", "lookup_order")
        assert result is not None
        assert result.trigger == "sibling_deferral"

    def test_check_sibling_outside_window(self):
        mgr = DeferralManager(sibling_window_seconds=0.01)
        mgr.record_deferral("s1")
        time.sleep(0.02)
        result = mgr.check_sibling_deferral("s1", "lookup_order")
        assert result is None

    def test_no_sibling_without_deferral(self):
        mgr = DeferralManager()
        result = mgr.check_sibling_deferral("s1", "lookup_order")
        assert result is None

    def test_record_call_clears_sibling_window(self):
        mgr = DeferralManager()
        mgr.record_deferral("s1")
        mgr.record_call("s1")  # successful call clears the window
        result = mgr.check_sibling_deferral("s1", "lookup_order")
        assert result is None

    def test_session_isolation(self):
        mgr = DeferralManager()
        mgr.record_deferral("s1")
        result = mgr.check_sibling_deferral("s2", "lookup_order")
        assert result is None  # different session

    def test_reset_session_clears_sibling(self):
        mgr = DeferralManager()
        mgr.record_deferral("s1")
        mgr.reset_session("s1")
        result = mgr.check_sibling_deferral("s1", "lookup_order")
        assert result is None

    def test_sibling_deferral_in_gate(self):
        """When query_database defers, lookup_order in same turn defers too."""
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
            ),
        ))
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            # NO defer_policy
        ))
        gate.create_session(user_id="alice", role="admin")

        # First call: query_database deferred (first_call_high_risk)
        r1 = gate.authorize("query_database", user_id="alice", role="admin")
        assert r1.decision == DecisionType.DEFER

        # Same turn: lookup_order should also defer (sibling)
        r2 = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert r2.decision == DecisionType.DEFER
        assert r2.denial["reason"] == "sibling_deferral"


# ===========================================================================
# Fix 4: Prompt scan carry-forward
# ===========================================================================


class TestPromptScanCarryForward:
    """Prompt scan signals defer ALL tools, not just those with defer_policy."""

    def _make_gate_with_scan(self):
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            defer_policy=DeferPolicyConfig(
                enabled=True,
                scan_plus_tool=True,
            ),
        ))
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            # NO defer_policy
        ))
        gate.register_tool("read_file", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            # NO defer_policy
        ))
        return gate

    def test_lookup_deferred_when_scan_fired(self):
        """lookup_order (no defer_policy) defers when prompt_scan signal exists."""
        gate = self._make_gate_with_scan()
        session = gate.create_session(user_id="alice", role="admin")

        # Simulate prompt scanner firing a signal
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="prompt_scan:injection",
                weight=4,
                source="prompt_scanner",
            ),
        )

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.decision == DecisionType.DEFER
        assert result.denial["reason"] == "scan_plus_tool"

    def test_read_file_deferred_when_scan_fired(self):
        gate = self._make_gate_with_scan()
        session = gate.create_session(user_id="alice", role="admin")

        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="prompt_scan:encoding",
                weight=3,
                source="prompt_scanner",
            ),
        )

        result = gate.authorize("read_file", user_id="alice", role="admin")
        assert result.decision == DecisionType.DEFER

    def test_no_defer_without_scan_signal(self):
        """Without prompt_scan signals, lookup_order is allowed normally."""
        gate = self._make_gate_with_scan()
        gate.create_session(user_id="alice", role="admin")

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed
        assert result.decision == DecisionType.ALLOW

    def test_tool_with_defer_policy_not_double_deferred(self):
        """query_database (has defer_policy) defers via its own policy, not carry-forward."""
        gate = self._make_gate_with_scan()
        session = gate.create_session(user_id="alice", role="admin")

        # Record a call so first_call_high_risk doesn't fire
        gate.deferral_manager.record_call(session.session_id)

        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="prompt_scan:injection",
                weight=4,
                source="prompt_scanner",
            ),
        )

        # query_database should be deferred by its own defer_policy's scan_plus_tool
        result = gate.authorize("query_database", user_id="alice", role="admin")
        assert result.decision == DecisionType.DEFER
        assert result.denial["reason"] == "scan_plus_tool"

    def test_carry_forward_across_turns(self):
        """Scan signal from turn 1 should defer lookup_order on turn 2."""
        gate = self._make_gate_with_scan()
        session = gate.create_session(user_id="alice", role="admin")

        # Turn 1: prompt scan fires
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="prompt_scan:authority_claim",
                weight=3,
                source="prompt_scanner",
            ),
        )

        # Turn 2: lookup_order call — scan signal persists in session
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.decision == DecisionType.DEFER

    def test_non_prompt_scan_signals_dont_trigger(self):
        """Hardening signals that are NOT prompt_scan shouldn't trigger carry-forward."""
        gate = self._make_gate_with_scan()
        session = gate.create_session(user_id="alice", role="admin")

        # Record a non-scan signal
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="rate_limit_hit",
                weight=1,
                source="rate_limiter",
            ),
        )

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed


# ===========================================================================
# Integration: multiple fixes interact correctly
# ===========================================================================


class TestFixInteraction:
    """Test that the fixes compose correctly."""

    def test_combo_escalates_to_enforce_all(self):
        """lookup_order + query_database combo pushes score, then enforce_all blocks."""
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(
                enabled=True,
                enforce_all_at_critical=True,
            ),
        )
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # Push close to critical
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="trust_degraded", weight=4),
        )

        # lookup_order call triggers combo with future query_database
        gate.authorize("lookup_order", user_id="alice", role="admin")
        # query_database triggers the combo signal (weight 4)
        gate.authorize("query_database", user_id="alice", role="admin")

        # Score should now be >= 10 (3 + 4 + combo 4 = 11, possibly more)
        score = gate.hardening_engine.get_session_risk(session.session_id)
        assert score >= 10

        # Now all tools should be blocked
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial["reason"] == "hardening_enforced_global"

    def test_scan_carry_forward_plus_enforce_all(self):
        """At critical severity with scan signals, tools hit enforce_all first."""
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(
                enabled=True,
                enforce_all_at_critical=True,
            ),
        )
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")
        _push_to_critical(gate, session.session_id)

        # Also add a scan signal
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(
                signal_type="prompt_scan:injection",
                weight=4,
                source="prompt_scanner",
            ),
        )

        # enforce_all_at_critical runs before DEFER, so it should deny
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial["reason"] == "hardening_enforced_global"
