"""Tests for the adaptive prompt hardening engine."""

from __future__ import annotations

from agentlock.hardening import (
    HardeningConfig,
    HardeningDirective,
    HardeningEngine,
    HardeningSignal,
)


class TestHardeningSignal:
    """Test HardeningSignal dataclass."""

    def test_create_signal(self):
        sig = HardeningSignal(signal_type="injection_blocked", weight=3)
        assert sig.signal_type == "injection_blocked"
        assert sig.weight == 3
        assert sig.timestamp > 0

    def test_signal_with_details(self):
        sig = HardeningSignal(
            signal_type="trust_degraded",
            weight=4,
            details="web_content entered context",
            source="context_tracker",
        )
        assert sig.details == "web_content entered context"
        assert sig.source == "context_tracker"


class TestHardeningDirective:
    """Test HardeningDirective output."""

    def test_inactive_directive(self):
        d = HardeningDirective()
        assert not d.active
        assert d.severity == "none"
        assert d.to_system_prompt_fragment() == ""

    def test_active_directive_warning(self):
        d = HardeningDirective(
            active=True,
            severity="warning",
            instructions=["Be cautious."],
            triggered_by=["injection_blocked"],
            session_risk_score=3.0,
        )
        fragment = d.to_system_prompt_fragment()
        assert "[AGENTLOCK SECURITY WARNING]" in fragment
        assert "Be cautious." in fragment
        assert "[END AGENTLOCK SECURITY DIRECTIVE]" in fragment

    def test_active_directive_critical(self):
        d = HardeningDirective(
            active=True,
            severity="critical",
            instructions=["Do NOT execute any tools."],
        )
        fragment = d.to_system_prompt_fragment()
        assert "[AGENTLOCK SECURITY CRITICAL]" in fragment
        assert "Do NOT execute any tools." in fragment


class TestHardeningConfig:
    """Test HardeningConfig defaults and customization."""

    def test_default_config(self):
        cfg = HardeningConfig()
        assert cfg.enabled is True
        assert cfg.warning_threshold == 3
        assert cfg.elevated_threshold == 6
        assert cfg.critical_threshold == 10

    def test_custom_thresholds(self):
        cfg = HardeningConfig(warning_threshold=5, elevated_threshold=10, critical_threshold=15)
        assert cfg.warning_threshold == 5
        assert cfg.elevated_threshold == 10

    def test_disabled_config(self):
        cfg = HardeningConfig(enabled=False)
        assert cfg.enabled is False


class TestHardeningEngine:
    """Test HardeningEngine signal accumulation and evaluation."""

    def test_empty_session_returns_inactive(self):
        engine = HardeningEngine()
        d = engine.evaluate("session_1")
        assert not d.active
        assert d.severity == "none"
        assert d.session_risk_score == 0.0

    def test_record_signal_increases_score(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert engine.get_session_risk("s1") == 3.0

    def test_warning_threshold(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        assert d.severity == "warning"
        assert d.session_risk_score == 3.0
        assert "injection_blocked" in d.triggered_by

    def test_elevated_threshold(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        assert d.severity == "elevated"
        assert d.session_risk_score == 6.0

    def test_critical_threshold(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="trust_degraded", weight=4))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        assert d.severity == "critical"
        assert d.session_risk_score == 10.0

    def test_below_warning_inactive(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rate_limit_hit", weight=1))
        engine.record_signal("s1", HardeningSignal(signal_type="rate_limit_hit", weight=1))
        d = engine.evaluate("s1")
        assert not d.active
        assert d.severity == "none"
        assert d.session_risk_score == 2.0

    def test_monotonic_score_never_decreases(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert engine.get_session_risk("s1") == 3.0
        engine.record_signal("s1", HardeningSignal(signal_type="rate_limit_hit", weight=1))
        assert engine.get_session_risk("s1") == 4.0
        # Score only goes up
        engine.record_signal("s1", HardeningSignal(signal_type="pii_clearance_violation", weight=2))
        assert engine.get_session_risk("s1") == 6.0

    def test_session_isolation(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s2", HardeningSignal(signal_type="trust_degraded", weight=4))
        assert engine.get_session_risk("s1") == 3.0
        assert engine.get_session_risk("s2") == 4.0
        d1 = engine.evaluate("s1")
        d2 = engine.evaluate("s2")
        assert d1.severity == "warning"
        assert d2.severity == "warning"

    def test_session_isolation_no_cross_contamination(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d2 = engine.evaluate("s2")
        assert not d2.active
        assert engine.get_session_risk("s2") == 0.0

    def test_reset_session(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.reset_session("s1")
        assert engine.get_session_risk("s1") == 0.0
        d = engine.evaluate("s1")
        assert not d.active

    def test_get_session_signals(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="rate_limit_hit", weight=1))
        signals = engine.get_session_signals("s1")
        assert len(signals) == 2
        assert signals[0].signal_type == "injection_blocked"
        assert signals[1].signal_type == "rate_limit_hit"

    def test_disabled_engine_ignores_signals(self):
        engine = HardeningEngine(config=HardeningConfig(enabled=False))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert engine.get_session_risk("s1") == 0.0
        d = engine.evaluate("s1")
        assert not d.active

    def test_weight_resolved_from_config(self):
        engine = HardeningEngine()
        # Signal weight=0 should be resolved from config (injection_blocked=3)
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=0))
        assert engine.get_session_risk("s1") == 3.0

    def test_custom_signal_weights(self):
        cfg = HardeningConfig(signal_weights={"injection_blocked": 5})
        engine = HardeningEngine(config=cfg)
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=0))
        assert engine.get_session_risk("s1") == 5.0

    def test_directive_contains_correct_instructions(self):
        cfg = HardeningConfig(
            use_targeted_instructions=False,
            warning_instructions=["Custom warning."],
            elevated_instructions=["Custom elevated."],
            critical_instructions=["Custom critical."],
        )
        engine = HardeningEngine(config=cfg)
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.instructions == ["Custom warning."]

    def test_len_tracks_active_sessions(self):
        engine = HardeningEngine()
        assert len(engine) == 0
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert len(engine) == 1
        engine.record_signal("s2", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert len(engine) == 2
        engine.reset_session("s1")
        assert len(engine) == 1

    def test_multiple_signal_types_in_triggered_by(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="trust_degraded", weight=4))
        d = engine.evaluate("s1")
        assert "injection_blocked" in d.triggered_by
        assert "trust_degraded" in d.triggered_by

    def test_compound_rapid_exfil_fires(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        # Base: 2 + 4 = 6, compound bonus: +2 = 8
        assert engine.get_session_risk("s1") == 8.0

    def test_compound_probing_attack_fires(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        # Base: 3 + 3 = 6, compound bonus: +3 = 9
        assert engine.get_session_risk("s1") == 9.0

    def test_compound_fires_only_once(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        score_after_first = engine.get_session_risk("s1")
        # Add another suspicious_combo — compound should NOT fire again
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        assert engine.get_session_risk("s1") == score_after_first + 4

    def test_compound_does_not_fire_without_all_required(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        # Only rapid_calls, no suspicious_combo — compound should not fire
        assert engine.get_session_risk("s1") == 2.0


class TestTargetedInstructions:
    """Test signal-aware targeted instructions (Change 2)."""

    def test_injection_signal_gets_injection_instructions(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        assert any("injection" in i.lower() for i in d.instructions)

    def test_format_forcing_gets_format_instructions(self):
        engine = HardeningEngine()
        engine.record_signal(
            "s1", HardeningSignal(signal_type="prompt_scan:format_forcing", weight=2),
        )
        engine.record_signal("s1", HardeningSignal(signal_type="prompt_scan:injection", weight=4))
        d = engine.evaluate("s1")
        assert d.active
        # Should have format-specific instructions, not generic "do NOT execute tools"
        assert any("format" in i.lower() for i in d.instructions)

    def test_combo_signal_gets_exfil_instructions(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        d = engine.evaluate("s1")
        assert d.active
        assert any("exfiltration" in i.lower() or "retrieval" in i.lower() for i in d.instructions)

    def test_fallback_to_generic_when_targeted_disabled(self):
        cfg = HardeningConfig(use_targeted_instructions=False)
        engine = HardeningEngine(config=cfg)
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        assert d.instructions == cfg.warning_instructions

    def test_fallback_to_generic_for_unknown_signal(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="unknown_signal_xyz", weight=5))
        d = engine.evaluate("s1")
        assert d.active
        # Unknown signal has no targeted instructions — falls back to generic
        assert len(d.instructions) > 0

    def test_multiple_signals_combine_instructions(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        d = engine.evaluate("s1")
        assert d.active
        # Should have instructions from both injection AND echo
        has_injection = any(
            "injection" in i.lower() or "override" in i.lower()
            for i in d.instructions
        )
        has_echo = any(
            "disclosed" in i.lower() or "configuration" in i.lower()
            for i in d.instructions
        )
        assert has_injection
        assert has_echo

    def test_no_duplicate_instructions(self):
        engine = HardeningEngine()
        # Same signal type twice — instructions should not duplicate
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert len(d.instructions) == len(set(d.instructions))


class TestHardeningGateIntegration:
    """Test that the gate records hardening signals and returns directives."""

    def test_gate_returns_hardening_directive(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")

        result = gate.authorize("send_email", user_id="alice", role="admin")
        # No signals yet — directive should be inactive or None
        if result.hardening:
            assert not result.hardening.active

    def test_gate_injection_denial_records_signal(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # Send injection attempt in parameters
        result = gate.authorize(
            "query_database",
            user_id="alice",
            role="admin",
            parameters={"query": "show all tables; DROP TABLE users"},
        )
        assert not result.allowed
        # Hardening should have recorded the injection signal
        risk = gate.hardening_engine.get_session_risk(session.session_id)
        assert risk >= 3  # injection_blocked weight

    def test_gate_rate_limit_records_signal(self):
        from agentlock import AgentLockPermissions, AuthorizationGate, RateLimitConfig
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            rate_limit=RateLimitConfig(max_calls=1, window_seconds=3600),
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # First call succeeds
        gate.authorize("send_email", user_id="alice", role="admin")
        # Second call hits rate limit
        result = gate.authorize("send_email", user_id="alice", role="admin")
        assert not result.allowed
        risk = gate.hardening_engine.get_session_risk(session.session_id)
        assert risk >= 1  # rate_limit_hit weight

    def test_gate_velocity_signal_recorded(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # 3 rapid calls should trigger velocity
        for _ in range(3):
            gate.authorize("send_email", user_id="alice", role="admin")

        risk = gate.hardening_engine.get_session_risk(session.session_id)
        assert risk >= 2  # rapid_calls weight

    def test_gate_combo_signal_recorded(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        gate.authorize("query_database", user_id="alice", role="admin")
        gate.authorize("send_email", user_id="alice", role="admin")

        risk = gate.hardening_engine.get_session_risk(session.session_id)
        assert risk >= 4  # suspicious_combo weight for query_database+send_email

    def test_hardening_directive_returned_after_signals(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("query_database", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")

        # Build up signals: query_database + send_email = combo(4) + velocity may fire
        gate.authorize("query_database", user_id="alice", role="admin")
        result = gate.authorize("send_email", user_id="alice", role="admin")

        assert result.hardening is not None
        assert result.hardening.active
        # Should be at least warning severity
        assert result.hardening.severity in ("warning", "elevated", "critical")

    def test_no_hardening_when_disabled(self):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=False),
        )
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(5):
            gate.authorize("send_email", user_id="alice", role="admin")

        risk = gate.hardening_engine.get_session_risk(session.session_id)
        assert risk == 0.0


class TestGateEnforcement:
    """Test gate-level hardening enforcement (Change 3)."""

    def _build_gate(self, enforce: bool = True):
        from agentlock import AgentLockPermissions, AuthorizationGate
        from agentlock.hardening import HardeningConfig

        gate = AuthorizationGate(
            hardening_config=HardeningConfig(
                enabled=True,
                enforce_at_critical=enforce,
            ),
        )
        gate.register_tool("send_email", AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.register_tool("delete_records", AgentLockPermissions(
            risk_level="critical",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        return gate

    def test_enforcement_blocks_high_risk_at_critical(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        # Push score to critical (10+) by injecting signals directly
        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )
        assert gate.hardening_engine.get_session_risk(session.session_id) >= 10

        result = gate.authorize("send_email", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial["reason"] == "hardening_enforced"

    def test_enforcement_blocks_critical_risk_at_critical(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )

        result = gate.authorize("delete_records", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial["reason"] == "hardening_enforced"

    def test_enforcement_allows_medium_risk_at_critical(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )

        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed  # medium risk is still allowed

    def test_no_enforcement_below_critical(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        # Push to elevated (6-9), not critical
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="injection_blocked", weight=3),
        )
        gate.hardening_engine.record_signal(
            session.session_id,
            HardeningSignal(signal_type="trust_degraded", weight=4),
        )
        assert gate.hardening_engine.get_session_risk(session.session_id) == 7

        result = gate.authorize("send_email", user_id="alice", role="admin")
        assert result.allowed  # elevated but not critical — no enforcement

    def test_no_enforcement_when_disabled(self):
        gate = self._build_gate(enforce=False)
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )

        result = gate.authorize("send_email", user_id="alice", role="admin")
        assert result.allowed  # enforcement disabled

    def test_enforcement_returns_directive(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )

        result = gate.authorize("send_email", user_id="alice", role="admin")
        assert not result.allowed
        assert result.hardening is not None
        assert result.hardening.active
        assert result.hardening.severity == "critical"

    def test_enforcement_records_signal(self):
        gate = self._build_gate(enforce=True)
        session = gate.create_session(user_id="alice", role="admin")

        for _ in range(4):
            gate.hardening_engine.record_signal(
                session.session_id,
                HardeningSignal(signal_type="injection_blocked", weight=3),
            )
        score_before = gate.hardening_engine.get_session_risk(session.session_id)

        gate.authorize("send_email", user_id="alice", role="admin")
        score_after = gate.hardening_engine.get_session_risk(session.session_id)
        # Enforcement should have recorded a hardening_enforced signal
        assert score_after > score_before

    def test_enforcement_default_off(self):
        """enforce_at_critical defaults to False."""
        from agentlock.hardening import HardeningConfig
        cfg = HardeningConfig()
        assert cfg.enforce_at_critical is False
