"""Tests for compound scoring rules in the hardening engine."""

from __future__ import annotations

import pytest

from agentlock.hardening import HardeningConfig, HardeningEngine, HardeningSignal


class TestRapidExfilCompound:
    """Test the rapid_exfil compound rule: velocity + combo."""

    def test_fires_with_both_signals(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        # 2 + 4 + 2 (bonus) = 8
        assert engine.get_session_risk("s1") == 8.0

    def test_does_not_fire_with_only_velocity(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        assert engine.get_session_risk("s1") == 2.0

    def test_does_not_fire_with_only_combo(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        assert engine.get_session_risk("s1") == 4.0

    def test_fires_regardless_of_order(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        assert engine.get_session_risk("s1") == 8.0


class TestProbingAttackCompound:
    """Test the probing_attack compound rule: echo + injection."""

    def test_fires_with_both_signals(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        # 3 + 3 + 3 (bonus) = 9
        assert engine.get_session_risk("s1") == 9.0

    def test_does_not_fire_with_only_echo(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        assert engine.get_session_risk("s1") == 3.0

    def test_does_not_fire_with_only_injection(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        assert engine.get_session_risk("s1") == 3.0


class TestMultipleCompounds:
    """Test interaction of multiple compound rules."""

    def test_both_compounds_can_fire(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        # rapid_calls(2) + suspicious_combo(4) + rapid_exfil_bonus(2)
        # + echo_detected(3) + injection_blocked(3) + probing_attack_bonus(3)
        # = 17
        assert engine.get_session_risk("s1") == 17.0

    def test_compound_fires_once_even_with_repeated_triggers(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        # rapid_exfil fires: 2 + 4 + 2 = 8
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        # rapid_exfil does NOT fire again: 8 + 2 + 4 = 14
        assert engine.get_session_risk("s1") == 14.0


class TestWeightsAddUp:
    """Test that all signal weights add up correctly."""

    def test_all_v112_signals(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="trust_degraded", weight=4))
        engine.record_signal("s1", HardeningSignal(signal_type="rate_limit_hit", weight=1))
        # 3 + 4 + 1 = 8
        assert engine.get_session_risk("s1") == 8.0

    def test_mixed_old_and_new_signals(self):
        engine = HardeningEngine()
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="echo_detected", weight=3))
        # 3 + 2 + 3 + probing_attack(3) = 11
        # Wait — probing_attack requires echo_detected + injection_blocked, which are both present
        assert engine.get_session_risk("s1") == 11.0

    def test_severity_escalation_with_accumulation(self):
        engine = HardeningEngine()
        # Start at none
        d = engine.evaluate("s1")
        assert d.severity == "none"

        # Add injection: 3 → warning
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.severity == "warning"

        # Add trust_degraded: 3+4=7 → elevated
        engine.record_signal("s1", HardeningSignal(signal_type="trust_degraded", weight=4))
        d = engine.evaluate("s1")
        assert d.severity == "elevated"

        # Add another injection: 7+3=10 → critical
        engine.record_signal("s1", HardeningSignal(signal_type="injection_blocked", weight=3))
        d = engine.evaluate("s1")
        assert d.severity == "critical"


class TestCompoundWithCustomRules:
    """Test compound rules with custom configuration."""

    def test_custom_compound_rule(self):
        cfg = HardeningConfig(
            compound_rules=[
                {
                    "name": "custom_compound",
                    "requires": {"signal_a", "signal_b"},
                    "bonus": 10,
                },
            ],
        )
        engine = HardeningEngine(config=cfg)
        engine.record_signal("s1", HardeningSignal(signal_type="signal_a", weight=1))
        engine.record_signal("s1", HardeningSignal(signal_type="signal_b", weight=1))
        # 1 + 1 + 10 (bonus) = 12
        assert engine.get_session_risk("s1") == 12.0

    def test_no_compound_rules(self):
        cfg = HardeningConfig(compound_rules=[])
        engine = HardeningEngine(config=cfg)
        engine.record_signal("s1", HardeningSignal(signal_type="rapid_calls", weight=2))
        engine.record_signal("s1", HardeningSignal(signal_type="suspicious_combo", weight=4))
        # No compound rules → just base signals
        assert engine.get_session_risk("s1") == 6.0
