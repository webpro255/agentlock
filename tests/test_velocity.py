"""Tests for behavioral velocity detection."""

from __future__ import annotations

import time

from agentlock.signals.velocity import VelocityConfig, VelocityDetector


class TestRapidCalls:
    """Test rapid_calls detection: 3+ calls in 60 seconds."""

    def test_no_signal_below_threshold(self):
        det = VelocityDetector()
        now = time.time()
        signals = det.record_call("s1", "send_email", "high", now)
        assert len(signals) == 0
        signals = det.record_call("s1", "query_database", "high", now + 1)
        assert len(signals) == 0

    def test_signal_fires_at_threshold(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        det.record_call("s1", "query_database", "high", now + 1)
        signals = det.record_call("s1", "read_file", "medium", now + 2)
        rapid = [s for s in signals if s.signal_type == "rapid_calls"]
        assert len(rapid) == 1
        assert rapid[0].weight == 2

    def test_signal_fires_only_once(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "a", "medium", now)
        det.record_call("s1", "b", "medium", now + 1)
        det.record_call("s1", "c", "medium", now + 2)
        signals = det.record_call("s1", "d", "medium", now + 3)
        rapid = [s for s in signals if s.signal_type == "rapid_calls"]
        assert len(rapid) == 0  # already fired on the 3rd call

    def test_no_signal_outside_window(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "a", "medium", now - 120)
        det.record_call("s1", "b", "medium", now - 90)
        signals = det.record_call("s1", "c", "medium", now)
        rapid = [s for s in signals if s.signal_type == "rapid_calls"]
        assert len(rapid) == 0  # first two are outside 60s window

    def test_custom_window_and_count(self):
        cfg = VelocityConfig(rapid_calls_count=2, rapid_calls_window=10.0)
        det = VelocityDetector(config=cfg)
        now = time.time()
        det.record_call("s1", "a", "medium", now)
        signals = det.record_call("s1", "b", "medium", now + 1)
        rapid = [s for s in signals if s.signal_type == "rapid_calls"]
        assert len(rapid) == 1


class TestBurstPattern:
    """Test burst_pattern detection: same tool 3+ times in 30 seconds."""

    def test_burst_fires(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        det.record_call("s1", "send_email", "high", now + 1)
        signals = det.record_call("s1", "send_email", "high", now + 2)
        burst = [s for s in signals if s.signal_type == "burst_pattern"]
        assert len(burst) == 1
        assert burst[0].weight == 2

    def test_no_burst_different_tools(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        det.record_call("s1", "query_database", "high", now + 1)
        signals = det.record_call("s1", "read_file", "medium", now + 2)
        burst = [s for s in signals if s.signal_type == "burst_pattern"]
        assert len(burst) == 0

    def test_burst_fires_once_per_tool(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        det.record_call("s1", "send_email", "high", now + 1)
        det.record_call("s1", "send_email", "high", now + 2)
        signals = det.record_call("s1", "send_email", "high", now + 3)
        burst = [s for s in signals if s.signal_type == "burst_pattern"]
        assert len(burst) == 0  # already fired

    def test_no_burst_outside_window(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now - 60)
        det.record_call("s1", "send_email", "high", now - 50)
        signals = det.record_call("s1", "send_email", "high", now)
        burst = [s for s in signals if s.signal_type == "burst_pattern"]
        assert len(burst) == 0


class TestTopicEscalation:
    """Test topic_escalation: risk jump from low/medium to high/critical."""

    def test_escalation_fires(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "lookup_order", "low", now)
        signals = det.record_call("s1", "delete_records", "critical", now + 1)
        esc = [s for s in signals if s.signal_type == "topic_escalation"]
        assert len(esc) == 1
        assert esc[0].weight == 3

    def test_no_escalation_same_level(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        signals = det.record_call("s1", "query_database", "high", now + 1)
        esc = [s for s in signals if s.signal_type == "topic_escalation"]
        assert len(esc) == 0

    def test_no_escalation_deescalation(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "send_email", "high", now)
        signals = det.record_call("s1", "lookup_order", "low", now + 1)
        esc = [s for s in signals if s.signal_type == "topic_escalation"]
        assert len(esc) == 0

    def test_escalation_medium_to_high(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "read_file", "medium", now)
        signals = det.record_call("s1", "send_email", "high", now + 1)
        esc = [s for s in signals if s.signal_type == "topic_escalation"]
        assert len(esc) == 1

    def test_no_escalation_low_to_medium(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "lookup_order", "low", now)
        signals = det.record_call("s1", "read_file", "medium", now + 1)
        esc = [s for s in signals if s.signal_type == "topic_escalation"]
        assert len(esc) == 0


class TestSessionIsolation:
    """Test that velocity detection is isolated per session."""

    def test_different_sessions_independent(self):
        det = VelocityDetector()
        now = time.time()
        det.record_call("s1", "a", "medium", now)
        det.record_call("s1", "b", "medium", now + 1)
        signals = det.record_call("s2", "c", "medium", now + 2)
        rapid = [s for s in signals if s.signal_type == "rapid_calls"]
        assert len(rapid) == 0  # s2 only has 1 call

    def test_reset_session(self):
        det = VelocityDetector()
        det.record_call("s1", "a", "medium")
        det.record_call("s1", "b", "medium")
        det.reset_session("s1")
        assert det.get_call_count("s1") == 0
