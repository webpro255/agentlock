"""Tests for tool combination anomaly detection."""

from __future__ import annotations

import pytest

from agentlock.signals.combos import ComboConfig, ComboDetector


class TestSuspiciousPairs:
    """Test suspicious tool pair detection."""

    def test_single_tool_no_signal(self):
        det = ComboDetector()
        signals = det.record_call("s1", "query_database")
        assert len(signals) == 0

    def test_benign_pair_no_signal(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "read_file")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 0

    def test_query_then_email_fires(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4

    def test_email_then_query_also_fires(self):
        """Pair detection is order-independent."""
        det = ComboDetector()
        det.record_call("s1", "send_email")
        signals = det.record_call("s1", "query_database")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1

    def test_contacts_then_email(self):
        det = ComboDetector()
        det.record_call("s1", "search_contacts")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_contacts_then_update_account(self):
        det = ComboDetector()
        det.record_call("s1", "search_contacts")
        signals = det.record_call("s1", "update_account")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4

    def test_check_balance_then_email(self):
        det = ComboDetector()
        det.record_call("s1", "check_balance")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4

    def test_pair_fires_only_once(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        det.record_call("s1", "send_email")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 0  # already fired

    def test_multiple_pairs_fire_independently(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        signals1 = det.record_call("s1", "send_email")
        det.record_call("s1", "search_contacts")
        # search_contacts+send_email should also fire (email was already seen)
        signals2 = det.record_call("s1", "update_account")
        combo1 = [s for s in signals1 if s.signal_type == "suspicious_combo"]
        combo2 = [s for s in signals2 if s.signal_type == "suspicious_combo"]
        assert len(combo1) >= 1  # query_database+send_email
        assert len(combo2) >= 1  # search_contacts+update_account


class TestSuspiciousSequences:
    """Test suspicious tool sequence detection (order-dependent)."""

    def test_read_write_email_sequence(self):
        det = ComboDetector()
        det.record_call("s1", "read_file")
        det.record_call("s1", "write_file")
        signals = det.record_call("s1", "send_email")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 1
        assert seq[0].weight == 5

    def test_query_contacts_email_sequence(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        det.record_call("s1", "search_contacts")
        signals = det.record_call("s1", "send_email")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 1

    def test_wrong_order_no_sequence(self):
        """Sequences are order-dependent."""
        det = ComboDetector()
        det.record_call("s1", "send_email")
        det.record_call("s1", "write_file")
        signals = det.record_call("s1", "read_file")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 0

    def test_sequence_with_intervening_tools(self):
        """Subsequence check allows other tools between sequence members."""
        det = ComboDetector()
        det.record_call("s1", "read_file")
        det.record_call("s1", "lookup_order")  # intervening
        det.record_call("s1", "write_file")
        det.record_call("s1", "check_balance")  # intervening
        signals = det.record_call("s1", "send_email")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 1

    def test_sequence_fires_only_once(self):
        det = ComboDetector()
        det.record_call("s1", "read_file")
        det.record_call("s1", "write_file")
        det.record_call("s1", "send_email")
        signals = det.record_call("s1", "send_email")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 0


class TestConfigurableMap:
    """Test that the suspicion map is configurable."""

    def test_custom_pair(self):
        cfg = ComboConfig(
            suspicious_pairs={("tool_a", "tool_b"): 10},
            suspicious_sequences={},
        )
        det = ComboDetector(config=cfg)
        det.record_call("s1", "tool_a")
        signals = det.record_call("s1", "tool_b")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 10

    def test_empty_map_no_signals(self):
        cfg = ComboConfig(suspicious_pairs={}, suspicious_sequences={})
        det = ComboDetector(config=cfg)
        det.record_call("s1", "query_database")
        signals = det.record_call("s1", "send_email")
        assert len(signals) == 0

    def test_custom_sequence(self):
        cfg = ComboConfig(
            suspicious_pairs={},
            suspicious_sequences={("a", "b", "c"): 7},
        )
        det = ComboDetector(config=cfg)
        det.record_call("s1", "a")
        det.record_call("s1", "b")
        signals = det.record_call("s1", "c")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 1
        assert seq[0].weight == 7


class TestToolChainAttackPairs:
    """Test the new tool chain attack pairs added in Change 4."""

    def test_lookup_order_update_account(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "update_account")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_check_balance_update_account(self):
        det = ComboDetector()
        det.record_call("s1", "check_balance")
        signals = det.record_call("s1", "update_account")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_lookup_order_send_email(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 3

    def test_lookup_update_email_sequence(self):
        det = ComboDetector()
        det.record_call("s1", "lookup_order")
        det.record_call("s1", "update_account")
        signals = det.record_call("s1", "send_email")
        seq = [s for s in signals if s.signal_type == "suspicious_sequence"]
        assert len(seq) == 1
        assert seq[0].weight == 5

    def test_search_database_alias(self):
        det = ComboDetector()
        det.record_call("s1", "search_database")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 1
        assert combo[0].weight == 4


class TestSessionIsolation:
    """Test session isolation for combo detection."""

    def test_sessions_independent(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        signals = det.record_call("s2", "send_email")
        assert len(signals) == 0  # different sessions

    def test_reset_session(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        det.reset_session("s1")
        signals = det.record_call("s1", "send_email")
        combo = [s for s in signals if s.signal_type == "suspicious_combo"]
        assert len(combo) == 0

    def test_get_tools_seen(self):
        det = ComboDetector()
        det.record_call("s1", "query_database")
        det.record_call("s1", "send_email")
        assert det.get_tools_seen("s1") == ["query_database", "send_email"]
        assert det.get_tools_seen("s2") == []
