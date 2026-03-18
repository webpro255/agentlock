"""Tests for agentlock.rate_limit — RateLimiter."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agentlock.exceptions import RateLimitedError
from agentlock.rate_limit import RateLimiter


class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = RateLimiter()
        for _ in range(5):
            limiter.check("tool", "user", max_calls=5, window_seconds=60)

    def test_raises_when_limit_exceeded(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool", "user", max_calls=3, window_seconds=60)
        with pytest.raises(RateLimitedError):
            limiter.check("tool", "user", max_calls=3, window_seconds=60)

    def test_retry_after_set(self):
        limiter = RateLimiter()
        for _ in range(2):
            limiter.check("tool", "user", max_calls=2, window_seconds=60)
        with pytest.raises(RateLimitedError) as exc_info:
            limiter.check("tool", "user", max_calls=2, window_seconds=60)
        assert exc_info.value.retry_after_seconds is not None
        assert exc_info.value.retry_after_seconds > 0

    def test_window_slides_old_calls_expire(self):
        limiter = RateLimiter()
        now = time.time()

        with patch("agentlock.rate_limit.time") as mock_time:
            # Make 3 calls at t=0
            mock_time.time.return_value = now
            for _ in range(3):
                limiter.check("tool", "user", max_calls=3, window_seconds=10)

            # At t=11, window has slid past the old calls
            mock_time.time.return_value = now + 11
            # Should succeed again
            limiter.check("tool", "user", max_calls=3, window_seconds=10)

    def test_per_user_isolation(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool", "alice", max_calls=3, window_seconds=60)
        # alice is maxed out
        with pytest.raises(RateLimitedError):
            limiter.check("tool", "alice", max_calls=3, window_seconds=60)
        # bob is fine
        limiter.check("tool", "bob", max_calls=3, window_seconds=60)

    def test_per_tool_isolation(self):
        limiter = RateLimiter()
        for _ in range(2):
            limiter.check("tool_a", "user", max_calls=2, window_seconds=60)
        with pytest.raises(RateLimitedError):
            limiter.check("tool_a", "user", max_calls=2, window_seconds=60)
        # tool_b is separate
        limiter.check("tool_b", "user", max_calls=2, window_seconds=60)

    def test_reset_specific_tool_user(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool", "user", max_calls=3, window_seconds=60)
        limiter.reset(tool_name="tool", user_id="user")
        # Should work again
        limiter.check("tool", "user", max_calls=3, window_seconds=60)

    def test_reset_by_tool(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool", "alice", max_calls=3, window_seconds=60)
        for _ in range(3):
            limiter.check("tool", "bob", max_calls=3, window_seconds=60)
        limiter.reset(tool_name="tool")
        limiter.check("tool", "alice", max_calls=3, window_seconds=60)
        limiter.check("tool", "bob", max_calls=3, window_seconds=60)

    def test_reset_by_user(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool_a", "alice", max_calls=3, window_seconds=60)
        for _ in range(3):
            limiter.check("tool_b", "alice", max_calls=3, window_seconds=60)
        limiter.reset(user_id="alice")
        limiter.check("tool_a", "alice", max_calls=3, window_seconds=60)
        limiter.check("tool_b", "alice", max_calls=3, window_seconds=60)

    def test_reset_all(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.check("tool", "user", max_calls=3, window_seconds=60)
        limiter.reset()
        limiter.check("tool", "user", max_calls=3, window_seconds=60)

    def test_remaining_returns_correct_count(self):
        limiter = RateLimiter()
        limiter.check("tool", "user", max_calls=5, window_seconds=60)
        limiter.check("tool", "user", max_calls=5, window_seconds=60)
        assert limiter.remaining("tool", "user") == 3

    def test_remaining_returns_none_when_no_limit_set(self):
        limiter = RateLimiter()
        assert limiter.remaining("tool", "user") is None

    def test_remaining_zero_when_maxed(self):
        limiter = RateLimiter()
        for _ in range(5):
            limiter.check("tool", "user", max_calls=5, window_seconds=60)
        assert limiter.remaining("tool", "user") == 0

    def test_remaining_recovers_after_window(self):
        limiter = RateLimiter()
        now = time.time()
        with patch("agentlock.rate_limit.time") as mock_time:
            mock_time.time.return_value = now
            for _ in range(5):
                limiter.check("tool", "user", max_calls=5, window_seconds=10)
            assert limiter.remaining("tool", "user") == 0

            mock_time.time.return_value = now + 11
            assert limiter.remaining("tool", "user") == 5
