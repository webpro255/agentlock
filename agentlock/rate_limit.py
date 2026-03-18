"""Sliding-window rate limiter for AgentLock tool calls."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

from agentlock.exceptions import RateLimitedError


@dataclass(slots=True)
class _Window:
    calls: list[float]
    max_calls: int
    window_seconds: int


class RateLimiter:
    """Per-user, per-tool sliding window rate limiter.

    Example::

        limiter = RateLimiter()
        limiter.check("send_email", "user_123", max_calls=5, window_seconds=3600)
    """

    def __init__(self) -> None:
        # key: (tool_name, user_id)
        self._windows: dict[tuple[str, str], _Window] = defaultdict(
            lambda: _Window(calls=[], max_calls=0, window_seconds=0)
        )

    def check(
        self,
        tool_name: str,
        user_id: str,
        max_calls: int,
        window_seconds: int,
    ) -> None:
        """Check rate limit and record the call.

        Args:
            tool_name: Tool being invoked.
            user_id: Caller identity.
            max_calls: Maximum calls allowed in the window.
            window_seconds: Window duration.

        Raises:
            RateLimitedError: If the caller has exceeded the limit.
        """
        key = (tool_name, user_id)
        now = time.time()
        cutoff = now - window_seconds

        window = self._windows[key]
        window.max_calls = max_calls
        window.window_seconds = window_seconds

        # Prune calls outside the window
        window.calls = [t for t in window.calls if t > cutoff]

        if len(window.calls) >= max_calls:
            oldest = min(window.calls) if window.calls else now
            retry_after = int(oldest + window_seconds - now) + 1
            raise RateLimitedError(
                retry_after_seconds=retry_after,
                detail=(
                    f"{tool_name}: {max_calls} calls per "
                    f"{window_seconds}s exceeded for user {user_id}"
                ),
                suggestion=f"Try again in {retry_after} seconds.",
            )

        window.calls.append(now)

    def remaining(self, tool_name: str, user_id: str) -> int | None:
        """Return remaining calls in the current window, or None if no limit set."""
        key = (tool_name, user_id)
        window = self._windows.get(key)
        if window is None or window.max_calls == 0:
            return None
        now = time.time()
        cutoff = now - window.window_seconds
        active = [t for t in window.calls if t > cutoff]
        return max(0, window.max_calls - len(active))

    def reset(self, tool_name: str | None = None, user_id: str | None = None) -> None:
        """Reset rate limit counters."""
        if tool_name and user_id:
            self._windows.pop((tool_name, user_id), None)
        elif tool_name:
            keys = [k for k in self._windows if k[0] == tool_name]
            for k in keys:
                del self._windows[k]
        elif user_id:
            keys = [k for k in self._windows if k[1] == user_id]
            for k in keys:
                del self._windows[k]
        else:
            self._windows.clear()
