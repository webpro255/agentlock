"""Behavioral velocity detection.

Tracks tool call frequency and topic shifts per session.  Normal users
ask one thing and wait.  Attackers blast through multi-turn sequences
with rapid topic shifts.

Signal fires when:
- 3+ tool call attempts in under 60 seconds (rapid_calls)
- Topic shifts from benign to sensitive in consecutive turns
  (topic_escalation)
- Same tool called 3+ times in under 30 seconds (burst_pattern)

Records both allowed AND denied calls — attackers who blast rapid
requests trigger velocity even if individual requests are denied.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from agentlock.hardening import HardeningSignal

__all__ = ["VelocityDetector", "VelocitySignal", "VelocityConfig"]


@dataclass(slots=True)
class VelocitySignal:
    """A velocity anomaly detection result."""

    signal_type: str  # rapid_calls, topic_escalation, burst_pattern
    weight: int
    details: str = ""


# Risk level ordering for topic escalation detection
_RISK_ORDER: dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class _CallRecord:
    """Internal record of a tool call attempt."""

    tool_name: str
    risk_level: str
    timestamp: float


@dataclass
class VelocityConfig:
    """Configuration for velocity detection."""

    rapid_calls_count: int = 3
    rapid_calls_window: float = 60.0
    rapid_calls_weight: int = 2
    burst_count: int = 3
    burst_window: float = 30.0
    burst_weight: int = 2
    escalation_weight: int = 3


class VelocityDetector:
    """Tracks tool call frequency and topic shifts per session.

    Call ``record_call()`` for every tool call attempt (allowed or denied).
    It returns a list of ``HardeningSignal`` objects if anomalies are
    detected, or an empty list if the call looks normal.
    """

    def __init__(self, config: VelocityConfig | None = None) -> None:
        self._config = config or VelocityConfig()
        self._session_calls: dict[str, list[_CallRecord]] = {}
        # Track which signals have fired per session to avoid duplicates
        self._session_fired: dict[str, set[str]] = {}

    def record_call(
        self,
        session_id: str,
        tool_name: str,
        risk_level: str = "medium",
        timestamp: float | None = None,
    ) -> list[HardeningSignal]:
        """Record a tool call attempt and check for velocity anomalies.

        Args:
            session_id: Session identifier.
            tool_name: Name of the tool being called.
            risk_level: Risk level of the tool (none/low/medium/high/critical).
            timestamp: Call timestamp (defaults to now).

        Returns:
            List of HardeningSignal objects if anomalies detected.
        """
        ts = timestamp if timestamp is not None else time.time()
        record = _CallRecord(tool_name=tool_name, risk_level=risk_level, timestamp=ts)

        if session_id not in self._session_calls:
            self._session_calls[session_id] = []
            self._session_fired[session_id] = set()

        self._session_calls[session_id].append(record)
        fired = self._session_fired[session_id]
        calls = self._session_calls[session_id]

        signals: list[HardeningSignal] = []

        # Check rapid calls: 3+ calls in 60 seconds
        if "rapid_calls" not in fired:
            signal = self._check_rapid_calls(calls, ts, fired)
            if signal:
                signals.append(signal)

        # Check burst pattern: same tool 3+ times in 30 seconds
        burst_key = f"burst:{tool_name}"
        if burst_key not in fired:
            signal = self._check_burst(calls, tool_name, ts, fired, burst_key)
            if signal:
                signals.append(signal)

        # Check topic escalation: risk jump in consecutive calls
        if len(calls) >= 2:
            signal = self._check_escalation(calls, fired)
            if signal:
                signals.append(signal)

        return signals

    def _check_rapid_calls(
        self,
        calls: list[_CallRecord],
        now: float,
        fired: set[str],
    ) -> HardeningSignal | None:
        """Check for rapid_calls: 3+ distinct calls in window."""
        cfg = self._config
        window_start = now - cfg.rapid_calls_window
        recent = [c for c in calls if c.timestamp >= window_start]
        if len(recent) >= cfg.rapid_calls_count:
            fired.add("rapid_calls")
            return HardeningSignal(
                signal_type="rapid_calls",
                weight=cfg.rapid_calls_weight,
                details=(
                    f"{len(recent)} tool calls in "
                    f"{cfg.rapid_calls_window:.0f}s window"
                ),
                source="velocity_detector",
            )
        return None

    def _check_burst(
        self,
        calls: list[_CallRecord],
        tool_name: str,
        now: float,
        fired: set[str],
        burst_key: str,
    ) -> HardeningSignal | None:
        """Check for burst_pattern: same tool N+ times in window."""
        cfg = self._config
        window_start = now - cfg.burst_window
        same_tool_recent = [
            c for c in calls
            if c.tool_name == tool_name and c.timestamp >= window_start
        ]
        if len(same_tool_recent) >= cfg.burst_count:
            fired.add(burst_key)
            return HardeningSignal(
                signal_type="burst_pattern",
                weight=cfg.burst_weight,
                details=(
                    f"{tool_name} called {len(same_tool_recent)} times in "
                    f"{cfg.burst_window:.0f}s"
                ),
                source="velocity_detector",
            )
        return None

    def _check_escalation(
        self,
        calls: list[_CallRecord],
        fired: set[str],
    ) -> HardeningSignal | None:
        """Check for topic_escalation: risk jump in consecutive calls."""
        prev = calls[-2]
        curr = calls[-1]
        prev_level = _RISK_ORDER.get(prev.risk_level, 2)
        curr_level = _RISK_ORDER.get(curr.risk_level, 2)

        # Escalation: jump from low/medium (0-2) to high/critical (3-4)
        if prev_level <= 2 and curr_level >= 3:
            key = f"escalation:{prev.tool_name}->{curr.tool_name}"
            if key not in fired:
                fired.add(key)
                return HardeningSignal(
                    signal_type="topic_escalation",
                    weight=self._config.escalation_weight,
                    details=(
                        f"Risk escalation: {prev.tool_name} "
                        f"({prev.risk_level}) -> {curr.tool_name} "
                        f"({curr.risk_level})"
                    ),
                    source="velocity_detector",
                )
        return None

    def reset_session(self, session_id: str) -> None:
        """Clear velocity tracking for a session."""
        self._session_calls.pop(session_id, None)
        self._session_fired.pop(session_id, None)

    def get_call_count(self, session_id: str) -> int:
        """Get the number of recorded calls for a session."""
        return len(self._session_calls.get(session_id, []))
