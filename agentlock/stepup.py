"""STEP_UP decision type — dynamic human approval.

When session state indicates elevated risk, STEP_UP pauses execution
and requires human approval before proceeding.  Unlike the static
``human_approval`` config (which always requires approval for certain
tools), STEP_UP is triggered dynamically by hardening signals, PII
tool usage patterns, and prior denials.

Triggers:

1. ``hardening_elevated_high_risk``: Hardening severity >= elevated
   AND the tool is HIGH or CRITICAL risk.
2. ``multi_pii_tool_session``: 2+ PII-returning tools already called
   in the session — the next one triggers step-up.
3. ``post_denial_retry``: A tool was denied earlier in the session
   and the user is now attempting a different HIGH risk tool.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
    "StepUpManager",
    "StepUpRequest",
    "StepUpNotifier",
]


def _generate_request_id() -> str:
    return f"stepup_{secrets.token_hex(8)}"


@dataclass
class StepUpRequest:
    """A pending human approval request."""

    request_id: str = field(default_factory=_generate_request_id)
    tool_name: str = ""
    user_id: str = ""
    role: str = ""
    risk_level: str = ""
    reason: str = ""
    trigger: str = ""
    hardening_severity: str = ""
    created_at: float = field(default_factory=time.time)
    timeout_seconds: int = 120
    resolution: str | None = None  # "approved", "denied", "timeout"
    resolved_at: float | None = None
    resolved_by: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.resolution is not None

    @property
    def is_expired(self) -> bool:
        if self.is_resolved:
            return False
        return time.time() > (self.created_at + self.timeout_seconds)


@runtime_checkable
class StepUpNotifier(Protocol):
    """Protocol for framework notification mechanisms.

    Frameworks plug in their own push/email/SMS/in-app notification.
    """

    def notify(self, request: StepUpRequest) -> None: ...
    def check_resolution(self, request_id: str) -> str | None: ...


class StepUpManager:
    """Orchestrates dynamic human approval for suspicious sessions.

    Evaluates trigger conditions and creates step-up requests.
    Resolution is handled via the ``StepUpNotifier`` protocol or
    external API calls.
    """

    def __init__(self, notifier: StepUpNotifier | None = None) -> None:
        self._requests: dict[str, StepUpRequest] = {}
        self._notifier = notifier
        self._session_pii_counts: dict[str, int] = {}
        self._session_denials: dict[str, list[str]] = {}

    def check_hardening_elevated_high_risk(
        self,
        session_id: str,
        tool_name: str,
        risk_level: str,
        hardening_severity: str,
    ) -> StepUpRequest | None:
        """Trigger: hardening >= elevated AND tool is HIGH/CRITICAL.

        Returns a StepUpRequest if triggered, None otherwise.
        """
        if risk_level not in ("high", "critical"):
            return None
        if hardening_severity not in ("elevated", "critical"):
            return None

        request = StepUpRequest(
            tool_name=tool_name,
            risk_level=risk_level,
            reason=(
                f"Session hardening at '{hardening_severity}' level. "
                f"Human approval required for {risk_level} risk tool '{tool_name}'."
            ),
            trigger="hardening_elevated_high_risk",
            hardening_severity=hardening_severity,
        )
        self._requests[request.request_id] = request
        if self._notifier:
            self._notifier.notify(request)
        return request

    def check_multi_pii_tool_session(
        self,
        session_id: str,
        tool_name: str,
        pii_tool_names: list[str],
        threshold: int = 2,
    ) -> StepUpRequest | None:
        """Trigger: 2+ PII tools already called, next one triggers step-up.

        Returns a StepUpRequest if triggered, None otherwise.
        """
        if tool_name not in pii_tool_names:
            return None

        count = self._session_pii_counts.get(session_id, 0)
        if count < threshold:
            return None

        request = StepUpRequest(
            tool_name=tool_name,
            reason=(
                f"Session has already executed {count} PII-returning tools. "
                f"Human approval required for '{tool_name}'."
            ),
            trigger="multi_pii_tool_session",
        )
        self._requests[request.request_id] = request
        if self._notifier:
            self._notifier.notify(request)
        return request

    def check_post_denial_retry(
        self,
        session_id: str,
        tool_name: str,
        risk_level: str,
    ) -> StepUpRequest | None:
        """Trigger: a tool was denied and user tries a different HIGH risk tool.

        Returns a StepUpRequest if triggered, None otherwise.
        """
        if risk_level not in ("high", "critical"):
            return None

        denials = self._session_denials.get(session_id, [])
        if not denials:
            return None

        # Only trigger if the current tool is DIFFERENT from denied ones
        if all(d == tool_name for d in denials):
            return None

        request = StepUpRequest(
            tool_name=tool_name,
            risk_level=risk_level,
            reason=(
                f"Tool(s) were denied earlier in this session "
                f"({', '.join(set(denials))}). "
                f"Human approval required for '{tool_name}'."
            ),
            trigger="post_denial_retry",
        )
        self._requests[request.request_id] = request
        if self._notifier:
            self._notifier.notify(request)
        return request

    def record_pii_call(self, session_id: str, tool_name: str, pii_tool_names: list[str]) -> None:
        """Record that a PII-returning tool was called in the session."""
        if tool_name in pii_tool_names:
            self._session_pii_counts[session_id] = (
                self._session_pii_counts.get(session_id, 0) + 1
            )

    def record_denial(self, session_id: str, tool_name: str) -> None:
        """Record that a tool call was denied in the session."""
        if session_id not in self._session_denials:
            self._session_denials[session_id] = []
        self._session_denials[session_id].append(tool_name)

    def resolve(
        self,
        request_id: str,
        resolution: str,
        resolved_by: str = "",
    ) -> StepUpRequest | None:
        """Resolve a step-up request.

        Args:
            request_id: The request to resolve.
            resolution: "approved", "denied", or "timeout".
            resolved_by: Who resolved.

        Returns:
            The resolved StepUpRequest, or None if not found.
        """
        request = self._requests.get(request_id)
        if request is None:
            return None
        request.resolution = resolution
        request.resolved_at = time.time()
        request.resolved_by = resolved_by
        return request

    def check_timeouts(self, timeout_action: str = "deny") -> list[StepUpRequest]:
        """Check for expired requests and resolve them."""
        timed_out: list[StepUpRequest] = []
        for request in self._requests.values():
            if not request.is_resolved and request.is_expired:
                request.resolution = timeout_action
                request.resolved_at = time.time()
                request.resolved_by = "timeout"
                timed_out.append(request)
        return timed_out

    def get(self, request_id: str) -> StepUpRequest | None:
        """Get a step-up request by ID."""
        return self._requests.get(request_id)

    def get_pii_count(self, session_id: str) -> int:
        """Get PII tool call count for a session."""
        return self._session_pii_counts.get(session_id, 0)

    def get_denials(self, session_id: str) -> list[str]:
        """Get denied tool names for a session."""
        return list(self._session_denials.get(session_id, []))

    def reset_session(self, session_id: str) -> None:
        """Clear tracking state for a session."""
        self._session_pii_counts.pop(session_id, None)
        self._session_denials.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._requests)
