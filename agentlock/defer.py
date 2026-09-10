"""DEFER decision type -- suspend authorization pending resolution.

When the gate cannot confidently allow or deny a tool call, DEFER
suspends execution.  The deferral times out to DENY by default.

Triggers:

1. ``first_call_high_risk``: The session's very first tool call is
   HIGH or CRITICAL risk with zero prior history.
2. ``scan_plus_tool``: The prompt scanner fired a signal on the
   current turn AND the LLM is attempting a tool call.
3. ``trust_below_threshold``: Session trust has degraded below
   DERIVED ceiling and the tool is HIGH risk.
"""

from __future__ import annotations

import copy
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import cycle
    from agentlock.policy import ActionFlags

__all__ = ["DeferralManager", "DeferralRecord"]


def _generate_deferral_id() -> str:
    return f"defer_{secrets.token_hex(8)}"


def _snapshot(parameters: dict[str, Any] | None) -> dict[str, Any] | None:
    """Copy queued parameters so a later mutation cannot reach the decision.

    Deep where the values allow it.  A value that refuses to be deep copied
    is kept by reference rather than dropped: an un-copyable parameter is
    still part of the call, and losing it would make the record describe a
    call that was never queued.
    """
    if parameters is None:
        return None
    try:
        return copy.deepcopy(parameters)
    except Exception:
        return dict(parameters)


@dataclass
class DeferralRecord:
    """A suspended authorization decision."""

    deferral_id: str = field(default_factory=_generate_deferral_id)
    tool_name: str = ""
    user_id: str = ""
    role: str = ""
    reason: str = ""
    trigger: str = ""
    created_at: float = field(default_factory=time.time)
    timeout_seconds: int = 60
    resolution: str | None = None  # "approved", "denied", "timeout", "committed"
    resolved_at: float | None = None
    resolved_by: str | None = None
    parameters: dict[str, Any] | None = None
    session_id: str = ""
    # v1.3 Feature 1 (deferred commit): taint snapshots at call vs commit.
    taint_at_call: dict[str, Any] | None = None
    taint_at_commit: dict[str, Any] | None = None
    # v1.10 (E6): why the commit-time re-decision denied, when it denied.  A
    # deferral that resolves to "denied" is a denial, and a denial that cannot
    # say what denied it is not evidence of anything.  Cleared on commit.
    denial_reason: str | None = None
    # v1.4 (defer-policy): the caller-asserted action classes, captured at
    # queue time so the commit-time re-decision can evaluate the same gating
    # disjunct the call-time path did.  ``None`` means the caller recorded
    # nothing, which the gate treats as FAIL-CLOSED (gated on taint) -- the
    # exact pre-v1.4 behavior.
    action_flags: ActionFlags | None = None

    @property
    def is_resolved(self) -> bool:
        return self.resolution is not None

    @property
    def is_expired(self) -> bool:
        if self.is_resolved:
            return False
        return time.time() > (self.created_at + self.timeout_seconds)


class DeferralManager:
    """Tracks deferred decisions and their resolution.

    The manager evaluates trigger conditions and creates deferral
    records.  Resolution is handled externally (human review, additional
    context, or timeout).
    """

    def __init__(self, sibling_window_seconds: float = 5.0) -> None:
        self._deferrals: dict[str, DeferralRecord] = {}
        self._session_call_counts: dict[str, int] = {}
        self._sibling_window = sibling_window_seconds
        # Tracks (session_id -> timestamp) of the most recent deferral
        self._session_last_deferral: dict[str, float] = {}
        # v1.3 Feature 1 -- per-session queue of consequential actions deferred
        # for end-of-turn commit-or-deny against the complete taint state.
        self._commit_queue: dict[str, list[DeferralRecord]] = {}

    def check_first_call_any_risk(
        self,
        session_id: str,
        tool_name: str,
    ) -> DeferralRecord | None:
        """Trigger: first tool call in session, ANY risk level.

        Unlike ``check_first_call_high_risk``, this fires regardless of
        the tool's risk level.  Use when all first-call tool executions
        should be deferred for additional context.

        Returns a DeferralRecord if triggered, None otherwise.
        """
        count = self._session_call_counts.get(session_id, 0)
        if count > 0:
            return None

        record = DeferralRecord(
            tool_name=tool_name,
            reason=(
                f"First tool call in session. "
                f"Deferring '{tool_name}' for additional context."
            ),
            trigger="first_call_any_risk",
        )
        self._deferrals[record.deferral_id] = record
        return record

    def check_first_call_high_risk(
        self,
        session_id: str,
        tool_name: str,
        risk_level: str,
    ) -> DeferralRecord | None:
        """Trigger: first tool call in session is HIGH/CRITICAL risk.

        Returns a DeferralRecord if triggered, None otherwise.
        """
        count = self._session_call_counts.get(session_id, 0)
        if count > 0:
            return None
        if risk_level not in ("high", "critical"):
            return None

        record = DeferralRecord(
            tool_name=tool_name,
            reason=(
                f"First tool call in session is {risk_level} risk. "
                f"Deferring for additional context."
            ),
            trigger="first_call_high_risk",
        )
        self._deferrals[record.deferral_id] = record
        return record

    def check_scan_plus_tool(
        self,
        session_id: str,
        tool_name: str,
        scan_signals_this_turn: list[Any],
    ) -> DeferralRecord | None:
        """Trigger: prompt scanner fired AND tool call attempted.

        Returns a DeferralRecord if triggered, None otherwise.
        """
        if not scan_signals_this_turn:
            return None

        signal_types = [
            s.signal_type if hasattr(s, "signal_type") else str(s)
            for s in scan_signals_this_turn
        ]
        record = DeferralRecord(
            tool_name=tool_name,
            reason=(
                f"Prompt scan detected suspicious input "
                f"({', '.join(signal_types)}) and tool call attempted. "
                f"Deferring pending review."
            ),
            trigger="scan_plus_tool",
        )
        self._deferrals[record.deferral_id] = record
        return record

    def check_trust_below_threshold(
        self,
        session_id: str,
        tool_name: str,
        risk_level: str,
        trust_ceiling: str,
    ) -> DeferralRecord | None:
        """Trigger: trust degraded below DERIVED and tool is HIGH risk.

        Returns a DeferralRecord if triggered, None otherwise.
        """
        if risk_level not in ("high", "critical"):
            return None
        if trust_ceiling not in ("untrusted",):
            return None

        record = DeferralRecord(
            tool_name=tool_name,
            reason=(
                f"Session trust at '{trust_ceiling}' -- too low for "
                f"{risk_level} risk tool '{tool_name}'. "
                f"Deferring pending human review."
            ),
            trigger="trust_below_threshold",
        )
        self._deferrals[record.deferral_id] = record
        return record

    def check_sibling_deferral(
        self,
        session_id: str,
        tool_name: str,
    ) -> DeferralRecord | None:
        """Trigger: another tool was DEFERRED in the same turn.

        If a deferral was recorded for this session within the sibling
        window (default 5 seconds), defer this tool call too.

        Returns a DeferralRecord if triggered, None otherwise.
        """
        last_ts = self._session_last_deferral.get(session_id)
        if last_ts is None:
            return None
        if time.time() - last_ts > self._sibling_window:
            return None

        record = DeferralRecord(
            tool_name=tool_name,
            reason=(
                f"Another tool was deferred in this turn. "
                f"Deferring '{tool_name}' as sibling."
            ),
            trigger="sibling_deferral",
        )
        self._deferrals[record.deferral_id] = record
        return record

    # -- v1.3 Feature 1: deferred-commit queue -----------------------------
    def queue_commit(
        self,
        session_id: str,
        tool_name: str,
        parameters: dict[str, Any] | None,
        *,
        taint_at_call: dict[str, Any] | None = None,
        action_flags: ActionFlags | None = None,
    ) -> DeferralRecord:
        """Queue a consequential action for end-of-turn commit/deny.

        Snapshots the taint state at call time; the resolution against the
        COMPLETE episode taint happens later in :meth:`resolve_commit_queue`.

        ``action_flags`` records the caller-asserted action classes so the
        commit-time re-decision can consult the tool's trusted permission
        block.  Omitting it is fail-closed.

        ``parameters`` are snapshotted, not aliased (E6).
        """
        record = DeferralRecord(
            tool_name=tool_name,
            session_id=session_id,
            # E6: the queued parameters are the ones re-decided at end of
            # turn, so they are snapshotted here rather than aliased.  A
            # caller that mutates its own dict after queuing must not be able
            # to change what the commit-time decision is taken over.
            parameters=_snapshot(parameters),
            trigger="deferred_commit",
            reason=f"'{tool_name}' deferred for end-of-turn commit review.",
            taint_at_call=taint_at_call,
            action_flags=action_flags,
        )
        self._deferrals[record.deferral_id] = record
        self._commit_queue.setdefault(session_id, []).append(record)
        return record

    def resolve_commit_queue(
        self,
        session_id: str,
        *,
        deny: bool | Callable[[DeferralRecord], bool],
        taint_at_commit: dict[str, Any] | None = None,
    ) -> list[DeferralRecord]:
        """Resolve every queued action for a session, in original order.

        E7, two rules this method did not have:

        * **A resolution is terminal.**  A record that already carries one is
          left exactly as it is.  Through 1.9.1 the assignment below was
          unconditional, so a record a timeout sweep had already resolved to
          ``"deny"`` was rewritten to ``"committed"`` by the next call here.
          A denial that a later call can undo is not a denial.
        * **Expiry is enforced here, not only by whoever remembers to sweep.**
          A record past its timeout resolves to ``"deny"`` whether or not
          :meth:`check_timeouts` ever ran.  A timeout that defaults to DENY
          and depends on an external cadence to be applied is advisory, which
          is the opposite of what it exists to be.

        Both are why every record leaves the pending queue: the queue holds
        what is still undecided, and after this call nothing in it is.

        Args:
            deny: either a single bool applied to every record (pre-v1.4
                behavior), or a per-record predicate.  The gate passes a
                predicate so each queued action is re-decided against its own
                permission block; this manager stays policy-free.
            taint_at_commit: the complete-episode taint snapshot (for logging).

        Returns the records that were queued, in order, resolved or already
        resolved (queue is emptied).
        """
        queued = self._commit_queue.pop(session_id, [])
        now = time.time()
        decide = deny if callable(deny) else (lambda _record, _d=deny: _d)
        for record in queued:
            if record.is_resolved:
                # Terminal.  Not re-decided, and not even re-annotated.
                continue
            record.taint_at_commit = taint_at_commit
            if record.is_expired:
                record.resolution = "deny"
                record.resolved_at = now
                record.resolved_by = "timeout"
                continue
            denied = decide(record)
            record.resolution = "denied" if denied else "committed"
            if not denied:
                record.denial_reason = None
            record.resolved_at = now
            record.resolved_by = "deferred_commit"
        return queued

    def get_commit_queue(self, session_id: str) -> list[DeferralRecord]:
        """Return (without removing) the queued actions for a session."""
        return list(self._commit_queue.get(session_id, []))

    def clear_commit_queue(self, session_id: str) -> None:
        """Drop any queued actions for a session (per-episode reset)."""
        self._commit_queue.pop(session_id, None)

    def record_deferral(self, session_id: str) -> None:
        """Record that a deferral just happened in this session/turn."""
        self._session_last_deferral[session_id] = time.time()

    def record_call(self, session_id: str) -> None:
        """Record that a tool call was attempted in the session.

        Also clears the sibling deferral window, since a successful call
        means the turn has progressed past the deferral point.
        """
        self._session_call_counts[session_id] = (
            self._session_call_counts.get(session_id, 0) + 1
        )
        # A successful call closes the sibling window
        self._session_last_deferral.pop(session_id, None)

    def get_call_count(self, session_id: str) -> int:
        """Get the number of tool calls recorded for a session."""
        return self._session_call_counts.get(session_id, 0)

    def resolve(
        self,
        deferral_id: str,
        resolution: str,
        resolved_by: str = "",
    ) -> DeferralRecord | None:
        """Resolve a deferred decision.

        Args:
            deferral_id: The deferral to resolve.
            resolution: "approved", "denied", or "timeout".
            resolved_by: Who resolved (user_id or "timeout").

        Returns:
            The resolved DeferralRecord, or None if not found.
        """
        record = self._deferrals.get(deferral_id)
        if record is None:
            return None
        record.resolution = resolution
        record.resolved_at = time.time()
        record.resolved_by = resolved_by
        return record

    def check_timeouts(self, timeout_action: str = "deny") -> list[DeferralRecord]:
        """Check for expired deferrals and resolve them.

        Returns list of newly timed-out records.
        """
        timed_out: list[DeferralRecord] = []
        for record in self._deferrals.values():
            if not record.is_resolved and record.is_expired:
                record.resolution = timeout_action
                record.resolved_at = time.time()
                record.resolved_by = "timeout"
                timed_out.append(record)
        return timed_out

    def get(self, deferral_id: str) -> DeferralRecord | None:
        """Get a deferral record by ID."""
        return self._deferrals.get(deferral_id)

    def reset_session(self, session_id: str) -> None:
        """Clear call count tracking for a session."""
        self._session_call_counts.pop(session_id, None)
        self._session_last_deferral.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._deferrals)
