"""Session management for AgentLock.

Sessions bind an authenticated identity to a scope and lifetime.
Re-authentication is required on expiry or scope change.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentlock.exceptions import SessionConflictError, SessionExpiredError
from agentlock.types import DataBoundary, SessionId


def _generate_session_id() -> SessionId:
    return f"als_{secrets.token_urlsafe(20)}"


@dataclass
class Session:
    """An authenticated session.

    Attributes:
        session_id: Unique session identifier.
        user_id: Verified identity.
        role: Active role for this session.
        data_boundary: Current scope of data access.
        created_at: Unix timestamp.
        expires_at: Unix timestamp.
        metadata: Arbitrary session metadata (device info, IP, etc.).
        known_contacts: Normalized recipient addresses supplied by the
            deployer at session creation.  Never populated from tool or
            model output.
    """

    user_id: str
    role: str
    data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    session_id: SessionId = field(default_factory=_generate_session_id)
    metadata: dict[str, Any] = field(default_factory=dict)
    known_contacts: frozenset[str] = field(default_factory=frozenset)

    _max_duration: int = 900

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + self._max_duration

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def validate(self) -> None:
        """Raise if session is expired."""
        if self.is_expired:
            raise SessionExpiredError(
                detail=f"Session {self.session_id} expired",
                suggestion="Re-authenticate to continue.",
            )

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())


class SessionStore:
    """In-memory session store.

    Production deployments should use Redis, database, or equivalent.

    Args:
        single_session_per_user: G2 candidate B.  When ``True``, ``create``
            refuses a second live session for a user unless the caller passes
            ``replace=True``.  ``False``, the default, keeps the 1.10.3
            behavior: a second session silently becomes the user's session
            for every lookup by user.
    """

    def __init__(self, single_session_per_user: bool = False) -> None:
        self._sessions: dict[SessionId, Session] = {}
        self._user_sessions: dict[str, SessionId] = {}
        self._single_session_per_user = single_session_per_user

    def create(
        self,
        user_id: str,
        role: str,
        data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY,
        max_duration: int = 900,
        metadata: dict[str, Any] | None = None,
        known_contacts: Iterable[str] | None = None,
        replace: bool = False,
    ) -> Session:
        """Create a new authenticated session.

        G2.  With ``replace=True`` the user's live session, if any, is
        destroyed first.  With ``replace=False``, the default, a live session
        for the user raises ``SessionConflictError`` when the store was built
        with ``single_session_per_user=True``, and is silently superseded for
        lookups by user otherwise, as through 1.10.3.
        """
        existing = self.get_by_user(user_id)
        if existing is not None:
            if replace:
                self.destroy(existing.session_id)
            elif self._single_session_per_user:
                raise SessionConflictError(user_id, existing.session_id)
        session = Session(
            user_id=user_id,
            role=role,
            data_boundary=data_boundary,
            metadata=metadata or {},
            known_contacts=frozenset(
                c.strip().casefold() for c in (known_contacts or ())
            ),
            _max_duration=max_duration,
        )
        self._sessions[session.session_id] = session
        self._user_sessions[user_id] = session.session_id
        return session

    def get(self, session_id: SessionId) -> Session | None:
        """Get a session by ID.  Returns None if not found or expired."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.is_expired:
            self.destroy(session_id)
            return None
        return session

    def get_by_user(self, user_id: str) -> Session | None:
        """Get the active session for a user."""
        sid = self._user_sessions.get(user_id)
        if sid is None:
            return None
        return self.get(sid)

    def destroy(self, session_id: SessionId) -> None:
        """Destroy a session."""
        session = self._sessions.pop(session_id, None)
        if session:
            self._user_sessions.pop(session.user_id, None)

    def cleanup_expired(self) -> int:
        """Remove all expired sessions.  Returns count removed."""
        expired = [
            sid for sid, s in self._sessions.items() if s.is_expired
        ]
        for sid in expired:
            self.destroy(sid)
        return len(expired)

    def __len__(self) -> int:
        return len(self._sessions)
