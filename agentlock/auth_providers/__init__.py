"""Pluggable authentication provider backends.

AgentLock does not perform authentication itself — it delegates to
external identity providers.  These adapters standardize the interface.

Authentication MUST occur out-of-band from the agent conversation.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuthProvider(Protocol):
    """Protocol for authentication providers.

    Implementations handle the out-of-band authentication flow and return
    verified identity information to the authorization gate.
    """

    def initiate_auth(
        self, user_hint: str = "", method: str = "oauth2"
    ) -> dict[str, Any]:
        """Start an authentication flow.

        Args:
            user_hint: Optional hint (email, username) to pre-fill.
            method: Authentication method to use.

        Returns:
            Dict with at least ``auth_url`` or ``challenge_id`` for the
            out-of-band flow.
        """
        ...

    def verify(self, token_or_code: str) -> dict[str, Any] | None:
        """Verify an authentication response.

        Args:
            token_or_code: The token, code, or response from the auth flow.

        Returns:
            Dict with ``user_id``, ``role``, and optional ``metadata`` if
            verification succeeds.  None if verification fails.
        """
        ...


class StaticAuthProvider:
    """Static auth provider for development and testing.

    Maps user IDs to roles directly.  NOT for production use.
    """

    def __init__(self, users: dict[str, str]) -> None:
        self._users = users  # user_id → role

    def initiate_auth(
        self, user_hint: str = "", method: str = "oauth2"
    ) -> dict[str, Any]:
        return {"type": "static", "message": "No auth flow needed in static mode."}

    def verify(self, token_or_code: str) -> dict[str, Any] | None:
        # token_or_code is treated as user_id
        role = self._users.get(token_or_code)
        if role is None:
            return None
        return {"user_id": token_or_code, "role": role}
