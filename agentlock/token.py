"""Single-use, time-limited execution tokens.

Tokens are issued by the authorization gate (Layer 2) and consumed by the
tool execution layer (Layer 3).  The agent never sees or handles tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from agentlock.exceptions import TokenExpiredError, TokenInvalidError, TokenReplayedError
from agentlock.types import TokenId, TokenStatus


def _generate_token_id() -> TokenId:
    return f"atk_{secrets.token_urlsafe(24)}"


@dataclass(slots=True)
class ExecutionToken:
    """A single-use, time-limited, operation-bound execution token.

    Attributes:
        token_id: Unique identifier.
        tool_name: The specific tool this token authorizes.
        user_id: Authenticated identity of the caller.
        role: The role under which this call is authorized.
        scope: Data boundary constraints snapshot.
        parameters_hash: SHA-256 of the serialized call parameters.
        issued_at: Unix timestamp of issuance.
        expires_at: Unix timestamp after which the token is invalid.
        status: Current lifecycle state.
    """

    tool_name: str
    user_id: str
    role: str
    scope: dict[str, Any] = field(default_factory=dict)
    parameters_hash: str = ""
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    token_id: TokenId = field(default_factory=_generate_token_id)
    status: TokenStatus = TokenStatus.ACTIVE
    _ttl_seconds: int = 60

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = self.issued_at + self._ttl_seconds

    @staticmethod
    def hash_parameters(params: dict[str, Any]) -> str:
        """Deterministic SHA-256 of call parameters."""
        import json

        raw = json.dumps(params, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def is_valid(self) -> bool:
        return self.status == TokenStatus.ACTIVE and time.time() < self.expires_at

    def consume(self) -> None:
        """Mark token as used.  Raises on replay or expiry."""
        if self.status == TokenStatus.USED:
            raise TokenReplayedError(f"Token {self.token_id} already consumed")
        if self.status in (TokenStatus.EXPIRED, TokenStatus.REVOKED):
            raise TokenInvalidError(f"Token {self.token_id} is {self.status.value}")
        if time.time() >= self.expires_at:
            self.status = TokenStatus.EXPIRED
            raise TokenExpiredError(f"Token {self.token_id} expired")
        self.status = TokenStatus.USED

    def revoke(self) -> None:
        """Revoke the token before use."""
        self.status = TokenStatus.REVOKED


class TokenStore:
    """In-memory token registry with single-use enforcement.

    Production deployments should replace this with Redis or a database-backed
    store via the ``TokenStoreBackend`` protocol.
    """

    def __init__(self, default_ttl: int = 60) -> None:
        self._tokens: dict[TokenId, ExecutionToken] = {}
        self._default_ttl = default_ttl

    def issue(
        self,
        tool_name: str,
        user_id: str,
        role: str,
        parameters: dict[str, Any] | None = None,
        scope: dict[str, Any] | None = None,
        ttl: int | None = None,
    ) -> ExecutionToken:
        """Issue a new execution token."""
        token = ExecutionToken(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            scope=scope or {},
            parameters_hash=(
                ExecutionToken.hash_parameters(parameters) if parameters else ""
            ),
            _ttl_seconds=ttl or self._default_ttl,
        )
        self._tokens[token.token_id] = token
        return token

    def validate_and_consume(
        self,
        token_id: TokenId,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
    ) -> ExecutionToken:
        """Validate a token and consume it (single-use).

        Args:
            token_id: The token to validate.
            tool_name: Must match the tool the token was issued for.
            parameters: If provided, hash must match the issued hash.

        Returns:
            The consumed token.

        Raises:
            TokenInvalidError: Token not found or wrong tool.
            TokenExpiredError: Token past expiry.
            TokenReplayedError: Token already used.
        """
        token = self._tokens.get(token_id)
        if token is None:
            raise TokenInvalidError(f"Unknown token: {token_id}")
        if token.tool_name != tool_name:
            raise TokenInvalidError(
                f"Token issued for '{token.tool_name}', not '{tool_name}'"
            )
        if parameters and token.parameters_hash:
            expected = ExecutionToken.hash_parameters(parameters)
            if expected != token.parameters_hash:
                raise TokenInvalidError("Parameter hash mismatch — token is operation-bound")
        token.consume()
        return token

    def revoke(self, token_id: TokenId) -> None:
        """Revoke a token."""
        token = self._tokens.get(token_id)
        if token:
            token.revoke()

    def cleanup_expired(self) -> int:
        """Remove expired/used tokens.  Returns count removed."""
        now = time.time()
        expired = [
            tid
            for tid, t in self._tokens.items()
            if t.status != TokenStatus.ACTIVE or now >= t.expires_at
        ]
        for tid in expired:
            if self._tokens[tid].status == TokenStatus.ACTIVE:
                self._tokens[tid].status = TokenStatus.EXPIRED
            del self._tokens[tid]
        return len(expired)

    def __len__(self) -> int:
        return len(self._tokens)
