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
            Always set by :meth:`TokenStore.issue`, including for a call
            carrying no parameters, which hashes the empty mapping.  The
            parameters hashed are the EFFECTIVE ones: what the tool will
            actually be invoked with, after any declared parameter
            transformation.  A grant is a grant to run one specific call.
        effective_parameters: The parameters ``parameters_hash`` was taken
            over, retained so the execution path can invoke the callable with
            exactly what was authorized without re-deriving it from policy.
        requested_parameters_hash: SHA-256 of the parameters the caller
            SUBMITTED to ``authorize()``, before any transformation.  Equal
            to ``parameters_hash`` unless a transformation rewrote something.
            It exists so that a caller who hands
            :meth:`AuthorizationGate.execute` the parameters it asked with is
            recognized as presenting this grant rather than a different call.
            It is never an alternative binding: whichever of the two a caller
            presents, the call that runs is the effective one, and anything
            matching neither is rejected exactly as before.
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
    effective_parameters: dict[str, Any] | None = None
    requested_parameters_hash: str = ""

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
        requested_parameters: dict[str, Any] | None = None,
    ) -> ExecutionToken:
        """Issue a new execution token.

        ``parameters`` are the EFFECTIVE parameters: whatever the gate has
        decided the tool will actually run with.  They are both hashed into
        the binding and retained on the token.  ``requested_parameters`` are
        what the caller asked with, and only their hash is kept; when omitted
        they are the same thing, which is the common case.
        """
        effective = dict(parameters or {})
        token = ExecutionToken(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            scope=scope or {},
            # G2: always bind, including the empty call.  A token issued
            # with no parameters used to carry no hash, which made it a token
            # for any parameters at all.
            parameters_hash=ExecutionToken.hash_parameters(effective),
            _ttl_seconds=ttl or self._default_ttl,
            # E1: the grant carries the call it is a grant for, not only a
            # hash of it, so the execution path never has to reconstruct it.
            effective_parameters=effective,
            requested_parameters_hash=ExecutionToken.hash_parameters(
                dict(requested_parameters)
                if requested_parameters is not None
                else effective
            ),
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
            parameters: The parameters the call will run with.  Must be the
                parameters the token was issued for.  ``None`` and ``{}`` are
                the same call and match a token issued for the empty call.

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
        # G2: unconditional.  There is no combination of empty parameters and
        # empty stored hash that skips the comparison, because the empty call
        # has a hash of its own.
        expected = ExecutionToken.hash_parameters(parameters or {})
        if expected != token.parameters_hash:
            raise TokenInvalidError("Parameter hash mismatch -- token is operation-bound")
        token.consume()
        return token

    def get(self, token_id: TokenId) -> ExecutionToken | None:
        """Look a token up WITHOUT validating, consuming, or mutating it.

        Read-only, and used only by the evidence path: an execution
        confirmation must be able to check what a token was issued for, after
        the token has already been consumed, without touching its lifecycle.
        Never call this to decide anything.  Authorization reads tokens through
        :meth:`validate_and_consume`, which is the only path that may consume.
        """
        return self._tokens.get(token_id)

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
