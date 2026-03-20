"""AgentLock exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentlock.types import AuditId, DenialReason, RoleName


class AgentLockError(Exception):
    """Base exception for all AgentLock errors."""


class DeniedError(AgentLockError):
    """Tool call was denied by the authorization gate.

    Attributes:
        reason: Standardized denial code.
        detail: Human-readable explanation.
        required_role: Role needed for access, if applicable.
        current_role: Caller's current role, if known.
        suggestion: Actionable guidance for the caller.
        audit_id: Audit record identifier for this denial.
    """

    def __init__(
        self,
        reason: DenialReason | str,
        detail: str = "",
        *,
        required_role: RoleName | None = None,
        current_role: RoleName | None = None,
        suggestion: str = "",
        audit_id: AuditId | None = None,
    ) -> None:
        self.reason = str(reason.value if hasattr(reason, "value") else reason)
        self.detail = detail
        self.required_role = required_role
        self.current_role = current_role
        self.suggestion = suggestion
        self.audit_id = audit_id
        super().__init__(self._format())

    def _format(self) -> str:
        parts = [f"denied: {self.reason}"]
        if self.detail:
            parts.append(self.detail)
        return " — ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the AgentLock denial response format."""
        d: dict[str, Any] = {
            "status": "denied",
            "reason": self.reason,
        }
        if self.required_role:
            d["required_role"] = self.required_role
        if self.current_role:
            d["current_role"] = self.current_role
        if self.suggestion:
            d["suggestion"] = self.suggestion
        if self.audit_id:
            d["audit_id"] = self.audit_id
        return d


class AuthenticationRequiredError(DeniedError):
    """Caller must authenticate before this tool can execute."""

    def __init__(self, auth_methods: list[str] | None = None, **kwargs: Any) -> None:
        self.auth_methods = auth_methods or []
        super().__init__(reason="not_authenticated", **kwargs)


class InsufficientRoleError(DeniedError):
    """Caller's role does not include required permissions."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="insufficient_role", **kwargs)


class ScopeViolationError(DeniedError):
    """Request exceeds the caller's data boundary or record limits."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="scope_violation", **kwargs)


class RateLimitedError(DeniedError):
    """Caller has exceeded rate limits for this tool."""

    def __init__(
        self,
        retry_after_seconds: int | None = None,
        **kwargs: Any,
    ) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(reason="rate_limited", **kwargs)


class SessionExpiredError(DeniedError):
    """Session has expired; re-authentication required."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="session_expired", **kwargs)


class ApprovalRequiredError(DeniedError):
    """Human approval is required before execution."""

    def __init__(
        self,
        channel: str = "push_notification",
        **kwargs: Any,
    ) -> None:
        self.channel = channel
        super().__init__(reason="approval_required", **kwargs)


class TrustDegradedError(DeniedError):
    """Session trust has been degraded by untrusted content in context."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="trust_degraded", **kwargs)


class UnattributedContextError(DeniedError):
    """Context contains entries without provenance attribution."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="unattributed_context", **kwargs)


class MemoryWriteDeniedError(DeniedError):
    """Memory write blocked by policy."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="memory_write_denied", **kwargs)


class MemoryReadDeniedError(DeniedError):
    """Memory read blocked by policy."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="memory_read_denied", **kwargs)


class MemoryRetentionExceededError(DeniedError):
    """Memory entry count exceeds retention limits."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="memory_retention_exceeded", **kwargs)


class MemoryProhibitedContentError(DeniedError):
    """Memory content matches prohibited patterns."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="memory_prohibited_content", **kwargs)


class MemoryConfirmationRequiredError(DeniedError):
    """User confirmation required for memory write."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(reason="memory_confirmation_required", **kwargs)


class TokenError(AgentLockError):
    """Base for token-related errors."""


class TokenInvalidError(TokenError):
    """Token is malformed or unrecognized."""


class TokenExpiredError(TokenError):
    """Token has passed its expiry time."""


class TokenReplayedError(TokenError):
    """Token has already been consumed (single-use enforcement)."""


class SchemaValidationError(AgentLockError):
    """AgentLock permissions block failed validation."""


class ConfigurationError(AgentLockError):
    """Library misconfiguration."""
