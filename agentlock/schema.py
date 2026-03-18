"""AgentLock permission schema — Pydantic models for tool authorization.

These models define the ``agentlock`` permissions block that any tool can carry.
Validation is strict: unknown fields are forbidden, enums are enforced, and
deny-by-default semantics mean an empty block still denies everything.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from agentlock.types import (
    ApprovalChannel,
    ApprovalThreshold,
    AuditLogLevel,
    AuthMethod,
    DataBoundary,
    DataClassification,
    RecipientPolicy,
    RedactionMode,
    RiskLevel,
    RoleName,
)

__all__ = [
    "AgentLockPermissions",
    "ScopeConfig",
    "RateLimitConfig",
    "DataPolicyConfig",
    "SessionConfig",
    "AuditConfig",
    "HumanApprovalConfig",
    "ToolDefinition",
]

SCHEMA_VERSION = "1.0"


class ScopeConfig(BaseModel):
    """Constrains what data a tool invocation can access."""

    data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY
    max_records: int | None = Field(default=None, ge=1)
    allowed_recipients: RecipientPolicy = RecipientPolicy.KNOWN_CONTACTS_ONLY

    model_config = {"extra": "forbid"}


class RateLimitConfig(BaseModel):
    """Per-user, per-session rate limiting."""

    max_calls: int = Field(ge=1)
    window_seconds: int = Field(ge=1)

    model_config = {"extra": "forbid"}


class DataPolicyConfig(BaseModel):
    """Data classification and redaction rules."""

    input_classification: DataClassification = DataClassification.PUBLIC
    output_classification: DataClassification = DataClassification.PUBLIC
    prohibited_in_output: list[str] = Field(default_factory=list)
    redaction: RedactionMode = RedactionMode.NONE

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _validate_redaction(self) -> DataPolicyConfig:
        if self.prohibited_in_output and self.redaction == RedactionMode.NONE:
            raise ValueError(
                "redaction must be 'auto' or 'manual' when prohibited_in_output is set"
            )
        return self


class SessionConfig(BaseModel):
    """Session lifetime and re-authentication rules."""

    max_duration_seconds: int = Field(default=900, ge=1)
    require_reauth_on_scope_change: bool = True

    model_config = {"extra": "forbid"}


class AuditConfig(BaseModel):
    """Audit logging requirements.  Audit is never optional."""

    log_level: AuditLogLevel = AuditLogLevel.STANDARD
    include_parameters: bool = True
    retention_days: int = Field(default=90, ge=1)

    model_config = {"extra": "forbid"}


class HumanApprovalConfig(BaseModel):
    """Human-in-the-loop approval gate."""

    required: bool = False
    threshold: ApprovalThreshold = ApprovalThreshold.ALWAYS
    channel: ApprovalChannel = ApprovalChannel.PUSH_NOTIFICATION

    model_config = {"extra": "forbid"}


class AgentLockPermissions(BaseModel):
    """The ``agentlock`` permissions block attached to a tool definition.

    This is the core of the specification.  Every field has a secure default
    so that an empty permissions block denies by default.

    Example::

        perms = AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        )
    """

    version: str = SCHEMA_VERSION
    risk_level: RiskLevel = RiskLevel.HIGH
    requires_auth: bool = True
    auth_methods: list[AuthMethod] = Field(
        default_factory=lambda: [AuthMethod.OAUTH2]
    )
    allowed_roles: list[RoleName] = Field(default_factory=list)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig | None = None
    data_policy: DataPolicyConfig = Field(default_factory=DataPolicyConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    human_approval: HumanApprovalConfig = Field(
        default_factory=HumanApprovalConfig
    )

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _deny_by_default(self) -> AgentLockPermissions:
        """Ensure deny-by-default: no roles = no access (unless risk is none)."""
        if not self.allowed_roles and self.risk_level != RiskLevel.NONE:
            # This is valid — it means "denied to everyone" which is the
            # secure default.  We leave it as-is; the gate will enforce.
            pass
        return self

    def requires_human_approval(self) -> bool:
        """Return True if human approval is needed for any invocation."""
        return self.human_approval.required

    def to_json_schema_block(self) -> dict[str, Any]:
        """Export as a dict suitable for embedding in a tool JSON definition."""
        return self.model_dump(mode="json", exclude_none=True)


class ToolDefinition(BaseModel):
    """A complete tool definition with AgentLock permissions.

    This wraps the standard tool schema (name + description + parameters)
    with the ``agentlock`` permissions block.
    """

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    agentlock: AgentLockPermissions = Field(
        default_factory=AgentLockPermissions
    )

    model_config = {"extra": "allow"}
