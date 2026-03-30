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
    ContextAuthority,
    ContextSource,
    DataBoundary,
    DataClassification,
    DegradationEffect,
    MemoryPersistence,
    MemoryWriter,
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
    "SourceAuthorityConfig",
    "DegradationTrigger",
    "TrustDegradationConfig",
    "ContextPolicyConfig",
    "MemoryRetentionConfig",
    "MemoryPolicyConfig",
    "DeferPolicyConfig",
    "StepUpPolicyConfig",
    "TransformationConfig",
    "ModifyPolicyConfig",
    "ToolDefinition",
]

SCHEMA_VERSION = "1.2"


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


class SourceAuthorityConfig(BaseModel):
    """Maps a context source to an authority level."""

    source: ContextSource
    authority: ContextAuthority

    model_config = {"extra": "forbid"}


class DegradationTrigger(BaseModel):
    """Defines when and how trust degrades."""

    source: ContextSource
    effect: DegradationEffect

    model_config = {"extra": "forbid"}


class TrustDegradationConfig(BaseModel):
    """Controls dynamic trust degradation."""

    enabled: bool = True
    triggers: list[DegradationTrigger] = Field(default_factory=list)
    minimum_authority: ContextAuthority = ContextAuthority.DERIVED
    allow_cascade_to_untrusted: bool = False

    model_config = {"extra": "forbid"}


def _default_source_authorities() -> list[SourceAuthorityConfig]:
    sa = SourceAuthorityConfig
    cs = ContextSource
    ca = ContextAuthority
    return [
        sa(source=cs.USER_MESSAGE, authority=ca.AUTHORITATIVE),
        sa(source=cs.SYSTEM_PROMPT, authority=ca.AUTHORITATIVE),
        sa(source=cs.TOOL_OUTPUT, authority=ca.DERIVED),
        sa(source=cs.RETRIEVED_DOCUMENT, authority=ca.UNTRUSTED),
        sa(source=cs.WEB_CONTENT, authority=ca.UNTRUSTED),
        sa(source=cs.AGENT_MEMORY, authority=ca.DERIVED),
        sa(source=cs.PEER_AGENT, authority=ca.UNTRUSTED),
    ]


class ContextPolicyConfig(BaseModel):
    """Governs what enters context and with what authority."""

    source_authorities: list[SourceAuthorityConfig] = Field(
        default_factory=_default_source_authorities
    )
    trust_degradation: TrustDegradationConfig = Field(
        default_factory=TrustDegradationConfig
    )
    reject_unattributed: bool = True

    model_config = {"extra": "forbid"}


class MemoryRetentionConfig(BaseModel):
    """Retention limits for persistent memory."""

    max_age_seconds: int = Field(default=86400, ge=0)
    max_entries: int = Field(default=100, ge=1)

    model_config = {"extra": "forbid"}


class MemoryPolicyConfig(BaseModel):
    """Governs what the agent can persist to memory."""

    persistence: MemoryPersistence = MemoryPersistence.NONE
    allowed_writers: list[MemoryWriter] = Field(
        default_factory=lambda: [MemoryWriter.SYSTEM]
    )
    allowed_readers: list[MemoryWriter] = Field(
        default_factory=lambda: [MemoryWriter.SYSTEM]
    )
    retention: MemoryRetentionConfig = Field(
        default_factory=MemoryRetentionConfig
    )
    prohibited_content: list[str] = Field(default_factory=list)
    require_write_confirmation: bool = True
    confirmation_channel: ApprovalChannel = ApprovalChannel.IN_APP

    model_config = {"extra": "forbid"}


class DeferPolicyConfig(BaseModel):
    """Governs when authorization is suspended pending resolution (v1.2).

    DEFER acknowledges uncertainty: the gate cannot confidently allow or
    deny.  The action is suspended until resolved by human review,
    additional context, or timeout.
    """

    enabled: bool = False
    first_call_high_risk: bool = True
    scan_plus_tool: bool = True
    trust_below_threshold: bool = True
    timeout_seconds: int = Field(default=60, ge=1)
    timeout_action: str = "deny"  # "deny" or "escalate"

    model_config = {"extra": "forbid"}


class StepUpPolicyConfig(BaseModel):
    """Governs when human approval is dynamically required (v1.2).

    STEP_UP pauses execution and notifies a human reviewer.  Unlike the
    static ``human_approval`` config, STEP_UP is triggered by session
    state (hardening signals, PII tool count, prior denials).
    """

    enabled: bool = False
    hardening_elevated_high_risk: bool = True
    multi_pii_tool_session: bool = True
    multi_pii_tool_threshold: int = Field(default=2, ge=1)
    post_denial_retry: bool = True
    timeout_seconds: int = Field(default=120, ge=1)
    timeout_action: str = "deny"
    pii_tool_names: list[str] = Field(default_factory=lambda: [
        "query_database", "search_contacts", "check_balance",
    ])

    model_config = {"extra": "forbid"}


class TransformationConfig(BaseModel):
    """A single parameter or output transformation rule (v1.2)."""

    field: str  # parameter field name or "output"
    action: str  # redact_pii, restrict_domain, whitelist_path, cap_records, custom
    config: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class ModifyPolicyConfig(BaseModel):
    """Governs parameter and output transformations (v1.2).

    When enabled, the gate applies transformations to tool parameters
    or outputs before/after execution.  The tool still runs, but its
    inputs or outputs are sanitized.
    """

    enabled: bool = False
    transformations: list[TransformationConfig] = Field(default_factory=list)
    apply_when_hardening_active: bool = True

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
    context_policy: ContextPolicyConfig | None = None
    memory_policy: MemoryPolicyConfig | None = None
    modify_policy: ModifyPolicyConfig | None = None
    defer_policy: DeferPolicyConfig | None = None
    stepup_policy: StepUpPolicyConfig | None = None

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
