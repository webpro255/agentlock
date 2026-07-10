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
    "parse_version",
    "version_at_least",
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
    "LineagePolicyConfig",
    "ActionClassConfig",
    "ToolDefinition",
]

SCHEMA_VERSION = "1.4"


def parse_version(version: str) -> tuple[int, ...] | None:
    """Parse a dotted schema version into an integer tuple.

    ``None`` when the version is not a plain dotted-integer string.  Callers
    must treat that as "unknown", never as "old".

    NEVER compare version strings directly.  ``"1.10" >= "1.3"`` is ``False``
    lexicographically, because ``"1"`` sorts before ``"3"``.  That comparison
    was live at three sites in policy.py and silently disabled the session
    write-gate, parameter lineage, and novel lineage for any ``1.10+`` block.
    """
    parts = version.strip().split(".")
    out: list[int] = []
    for part in parts:
        if not part.isdigit():  # rejects "", "-1", "1a", "beta"
            return None
        out.append(int(part))
    return tuple(out) if out else None


def version_at_least(version: str, minimum: tuple[int, ...]) -> bool:
    """Is ``version`` at least ``minimum``?  Numeric, component-wise.

    FAILS CLOSED.  An unparseable version returns ``True``, so a malformed
    permission block still runs the lineage gate rather than skipping it.
    The guards this feeds are all of the form
    ``if policy_enabled and version_at_least(...)`` — enforcement, not
    exemption — so "unknown version" must mean "enforce", never "skip".
    """
    parsed = parse_version(version)
    if parsed is None:
        return True
    width = max(len(parsed), len(minimum))
    padded = parsed + (0,) * (width - len(parsed))
    floor = minimum + (0,) * (width - len(minimum))
    return padded >= floor


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
    first_call_any_risk: bool = False
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


class LineagePolicyConfig(BaseModel):
    """Governs provenance-lineage gating of tool calls (v1.3).

    A tool is gated purely on the *provenance* of what is already in the
    session's context window — not on the content of its parameters.  If
    untrusted content (authority ``UNTRUSTED``) has entered context, a
    gated action (financial / external / bulk) is blocked.  This is the
    opposite of a content rule: it never inspects the payload, only where
    the session's context came from.

    When ``require_post_authoritative`` is True, only untrusted content
    that entered *after* the last authoritative (user/system) message
    taints the action — an untrusted document read before the user's
    instruction does not, but one read after it does.
    """

    enabled: bool = False
    gate_financial: bool = True
    gate_external: bool = True
    gate_bulk: bool = True
    gate_account_modification: bool = True
    gate_consequential: bool = True

    # v1.4 selective action-class gating. ``is_consequential`` is a mixed
    # bucket of {delete, reserve, membership change}: ``reserve`` is a
    # value-CARRYING write, whose attacker-chosen target is already covered
    # by parameter/novel lineage, while ``delete`` and membership change are
    # value-FREE — they admit malice with no attacker-chosen parameter for
    # per-value lineage to trace.  Splitting them lets a deployment set
    # ``gate_consequential=False`` (recovering the utility lost to gating
    # every consequential write on any session taint) while keeping the
    # value-free classes taint-gated.  Both default True, so an existing
    # config that only sets ``gate_consequential`` is unchanged.
    gate_deletion: bool = True
    gate_membership_change: bool = True

    decision: str = "step_up"  # "step_up" | "defer" | "deny"
    require_post_authoritative: bool = True

    # v1.3 ablation — session-level taint write-gate enforcement. When False,
    # the call-time "untrusted_lineage" block is NOT enforced (the write is
    # allowed to proceed), but the decision it WOULD have made is still
    # computed and surfaced as a shadow ("session_gate_shadow"), and all
    # provenance/taint recording, parameter-lineage, and deferred-commit
    # remain fully active. This removes ONE enforcement mechanism while
    # keeping the instrumentation, for ablation.
    session_write_gate: bool = True

    # v1.3 Feature 2 — parameter lineage. Independent of the write-gating
    # flags above: when enabled, EVERY tool call (reads included) is checked
    # for a parameter value that originated in untrusted context but not in
    # the authoritative user request/config. Targets read-goal attacks that
    # write-gating is structurally blind to.
    param_lineage_enabled: bool = False
    param_lineage_action: str = "deny"  # "deny" | "step_up" | "log"
    param_lineage_min_len: int = 6      # min length for a plain-string match

    # v1.4 — novel lineage. Sibling of parameter lineage: classifies a target
    # token as trusted / untrusted / NOVEL by EXACT token-set membership. A
    # NOVEL token traces to neither the authoritative nor the untrusted
    # context — a target the session cannot account for. Independent of the
    # param_lineage_* flags; off by default.
    novel_lineage_enabled: bool = False
    novel_lineage_action: str = "step_up"  # "deny" | "step_up" | "log"

    model_config = {"extra": "forbid"}


class ActionClassConfig(BaseModel):
    """Declares a tool's action class in the trusted permission block (v1.4).

    Selective action-class gating expands the *trusted-assertion surface*.
    Under a uniform write-gate, the ``is_*`` flags a caller passes to
    ``authorize()`` are safe to get wrong at the sub-class level: any
    consequential write is gated regardless.  Once ``gate_consequential`` can
    be turned off independently of ``gate_deletion`` /
    ``gate_membership_change``, a caller that simply *omits* ``is_deletion``
    would slip a deletion past the taint gate.  The action class therefore
    lives here — registered with the tool, on the trusted side — rather than
    only in the per-call, caller-asserted kwarg.

    Resolution is **monotone OR**: the effective class is
    ``declared or caller_asserted``.  A declaration can only ever *add*
    gating.  A tool declared ``is_deletion=True`` cannot be escaped by
    omitting the kwarg, and an absent (or False) declaration can never cancel
    a class the caller did assert.  There is deliberately no way to use this
    block to switch a class *off*; ``gate_*`` on ``LineagePolicyConfig`` is
    the knob for that, and it lives in trusted config too.

    THE POLARITY RULE — the invariant future contributors must not break:

    * **Gating-ADDING** signals (``is_deletion``, ``is_membership_change``)
      may originate from the trusted block OR the caller's ``authorize()``
      kwarg, and combine by OR.  A wrong or missing one can only under-gate
      the tool relative to a correct one, and the caller can always add.
    * **Gating-REMOVING** signals (``is_value_carrying``) may originate
      **ONLY** from the trusted block — never a caller kwarg — and may weaken
      **ONLY** the residual ``is_consequential`` disjunct, never a named
      class.  Admitting a removing signal from the caller, or letting one
      reach the deletion / membership terms, reintroduces exactly the bypass
      this design closes.

    Classify every future action class into one polarity before adding it.

    ``is_value_carrying`` is a positive, trusted, auditable claim that this
    tool's consequential effect is fully determined by an attacker-choosable
    parameter value — so parameter/novel lineage already covers it and
    session taint need not.  It exists because ``is_consequential`` is not a
    class but the *residual bucket* ("consequential, but none of the named
    classes"), which makes ``gate_consequential=False`` un-gate an open-ended
    set: every consequential tool nobody got around to classifying.  Requiring
    a positive declaration to un-gate means an unclassified consequential
    action fails CLOSED (stays gated, costing recoverable utility) rather
    than OPEN (a silent hole on precisely the value-free classes for which
    session taint is the only available signal).

    Un-gating therefore takes two affirmative acts: the deployment sets
    ``gate_consequential=False``, and the tool declares
    ``is_value_carrying=True``.  Omitting either leaves the action gated.
    """

    is_deletion: bool = False
    is_membership_change: bool = False
    is_value_carrying: bool = False

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _value_carrying_excludes_value_free(self) -> ActionClassConfig:
        """A value-free class cannot also be value-carrying.

        Catches the mislabel at ``register_tool()`` — a startup
        ``ValidationError`` instead of a runtime fail-open.
        """
        if self.is_value_carrying and (
            self.is_deletion or self.is_membership_change
        ):
            contradicts = "is_deletion" if self.is_deletion else (
                "is_membership_change"
            )
            raise ValueError(
                f"action_class declares is_value_carrying=True together with "
                f"{contradicts}=True. A value-free class has no "
                f"attacker-chosen parameter value for lineage to trace, so it "
                f"cannot be value-carrying. Declare exactly one."
            )
        return self


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
    lineage_policy: LineagePolicyConfig | None = None
    action_class: ActionClassConfig | None = None

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
