"""Policy evaluation engine.

Evaluates an AgentLock permissions block against a request context to
produce an allow/deny decision with a specific reason.

The engine runs two independent filter chains after base authorization:

1. **Injection filter** — checks tool call parameters for adversarial
   patterns (reconnaissance, schema enumeration, prompt extraction,
   social engineering).  Runs first.  A blocked request never reaches
   the PII filter.

2. **PII filter** — checks the caller's ``max_output_classification``
   against the tool's ``output_classification``.  Blocks at the gate
   if clearance is too low.  Output redaction in ``execute()`` remains
   as the defense-in-depth backup.

These filters share no logic and do not affect each other's decisions.
Trust degradation (v1.1 context authority) runs independently of both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentlock.context import ContextState
from agentlock.schema import AgentLockPermissions
from agentlock.types import (
    ApprovalThreshold,
    DataBoundary,
    DataClassification,
    DegradationEffect,
    DenialReason,
    RiskLevel,
)


@dataclass(slots=True)
class RequestContext:
    """Context for a single tool call request.

    Attributes:
        user_id: Authenticated identity (empty = unauthenticated).
        role: Caller's role.
        session_id: Active session ID.
        data_boundary: Requested data scope.
        record_count: Number of records requested.
        recipient: For outbound tools, the target recipient.
        is_bulk: Whether this is a bulk operation.
        is_external: Whether this sends data externally.
        is_financial: Whether this involves financial operations.
        amount: Financial amount, if applicable.
        metadata: Additional context.
    """

    user_id: str = ""
    role: str = ""
    session_id: str = ""
    data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY
    record_count: int = 1
    recipient: str = ""
    is_bulk: bool = False
    is_external: bool = False
    is_financial: bool = False
    amount: float = 0.0
    max_output_classification: DataClassification | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    context_state: ContextState | None = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.user_id)


@dataclass(slots=True)
class PolicyDecision:
    """Result of policy evaluation."""

    allowed: bool
    reason: DenialReason | None = None
    detail: str = ""
    required_role: str = ""
    suggestion: str = ""
    needs_auth: bool = False
    needs_approval: bool = False
    approval_channel: str = ""


# ---------------------------------------------------------------------------
# Injection filter patterns
# ---------------------------------------------------------------------------
# These patterns detect adversarial parameter content: reconnaissance,
# schema enumeration, prompt extraction, and social engineering.  They
# are intentionally simple and conservative — false positives are
# preferable to missed injections.

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Reconnaissance / schema enumeration
    (
        "reconnaissance",
        re.compile(
            r"(?i)"
            r"(?:show\s+(?:all\s+)?(?:tables|databases|schemas|columns|users))"
            r"|(?:information_schema)"
            r"|(?:pg_catalog)"
            r"|(?:sys\.(?:tables|columns|objects))"
            r"|(?:sqlite_master)"
            r"|(?:DESCRIBE\s+\w+)"
            r"|(?:SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+1\s*=\s*1)",
        ),
    ),
    # Prompt / system instruction extraction
    (
        "prompt_extraction",
        re.compile(
            r"(?i)"
            r"(?:(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+"
            r"(?:instructions?|prompts?|rules?))"
            r"|(?:(?:repeat|print|show|reveal|output)\s+(?:your\s+)?"
            r"(?:system\s+)?(?:prompt|instructions?|rules?))"
            r"|(?:what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions?)",
        ),
    ),
    # Social engineering — impersonation / authority assertion
    (
        "social_engineering",
        re.compile(
            r"(?i)"
            r"(?:(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:admin|administrator|root|owner|ceo|cto))"
            r"|(?:(?:acting\s+as|on\s+behalf\s+of|authorized\s+by)\s+(?:the\s+)?"
            r"(?:admin|administrator|system|owner))"
            r"|(?:emergency\s+(?:override|access|mode))"
            r"|(?:maintenance\s+mode\s+(?:enabled|activated))",
        ),
    ),
    # Direct injection — command separators, escapes
    (
        "command_injection",
        re.compile(
            r"(?:"
            r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|EXEC|EXECUTE)\b"
            r"|--\s*$"
            r"|/\*.*\*/"
            r"|(?:UNION\s+(?:ALL\s+)?SELECT)"
            r")",
            re.IGNORECASE,
        ),
    ),
]

# Classification hierarchy — shared by the PII filter
_CLASSIFICATION_ORDER = [
    DataClassification.PUBLIC,
    DataClassification.INTERNAL,
    DataClassification.CONFIDENTIAL,
    DataClassification.MAY_CONTAIN_PII,
    DataClassification.CONTAINS_PII,
    DataClassification.CONTAINS_PHI,
    DataClassification.CONTAINS_FINANCIAL,
]


class InjectionFilter:
    """Checks tool call parameters for adversarial injection patterns.

    This filter is stateless and shares no logic with the PII filter.
    """

    def __init__(
        self,
        patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        self._patterns = patterns if patterns is not None else _INJECTION_PATTERNS

    def evaluate(
        self,
        parameters: dict[str, Any] | None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision | None:
        """Check parameters for injection patterns.

        Returns:
            PolicyDecision denial if injection detected, None if clean.
        """
        if not parameters:
            return None

        text_values = self._extract_text_values(parameters)
        if metadata:
            text_values.extend(self._extract_text_values(metadata))

        for text in text_values:
            for pattern_name, pattern in self._patterns:
                if pattern.search(text):
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.DATA_POLICY_VIOLATION,
                        detail=(
                            f"Parameter content matches {pattern_name} "
                            f"injection pattern."
                        ),
                        suggestion=(
                            "The request contains content that resembles "
                            "an injection attack and has been blocked."
                        ),
                    )
        return None

    @staticmethod
    def _extract_text_values(d: dict[str, Any]) -> list[str]:
        """Recursively extract all string values from a dict."""
        texts: list[str] = []
        for v in d.values():
            if isinstance(v, str):
                texts.append(v)
            elif isinstance(v, dict):
                texts.extend(InjectionFilter._extract_text_values(v))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        texts.append(item)
                    elif isinstance(item, dict):
                        texts.extend(InjectionFilter._extract_text_values(item))
        return texts


class PiiFilter:
    """Checks caller's data classification clearance against tool output.

    This filter is stateless and shares no logic with the injection filter.
    """

    def evaluate(
        self,
        caller_clearance: DataClassification | None,
        tool_output_classification: DataClassification,
    ) -> PolicyDecision | None:
        """Check if the caller's clearance permits access to this tool's output.

        Returns:
            PolicyDecision denial if clearance too low, None if sufficient.
        """
        if caller_clearance is None:
            return None

        if (
            tool_output_classification in _CLASSIFICATION_ORDER
            and caller_clearance in _CLASSIFICATION_ORDER
        ):
            tool_idx = _CLASSIFICATION_ORDER.index(tool_output_classification)
            caller_idx = _CLASSIFICATION_ORDER.index(caller_clearance)
            if tool_idx > caller_idx:
                return PolicyDecision(
                    allowed=False,
                    reason=DenialReason.DATA_POLICY_VIOLATION,
                    detail=(
                        f"Tool output classification "
                        f"'{tool_output_classification.value}' exceeds "
                        f"caller's clearance "
                        f"'{caller_clearance.value}'."
                    ),
                    suggestion=(
                        "Request access to a higher data classification, "
                        "or use a tool with a lower output classification."
                    ),
                )
        return None


class PolicyEngine:
    """Evaluates AgentLock permissions against a request context.

    Runs three independent evaluation stages:

    1. **Base authorization** — auth, role, scope, records, approval
    2. **Injection filter** — parameter content analysis (blocks first)
    3. **PII filter** — data classification clearance check
    4. **Trust degradation** — v1.1 context authority (independent)

    Stages 2 and 3 are fully decoupled: they share no logic, no state,
    and no code paths.  A request blocked by the injection filter never
    reaches the PII filter.
    """

    def __init__(self) -> None:
        self._injection_filter = InjectionFilter()
        self._pii_filter = PiiFilter()

    @property
    def injection_filter(self) -> InjectionFilter:
        """Access the injection filter for testing or customization."""
        return self._injection_filter

    @property
    def pii_filter(self) -> PiiFilter:
        """Access the PII filter for testing or customization."""
        return self._pii_filter

    def evaluate(
        self,
        permissions: AgentLockPermissions,
        context: RequestContext,
    ) -> PolicyDecision:
        """Run all policy checks in order.  First failure wins.

        Check order:
        1. Risk level none → auto-allow
        2. Authentication required
        3. Role check
        4. Scope / data boundary
        5. Max records
        --- filter boundary ---
        6. Injection filter (parameter content analysis)
        7. PII filter (data classification clearance)
        --- filter boundary ---
        8. Recipient policy
        9. Human approval
        10. Trust degradation (v1.1)
        11. Unattributed context (v1.1)
        """
        # 1. Risk level none → auto-allow with minimal logging
        if permissions.risk_level == RiskLevel.NONE:
            return PolicyDecision(allowed=True)

        # 2. Authentication
        if permissions.requires_auth and not context.is_authenticated:
            return PolicyDecision(
                allowed=False,
                reason=DenialReason.NOT_AUTHENTICATED,
                detail="Authentication required before this tool can execute.",
                needs_auth=True,
                suggestion="Complete authentication via the out-of-band channel.",
            )

        # 3. Role check — empty allowed_roles means denied to everyone
        if permissions.allowed_roles:
            if context.role not in permissions.allowed_roles:
                return PolicyDecision(
                    allowed=False,
                    reason=DenialReason.INSUFFICIENT_ROLE,
                    detail=f"Role '{context.role}' not in allowed roles.",
                    required_role=", ".join(permissions.allowed_roles),
                    suggestion=(
                        f"This operation requires one of: "
                        f"{', '.join(permissions.allowed_roles)}"
                    ),
                )
        else:
            # No roles defined = deny by default (risk_level NONE already returned above)
            return PolicyDecision(
                allowed=False,
                reason=DenialReason.NO_PERMISSIONS,
                detail="No roles configured — denied by default.",
                suggestion="Add allowed_roles to this tool's agentlock permissions.",
            )

        # 4. Data boundary
        scope = permissions.scope
        boundary_order = [
            DataBoundary.AUTHENTICATED_USER_ONLY,
            DataBoundary.TEAM,
            DataBoundary.ORGANIZATION,
        ]
        if (
            context.data_boundary in boundary_order
            and scope.data_boundary in boundary_order
        ):
            requested_idx = boundary_order.index(context.data_boundary)
            allowed_idx = boundary_order.index(scope.data_boundary)
            if requested_idx > allowed_idx:
                return PolicyDecision(
                    allowed=False,
                    reason=DenialReason.SCOPE_VIOLATION,
                    detail=(
                        f"Requested boundary '{context.data_boundary.value}' "
                        f"exceeds allowed '{scope.data_boundary.value}'."
                    ),
                    suggestion="Reduce the scope of your request.",
                )

        # 5. Max records
        if scope.max_records and context.record_count > scope.max_records:
            return PolicyDecision(
                allowed=False,
                reason=DenialReason.MAX_RECORDS_EXCEEDED,
                detail=(
                    f"Requested {context.record_count} records; "
                    f"limit is {scope.max_records}."
                ),
                suggestion=(
                    f"Reduce your request to {scope.max_records} records "
                    f"or fewer."
                ),
            )

        # ── Independent filter chains ─────────────────────────────────
        # These two filters are fully decoupled.  A request blocked by
        # the injection filter never reaches the PII filter.

        # 6. Injection filter — parameter content analysis
        injection_decision = self._injection_filter.evaluate(
            context.metadata.get("parameters"),
            context.metadata,
        )
        if injection_decision is not None:
            return injection_decision

        # 7. PII filter — data classification clearance
        pii_decision = self._pii_filter.evaluate(
            context.max_output_classification,
            permissions.data_policy.output_classification,
        )
        if pii_decision is not None:
            return pii_decision

        # ── End filter chains ─────────────────────────────────────────

        # 8. Recipient policy (only if recipient is provided)
        # Detailed validation delegated to the tool or deployer;
        # here we enforce "known_contacts_only" as a marker.
        # Real-world enforcement uses a contacts backend.

        # 9. Human approval
        if permissions.human_approval.required:
            threshold = permissions.human_approval.threshold
            needs_approval = False

            if threshold == ApprovalThreshold.ALWAYS:
                needs_approval = True
            elif (
                threshold == ApprovalThreshold.BULK_OPERATIONS and context.is_bulk
            ):
                needs_approval = True
            elif (
                threshold == ApprovalThreshold.EXTERNAL_COMMUNICATION
                and context.is_external
            ):
                needs_approval = True
            elif (
                threshold == ApprovalThreshold.FINANCIAL_ABOVE_LIMIT
                and context.is_financial
            ):
                needs_approval = True
            elif (
                threshold == ApprovalThreshold.FIRST_INVOCATION_PER_SESSION
                and context.metadata.get("first_invocation", False)
            ):
                # Caller must track "first invocation" externally
                needs_approval = True

            if needs_approval:
                return PolicyDecision(
                    allowed=False,
                    reason=DenialReason.APPROVAL_REQUIRED,
                    detail="Human approval required for this operation.",
                    needs_approval=True,
                    approval_channel=permissions.human_approval.channel.value,
                    suggestion=(
                        f"Approval request sent via "
                        f"{permissions.human_approval.channel.value}."
                    ),
                )

        # 10-11. v1.1 checks — trust degradation and unattributed context
        # These run independently of both filters above.  Trust degradation
        # fires based on session state from notify_context_write(), not
        # from parameter content or PII classification.
        if permissions.version >= "1.1" and context.context_state is not None:
            cs = context.context_state

            # 10. Trust degradation
            if cs.is_degraded and cs.active_effects:
                if DegradationEffect.REQUIRE_APPROVAL in cs.active_effects:
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.TRUST_DEGRADED,
                        detail=(
                            f"Session trust degraded after "
                            f"{cs.degradation_reason} entered context."
                        ),
                        needs_approval=True,
                        suggestion=(
                            "Human approval required because untrusted "
                            "content is in the session context. Start a "
                            "new session to restore full trust."
                        ),
                    )
                if (
                    DegradationEffect.DENY_WRITES in cs.active_effects
                    and permissions.risk_level in (
                        RiskLevel.MEDIUM,
                        RiskLevel.HIGH,
                        RiskLevel.CRITICAL,
                    )
                ):
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.TRUST_DEGRADED,
                        detail=(
                            "Write operations denied — session trust "
                            "degraded after "
                            f"{cs.degradation_reason} entered context."
                        ),
                        suggestion=(
                            "Only read operations are allowed in this "
                            "session."
                        ),
                    )

            # 11. Unattributed context
            ctx_policy = permissions.context_policy
            reject_unattributed = True
            if ctx_policy is not None:
                reject_unattributed = ctx_policy.reject_unattributed

            if reject_unattributed and cs.unattributed_count > 0:
                return PolicyDecision(
                    allowed=False,
                    reason=DenialReason.UNATTRIBUTED_CONTEXT,
                    detail=(
                        f"{cs.unattributed_count} context entries lack "
                        f"provenance."
                    ),
                    suggestion=(
                        "All context entries must have provenance "
                        "attribution."
                    ),
                )

        return PolicyDecision(allowed=True)
