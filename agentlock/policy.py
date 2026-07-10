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
from agentlock.schema import AgentLockPermissions, version_at_least
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
        is_account_modification: Whether this changes account credentials
            or profile (e.g. password / user info).
        is_consequential: Whether this is a destructive / committing action
            that is not financial/external/account-mod (e.g. reserve).  As of
            v1.4 the value-free members of this bucket have their own flags
            below; this one now covers the value-CARRYING remainder.
        is_deletion: Whether this destroys existing state (value-free).
        is_membership_change: Whether this adds/removes a principal from a
            group, channel, or ACL (value-free).
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
    is_account_modification: bool = False
    is_consequential: bool = False
    is_deletion: bool = False
    is_membership_change: bool = False
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
# The lineage gating predicate — ONE definition, TWO enforcement points.
# ---------------------------------------------------------------------------
# This is the single source of truth for "does session taint block this
# action?".  It is consulted at CALL time by ``PolicyEngine.evaluate`` and at
# COMMIT time by ``AuthorizationGate.resolve_deferred_commits``.
#
# It MUST NOT be duplicated.  A deferred write is authorized twice — once when
# the agent asks for it and once at end-of-turn against the complete taint
# state — and if the two sites compute gating differently, a policy that
# un-gates at call time can be silently re-gated at commit time (or, worse,
# the reverse).  That divergence is exactly the defect this module closes:
# before v1.4-defer-policy the commit path denied on taint alone, ignoring
# ``permissions.action_class`` entirely, which made ``gate_consequential=False``
# inert whenever deferred commit was enabled.


@dataclass(frozen=True, slots=True)
class ActionFlags:
    """The caller-asserted action classes for one tool call.

    These are the ``is_*`` kwargs of ``authorize()``, captured so the
    commit-time re-decision can evaluate the SAME disjunct the call-time path
    evaluated.  A deferred record that carries no ActionFlags is treated as
    fail-closed (gated), preserving pre-v1.4 behavior exactly.

    Note the asymmetry, per the polarity rule in ``ActionClassConfig``:
    every field here is gating-ADDING.  ``is_value_carrying`` is absent by
    design — it is gating-REMOVING and is readable only from the trusted
    permission block.
    """

    is_financial: bool = False
    is_external: bool = False
    is_bulk: bool = False
    is_account_modification: bool = False
    is_consequential: bool = False
    is_deletion: bool = False
    is_membership_change: bool = False


def active_lineage_policy(permissions: AgentLockPermissions):
    """The tool's lineage policy if it is live, else ``None``.

    Live means: present, ``enabled``, and on a v1.3+ permission block.  Both
    enforcement points gate on this identical condition.
    """
    lp = permissions.lineage_policy
    if (
        lp is not None
        and lp.enabled
        and version_at_least(permissions.version, (1, 3))
    ):
        return lp
    return None


def resolve_action_classes(
    permissions: AgentLockPermissions, flags: ActionFlags
) -> tuple[bool, bool, bool]:
    """Resolve ``(is_deletion, is_membership_change, is_value_carrying)``.

    Monotone OR for the gating-ADDING classes: the trusted per-tool
    declaration is OR-ed with the caller's assertion, so a declaration can
    only ever ADD gating and an omitted kwarg can never escape a class the
    tool itself declares.

    ``is_value_carrying`` is read ONLY from the trusted block — never from the
    caller — because it is gating-REMOVING.
    """
    ac = permissions.action_class
    is_deletion = bool(ac and ac.is_deletion) or flags.is_deletion
    is_membership_change = (
        bool(ac and ac.is_membership_change) or flags.is_membership_change
    )
    value_carrying = bool(ac and ac.is_value_carrying)
    return is_deletion, is_membership_change, value_carrying


def lineage_gated_action(
    lineage_policy, permissions: AgentLockPermissions, flags: ActionFlags
) -> bool:
    """Is this action subject to the session-taint gate?

    ``is_consequential`` is the RESIDUAL bucket, not a class, so
    ``gate_consequential=False`` would un-gate an open-ended set: every
    consequential tool nobody classified.  Inverted as ``C and (G or not V)``,
    an unclassified consequential action fails CLOSED — un-gating needs BOTH
    the deployment flag AND a positive per-tool ``is_value_carrying``
    declaration.  With ``gate_consequential=True`` this reduces to
    ``is_consequential``, exactly as before v1.4.

    The value-free classes (deletion, membership change) are gated
    independently of ``gate_consequential``: they admit no attacker-chosen
    parameter value for per-value lineage to trace, so session taint is the
    only signal that catches them.
    """
    is_deletion, is_membership_change, value_carrying = resolve_action_classes(
        permissions, flags
    )
    return (
        (lineage_policy.gate_financial and flags.is_financial)
        or (lineage_policy.gate_external and flags.is_external)
        or (lineage_policy.gate_bulk and flags.is_bulk)
        or (
            lineage_policy.gate_account_modification
            and flags.is_account_modification
        )
        or (
            flags.is_consequential
            and (lineage_policy.gate_consequential or not value_carrying)
        )
        or (lineage_policy.gate_deletion and is_deletion)
        or (lineage_policy.gate_membership_change and is_membership_change)
    )


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

        # 10.4. Parameter-lineage gate (v1.3 Feature 2) — runs for EVERY tool
        # call, reads included.  Denies when a parameter value traces to
        # untrusted context but not the authoritative user request (the gate
        # attached the match as context.metadata["param_lineage"]).  Targets
        # read-goal attacks that write-gating cannot see.  Independent of the
        # write-gating flags: fires whenever param_lineage_enabled.
        _lp = permissions.lineage_policy
        if (
            _lp is not None
            and _lp.param_lineage_enabled
            and version_at_least(permissions.version, (1, 3))
        ):
            pmatch = context.metadata.get("param_lineage")
            if pmatch is not None:
                action = _lp.param_lineage_action
                detail = (
                    f"Parameter '{pmatch.get('matched_param')}' carries a value "
                    f"that originated in untrusted context "
                    f"({pmatch.get('untrusted_source_ref')}) and is absent from "
                    f"the authoritative user request. Gated on parameter "
                    f"provenance, not content."
                )
                if action == "log":
                    # Observe-only: do not block, but the caller can see the
                    # match in metadata / audit.  Fall through to later checks.
                    pass
                elif action == "step_up":
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.PARAM_LINEAGE,
                        detail=detail,
                        needs_approval=True,
                        suggestion=(
                            "Human step-up required: a tool parameter came "
                            "from untrusted content, not the user's request."
                        ),
                    )
                else:  # "deny" (default)
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.PARAM_LINEAGE,
                        detail=detail,
                        suggestion=(
                            "The parameter value originated from untrusted "
                            "context. Re-issue using a value from the user's "
                            "own request or trusted configuration."
                        ),
                    )

        # 10.47. Novel-lineage gate (v1.4) — sibling of parameter lineage.
        # Deliberately placed ABOVE the coarse session-taint gate below: a
        # NOVEL target (traceable to neither authoritative nor untrusted
        # context) is a strictly sharper finding than "this session is
        # tainted somewhere".  Running it second would let the session-wide
        # taint verdict mask the per-target one.
        if (
            _lp is not None
            and _lp.novel_lineage_enabled
            and version_at_least(permissions.version, (1, 3))
        ):
            nmatch = context.metadata.get("novel_lineage")
            if nmatch is not None:
                naction = _lp.novel_lineage_action
                ndetail = (
                    f"Parameter '{nmatch.get('matched_param')}' carries token "
                    f"'{nmatch.get('matched_token')}', which traces to neither "
                    f"the authoritative user request nor any untrusted context "
                    f"in this session. The target is novel — unaccounted for by "
                    f"provenance. Gated on token provenance, not content."
                )
                if naction == "log":
                    # Observe-only: the caller can still see the match in
                    # metadata / audit.  Fall through to later checks.
                    pass
                elif naction == "step_up":
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.NOVEL_LINEAGE,
                        detail=ndetail,
                        needs_approval=True,
                        suggestion=(
                            "Human step-up required: the tool's target appears "
                            "in neither the user's request nor any content the "
                            "session read."
                        ),
                    )
                else:  # "deny"
                    return PolicyDecision(
                        allowed=False,
                        reason=DenialReason.NOVEL_LINEAGE,
                        detail=ndetail,
                        suggestion=(
                            "The target originated outside all recorded "
                            "provenance. Re-issue using a target from the "
                            "user's own request or trusted configuration."
                        ),
                    )

        # 10.5. Provenance-lineage gate (v1.3) — independent of everything
        # above.  This rule inspects ONLY the provenance of what is already
        # in the session's context window (the worst-case taint summary the
        # gate attached as context.metadata["lineage"]).  It never looks at
        # the tool call's parameter content.  A gated action (financial /
        # external / bulk) is blocked when untrusted content has entered
        # context.  Inert unless a lineage_policy is present, enabled, and
        # the permission block is v1.3+.
        lineage_policy = active_lineage_policy(permissions)
        if lineage_policy is not None:
            # v1.4 — the gating disjunct lives in ``lineage_gated_action`` and
            # is shared verbatim with the commit-time re-decision in
            # ``AuthorizationGate.resolve_deferred_commits``.  Do not inline it
            # here again: two copies WILL drift, and a deferred write is
            # decided at both sites.
            _flags = ActionFlags(
                is_financial=context.is_financial,
                is_external=context.is_external,
                is_bulk=context.is_bulk,
                is_account_modification=context.is_account_modification,
                is_consequential=context.is_consequential,
                is_deletion=context.is_deletion,
                is_membership_change=context.is_membership_change,
            )
            is_deletion, is_membership_change, _ = resolve_action_classes(
                permissions, _flags
            )
            gated_action = lineage_gated_action(lineage_policy, permissions, _flags)
            summary = context.metadata.get("lineage")
            if gated_action and summary is not None:
                if lineage_policy.require_post_authoritative:
                    taint = bool(summary.get("post_authoritative_taint"))
                    taint_kind = "post-authoritative untrusted"
                else:
                    taint = bool(summary.get("tainted"))
                    taint_kind = "untrusted"
                if taint:
                    if context.is_financial:
                        action_kind = "financial"
                    elif context.is_external:
                        action_kind = "external"
                    elif context.is_bulk:
                        action_kind = "bulk"
                    elif context.is_account_modification:
                        action_kind = "account-modification"
                    elif is_deletion:
                        action_kind = "deletion"
                    elif is_membership_change:
                        action_kind = "membership-change"
                    elif context.is_consequential:
                        action_kind = "consequential"
                    else:
                        action_kind = "gated"
                    detail = (
                        f"Action gated on provenance/lineage, not content: "
                        f"{taint_kind} content is present in the session's "
                        f"context window before this {action_kind} "
                        f"action. No parameter content was inspected."
                    )
                    # v1.3 ablation: when the session write-gate is DISABLED,
                    # do NOT block — record what it WOULD have blocked as a
                    # shadow and fall through (provenance recording,
                    # parameter-lineage, and deferred-commit are unaffected).
                    if not lineage_policy.session_write_gate:
                        context.metadata["session_gate_shadow"] = "DENY"
                        context.metadata["session_gate_shadow_detail"] = detail
                    elif lineage_policy.decision == "deny":
                        return PolicyDecision(
                            allowed=False,
                            reason=DenialReason.UNTRUSTED_LINEAGE,
                            detail=detail,
                            suggestion=(
                                "The tool call was denied purely because "
                                "untrusted-provenance content preceded it. "
                                "Start a clean session or re-issue the "
                                "instruction without intervening untrusted "
                                "context."
                            ),
                        )
                    else:
                        # step_up / defer → block pending out-of-band approval
                        return PolicyDecision(
                            allowed=False,
                            reason=DenialReason.UNTRUSTED_LINEAGE,
                            detail=detail,
                            needs_approval=True,
                            suggestion=(
                                "Human step-up approval required: untrusted-"
                                "provenance content preceded this gated action. "
                                "This is a provenance decision, not a content "
                                "scan."
                            ),
                        )

        # 10-11. v1.1 checks — trust degradation and unattributed context
        # These run independently of both filters above.  Trust degradation
        # fires based on session state from notify_context_write(), not
        # from parameter content or PII classification.
        if (
            version_at_least(permissions.version, (1, 1))
            and context.context_state is not None
        ):
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
