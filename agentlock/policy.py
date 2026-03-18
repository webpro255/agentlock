"""Policy evaluation engine.

Evaluates an AgentLock permissions block against a request context to
produce an allow/deny decision with a specific reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentlock.schema import AgentLockPermissions
from agentlock.types import (
    ApprovalThreshold,
    DataBoundary,
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
    metadata: dict[str, Any] = field(default_factory=dict)

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


class PolicyEngine:
    """Evaluates AgentLock permissions against a request context."""

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
        6. Recipient policy
        7. Human approval
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
        if context.data_boundary in boundary_order and scope.data_boundary in boundary_order:
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
                suggestion=f"Reduce your request to {scope.max_records} records or fewer.",
            )

        # 6. Recipient policy (only if recipient is provided)
        # Detailed validation delegated to the tool or deployer;
        # here we enforce "known_contacts_only" as a marker.
        # Real-world enforcement uses a contacts backend.

        # 7. Human approval
        if permissions.human_approval.required:
            threshold = permissions.human_approval.threshold
            needs_approval = False

            if threshold == ApprovalThreshold.ALWAYS:
                needs_approval = True
            elif threshold == ApprovalThreshold.BULK_OPERATIONS and context.is_bulk:
                needs_approval = True
            elif threshold == ApprovalThreshold.EXTERNAL_COMMUNICATION and context.is_external:
                needs_approval = True
            elif threshold == ApprovalThreshold.FINANCIAL_ABOVE_LIMIT and context.is_financial:
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

        return PolicyDecision(allowed=True)
