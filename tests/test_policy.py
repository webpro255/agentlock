"""Tests for agentlock.policy — PolicyEngine."""

from __future__ import annotations

import pytest

from agentlock.policy import PolicyEngine, RequestContext
from agentlock.schema import (
    AgentLockPermissions,
    HumanApprovalConfig,
    ScopeConfig,
)
from agentlock.types import (
    ApprovalThreshold,
    DataBoundary,
    DenialReason,
    RiskLevel,
)


@pytest.fixture
def engine():
    return PolicyEngine()


# ---- Risk level none auto-allows ------------------------------------------

class TestRiskNone:
    def test_risk_none_auto_allows(self, engine):
        perms = AgentLockPermissions(risk_level=RiskLevel.NONE)
        ctx = RequestContext()
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_risk_none_allows_unauthenticated(self, engine):
        perms = AgentLockPermissions(risk_level=RiskLevel.NONE)
        ctx = RequestContext(user_id="", role="")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_risk_none_allows_no_roles(self, engine):
        perms = AgentLockPermissions(risk_level=RiskLevel.NONE, allowed_roles=[])
        ctx = RequestContext()
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Authentication -------------------------------------------------------

class TestAuthentication:
    def test_unauthenticated_denied_when_requires_auth(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
        )
        ctx = RequestContext(user_id="", role="user")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.NOT_AUTHENTICATED

    def test_authenticated_passes_auth_check(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
        )
        ctx = RequestContext(user_id="alice", role="user")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Role check -----------------------------------------------------------

class TestRoleCheck:
    def test_wrong_role_denied(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["admin"],
        )
        ctx = RequestContext(user_id="alice", role="user")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.INSUFFICIENT_ROLE

    def test_correct_role_allowed(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["admin"],
        )
        ctx = RequestContext(user_id="alice", role="admin")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_empty_roles_denied_by_default(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=[],
        )
        ctx = RequestContext(user_id="alice", role="admin")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.NO_PERMISSIONS

    def test_multiple_allowed_roles(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["admin", "support"],
        )
        ctx = RequestContext(user_id="alice", role="support")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Scope / data boundary ------------------------------------------------

class TestScopeViolation:
    def test_scope_violation_detected(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(data_boundary=DataBoundary.AUTHENTICATED_USER_ONLY),
        )
        ctx = RequestContext(
            user_id="alice",
            role="user",
            data_boundary=DataBoundary.ORGANIZATION,
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.SCOPE_VIOLATION

    def test_equal_boundary_allowed(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(data_boundary=DataBoundary.TEAM),
        )
        ctx = RequestContext(
            user_id="alice",
            role="user",
            data_boundary=DataBoundary.TEAM,
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_narrower_boundary_allowed(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(data_boundary=DataBoundary.ORGANIZATION),
        )
        ctx = RequestContext(
            user_id="alice",
            role="user",
            data_boundary=DataBoundary.TEAM,
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Max records ----------------------------------------------------------

class TestMaxRecords:
    def test_max_records_exceeded(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(max_records=10),
        )
        ctx = RequestContext(user_id="alice", role="user", record_count=50)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.MAX_RECORDS_EXCEEDED

    def test_within_max_records(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(max_records=100),
        )
        ctx = RequestContext(user_id="alice", role="user", record_count=50)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_exact_max_records_allowed(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(max_records=10),
        )
        ctx = RequestContext(user_id="alice", role="user", record_count=10)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_no_max_records_allows_any(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
        )
        ctx = RequestContext(user_id="alice", role="user", record_count=99999)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Human approval -------------------------------------------------------

class TestHumanApproval:
    def test_always_threshold_triggers(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.CRITICAL,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.ALWAYS,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.APPROVAL_REQUIRED
        assert decision.needs_approval is True

    def test_bulk_operations_threshold(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.BULK_OPERATIONS,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_bulk=True)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.APPROVAL_REQUIRED

    def test_bulk_threshold_not_triggered_when_not_bulk(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.BULK_OPERATIONS,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_bulk=False)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_external_communication_threshold(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.EXTERNAL_COMMUNICATION,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_external=True)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.APPROVAL_REQUIRED

    def test_external_not_triggered_when_internal(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.EXTERNAL_COMMUNICATION,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_external=False)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_financial_above_limit_threshold(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.FINANCIAL_ABOVE_LIMIT,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_financial=True, amount=10000)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.APPROVAL_REQUIRED

    def test_financial_not_triggered_when_not_financial(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.FINANCIAL_ABOVE_LIMIT,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin", is_financial=False)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_first_invocation_per_session_threshold(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.FIRST_INVOCATION_PER_SESSION,
            ),
        )
        ctx = RequestContext(
            user_id="alice",
            role="admin",
            metadata={"first_invocation": True},
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.APPROVAL_REQUIRED

    def test_first_invocation_not_triggered_on_subsequent(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.FIRST_INVOCATION_PER_SESSION,
            ),
        )
        ctx = RequestContext(
            user_id="alice",
            role="admin",
            metadata={"first_invocation": False},
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_approval_not_required_when_flag_false(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(required=False),
        )
        ctx = RequestContext(user_id="alice", role="admin")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_approval_channel_in_decision(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.CRITICAL,
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(
                required=True,
                threshold=ApprovalThreshold.ALWAYS,
            ),
        )
        ctx = RequestContext(user_id="alice", role="admin")
        decision = engine.evaluate(perms, ctx)
        assert decision.approval_channel == "push_notification"
