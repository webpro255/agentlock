"""Shared fixtures for AgentLock test suite."""

from __future__ import annotations

import pytest

from agentlock.audit import InMemoryAuditBackend
from agentlock.gate import AuthorizationGate
from agentlock.schema import (
    AgentLockPermissions,
    DataPolicyConfig,
    HumanApprovalConfig,
    RateLimitConfig,
    ScopeConfig,
)
from agentlock.types import (
    ApprovalThreshold,
    DataBoundary,
    DataClassification,
    RedactionMode,
    RiskLevel,
)


@pytest.fixture
def audit_backend():
    """Fresh in-memory audit backend."""
    return InMemoryAuditBackend()


@pytest.fixture
def gate(audit_backend):
    """AuthorizationGate wired to an in-memory audit backend."""
    return AuthorizationGate(audit_backend=audit_backend, token_ttl=60, session_duration=900)


@pytest.fixture
def sample_permissions():
    """Medium-risk permissions with a single allowed role."""
    return AgentLockPermissions(
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user", "admin"],
        rate_limit=RateLimitConfig(max_calls=10, window_seconds=60),
        scope=ScopeConfig(
            data_boundary=DataBoundary.AUTHENTICATED_USER_ONLY,
            max_records=100,
        ),
    )


@pytest.fixture
def high_risk_permissions():
    """High-risk permissions requiring admin role."""
    return AgentLockPermissions(
        risk_level=RiskLevel.HIGH,
        requires_auth=True,
        allowed_roles=["admin"],
        rate_limit=RateLimitConfig(max_calls=5, window_seconds=3600),
        scope=ScopeConfig(
            data_boundary=DataBoundary.TEAM,
            max_records=50,
        ),
        data_policy=DataPolicyConfig(
            input_classification=DataClassification.CONFIDENTIAL,
            output_classification=DataClassification.MAY_CONTAIN_PII,
            prohibited_in_output=["ssn", "credit_card"],
            redaction=RedactionMode.AUTO,
        ),
    )


@pytest.fixture
def critical_permissions():
    """Critical permissions requiring human approval."""
    return AgentLockPermissions(
        risk_level=RiskLevel.CRITICAL,
        requires_auth=True,
        allowed_roles=["admin"],
        human_approval=HumanApprovalConfig(
            required=True,
            threshold=ApprovalThreshold.ALWAYS,
        ),
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def make_permissions(**overrides) -> AgentLockPermissions:
    """Build AgentLockPermissions with sensible test defaults, applying overrides."""
    defaults = dict(
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
    )
    defaults.update(overrides)
    return AgentLockPermissions(**defaults)


def dummy_tool(**kwargs):
    """A trivial tool function for testing execution."""
    return "ok"


def echo_tool(**kwargs):
    """A tool that echoes its keyword arguments."""
    return str(kwargs)
