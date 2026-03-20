"""Tests for agentlock.policy — v1.1 policy checks (trust degradation, context)."""

from __future__ import annotations

import pytest

from agentlock.context import ContextState
from agentlock.policy import PolicyEngine, RequestContext
from agentlock.schema import (
    AgentLockPermissions,
    ContextPolicyConfig,
)
from agentlock.types import (
    DegradationEffect,
    DenialReason,
    RiskLevel,
)


@pytest.fixture
def engine():
    return PolicyEngine()


def _v11_perms(**kwargs) -> AgentLockPermissions:
    """Build v1.1 permissions that pass auth and role checks."""
    defaults = dict(
        version="1.1",
        risk_level=RiskLevel.MEDIUM,
        allowed_roles=["user"],
    )
    defaults.update(kwargs)
    return AgentLockPermissions(**defaults)


def _authed_ctx(**kwargs) -> RequestContext:
    """Build an authenticated request context."""
    defaults = dict(user_id="alice", role="user")
    defaults.update(kwargs)
    return RequestContext(**defaults)


# ---- Trust degradation: REQUIRE_APPROVAL -----------------------------------

class TestTrustDegradationRequireApproval:
    def test_require_approval_denies(self, engine):
        cs = ContextState(
            is_degraded=True,
            degradation_reason="web_content",
            active_effects=[DegradationEffect.REQUIRE_APPROVAL],
        )
        perms = _v11_perms()
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.TRUST_DEGRADED
        assert decision.needs_approval is True


# ---- Trust degradation: DENY_WRITES ---------------------------------------

class TestTrustDegradationDenyWrites:
    def test_deny_writes_blocks_medium_risk(self, engine):
        cs = ContextState(
            is_degraded=True,
            degradation_reason="peer_agent",
            active_effects=[DegradationEffect.DENY_WRITES],
        )
        perms = _v11_perms(risk_level=RiskLevel.MEDIUM)
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.TRUST_DEGRADED

    def test_deny_writes_allows_none_risk(self, engine):
        cs = ContextState(
            is_degraded=True,
            degradation_reason="peer_agent",
            active_effects=[DegradationEffect.DENY_WRITES],
        )
        perms = _v11_perms(risk_level=RiskLevel.NONE)
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Unattributed context --------------------------------------------------

class TestUnattributedContext:
    def test_unattributed_denied_by_default(self, engine):
        cs = ContextState(unattributed_count=3)
        perms = _v11_perms()
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.UNATTRIBUTED_CONTEXT

    def test_unattributed_allowed_when_reject_false(self, engine):
        cs = ContextState(unattributed_count=3)
        perms = _v11_perms(
            context_policy=ContextPolicyConfig(reject_unattributed=False),
        )
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Version gating --------------------------------------------------------

class TestVersionGating:
    def test_v10_skips_v11_checks(self, engine):
        """v1.0 permissions skip v1.1 checks even with degraded context."""
        cs = ContextState(
            is_degraded=True,
            degradation_reason="web_content",
            active_effects=[DegradationEffect.REQUIRE_APPROVAL],
            unattributed_count=5,
        )
        perms = AgentLockPermissions(
            version="1.0",
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
        )
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_no_context_state_skips_v11_checks(self, engine):
        """None context_state skips v1.1 checks even with v1.1 version."""
        perms = _v11_perms()
        ctx = _authed_ctx(context_state=None)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- Degradation with no active effects ------------------------------------

class TestDegradationNoEffects:
    def test_degraded_but_no_effects_allows(self, engine):
        """is_degraded=True but empty active_effects should not deny."""
        cs = ContextState(
            is_degraded=True,
            degradation_reason="web_content",
            active_effects=[],
        )
        perms = _v11_perms()
        ctx = _authed_ctx(context_state=cs)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True
