"""Tests for agentlock.schema — v1.1 models (context policy, memory policy)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentlock.schema import (
    AgentLockPermissions,
    ContextPolicyConfig,
    DegradationTrigger,
    MemoryPolicyConfig,
    MemoryRetentionConfig,
    SourceAuthorityConfig,
    TrustDegradationConfig,
)
from agentlock.types import (
    ContextAuthority,
    ContextSource,
    DegradationEffect,
    MemoryPersistence,
    MemoryWriter,
    RiskLevel,
)

# ---- SourceAuthorityConfig ------------------------------------------------

class TestSourceAuthorityConfig:
    def test_valid_construction(self):
        sa = SourceAuthorityConfig(
            source=ContextSource.USER_MESSAGE,
            authority=ContextAuthority.AUTHORITATIVE,
        )
        assert sa.source == ContextSource.USER_MESSAGE
        assert sa.authority == ContextAuthority.AUTHORITATIVE

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError):
            SourceAuthorityConfig(
                source=ContextSource.USER_MESSAGE,
                authority=ContextAuthority.AUTHORITATIVE,
                extra_field="nope",
            )


# ---- DegradationTrigger ---------------------------------------------------

class TestDegradationTrigger:
    def test_valid_construction(self):
        trigger = DegradationTrigger(
            source=ContextSource.WEB_CONTENT,
            effect=DegradationEffect.DENY_WRITES,
        )
        assert trigger.source == ContextSource.WEB_CONTENT
        assert trigger.effect == DegradationEffect.DENY_WRITES


# ---- TrustDegradationConfig -----------------------------------------------

class TestTrustDegradationConfig:
    def test_defaults(self):
        td = TrustDegradationConfig()
        assert td.enabled is True
        assert td.triggers == []
        assert td.minimum_authority == ContextAuthority.DERIVED
        assert td.allow_cascade_to_untrusted is False

    def test_with_triggers(self):
        trigger = DegradationTrigger(
            source=ContextSource.PEER_AGENT,
            effect=DegradationEffect.REQUIRE_APPROVAL,
        )
        td = TrustDegradationConfig(triggers=[trigger])
        assert len(td.triggers) == 1
        assert td.triggers[0].source == ContextSource.PEER_AGENT
        assert td.triggers[0].effect == DegradationEffect.REQUIRE_APPROVAL


# ---- ContextPolicyConfig --------------------------------------------------

class TestContextPolicyConfig:
    def test_defaults(self):
        cp = ContextPolicyConfig()
        assert len(cp.source_authorities) == 7
        assert cp.trust_degradation.enabled is True
        assert cp.reject_unattributed is True

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError):
            ContextPolicyConfig(unknown_field="bad")


# ---- MemoryRetentionConfig ------------------------------------------------

class TestMemoryRetentionConfig:
    def test_defaults(self):
        mr = MemoryRetentionConfig()
        assert mr.max_age_seconds == 86400
        assert mr.max_entries == 100

    def test_validates_max_entries_ge_1(self):
        with pytest.raises(ValidationError):
            MemoryRetentionConfig(max_entries=0)

    def test_validates_max_age_seconds_ge_0(self):
        with pytest.raises(ValidationError):
            MemoryRetentionConfig(max_age_seconds=-1)


# ---- MemoryPolicyConfig ---------------------------------------------------

class TestMemoryPolicyConfig:
    def test_defaults(self):
        mp = MemoryPolicyConfig()
        assert mp.persistence == MemoryPersistence.NONE
        assert mp.allowed_writers == [MemoryWriter.SYSTEM]
        assert mp.allowed_readers == [MemoryWriter.SYSTEM]
        assert mp.require_write_confirmation is True

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError):
            MemoryPolicyConfig(bogus=42)


# ---- AgentLockPermissions with v1.1 fields --------------------------------

class TestPermissionsV11:
    def test_with_context_and_memory_policy(self):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["admin"],
            context_policy=ContextPolicyConfig(),
            memory_policy=MemoryPolicyConfig(),
        )
        assert perms.context_policy is not None
        assert perms.memory_policy is not None

    def test_context_policy_defaults_to_none(self):
        perms = AgentLockPermissions()
        assert perms.context_policy is None

    def test_json_roundtrip_with_v11_fields(self):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["admin"],
            context_policy=ContextPolicyConfig(),
            memory_policy=MemoryPolicyConfig(),
        )
        block = perms.to_json_schema_block()
        restored = AgentLockPermissions(**block)
        assert restored.context_policy is not None
        assert len(restored.context_policy.source_authorities) == 7
        assert restored.memory_policy is not None
        assert restored.memory_policy.persistence == MemoryPersistence.NONE


# ---- Invalid enum values --------------------------------------------------

class TestInvalidEnumValues:
    def test_invalid_context_source_rejected(self):
        with pytest.raises(ValidationError):
            SourceAuthorityConfig(
                source="made_up_source",
                authority=ContextAuthority.AUTHORITATIVE,
            )

    def test_invalid_context_authority_rejected(self):
        with pytest.raises(ValidationError):
            SourceAuthorityConfig(
                source=ContextSource.USER_MESSAGE,
                authority="super_trusted",
            )

    def test_invalid_degradation_effect_rejected(self):
        with pytest.raises(ValidationError):
            DegradationTrigger(
                source=ContextSource.WEB_CONTENT,
                effect="explode",
            )
