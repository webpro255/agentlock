"""Tests for agentlock.schema — AgentLockPermissions validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentlock.schema import (
    AgentLockPermissions,
    AuditConfig,
    DataPolicyConfig,
    HumanApprovalConfig,
    RateLimitConfig,
    ScopeConfig,
    SessionConfig,
    ToolDefinition,
)
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
)

# ---- Deny-by-default semantics -------------------------------------------

class TestDenyByDefault:
    def test_empty_permissions_has_no_roles(self):
        """An empty permissions block has empty allowed_roles (deny everyone)."""
        perms = AgentLockPermissions()
        assert perms.allowed_roles == []

    def test_default_risk_level_is_high(self):
        perms = AgentLockPermissions()
        assert perms.risk_level == RiskLevel.HIGH

    def test_default_requires_auth(self):
        perms = AgentLockPermissions()
        assert perms.requires_auth is True

    def test_default_data_boundary_is_user_only(self):
        perms = AgentLockPermissions()
        assert perms.scope.data_boundary == DataBoundary.AUTHENTICATED_USER_ONLY

    def test_default_redaction_none(self):
        perms = AgentLockPermissions()
        assert perms.data_policy.redaction == RedactionMode.NONE


# ---- Enum validation -----------------------------------------------------

class TestEnumValidation:
    @pytest.mark.parametrize("level", list(RiskLevel))
    def test_all_risk_levels_accepted(self, level):
        perms = AgentLockPermissions(risk_level=level, allowed_roles=["x"])
        assert perms.risk_level == level

    @pytest.mark.parametrize("method", list(AuthMethod))
    def test_all_auth_methods_accepted(self, method):
        perms = AgentLockPermissions(auth_methods=[method], allowed_roles=["x"])
        assert method in perms.auth_methods

    @pytest.mark.parametrize("classification", list(DataClassification))
    def test_all_data_classifications_accepted(self, classification):
        dp = DataPolicyConfig(input_classification=classification)
        assert dp.input_classification == classification

    @pytest.mark.parametrize("boundary", list(DataBoundary))
    def test_all_data_boundaries_accepted(self, boundary):
        sc = ScopeConfig(data_boundary=boundary)
        assert sc.data_boundary == boundary

    @pytest.mark.parametrize("policy", list(RecipientPolicy))
    def test_all_recipient_policies_accepted(self, policy):
        sc = ScopeConfig(allowed_recipients=policy)
        assert sc.allowed_recipients == policy

    @pytest.mark.parametrize("mode", list(RedactionMode))
    def test_all_redaction_modes_accepted(self, mode):
        dp = DataPolicyConfig(redaction=mode)
        assert dp.redaction == mode

    @pytest.mark.parametrize("level", list(AuditLogLevel))
    def test_all_audit_log_levels_accepted(self, level):
        ac = AuditConfig(log_level=level)
        assert ac.log_level == level

    @pytest.mark.parametrize("threshold", list(ApprovalThreshold))
    def test_all_approval_thresholds_accepted(self, threshold):
        hac = HumanApprovalConfig(threshold=threshold)
        assert hac.threshold == threshold

    @pytest.mark.parametrize("channel", list(ApprovalChannel))
    def test_all_approval_channels_accepted(self, channel):
        hac = HumanApprovalConfig(channel=channel)
        assert hac.channel == channel


# ---- Invalid values -------------------------------------------------------

class TestInvalidValues:
    def test_invalid_risk_level_raises(self):
        with pytest.raises(ValidationError):
            AgentLockPermissions(risk_level="super_bad")

    def test_invalid_auth_method_raises(self):
        with pytest.raises(ValidationError):
            AgentLockPermissions(auth_methods=["telepathy"])

    def test_invalid_data_classification_raises(self):
        with pytest.raises(ValidationError):
            DataPolicyConfig(input_classification="top_secret")

    def test_rate_limit_zero_calls_raises(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(max_calls=0, window_seconds=60)

    def test_rate_limit_zero_window_raises(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(max_calls=5, window_seconds=0)

    def test_rate_limit_negative_calls_raises(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(max_calls=-1, window_seconds=60)

    def test_max_records_zero_raises(self):
        with pytest.raises(ValidationError):
            ScopeConfig(max_records=0)

    def test_session_duration_zero_raises(self):
        with pytest.raises(ValidationError):
            SessionConfig(max_duration_seconds=0)

    def test_retention_days_zero_raises(self):
        with pytest.raises(ValidationError):
            AuditConfig(retention_days=0)


# ---- JSON schema roundtrip -----------------------------------------------

class TestJsonSchemaBlock:
    def test_roundtrip_basic(self):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.HIGH,
            requires_auth=True,
            allowed_roles=["admin"],
        )
        block = perms.to_json_schema_block()
        restored = AgentLockPermissions(**block)
        assert restored.risk_level == RiskLevel.HIGH
        assert restored.allowed_roles == ["admin"]

    def test_roundtrip_with_rate_limit(self):
        perms = AgentLockPermissions(
            risk_level="medium",
            allowed_roles=["user"],
            rate_limit=RateLimitConfig(max_calls=10, window_seconds=60),
        )
        block = perms.to_json_schema_block()
        restored = AgentLockPermissions(**block)
        assert restored.rate_limit is not None
        assert restored.rate_limit.max_calls == 10
        assert restored.rate_limit.window_seconds == 60

    def test_roundtrip_none_rate_limit_excluded(self):
        perms = AgentLockPermissions(allowed_roles=["x"])
        block = perms.to_json_schema_block()
        assert "rate_limit" not in block

    def test_roundtrip_preserves_data_policy(self):
        perms = AgentLockPermissions(
            allowed_roles=["admin"],
            data_policy=DataPolicyConfig(
                input_classification=DataClassification.CONTAINS_PII,
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.AUTO,
            ),
        )
        block = perms.to_json_schema_block()
        restored = AgentLockPermissions(**block)
        assert restored.data_policy.prohibited_in_output == ["ssn"]
        assert restored.data_policy.redaction == RedactionMode.AUTO


# ---- Extra fields forbidden -----------------------------------------------

class TestExtraFields:
    def test_permissions_extra_forbidden(self):
        with pytest.raises(ValidationError):
            AgentLockPermissions(risk_level="high", bogus_field="nope")

    def test_scope_extra_forbidden(self):
        with pytest.raises(ValidationError):
            ScopeConfig(extra_thing=42)

    def test_rate_limit_extra_forbidden(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(max_calls=1, window_seconds=1, extra=True)

    def test_data_policy_extra_forbidden(self):
        with pytest.raises(ValidationError):
            DataPolicyConfig(nonsense="yes")

    def test_session_extra_forbidden(self):
        with pytest.raises(ValidationError):
            SessionConfig(foo="bar")

    def test_audit_extra_forbidden(self):
        with pytest.raises(ValidationError):
            AuditConfig(baz=1)

    def test_human_approval_extra_forbidden(self):
        with pytest.raises(ValidationError):
            HumanApprovalConfig(unknown=True)


# ---- Nested model validation -----------------------------------------------

class TestNestedModels:
    def test_scope_config_defaults(self):
        sc = ScopeConfig()
        assert sc.data_boundary == DataBoundary.AUTHENTICATED_USER_ONLY
        assert sc.max_records is None
        assert sc.allowed_recipients == RecipientPolicy.KNOWN_CONTACTS_ONLY

    def test_rate_limit_config_valid(self):
        rl = RateLimitConfig(max_calls=5, window_seconds=3600)
        assert rl.max_calls == 5
        assert rl.window_seconds == 3600

    def test_session_config_defaults(self):
        sc = SessionConfig()
        assert sc.max_duration_seconds == 900
        assert sc.require_reauth_on_scope_change is True

    def test_human_approval_defaults(self):
        hac = HumanApprovalConfig()
        assert hac.required is False
        assert hac.threshold == ApprovalThreshold.ALWAYS
        assert hac.channel == ApprovalChannel.PUSH_NOTIFICATION


# ---- DataPolicy: prohibited_in_output requires redaction != none -----------

class TestDataPolicyValidation:
    def test_prohibited_with_redaction_none_raises(self):
        with pytest.raises(ValidationError, match="redaction"):
            DataPolicyConfig(
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.NONE,
            )

    def test_prohibited_with_auto_redaction_ok(self):
        dp = DataPolicyConfig(
            prohibited_in_output=["ssn"],
            redaction=RedactionMode.AUTO,
        )
        assert dp.prohibited_in_output == ["ssn"]

    def test_prohibited_with_manual_redaction_ok(self):
        dp = DataPolicyConfig(
            prohibited_in_output=["credit_card"],
            redaction=RedactionMode.MANUAL,
        )
        assert dp.prohibited_in_output == ["credit_card"]

    def test_empty_prohibited_with_none_ok(self):
        dp = DataPolicyConfig(
            prohibited_in_output=[],
            redaction=RedactionMode.NONE,
        )
        assert dp.prohibited_in_output == []

    def test_no_prohibited_with_none_ok(self):
        dp = DataPolicyConfig(redaction=RedactionMode.NONE)
        assert dp.prohibited_in_output == []


# ---- ToolDefinition -------------------------------------------------------

class TestToolDefinition:
    def test_tool_definition_basic(self):
        td = ToolDefinition(name="my_tool", description="Does stuff")
        assert td.name == "my_tool"
        assert td.agentlock.risk_level == RiskLevel.HIGH  # default

    def test_tool_definition_with_permissions(self):
        td = ToolDefinition(
            name="safe_tool",
            agentlock=AgentLockPermissions(
                risk_level=RiskLevel.NONE,
            ),
        )
        assert td.agentlock.risk_level == RiskLevel.NONE

    def test_requires_human_approval(self):
        perms = AgentLockPermissions(
            allowed_roles=["admin"],
            human_approval=HumanApprovalConfig(required=True),
        )
        assert perms.requires_human_approval() is True

    def test_no_human_approval_by_default(self):
        perms = AgentLockPermissions()
        assert perms.requires_human_approval() is False
