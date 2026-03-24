"""Tests for combined PII defense: gate-level blocking + output-layer redaction.

The gate blocks unauthorized PII-returning queries at Layer 2 (authorize).
Output redaction catches any PII that slips through at Layer 3 (execute).
Both layers work together as defense-in-depth.
"""

from __future__ import annotations

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions, DataPolicyConfig
from agentlock.types import (
    DataClassification,
    DenialReason,
    RedactionMode,
    RiskLevel,
)


def _make_pii_tool_perms(**overrides) -> AgentLockPermissions:
    defaults = dict(
        risk_level=RiskLevel.HIGH,
        requires_auth=True,
        allowed_roles=["analyst", "admin"],
        data_policy=DataPolicyConfig(
            output_classification=DataClassification.CONTAINS_PII,
            prohibited_in_output=["ssn", "credit_card"],
            redaction=RedactionMode.AUTO,
        ),
    )
    defaults.update(overrides)
    return AgentLockPermissions(**defaults)


def _db_query(**kwargs):
    """Simulates a database query that returns raw PII."""
    return (
        "Customer: Jane Doe\n"
        "SSN: 123-45-6789\n"
        "Card: 4111-1111-1111-1111\n"
        "Email: jane@example.com"
    )


def _safe_query(**kwargs):
    """Returns non-PII data."""
    return "Customer count: 42"


class TestGateLevelBlock:
    """Layer 2: authorize() blocks callers without sufficient clearance."""

    def test_caller_with_low_clearance_denied(self):
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="analyst",
            max_output_classification="internal",
        )
        assert not result.allowed
        assert result.denial["reason"] == DenialReason.DATA_POLICY_VIOLATION.value
        assert "contains_pii" in result.denial["detail"]
        assert "internal" in result.denial["detail"]

    def test_caller_with_matching_clearance_allowed(self):
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="analyst",
            max_output_classification="contains_pii",
        )
        assert result.allowed

    def test_caller_with_higher_clearance_allowed(self):
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="analyst",
            max_output_classification="contains_financial",
        )
        assert result.allowed

    def test_no_clearance_specified_skips_check(self):
        """Backward compat: if max_output_classification is not set, no block."""
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="analyst",
        )
        assert result.allowed

    def test_public_tool_allows_any_clearance(self):
        gate = AuthorizationGate()
        gate.register_tool("get_time", AgentLockPermissions(
            risk_level=RiskLevel.LOW,
            requires_auth=True,
            allowed_roles=["viewer"],
            data_policy=DataPolicyConfig(
                output_classification=DataClassification.PUBLIC,
            ),
        ))

        result = gate.authorize(
            "get_time",
            user_id="alice",
            role="viewer",
            max_output_classification="public",
        )
        assert result.allowed

    def test_confidential_tool_blocked_by_internal_clearance(self):
        gate = AuthorizationGate()
        gate.register_tool("read_config", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            data_policy=DataPolicyConfig(
                output_classification=DataClassification.CONFIDENTIAL,
            ),
        ))

        result = gate.authorize(
            "read_config",
            user_id="alice",
            role="user",
            max_output_classification="internal",
        )
        assert not result.allowed
        assert result.denial["reason"] == DenialReason.DATA_POLICY_VIOLATION.value


class TestOutputRedaction:
    """Layer 3: execute() redacts PII from tool output even when gate allows."""

    def test_pii_redacted_from_output(self):
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="admin",
        )
        assert result.allowed

        output = gate.execute(
            "query_customers",
            _db_query,
            token=result.token,
        )
        assert "123-45-6789" not in output
        assert "4111-1111-1111-1111" not in output
        assert "[REDACTED:ssn]" in output
        assert "[REDACTED:credit_card]" in output
        # Non-PII content preserved
        assert "Jane Doe" in output

    def test_no_redaction_when_output_clean(self):
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="alice",
            role="admin",
        )
        output = gate.execute(
            "query_customers",
            _safe_query,
            token=result.token,
        )
        assert output == "Customer count: 42"


class TestCombinedDefense:
    """Both layers working together: gate blocks, redaction catches leaks."""

    def test_low_clearance_blocked_at_gate_pii_never_fetched(self):
        """A viewer with internal clearance cannot reach the PII tool at all."""
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="viewer_user",
            role="analyst",
            max_output_classification="internal",
        )
        assert not result.allowed
        assert result.denial["reason"] == DenialReason.DATA_POLICY_VIOLATION.value
        # The tool function never runs — no PII was ever fetched

    def test_high_clearance_allowed_but_output_still_redacted(self):
        """An admin with PII clearance gets through gate, but output is
        still redacted. Defense-in-depth: even authorized callers don't
        see raw PII patterns in the response."""
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        result = gate.authorize(
            "query_customers",
            user_id="admin_user",
            role="admin",
            max_output_classification="contains_pii",
        )
        assert result.allowed

        output = gate.execute(
            "query_customers",
            _db_query,
            token=result.token,
        )
        # Gate allowed, but redaction still scrubs the output
        assert "123-45-6789" not in output
        assert "[REDACTED:ssn]" in output

    def test_call_convenience_method_applies_both_layers(self):
        """gate.call() applies both authorize (gate block) and execute (redact)."""
        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        # Admin with clearance — passes gate, gets redacted output
        output = gate.call(
            "query_customers",
            _db_query,
            user_id="admin_user",
            role="admin",
            max_output_classification="contains_pii",
        )
        assert "123-45-6789" not in output
        assert "[REDACTED:ssn]" in output

    def test_call_blocked_at_gate_with_insufficient_clearance(self):
        """gate.call() raises DeniedError when clearance is too low."""
        import pytest

        from agentlock.exceptions import DeniedError

        gate = AuthorizationGate()
        gate.register_tool("query_customers", _make_pii_tool_perms())

        with pytest.raises(DeniedError) as exc_info:
            gate.call(
                "query_customers",
                _db_query,
                user_id="viewer_user",
                role="analyst",
                max_output_classification="public",
            )
        assert exc_info.value.reason == DenialReason.DATA_POLICY_VIOLATION.value

    def test_may_contain_pii_tool_allowed_with_pii_clearance(self):
        """MAY_CONTAIN_PII is less sensitive than CONTAINS_PII."""
        gate = AuthorizationGate()
        gate.register_tool("search_logs", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["analyst"],
            data_policy=DataPolicyConfig(
                output_classification=DataClassification.MAY_CONTAIN_PII,
                prohibited_in_output=["ssn"],
                redaction=RedactionMode.AUTO,
            ),
        ))

        result = gate.authorize(
            "search_logs",
            user_id="alice",
            role="analyst",
            max_output_classification="may_contain_pii",
        )
        assert result.allowed

    def test_may_contain_pii_tool_blocked_with_internal_clearance(self):
        gate = AuthorizationGate()
        gate.register_tool("search_logs", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["analyst"],
            data_policy=DataPolicyConfig(
                output_classification=DataClassification.MAY_CONTAIN_PII,
            ),
        ))

        result = gate.authorize(
            "search_logs",
            user_id="alice",
            role="analyst",
            max_output_classification="internal",
        )
        assert not result.allowed

    def test_audit_records_data_policy_denial(self):
        """Verify the gate logs the denial with the correct reason."""
        from agentlock.audit import InMemoryAuditBackend

        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)
        gate.register_tool("query_customers", _make_pii_tool_perms())

        gate.authorize(
            "query_customers",
            user_id="alice",
            role="analyst",
            max_output_classification="public",
        )

        denied = [r for r in backend.records if r.action == "denied"]
        assert len(denied) == 1
        assert denied[0].reason == DenialReason.DATA_POLICY_VIOLATION.value

    def test_classification_hierarchy_all_levels(self):
        """Verify the full classification hierarchy is enforced correctly."""
        gate = AuthorizationGate()

        levels = [
            "public", "internal", "confidential",
            "may_contain_pii", "contains_pii", "contains_phi",
            "contains_financial",
        ]

        # Register a tool at each level
        for level in levels:
            gate.register_tool(f"tool_{level}", AgentLockPermissions(
                risk_level=RiskLevel.MEDIUM,
                requires_auth=True,
                allowed_roles=["user"],
                data_policy=DataPolicyConfig(
                    output_classification=DataClassification(level),
                ),
            ))

        # Caller with "confidential" clearance
        for level in levels:
            result = gate.authorize(
                f"tool_{level}",
                user_id="alice",
                role="user",
                max_output_classification="confidential",
            )
            level_idx = levels.index(level)
            confidential_idx = levels.index("confidential")
            if level_idx <= confidential_idx:
                assert result.allowed, f"Expected {level} to be allowed"
            else:
                assert not result.allowed, f"Expected {level} to be denied"
