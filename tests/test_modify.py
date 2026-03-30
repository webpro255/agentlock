"""Tests for the MODIFY decision type — parameter and output transformations."""

from __future__ import annotations

from agentlock.modify import ModifyEngine, ModifyResult
from agentlock.schema import ModifyPolicyConfig, TransformationConfig


class TestRedactPii:
    """Test the redact_pii transformation action."""

    def test_redacts_email_from_output(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        result = engine.apply_output(
            "query_database",
            "Customer: jane@example.com, phone: 555-0123",
            transforms,
        )
        assert result.modified
        assert "jane@example.com" not in result.modified_output
        assert "[REDACTED" in result.modified_output or "***" in result.modified_output
        assert "redact_pii" in result.transformations_applied

    def test_redacts_ssn_from_output(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        result = engine.apply_output(
            "query_database",
            "SSN: 123-45-6789",
            transforms,
        )
        assert result.modified
        assert "123-45-6789" not in result.modified_output

    def test_redacts_phone_from_output(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        result = engine.apply_output(
            "query_database",
            "Phone: 555-012-3456",
            transforms,
        )
        assert result.modified
        assert "555-012-3456" not in result.modified_output

    def test_redacts_full_db_response(self):
        """Test with a realistic query_database response."""
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        db_output = (
            "Results: [{'customer_id': 'C-1024', 'name': 'Jane Doe', "
            "'email': 'jane@example.com', 'phone': '555-012-3456', "
            "'ssn': '123-45-6789', 'balance': '$4,521.00'}]"
        )
        result = engine.apply_output("query_database", db_output, transforms)
        assert result.modified
        assert "jane@example.com" not in result.modified_output
        assert "555-012-3456" not in result.modified_output
        assert "123-45-6789" not in result.modified_output
        # customer_id and name should still be there
        assert "C-1024" in result.modified_output
        assert "Jane Doe" in result.modified_output

    def test_no_pii_no_modification(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        result = engine.apply_output(
            "lookup_order",
            "Order #12345: laptop, shipped",
            transforms,
        )
        assert not result.modified
        assert result.modified_output == "Order #12345: laptop, shipped"

    def test_preserves_original(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        original = "Email: test@example.com"
        result = engine.apply_output("query_database", original, transforms)
        assert result.original_output == original
        assert result.modified_output != original


class TestRestrictDomain:
    """Test the restrict_domain transformation action."""

    def test_blocks_external_domain(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="to",
            action="restrict_domain",
            config={"allowed_domains": ["company.com"]},
        )]
        result = engine.apply_params("send_email", {"to": "attacker@evil.com"}, transforms)
        assert result.modified
        assert "BLOCKED" in result.modified_params["to"]

    def test_allows_internal_domain(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="to",
            action="restrict_domain",
            config={"allowed_domains": ["company.com"]},
        )]
        result = engine.apply_params("send_email", {"to": "alice@company.com"}, transforms)
        assert not result.modified
        assert result.modified_params["to"] == "alice@company.com"

    def test_multiple_allowed_domains(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="to",
            action="restrict_domain",
            config={"allowed_domains": ["company.com", "partner.org"]},
        )]
        result = engine.apply_params("send_email", {"to": "bob@partner.org"}, transforms)
        assert not result.modified

    def test_no_email_in_field(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="to",
            action="restrict_domain",
            config={"allowed_domains": ["company.com"]},
        )]
        result = engine.apply_params("send_email", {"to": "not-an-email"}, transforms)
        assert not result.modified


class TestWhitelistPath:
    """Test the whitelist_path transformation action."""

    def test_blocks_unauthorized_path(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="path",
            action="whitelist_path",
            config={"allowed_prefixes": ["/data/", "/public/"]},
        )]
        result = engine.apply_params("read_file", {"path": "/etc/passwd"}, transforms)
        assert result.modified
        assert "BLOCKED" in result.modified_params["path"]

    def test_allows_authorized_path(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="path",
            action="whitelist_path",
            config={"allowed_prefixes": ["/data/", "/public/"]},
        )]
        result = engine.apply_params("read_file", {"path": "/data/customers.csv"}, transforms)
        assert not result.modified
        assert result.modified_params["path"] == "/data/customers.csv"

    def test_blocks_relative_path(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="path",
            action="whitelist_path",
            config={"allowed_prefixes": ["/data/"]},
        )]
        result = engine.apply_params("read_file", {"path": "./config.json"}, transforms)
        assert result.modified
        assert "BLOCKED" in result.modified_params["path"]


class TestCapRecords:
    """Test the cap_records transformation action."""

    def test_caps_excess_records(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="output",
            action="cap_records",
            config={"max_records": 2},
        )]
        output = "[{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}]"
        result = engine.apply_output("query_database", output, transforms)
        assert result.modified
        assert "redacted" in result.modified_output.lower()

    def test_does_not_cap_within_limit(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="output",
            action="cap_records",
            config={"max_records": 10},
        )]
        output = "[{'id': 1}, {'id': 2}]"
        result = engine.apply_output("query_database", output, transforms)
        assert not result.modified


class TestModifyResult:
    """Test ModifyResult dataclass."""

    def test_default_unmodified(self):
        r = ModifyResult()
        assert not r.modified
        assert r.transformations_applied == []

    def test_tracks_transformations(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        result = engine.apply_output(
            "query_database", "Email: test@example.com", transforms,
        )
        assert "redact_pii" in result.transformations_applied


class TestBuildOutputModifier:
    """Test building a callable output modifier."""

    def test_returns_callable(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        modifier = engine.build_output_modifier("query_database", transforms)
        assert modifier is not None
        assert callable(modifier)

    def test_modifier_redacts(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="redact_pii")]
        modifier = engine.build_output_modifier("query_database", transforms)
        result = modifier("Email: test@example.com, SSN: 123-45-6789")
        assert "test@example.com" not in result
        assert "123-45-6789" not in result

    def test_returns_none_for_param_only(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="to", action="restrict_domain")]
        modifier = engine.build_output_modifier("send_email", transforms)
        assert modifier is None

    def test_returns_none_for_empty_list(self):
        engine = ModifyEngine()
        modifier = engine.build_output_modifier("query_database", [])
        assert modifier is None


class TestNoOpBehavior:
    """Test that MODIFY is a no-op when not configured or not applicable."""

    def test_no_transformations_no_modification(self):
        engine = ModifyEngine()
        result = engine.apply_output("query_database", "some output", [])
        assert not result.modified

    def test_wrong_field_no_modification(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="to", action="restrict_domain")]
        result = engine.apply_output("query_database", "some output", transforms)
        assert not result.modified

    def test_unknown_action_ignored(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(field="output", action="nonexistent_action")]
        result = engine.apply_output("query_database", "some output", transforms)
        assert not result.modified

    def test_param_not_in_dict_ignored(self):
        engine = ModifyEngine()
        transforms = [TransformationConfig(
            field="nonexistent_param",
            action="restrict_domain",
            config={"allowed_domains": ["company.com"]},
        )]
        result = engine.apply_params("send_email", {"to": "test@evil.com"}, transforms)
        assert not result.modified


class TestMultipleTransformations:
    """Test applying multiple transformations."""

    def test_redact_pii_then_cap_records(self):
        engine = ModifyEngine()
        transforms = [
            TransformationConfig(field="output", action="redact_pii"),
            TransformationConfig(field="output", action="cap_records", config={"max_records": 1}),
        ]
        output = "[{'email': 'a@b.com'}, {'email': 'c@d.com'}, {'email': 'e@f.com'}]"
        result = engine.apply_output("query_database", output, transforms)
        assert result.modified
        assert "a@b.com" not in result.modified_output


class TestModifyPolicyConfig:
    """Test the schema configuration model."""

    def test_default_disabled(self):
        cfg = ModifyPolicyConfig()
        assert not cfg.enabled
        assert cfg.transformations == []
        assert cfg.apply_when_hardening_active is True

    def test_with_transformations(self):
        cfg = ModifyPolicyConfig(
            enabled=True,
            transformations=[
                TransformationConfig(field="output", action="redact_pii"),
                TransformationConfig(
                    field="to",
                    action="restrict_domain",
                    config={"allowed_domains": ["company.com"]},
                ),
            ],
        )
        assert cfg.enabled
        assert len(cfg.transformations) == 2

    def test_permissions_with_modify_policy(self):
        from agentlock.schema import AgentLockPermissions
        perms = AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
            modify_policy=ModifyPolicyConfig(
                enabled=True,
                transformations=[
                    TransformationConfig(field="output", action="redact_pii"),
                ],
            ),
        )
        assert perms.modify_policy is not None
        assert perms.modify_policy.enabled

    def test_permissions_without_modify_policy(self):
        from agentlock.schema import AgentLockPermissions
        perms = AgentLockPermissions(
            risk_level="high",
            requires_auth=True,
            allowed_roles=["admin"],
        )
        assert perms.modify_policy is None
