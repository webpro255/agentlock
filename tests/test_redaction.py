"""Tests for agentlock.redaction — RedactionEngine."""

from __future__ import annotations

import re

from agentlock.redaction import RedactionEngine


class TestRedactionEngine:
    def test_redacts_ssn(self):
        engine = RedactionEngine(prohibited=["ssn"])
        result = engine.redact("My SSN is 123-45-6789.")
        assert "123-45-6789" not in result.redacted
        assert "[REDACTED:ssn]" in result.redacted
        assert result.was_redacted is True

    def test_redacts_credit_card(self):
        engine = RedactionEngine(prohibited=["credit_card"])
        result = engine.redact("Card: 4111-1111-1111-1111")
        assert "4111-1111-1111-1111" not in result.redacted
        assert "[REDACTED:credit_card]" in result.redacted

    def test_redacts_credit_card_no_dashes(self):
        engine = RedactionEngine(prohibited=["credit_card"])
        result = engine.redact("Card: 4111111111111111")
        assert "4111111111111111" not in result.redacted
        assert "[REDACTED:credit_card]" in result.redacted

    def test_redacts_multiple_types_in_one_pass(self):
        engine = RedactionEngine(prohibited=["ssn", "credit_card"])
        text = "SSN: 123-45-6789, Card: 4111-1111-1111-1111"
        result = engine.redact(text)
        assert "123-45-6789" not in result.redacted
        assert "4111-1111-1111-1111" not in result.redacted
        assert "[REDACTED:ssn]" in result.redacted
        assert "[REDACTED:credit_card]" in result.redacted
        assert len(result.redactions) == 2

    def test_custom_patterns_work(self):
        engine = RedactionEngine(
            custom_patterns={"badge_id": re.compile(r"BADGE-\d{6}")}
        )
        result = engine.redact("Employee BADGE-123456 entered.")
        assert "BADGE-123456" not in result.redacted
        assert "[REDACTED:badge_id]" in result.redacted

    def test_custom_pattern_as_string(self):
        engine = RedactionEngine(
            custom_patterns={"order_id": r"ORD-\d+"}
        )
        result = engine.redact("Order ORD-99887766 shipped.")
        assert "ORD-99887766" not in result.redacted
        assert "[REDACTED:order_id]" in result.redacted

    def test_no_false_positives_on_clean_text(self):
        engine = RedactionEngine(prohibited=["ssn", "credit_card", "email"])
        result = engine.redact("Hello, this is a perfectly normal sentence.")
        assert result.was_redacted is False
        assert result.redacted == result.original
        assert result.redactions == []

    def test_was_redacted_true_when_match(self):
        engine = RedactionEngine(prohibited=["ssn"])
        result = engine.redact("SSN: 111-22-3333")
        assert result.was_redacted is True

    def test_was_redacted_false_when_no_match(self):
        engine = RedactionEngine(prohibited=["ssn"])
        result = engine.redact("No sensitive data here.")
        assert result.was_redacted is False

    def test_redaction_result_preserves_original(self):
        engine = RedactionEngine(prohibited=["ssn"])
        text = "SSN: 999-88-7777"
        result = engine.redact(text)
        assert result.original == text
        assert result.redacted != text

    def test_redaction_records_details(self):
        engine = RedactionEngine(prohibited=["ssn"])
        result = engine.redact("SSN: 123-45-6789")
        assert len(result.redactions) == 1
        r = result.redactions[0]
        assert r["type"] == "ssn"
        assert r["original"] == "123-45-6789"
        assert r["replacement"] == "[REDACTED:ssn]"

    def test_multiple_occurrences_of_same_type(self):
        engine = RedactionEngine(prohibited=["ssn"])
        result = engine.redact("SSN1: 111-22-3333, SSN2: 444-55-6666")
        assert len(result.redactions) == 2
        assert result.redacted.count("[REDACTED:ssn]") == 2

    def test_custom_placeholder(self):
        engine = RedactionEngine(
            prohibited=["ssn"],
            placeholder="***{type}***",
        )
        result = engine.redact("SSN: 123-45-6789")
        assert "***ssn***" in result.redacted

    def test_add_pattern_at_runtime(self):
        engine = RedactionEngine()
        engine.add_pattern("secret_code", r"SC-\d{4}")
        result = engine.redact("Code: SC-1234")
        assert "SC-1234" not in result.redacted
        assert "[REDACTED:secret_code]" in result.redacted

    def test_prohibited_types_property(self):
        engine = RedactionEngine(prohibited=["ssn", "email"])
        assert "ssn" in engine.prohibited_types
        assert "email" in engine.prohibited_types

    def test_redacts_email(self):
        engine = RedactionEngine(prohibited=["email"])
        result = engine.redact("Contact: alice@example.com")
        assert "alice@example.com" not in result.redacted
        assert "[REDACTED:email]" in result.redacted

    def test_redacts_password_pattern(self):
        engine = RedactionEngine(prohibited=["password"])
        result = engine.redact("password: s3cret123!")
        assert "s3cret123!" not in result.redacted

    def test_empty_prohibited_list(self):
        engine = RedactionEngine(prohibited=[])
        result = engine.redact("SSN: 123-45-6789")
        assert result.was_redacted is False
        assert result.redacted == result.original
