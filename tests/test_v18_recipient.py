"""Tests for v1.8 recipient policy enforcement at pipeline Step 8.

Step 8 was a comment block through v1.7.0.  These tests cover the four
RecipientPolicy semantics at schema version 1.5, the additive version floor
that leaves 1.4 blocks unchanged, the session threading of known contacts,
the signed receipt on a recipient denial, and the RATE_LIMITED enum member.
"""

from __future__ import annotations

import pytest

try:
    import nacl  # noqa: F401

    HAS_NACL = True
except ImportError:
    HAS_NACL = False

requires_nacl = pytest.mark.skipif(not HAS_NACL, reason="PyNaCl not installed")

from agentlock.exceptions import RateLimitedError  # noqa: E402
from agentlock.gate import AuthorizationGate  # noqa: E402
from agentlock.policy import PolicyEngine, RequestContext  # noqa: E402
from agentlock.receipts import ReceiptSigner, ReceiptVerifier  # noqa: E402
from agentlock.schema import (  # noqa: E402
    AgentLockPermissions,
    RateLimitConfig,
    ScopeConfig,
)
from agentlock.types import (  # noqa: E402
    DenialReason,
    RecipientPolicy,
    RiskLevel,
)


@pytest.fixture
def engine():
    return PolicyEngine()


def _perms(policy, *, version="1.5", allowlist=None):
    """A minimal permission block whose only restriction is the recipient."""
    scope = ScopeConfig(
        allowed_recipients=policy,
        recipient_allowlist=list(allowlist or []),
    )
    return AgentLockPermissions(
        version=version,
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
        scope=scope,
    )


def _ctx(recipient, *, user_id="alice@company.com", known_contacts=()):
    return RequestContext(
        user_id=user_id,
        role="user",
        recipient=recipient,
        known_contacts=frozenset(known_contacts),
    )


# ---- known_contacts_only --------------------------------------------------

class TestKnownContactsOnly:
    def test_recipient_in_known_contacts_allows(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        ctx = _ctx("bob@company.com", known_contacts={"bob@company.com"})
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True
        assert decision.reason is None

    def test_recipient_not_in_known_contacts_denies(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        ctx = _ctx("attacker@evil.com", known_contacts={"bob@company.com"})
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_empty_known_contacts_denies(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        ctx = _ctx("bob@company.com")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_match_is_case_and_whitespace_insensitive(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        ctx = _ctx("  BOB@Company.COM  ", known_contacts={"bob@company.com"})
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True


# ---- allowlist ------------------------------------------------------------

class TestAllowlist:
    def test_exact_address_match_allows(self, engine):
        perms = _perms(
            RecipientPolicy.ALLOWLIST, allowlist=["bob@company.com"]
        )
        decision = engine.evaluate(perms, _ctx("bob@company.com"))
        assert decision.allowed is True
        assert decision.reason is None

    def test_domain_entry_in_domain_allows(self, engine):
        perms = _perms(RecipientPolicy.ALLOWLIST, allowlist=["@company.com"])
        decision = engine.evaluate(perms, _ctx("anyone@company.com"))
        assert decision.allowed is True

    def test_domain_entry_out_of_domain_denies(self, engine):
        perms = _perms(RecipientPolicy.ALLOWLIST, allowlist=["@company.com"])
        decision = engine.evaluate(perms, _ctx("attacker@evil.com"))
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_subdomain_of_domain_entry_denies(self, engine):
        perms = _perms(RecipientPolicy.ALLOWLIST, allowlist=["@company.com"])
        decision = engine.evaluate(perms, _ctx("bob@mail.company.com"))
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_empty_allowlist_denies(self, engine):
        perms = _perms(RecipientPolicy.ALLOWLIST)
        decision = engine.evaluate(perms, _ctx("bob@company.com"))
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_entries_are_normalized(self, engine):
        perms = _perms(
            RecipientPolicy.ALLOWLIST, allowlist=["  @Company.COM  "]
        )
        decision = engine.evaluate(perms, _ctx("BOB@company.com"))
        assert decision.allowed is True


# ---- same_domain ----------------------------------------------------------

class TestSameDomain:
    def test_matching_domain_allows(self, engine):
        perms = _perms(RecipientPolicy.SAME_DOMAIN)
        ctx = _ctx("bob@company.com", user_id="alice@company.com")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True
        assert decision.reason is None

    def test_different_domain_denies(self, engine):
        perms = _perms(RecipientPolicy.SAME_DOMAIN)
        ctx = _ctx("attacker@evil.com", user_id="alice@company.com")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_user_id_without_domain_denies(self, engine):
        perms = _perms(RecipientPolicy.SAME_DOMAIN)
        ctx = _ctx("bob@company.com", user_id="alice")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_subdomain_does_not_match(self, engine):
        perms = _perms(RecipientPolicy.SAME_DOMAIN)
        ctx = _ctx("bob@mail.company.com", user_id="alice@company.com")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED


# ---- any and the skip conditions ------------------------------------------

class TestUnrestrictedAndSkips:
    def test_any_policy_allows_arbitrary_recipient(self, engine):
        perms = _perms(RecipientPolicy.ANY)
        decision = engine.evaluate(perms, _ctx("attacker@evil.com"))
        assert decision.allowed is True
        assert decision.reason is None

    def test_any_policy_allows_malformed_recipient(self, engine):
        perms = _perms(RecipientPolicy.ANY)
        decision = engine.evaluate(perms, _ctx("a@b.com, c@d.com"))
        assert decision.allowed is True

    def test_empty_recipient_skips_the_step(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        decision = engine.evaluate(perms, _ctx(""))
        assert decision.allowed is True
        assert decision.reason is None


# ---- malformed recipients, one per D11 form -------------------------------

class TestMalformedRecipients:
    @pytest.mark.parametrize(
        "recipient",
        [
            "not an address",
            "bob@company.com\x00",
            "bob@company.com\nbcc@evil.com",
            "a@b.com, c@d.com",
            "a@b.com; c@d.com",
        ],
    )
    def test_malformed_denies_under_known_contacts(self, engine, recipient):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY)
        ctx = _ctx(recipient, known_contacts={recipient.strip().casefold()})
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    @pytest.mark.parametrize(
        "recipient",
        [
            "not an address",
            "bob@company.com\x00",
            "bob@company.com\nbcc@evil.com",
            "a@b.com, c@d.com",
            "a@b.com; c@d.com",
        ],
    )
    def test_malformed_denies_under_allowlist(self, engine, recipient):
        perms = _perms(
            RecipientPolicy.ALLOWLIST,
            allowlist=[recipient.strip().casefold(), "@company.com"],
        )
        decision = engine.evaluate(perms, _ctx(recipient))
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    @pytest.mark.parametrize(
        "recipient",
        [
            "not an address",
            "bob@company.com\x00",
            "bob@company.com\nbcc@evil.com",
            "a@b.com, c@d.com",
            "a@b.com; c@d.com",
        ],
    )
    def test_malformed_denies_under_same_domain(self, engine, recipient):
        perms = _perms(RecipientPolicy.SAME_DOMAIN)
        ctx = _ctx(recipient, user_id="alice@company.com")
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED


# ---- version floor: 1.4 blocks are unaffected -----------------------------

class TestVersionFloor:
    def test_v14_block_allows_cross_domain_recipient(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY, version="1.4")
        decision = engine.evaluate(perms, _ctx("attacker@evil.com"))
        assert decision.allowed is True
        assert decision.reason is None

    def test_v14_block_allows_malformed_recipient(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY, version="1.4")
        decision = engine.evaluate(perms, _ctx("a@b.com, c@d.com"))
        assert decision.allowed is True

    def test_v15_block_denies_the_same_call(self, engine):
        perms = _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY, version="1.5")
        decision = engine.evaluate(perms, _ctx("attacker@evil.com"))
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED


# ---- session threading through the gate -----------------------------------

def _gate_with_send_tool(**gate_kwargs):
    gate = AuthorizationGate(**gate_kwargs)
    gate.register_tool(
        "send_email",
        _perms(RecipientPolicy.KNOWN_CONTACTS_ONLY),
    )
    return gate


class TestSessionThreading:
    def test_known_contact_from_session_allows(self):
        gate = _gate_with_send_tool()
        gate.create_session(
            user_id="alice",
            role="user",
            known_contacts=["Bob@Company.com"],
        )
        result = gate.authorize(
            "send_email",
            user_id="alice",
            role="user",
            recipient="bob@company.com",
        )
        assert result.allowed is True

    def test_unknown_contact_denied_through_the_gate(self):
        gate = _gate_with_send_tool()
        gate.create_session(
            user_id="alice",
            role="user",
            known_contacts=["Bob@Company.com"],
        )
        result = gate.authorize(
            "send_email",
            user_id="alice",
            role="user",
            recipient="attacker@evil.com",
        )
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.RECIPIENT_NOT_ALLOWED.value

    def test_session_without_contacts_denies(self):
        gate = _gate_with_send_tool()
        gate.create_session(user_id="alice", role="user")
        result = gate.authorize(
            "send_email",
            user_id="alice",
            role="user",
            recipient="bob@company.com",
        )
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.RECIPIENT_NOT_ALLOWED.value

    def test_contacts_are_frozen_on_the_session(self):
        gate = _gate_with_send_tool()
        session = gate.create_session(
            user_id="alice",
            role="user",
            known_contacts=["  Bob@Company.com  "],
        )
        assert session.known_contacts == frozenset({"bob@company.com"})


# ---- signed receipt on a recipient denial ---------------------------------

class TestRecipientDenialReceipt:
    def test_denial_is_signed_and_verifies(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        gate = _gate_with_send_tool(receipt_signer=signer)
        gate.create_session(user_id="alice", role="user")
        result = gate.authorize(
            "send_email",
            user_id="alice",
            role="user",
            recipient="attacker@evil.com",
        )
        assert result.allowed is False
        assert result.receipt is not None
        assert result.receipt.decision == "deny"

        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is True

    @requires_nacl
    def test_denial_is_signed_under_ed25519(self):
        signer = ReceiptSigner(signing_method="ed25519")
        gate = _gate_with_send_tool(receipt_signer=signer)
        gate.create_session(user_id="alice", role="user")
        result = gate.authorize(
            "send_email",
            user_id="alice",
            role="user",
            recipient="attacker@evil.com",
        )
        assert result.receipt is not None

        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is True


# ---- RATE_LIMITED is the enum member, wire value unchanged ----------------

class TestRateLimitedEnum:
    def test_exception_reason_wire_value_unchanged(self):
        assert RateLimitedError().to_dict()["reason"] == "rate_limited"
        assert (
            RateLimitedError().to_dict()["reason"]
            == DenialReason.RATE_LIMITED.value
        )

    def test_gate_denial_reason_wire_value_unchanged(self):
        gate = AuthorizationGate()
        gate.register_tool("limited_tool", AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            requires_auth=True,
            allowed_roles=["user"],
            rate_limit=RateLimitConfig(max_calls=1, window_seconds=60),
        ))
        gate.create_session(user_id="alice", role="user")
        gate.authorize("limited_tool", user_id="alice", role="user")
        result = gate.authorize("limited_tool", user_id="alice", role="user")
        assert result.allowed is False
        assert result.denial["reason"] == DenialReason.RATE_LIMITED.value

    def test_audit_reason_is_a_plain_str(self):
        assert type(RateLimitedError().to_dict()["reason"]) is str
