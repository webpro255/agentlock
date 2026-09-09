"""Tests for the declared recipient parameter, v1.8 increment 2.

Increment 1 made pipeline Step 8 enforce; it did not make Step 8 reachable,
because no adapter passes ``recipient=`` to ``authorize()``.  These tests cover
the trusted permission block declaring which top-level parameter carries the
recipient, the gate reading that one key, recipient sets resolved from
list-valued parameters, the two recipient faults, and the guarantee that the
extraction writes nothing back into the parameters or the request metadata.
"""

from __future__ import annotations

import copy

import pytest

try:
    import nacl  # noqa: F401

    HAS_NACL = True
except ImportError:
    HAS_NACL = False

requires_nacl = pytest.mark.skipif(not HAS_NACL, reason="PyNaCl not installed")

from agentlock.gate import AuthorizationGate  # noqa: E402
from agentlock.policy import PolicyEngine, RequestContext  # noqa: E402
from agentlock.receipts import ReceiptSigner, ReceiptVerifier  # noqa: E402
from agentlock.schema import AgentLockPermissions, ScopeConfig  # noqa: E402
from agentlock.types import (  # noqa: E402
    DenialReason,
    RecipientPolicy,
    RiskLevel,
)

KNOWN = ["bob@company.com", "carol@company.com"]
HOSTILE = "attacker@evil.com"


@pytest.fixture
def engine():
    return PolicyEngine()


def _perms(
    *,
    version="1.5",
    policy=RecipientPolicy.KNOWN_CONTACTS_ONLY,
    recipient_parameter="to",
):
    """A block whose only restriction is the recipient, with a declared key."""
    return AgentLockPermissions(
        version=version,
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
        scope=ScopeConfig(
            allowed_recipients=policy,
            recipient_parameter=recipient_parameter,
        ),
    )


def _gate(*, known_contacts=KNOWN, gate_kwargs=None, **perm_kwargs):
    """A gate with one registered send tool and one session for alice."""
    gate = AuthorizationGate(**(gate_kwargs or {}))
    gate.register_tool("send_email", _perms(**perm_kwargs))
    gate.create_session(
        user_id="alice",
        role="user",
        known_contacts=list(known_contacts),
    )
    return gate


def _authorize(gate, **kwargs):
    return gate.authorize("send_email", user_id="alice", role="user", **kwargs)


def _assert_recipient_denial(result):
    assert result.allowed is False
    assert result.denial["reason"] == DenialReason.RECIPIENT_NOT_ALLOWED.value


# ---- the declared key, string valued ---------------------------------------

class TestDeclaredKeyStringValue:
    def test_hostile_value_with_no_caller_recipient_denies(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": HOSTILE})
        _assert_recipient_denial(result)

    def test_known_contact_value_allows(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": "bob@company.com"})
        assert result.allowed is True

    def test_declared_key_absent_and_no_caller_recipient_allows(self):
        gate = _gate()
        result = _authorize(gate, parameters={"subject": "hello"})
        assert result.allowed is True


# ---- the declared key present but carrying nothing -------------------------

class TestDeclaredKeyEmptyValues:
    def test_none_value_skips_the_step(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": None})
        assert result.allowed is True

    def test_empty_string_value_skips_the_step(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": ""})
        assert result.allowed is True

    def test_empty_list_value_skips_the_step(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": []})
        assert result.allowed is True


# ---- malformed declared values ---------------------------------------------

class TestMalformedDeclaredValue:
    def test_int_value_denies(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": 42})
        _assert_recipient_denial(result)

    def test_list_containing_a_non_string_denies(self):
        gate = _gate()
        result = _authorize(
            gate, parameters={"to": ["bob@company.com", 42]}
        )
        _assert_recipient_denial(result)

    def test_malformed_detail_carries_no_recipient_value(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": {"address": HOSTILE}})
        _assert_recipient_denial(result)
        assert HOSTILE not in result.denial["detail"]


# ---- recipient sets from list-valued parameters -----------------------------

class TestRecipientSets:
    def test_list_of_two_known_contacts_allows(self):
        gate = _gate()
        result = _authorize(
            gate, parameters={"to": ["bob@company.com", "carol@company.com"]}
        )
        assert result.allowed is True

    def test_list_with_one_unknown_contact_denies(self):
        gate = _gate()
        result = _authorize(
            gate, parameters={"to": ["bob@company.com", HOSTILE]}
        )
        _assert_recipient_denial(result)


# ---- the caller assertion against the declared parameter --------------------

class TestCallerAssertion:
    def test_assertion_matching_the_declared_value_allows(self):
        gate = _gate()
        result = _authorize(
            gate,
            parameters={"to": "bob@company.com"},
            recipient="bob@company.com",
        )
        assert result.allowed is True

    def test_assertion_disagreeing_with_the_declared_value_denies(self):
        gate = _gate()
        result = _authorize(
            gate,
            parameters={"to": "bob@company.com"},
            recipient="carol@company.com",
        )
        _assert_recipient_denial(result)

    def test_disagreement_detail_carries_neither_recipient_value(self):
        gate = _gate()
        result = _authorize(
            gate,
            parameters={"to": "bob@company.com"},
            recipient=HOSTILE,
        )
        _assert_recipient_denial(result)
        detail = result.denial["detail"]
        assert "bob@company.com" not in detail
        assert HOSTILE not in detail

    def test_assertion_used_when_the_declared_key_is_absent_and_allowed(self):
        gate = _gate()
        result = _authorize(
            gate,
            parameters={"subject": "hello"},
            recipient="bob@company.com",
        )
        assert result.allowed is True

    def test_assertion_used_when_the_declared_key_is_absent_and_denied(self):
        gate = _gate()
        result = _authorize(
            gate,
            parameters={"subject": "hello"},
            recipient=HOSTILE,
        )
        _assert_recipient_denial(result)


# ---- the version floor ------------------------------------------------------

class TestVersionFloor:
    def test_version_1_4_leaves_the_declared_parameter_inert(self):
        gate = _gate(version="1.4")
        result = _authorize(gate, parameters={"to": HOSTILE})
        assert result.allowed is True

    def test_version_1_4_leaves_a_malformed_value_inert(self):
        gate = _gate(version="1.4")
        result = _authorize(gate, parameters={"to": 42})
        assert result.allowed is True


# ---- a fault denies even under RecipientPolicy.ANY --------------------------

class TestFaultUnderAnyPolicy:
    def test_malformed_parameter_denies_under_any(self):
        gate = _gate(policy=RecipientPolicy.ANY, known_contacts=[])
        result = _authorize(gate, parameters={"to": 42})
        _assert_recipient_denial(result)

    def test_assertion_disagreement_denies_under_any(self):
        gate = _gate(policy=RecipientPolicy.ANY, known_contacts=[])
        result = _authorize(
            gate,
            parameters={"to": "bob@company.com"},
            recipient=HOSTILE,
        )
        _assert_recipient_denial(result)

    def test_a_well_formed_agreeing_recipient_still_allows_under_any(self):
        gate = _gate(policy=RecipientPolicy.ANY, known_contacts=[])
        result = _authorize(
            gate,
            parameters={"to": HOSTILE},
            recipient=HOSTILE,
        )
        assert result.allowed is True


# ---- policy level: the recipients tuple on RequestContext -------------------

class TestPolicyLevelRecipientSet:
    def test_one_bad_entry_denies(self, engine):
        perms = _perms()
        ctx = RequestContext(
            user_id="alice@company.com",
            role="user",
            recipients=("bob@company.com", HOSTILE),
            known_contacts=frozenset(KNOWN),
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_all_entries_good_allows(self, engine):
        perms = _perms()
        ctx = RequestContext(
            user_id="alice@company.com",
            role="user",
            recipients=("bob@company.com", "carol@company.com"),
            known_contacts=frozenset(KNOWN),
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_recipients_takes_precedence_over_recipient(self, engine):
        perms = _perms()
        ctx = RequestContext(
            user_id="alice@company.com",
            role="user",
            recipient=HOSTILE,
            recipients=("bob@company.com",),
            known_contacts=frozenset(KNOWN),
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is True

    def test_a_fault_alone_makes_the_step_live(self, engine):
        perms = _perms()
        ctx = RequestContext(
            user_id="alice@company.com",
            role="user",
            recipient_fault="malformed_parameter",
            known_contacts=frozenset(KNOWN),
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED

    def test_an_unrecognized_fault_kind_fails_safe(self, engine):
        perms = _perms()
        ctx = RequestContext(
            user_id="alice@company.com",
            role="user",
            recipient_fault="something_new",
            known_contacts=frozenset(KNOWN),
        )
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED


# ---- signed receipt on a parameter-driven recipient denial ------------------

class TestParameterDenialReceipt:
    def test_denial_is_signed_and_verifies(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        gate = _gate(gate_kwargs={"receipt_signer": signer})
        result = _authorize(gate, parameters={"to": HOSTILE})
        _assert_recipient_denial(result)
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
        gate = _gate(gate_kwargs={"receipt_signer": signer})
        result = _authorize(gate, parameters={"to": HOSTILE})
        assert result.receipt is not None

        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is True


# ---- the extraction writes nothing back ------------------------------------

class TestExtractionWritesNothing:
    def test_parameters_dict_is_unchanged_by_a_denial(self):
        gate = _gate()
        parameters = {"to": HOSTILE, "subject": "hello"}
        before = copy.deepcopy(parameters)
        result = _authorize(gate, parameters=parameters)
        _assert_recipient_denial(result)
        assert parameters == before
        assert set(parameters) == {"to", "subject"}

    def test_parameters_dict_is_unchanged_by_an_allow(self):
        gate = _gate()
        parameters = {"to": ["bob@company.com", "carol@company.com"]}
        before = copy.deepcopy(parameters)
        result = _authorize(gate, parameters=parameters)
        assert result.allowed is True
        assert parameters == before

    def test_parameters_dict_is_unchanged_by_a_fault(self):
        gate = _gate()
        parameters = {"to": 42}
        before = copy.deepcopy(parameters)
        result = _authorize(gate, parameters=parameters)
        _assert_recipient_denial(result)
        assert parameters == before

    def test_audit_metadata_gains_no_recipient_key(self):
        gate = _gate()
        result = _authorize(gate, parameters={"to": HOSTILE})
        _assert_recipient_denial(result)

        records = gate.audit_logger.query(limit=50)
        assert records
        for record in records:
            for key in record.metadata:
                assert "recipient" not in key
                assert key != "recipients"
