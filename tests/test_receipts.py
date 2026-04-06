"""Tests for Ed25519 signed receipts (AARM R5).

Phase 3: SignedReceipt, ReceiptSigner, ReceiptVerifier (20 tests)
Phase 5: Receipts wired into gate (8 tests)
"""

from __future__ import annotations

import pytest

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
)
from agentlock.hardening import HardeningConfig
from agentlock.receipts import ReceiptSigner, ReceiptVerifier, SignedReceipt

# ===========================================================================
# Phase 3: SignedReceipt unit tests (20 tests)
# ===========================================================================


class TestSignedReceipt:
    """Test SignedReceipt dataclass."""

    def test_create_receipt(self):
        r = SignedReceipt(decision="allow", tool_name="query_database")
        assert r.receipt_id.startswith("rcpt_")
        assert r.decision == "allow"
        assert r.timestamp > 0

    def test_canonical_bytes_deterministic(self):
        r = SignedReceipt(
            receipt_id="rcpt_fixed",
            timestamp=1000000.0,
            decision="allow",
            tool_name="query_database",
            user_id="alice",
            role="admin",
        )
        assert r.canonical_bytes() == r.canonical_bytes()

    def test_canonical_bytes_changes_on_decision(self):
        base = dict(
            receipt_id="rcpt_1",
            timestamp=1000.0,
            tool_name="t",
            user_id="u",
            role="r",
        )
        r1 = SignedReceipt(decision="allow", **base)
        r2 = SignedReceipt(decision="deny", **base)
        assert r1.canonical_bytes() != r2.canonical_bytes()

    def test_canonical_bytes_changes_on_tool_name(self):
        base = dict(
            receipt_id="rcpt_1",
            timestamp=1000.0,
            decision="allow",
            user_id="u",
            role="r",
        )
        r1 = SignedReceipt(tool_name="query_database", **base)
        r2 = SignedReceipt(tool_name="send_email", **base)
        assert r1.canonical_bytes() != r2.canonical_bytes()

    def test_canonical_bytes_changes_on_parameters_hash(self):
        base = dict(
            receipt_id="rcpt_1",
            timestamp=1000.0,
            decision="allow",
            tool_name="t",
            user_id="u",
            role="r",
        )
        r1 = SignedReceipt(parameters_hash="abc", **base)
        r2 = SignedReceipt(parameters_hash="def", **base)
        assert r1.canonical_bytes() != r2.canonical_bytes()

    def test_receipt_id_unique(self):
        r1 = SignedReceipt()
        r2 = SignedReceipt()
        assert r1.receipt_id != r2.receipt_id

    def test_empty_parameters_hash(self):
        r = SignedReceipt(parameters_hash="")
        assert b"\x00" in r.canonical_bytes()


class TestReceiptSignerEd25519:
    """Test Ed25519 signing."""

    def test_sign_receipt(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signed = signer.sign(receipt)
        assert signed.signature != ""
        assert signed.signing_key_id != ""

    def test_verify_valid_signature(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)

        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is True

    def test_reject_tampered_decision(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)

        receipt.decision = "deny"  # tamper
        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is False

    def test_reject_tampered_tool_name(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="allow", tool_name="query_database")
        signer.sign(receipt)

        receipt.tool_name = "delete_records"  # tamper
        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is False

    def test_reject_tampered_parameters_hash(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(
            decision="allow",
            tool_name="test",
            parameters_hash="original",
        )
        signer.sign(receipt)

        receipt.parameters_hash = "tampered"
        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is False

    def test_reject_tampered_signature_bytes(self):
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)

        receipt.signature = "00" * 64  # garbage signature
        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is False

    def test_generate_key_pair(self):
        signer = ReceiptSigner(signing_method="ed25519")
        private, public = signer.generate_key_pair()
        assert len(private) == 32
        assert len(public) == 32

    def test_different_verifier_instance(self):
        """Signed receipt verified by a separate ReceiptVerifier instance."""
        signer = ReceiptSigner(signing_method="ed25519")
        receipt = SignedReceipt(decision="deny", tool_name="send_email")
        signer.sign(receipt)

        # Create a fresh verifier with the public key
        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is True

    def test_key_id_set_on_signed_receipt(self):
        signer = ReceiptSigner(signing_method="ed25519", key_id="prod-key-1")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)
        assert receipt.signing_key_id == "prod-key-1"


class TestReceiptSignerHMAC:
    """Test HMAC-SHA256 signing."""

    def test_sign_receipt(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signed = signer.sign(receipt)
        assert signed.signature != ""

    def test_verify_valid_signature(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)

        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is True

    def test_reject_tampered_receipt(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)

        receipt.decision = "deny"
        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(receipt) is False

    def test_hmac_does_not_require_pynacl(self):
        """HMAC signer works without PyNaCl."""
        signer = ReceiptSigner(signing_method="hmac-sha256")
        receipt = SignedReceipt(decision="allow", tool_name="test")
        signer.sign(receipt)
        assert receipt.signature != ""

    def test_generate_key_pair_not_available(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        with pytest.raises(TypeError):
            signer.generate_key_pair()


class TestReceiptDecisionTypes:
    """Test receipts for each decision type."""

    def test_receipt_for_each_decision_type(self):
        signer = ReceiptSigner(signing_method="ed25519")
        for decision in ["allow", "deny", "defer", "step_up", "modify"]:
            receipt = SignedReceipt(decision=decision, tool_name="test")
            signer.sign(receipt)
            verifier = ReceiptVerifier(
                signing_method="ed25519",
                verify_key=signer.verify_key_bytes,
            )
            assert verifier.verify(receipt), f"Failed for decision={decision}"


# ===========================================================================
# Phase 5: Receipts wired into gate (8 tests)
# ===========================================================================


def _make_gate_with_signer(
    method: str = "hmac-sha256",
) -> tuple[AuthorizationGate, ReceiptSigner]:
    """Build a gate with receipt signing enabled."""
    signer = ReceiptSigner(signing_method=method)
    gate = AuthorizationGate(
        hardening_config=HardeningConfig(enabled=True),
        receipt_signer=signer,
    )
    gate.register_tool("query_database", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ))
    gate.register_tool("lookup_order", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["admin"],
    ))
    return gate, signer


class TestReceiptsInGate:
    """Test that the gate produces signed receipts."""

    def test_allow_produces_receipt(self):
        gate, signer = _make_gate_with_signer()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed
        assert result.receipt is not None
        assert result.receipt.decision == "allow"
        assert result.receipt.tool_name == "lookup_order"

    def test_deny_produces_receipt(self):
        gate, signer = _make_gate_with_signer()
        # No session → denied (requires_auth)
        result = gate.authorize("lookup_order", user_id="alice", role="viewer")
        assert not result.allowed
        assert result.receipt is not None
        assert result.receipt.decision == "deny"

    def test_receipt_verifiable(self):
        gate, signer = _make_gate_with_signer()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.receipt is not None

        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is True

    def test_receipt_tamper_detected(self):
        gate, signer = _make_gate_with_signer()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.receipt is not None

        result.receipt.decision = "deny"  # tamper
        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is False

    def test_no_receipt_without_signer(self):
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
        )
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.receipt is None

    def test_receipt_parameters_hash(self):
        gate, signer = _make_gate_with_signer()
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize(
            "lookup_order",
            user_id="alice",
            role="admin",
            parameters={"order_id": "12345"},
        )
        assert result.receipt is not None
        assert result.receipt.parameters_hash != ""

    def test_ed25519_receipts_in_gate(self):
        gate, signer = _make_gate_with_signer(method="ed25519")
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.receipt is not None

        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt) is True

    def test_deny_on_block_produces_receipt(self):
        """parameter_blocked denial also gets a signed receipt."""
        from agentlock.schema import ModifyPolicyConfig, TransformationConfig

        signer = ReceiptSigner(signing_method="hmac-sha256")
        gate = AuthorizationGate(
            hardening_config=HardeningConfig(enabled=True),
            receipt_signer=signer,
        )
        gate.register_tool("read_file", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
            modify_policy=ModifyPolicyConfig(
                enabled=True,
                apply_when_hardening_active=False,
                transformations=[
                    TransformationConfig(
                        field="path",
                        action="whitelist_path",
                        config={"allowed_prefixes": ["/data/"]},
                    ),
                ],
            ),
        ))
        gate.create_session(user_id="alice", role="admin")
        result = gate.authorize(
            "read_file",
            user_id="alice",
            role="admin",
            parameters={"path": "/etc/passwd"},
        )
        assert not result.allowed
        assert result.receipt is not None
        assert result.receipt.decision == "deny"
