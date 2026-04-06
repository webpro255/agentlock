"""Signed authorization receipts (AARM R5).

Every authorization decision can produce a cryptographically signed
receipt.  Receipts are verifiable offline without gate access.

Signing methods:

- **Ed25519** (via PyNaCl) — default when available.  Fast, small
  signatures, widely supported.
- **HMAC-SHA256** — fallback when PyNaCl is not installed.  Symmetric
  key, suitable for single-service deployments.

Install PyNaCl for Ed25519::

    pip install agentlock[crypto]
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SignedReceipt",
    "ReceiptSigner",
    "ReceiptVerifier",
]


def _generate_receipt_id() -> str:
    return f"rcpt_{secrets.token_hex(12)}"


@dataclass
class SignedReceipt:
    """A signed record of an authorization decision."""

    receipt_id: str = field(default_factory=_generate_receipt_id)
    timestamp: float = field(default_factory=time.time)
    decision: str = ""           # allow/deny/defer/step_up/modify
    tool_name: str = ""
    user_id: str = ""
    role: str = ""
    parameters_hash: str = ""    # SHA-256 of parameters
    reason: str | None = None
    policy_version_hash: str = ""
    context_hash: str = ""
    trust_ceiling: str | None = None
    signing_key_id: str = ""
    signature: str = ""          # hex-encoded signature
    metadata: dict[str, Any] = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for signing.

        Fields are concatenated in a fixed order with null-byte
        separators.  This avoids JSON serialization ambiguity.
        """
        parts = [
            self.receipt_id,
            f"{self.timestamp:.6f}",
            self.decision,
            self.tool_name,
            self.user_id,
            self.role,
            self.parameters_hash,
            self.reason or "",
            self.policy_version_hash,
            self.context_hash,
            self.trust_ceiling or "",
            self.signing_key_id,
        ]
        return b"\x00".join(p.encode("utf-8") for p in parts)


class ReceiptSigner:
    """Signs authorization receipts.

    Args:
        signing_method: ``"ed25519"`` or ``"hmac-sha256"``.
        signing_key: Raw key bytes.  For Ed25519 this is the 32-byte
            seed/private key.  For HMAC this is the shared secret.
            If ``None``, a key is generated automatically.
        key_id: Human-readable identifier for the signing key.
    """

    def __init__(
        self,
        signing_method: str = "ed25519",
        signing_key: bytes | None = None,
        key_id: str = "",
    ) -> None:
        self._method = signing_method
        self._key_id = key_id or f"key_{secrets.token_hex(4)}"

        if signing_method == "ed25519":
            try:
                from nacl.signing import SigningKey as _Ed25519SigningKey
            except ImportError:
                raise ImportError(
                    "PyNaCl is required for Ed25519 signing. "
                    "Install with: pip install agentlock[crypto]"
                ) from None
            if signing_key is None:
                self._ed_key = _Ed25519SigningKey.generate()
            else:
                self._ed_key = _Ed25519SigningKey(signing_key)
            self._verify_key_bytes: bytes = bytes(self._ed_key.verify_key)
        elif signing_method == "hmac-sha256":
            self._hmac_key = signing_key or secrets.token_bytes(32)
            self._verify_key_bytes = self._hmac_key
        else:
            raise ValueError(
                f"Unknown signing method: {signing_method!r}. "
                f"Use 'ed25519' or 'hmac-sha256'."
            )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def verify_key_bytes(self) -> bytes:
        """Public key (Ed25519) or shared secret (HMAC) for verification."""
        return self._verify_key_bytes

    def sign(self, receipt: SignedReceipt) -> SignedReceipt:
        """Sign a receipt, populating ``.signature`` and ``.signing_key_id``."""
        receipt.signing_key_id = self._key_id
        payload = receipt.canonical_bytes()

        if self._method == "ed25519":
            signed = self._ed_key.sign(payload)
            receipt.signature = signed.signature.hex()
        else:
            sig = hmac.new(self._hmac_key, payload, hashlib.sha256).hexdigest()
            receipt.signature = sig

        return receipt

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate an Ed25519 key pair (private_seed, public_key).

        Only available when signing_method is ``"ed25519"``.

        Returns:
            Tuple of (32-byte seed, 32-byte public key).
        """
        if self._method != "ed25519":
            raise TypeError(
                "generate_key_pair() is only available for Ed25519 signing."
            )
        from nacl.signing import SigningKey as _Ed25519SigningKey
        new_key = _Ed25519SigningKey.generate()
        return bytes(new_key), bytes(new_key.verify_key)


class ReceiptVerifier:
    """Verifies signed authorization receipts.

    Args:
        signing_method: Must match the signer's method.
        verify_key: Public key (Ed25519) or shared secret (HMAC).
    """

    def __init__(
        self,
        signing_method: str = "ed25519",
        verify_key: bytes = b"",
    ) -> None:
        self._method = signing_method
        if signing_method == "ed25519":
            try:
                from nacl.signing import VerifyKey as _Ed25519VerifyKey
            except ImportError:
                raise ImportError(
                    "PyNaCl is required for Ed25519 verification. "
                    "Install with: pip install agentlock[crypto]"
                ) from None
            self._ed_verify = _Ed25519VerifyKey(verify_key)
        elif signing_method == "hmac-sha256":
            self._hmac_key = verify_key
        else:
            raise ValueError(
                f"Unknown signing method: {signing_method!r}. "
                f"Use 'ed25519' or 'hmac-sha256'."
            )

    def verify(self, receipt: SignedReceipt) -> bool:
        """Verify the receipt's signature.

        Returns ``True`` if valid, ``False`` if tampered or invalid.
        """
        payload = receipt.canonical_bytes()

        if self._method == "ed25519":
            try:
                sig_bytes = bytes.fromhex(receipt.signature)
                self._ed_verify.verify(payload, sig_bytes)
                return True
            except Exception:
                return False
        else:
            expected = hmac.new(
                self._hmac_key, payload, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, receipt.signature)
