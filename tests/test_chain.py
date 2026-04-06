"""Tests for hash-chained context (AARM R2).

Phase 4: ContextChain unit tests (15 tests)
Phase 6: Chain wired into ContextTracker (6 tests)
Phase 7: Integration tests (5 tests)
"""

from __future__ import annotations

import pytest

try:
    import nacl  # noqa: F401

    HAS_NACL = True
except ImportError:
    HAS_NACL = False

requires_nacl = pytest.mark.skipif(not HAS_NACL, reason="PyNaCl not installed")

from agentlock import AgentLockPermissions, AuthorizationGate  # noqa: E402
from agentlock.chain import GENESIS_HASH, ContextChain  # noqa: E402
from agentlock.context import ContextTracker  # noqa: E402
from agentlock.receipts import ReceiptSigner, ReceiptVerifier  # noqa: E402
from agentlock.types import ContextAuthority, ContextSource  # noqa: E402

# ===========================================================================
# Phase 4: ContextChain unit tests (15 tests)
# ===========================================================================


class TestContextChainBasics:
    """Test basic chain operations."""

    def test_empty_chain_genesis_hash(self):
        chain = ContextChain()
        assert chain.head_hash == GENESIS_HASH

    def test_append_single_entry_links_to_genesis(self):
        chain = ContextChain()
        entry = chain.append(
            source="user_message",
            authority="authoritative",
            content_hash="abc123",
        )
        assert entry.previous_hash == GENESIS_HASH
        assert entry.entry_hash != GENESIS_HASH

    def test_append_two_entries_second_links_to_first(self):
        chain = ContextChain()
        e1 = chain.append(
            source="user_message",
            authority="authoritative",
            content_hash="abc123",
        )
        e2 = chain.append(
            source="tool_output",
            authority="derived",
            content_hash="def456",
        )
        assert e2.previous_hash == e1.entry_hash

    def test_verify_valid_chain(self):
        chain = ContextChain()
        chain.append(source="a", authority="b", content_hash="c1")
        chain.append(source="d", authority="e", content_hash="c2")
        chain.append(source="f", authority="g", content_hash="c3")
        valid, broken_at = chain.verify_chain()
        assert valid is True
        assert broken_at is None


class TestContextChainTamperDetection:
    """Test tamper detection."""

    def test_tamper_content_hash(self):
        chain = ContextChain()
        chain.append(source="a", authority="b", content_hash="c1")
        chain.append(source="d", authority="e", content_hash="c2")

        # Tamper with first entry's content_hash
        chain._entries[0].content_hash = "tampered"
        valid, broken_at = chain.verify_chain()
        assert valid is False
        assert broken_at == 0

    def test_tamper_previous_hash(self):
        chain = ContextChain()
        chain.append(source="a", authority="b", content_hash="c1")
        chain.append(source="d", authority="e", content_hash="c2")

        # Tamper with second entry's previous_hash
        chain._entries[1].previous_hash = "tampered"
        valid, broken_at = chain.verify_chain()
        assert valid is False
        assert broken_at == 1

    def test_tamper_first_entry_invalidates_chain(self):
        chain = ContextChain()
        for i in range(5):
            chain.append(source="s", authority="a", content_hash=f"c{i}")

        # Tamper with first entry
        chain._entries[0].entry_hash = "tampered"
        valid, broken_at = chain.verify_chain()
        assert valid is False
        # Either entry 0 (hash mismatch) or entry 1 (previous_hash mismatch)
        assert broken_at in (0, 1)

    def test_ten_entries_valid(self):
        chain = ContextChain()
        for i in range(10):
            chain.append(source=f"s{i}", authority="a", content_hash=f"hash_{i}")
        valid, broken_at = chain.verify_chain()
        assert valid is True
        assert broken_at is None


class TestContextChainEntryHash:
    """Test entry_hash determinism."""

    def test_entry_hash_deterministic(self):
        """Same inputs produce same hash (when timestamp is fixed)."""
        from agentlock.chain import _compute_entry_hash

        h1 = _compute_entry_hash("prev", "content", "src", "auth", "writer", 1000.0)
        h2 = _compute_entry_hash("prev", "content", "src", "auth", "writer", 1000.0)
        assert h1 == h2

    def test_entry_hash_changes_on_content_hash(self):
        from agentlock.chain import _compute_entry_hash

        h1 = _compute_entry_hash("prev", "content_a", "src", "auth", "w", 1000.0)
        h2 = _compute_entry_hash("prev", "content_b", "src", "auth", "w", 1000.0)
        assert h1 != h2

    def test_entry_hash_changes_on_previous_hash(self):
        from agentlock.chain import _compute_entry_hash

        h1 = _compute_entry_hash("prev_a", "content", "src", "auth", "w", 1000.0)
        h2 = _compute_entry_hash("prev_b", "content", "src", "auth", "w", 1000.0)
        assert h1 != h2


class TestContextChainProperties:
    """Test chain properties."""

    def test_head_hash_updates_after_append(self):
        chain = ContextChain()
        h0 = chain.head_hash
        chain.append(source="s", authority="a", content_hash="c")
        h1 = chain.head_hash
        assert h0 != h1
        chain.append(source="s", authority="a", content_hash="c2")
        h2 = chain.head_hash
        assert h1 != h2

    def test_length_tracks_correctly(self):
        chain = ContextChain()
        assert len(chain) == 0
        chain.append(source="s", authority="a", content_hash="c")
        assert len(chain) == 1
        chain.append(source="s", authority="a", content_hash="c2")
        assert len(chain) == 2

    def test_getitem(self):
        chain = ContextChain()
        e = chain.append(source="s", authority="a", content_hash="c")
        assert chain[0].entry_id == e.entry_id


# ===========================================================================
# Phase 6: Chain wired into ContextTracker (6 tests)
# ===========================================================================


class TestChainInContextTracker:
    """Test that ContextTracker uses hash chains."""

    def test_record_write_creates_chain_entry(self):
        tracker = ContextTracker()
        tracker.record_write(
            session_id="s1",
            source=ContextSource.USER_MESSAGE,
            content_hash="abc123",
        )
        state = tracker.get("s1")
        assert state is not None
        assert len(state.context_chain) == 1

    def test_two_writes_form_valid_chain(self):
        tracker = ContextTracker()
        tracker.record_write(
            session_id="s1",
            source=ContextSource.USER_MESSAGE,
            content_hash="abc123",
        )
        tracker.record_write(
            session_id="s1",
            source=ContextSource.TOOL_OUTPUT,
            content_hash="def456",
        )
        valid, broken_at = tracker.verify_context_chain("s1")
        assert valid is True
        assert broken_at is None

    def test_verify_returns_true_for_unknown_session(self):
        tracker = ContextTracker()
        valid, broken_at = tracker.verify_context_chain("nonexistent")
        assert valid is True

    def test_provenance_previous_hash_populated(self):
        tracker = ContextTracker()
        prov1 = tracker.record_write(
            session_id="s1",
            source=ContextSource.USER_MESSAGE,
            content_hash="abc123",
        )
        assert prov1.previous_hash == GENESIS_HASH

        prov2 = tracker.record_write(
            session_id="s1",
            source=ContextSource.TOOL_OUTPUT,
            content_hash="def456",
        )
        assert prov2.previous_hash != ""
        assert prov2.previous_hash != GENESIS_HASH

    def test_chain_integrates_with_trust_degradation(self):
        """Chain entries are created even when trust degrades."""
        from agentlock.schema import (
            ContextPolicyConfig,
            DegradationTrigger,
            SourceAuthorityConfig,
            TrustDegradationConfig,
        )

        policy = ContextPolicyConfig(
            source_authorities=[
                SourceAuthorityConfig(
                    source=ContextSource.WEB_CONTENT,
                    authority=ContextAuthority.UNTRUSTED,
                ),
            ],
            trust_degradation=TrustDegradationConfig(
                enabled=True,
                triggers=[
                    DegradationTrigger(
                        source=ContextSource.WEB_CONTENT,
                        effect="restrict_scope",
                    ),
                ],
            ),
        )
        tracker = ContextTracker()
        tracker.record_write(
            session_id="s1",
            source=ContextSource.WEB_CONTENT,
            content_hash="web_hash",
            policy=policy,
        )
        state = tracker.get("s1")
        assert state is not None
        assert state.is_degraded
        assert len(state.context_chain) == 1
        valid, _ = tracker.verify_context_chain("s1")
        assert valid

    def test_destroy_clears_chain(self):
        tracker = ContextTracker()
        tracker.record_write(
            session_id="s1",
            source=ContextSource.USER_MESSAGE,
            content_hash="abc",
        )
        tracker.destroy("s1")
        assert tracker.get("s1") is None


# ===========================================================================
# Phase 7: Integration tests (5 tests)
# ===========================================================================


class TestIntegration:
    """End-to-end integration of receipts + chain + gate."""

    def test_full_authorize_execute_with_receipt_and_chain(self):
        """Full flow: authorize with receipt, then verify context chain."""
        signer = ReceiptSigner(signing_method="hmac-sha256")
        gate = AuthorizationGate(receipt_signer=signer)
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # Authorize
        result = gate.authorize("lookup_order", user_id="alice", role="admin")
        assert result.allowed
        assert result.receipt is not None

        # Write context
        gate.notify_context_write(
            session.session_id,
            source=ContextSource.TOOL_OUTPUT,
            content_hash="order_data_hash",
            tool_name="lookup_order",
        )

        # Verify chain
        valid, _ = gate.context_tracker.verify_context_chain(session.session_id)
        assert valid

    @requires_nacl
    def test_receipt_chain_across_multiple_calls(self):
        """Multiple tool calls each produce verifiable receipts."""
        signer = ReceiptSigner(signing_method="ed25519")
        gate = AuthorizationGate(receipt_signer=signer)
        gate.register_tool("lookup_order", AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")

        verifier = ReceiptVerifier(
            signing_method="ed25519",
            verify_key=signer.verify_key_bytes,
        )

        receipts = []
        for _ in range(3):
            result = gate.authorize("lookup_order", user_id="alice", role="admin")
            assert result.receipt is not None
            assert verifier.verify(result.receipt)
            receipts.append(result.receipt)

        # All receipts are unique
        ids = [r.receipt_id for r in receipts]
        assert len(set(ids)) == 3

    def test_verify_context_chain_after_trust_degradation(self):
        """Chain remains valid even after trust degrades."""
        from agentlock.schema import (
            ContextPolicyConfig,
            DegradationTrigger,
            SourceAuthorityConfig,
            TrustDegradationConfig,
        )

        gate = AuthorizationGate()
        gate.register_tool("test_tool", AgentLockPermissions(
            risk_level="low",
            requires_auth=True,
            allowed_roles=["admin"],
            context_policy=ContextPolicyConfig(
                source_authorities=[
                    SourceAuthorityConfig(
                        source=ContextSource.WEB_CONTENT,
                        authority=ContextAuthority.UNTRUSTED,
                    ),
                ],
                trust_degradation=TrustDegradationConfig(
                    enabled=True,
                    triggers=[
                        DegradationTrigger(
                            source=ContextSource.WEB_CONTENT,
                            effect="restrict_scope",
                        ),
                    ],
                ),
            ),
        ))
        session = gate.create_session(user_id="alice", role="admin")

        # Normal write
        gate.notify_context_write(
            session.session_id,
            source=ContextSource.USER_MESSAGE,
            content_hash="msg_hash",
        )

        # Untrusted write (triggers degradation)
        gate.notify_context_write(
            session.session_id,
            source=ContextSource.WEB_CONTENT,
            content_hash="web_hash",
        )

        valid, _ = gate.context_tracker.verify_context_chain(session.session_id)
        assert valid

        state = gate.context_tracker.get(session.session_id)
        assert state is not None
        assert state.is_degraded

    def test_hmac_fallback_end_to_end(self):
        """HMAC-SHA256 works end-to-end through gate."""
        signer = ReceiptSigner(signing_method="hmac-sha256")
        gate = AuthorizationGate(receipt_signer=signer)
        gate.register_tool("t", AgentLockPermissions(
            risk_level="low",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")

        result = gate.authorize("t", user_id="alice", role="admin")
        assert result.receipt is not None

        verifier = ReceiptVerifier(
            signing_method="hmac-sha256",
            verify_key=signer.verify_key_bytes,
        )
        assert verifier.verify(result.receipt)

    def test_backward_compat_no_crypto(self):
        """Gate without receipt_signer works exactly as before."""
        gate = AuthorizationGate()
        gate.register_tool("t", AgentLockPermissions(
            risk_level="low",
            requires_auth=True,
            allowed_roles=["admin"],
        ))
        gate.create_session(user_id="alice", role="admin")

        result = gate.authorize("t", user_id="alice", role="admin")
        assert result.allowed
        assert result.receipt is None
        assert result.token is not None
