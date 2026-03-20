"""Tests for agentlock.memory_gate — MemoryGate, MemoryEntry, InMemoryMemoryStore."""

from __future__ import annotations

import time

import pytest

from agentlock.memory_gate import (
    InMemoryMemoryStore,
    MemoryEntry,
    MemoryGate,
    MemoryStore,
)
from agentlock.types import DenialReason, MemoryPersistence, MemoryWriter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gate_kwargs(**overrides) -> dict:
    """Return default keyword arguments for ``MemoryGate.authorize_write``."""
    defaults = dict(
        content="some safe content",
        content_hash="abc123",
        user_id="user-1",
        tool_name="test_tool",
        writer=MemoryWriter.AGENT,
        persistence=MemoryPersistence.SESSION,
        allowed_writers=[MemoryWriter.AGENT, MemoryWriter.SYSTEM],
        allowed_persistence=MemoryPersistence.SESSION,
        prohibited_content=["credentials", "pii", "financial_data"],
        max_entries=100,
        require_write_confirmation=False,
    )
    defaults.update(overrides)
    return defaults


# ===========================================================================
# MemoryEntry
# ===========================================================================

class TestMemoryEntry:
    """MemoryEntry creation and defaults."""

    def test_defaults(self):
        entry = MemoryEntry()
        assert entry.user_id == ""
        assert entry.tool_name == ""
        assert entry.content == ""
        assert entry.persistence == MemoryPersistence.SESSION
        assert entry.writer == MemoryWriter.SYSTEM
        assert entry.provenance is None
        assert entry.metadata == {}

    def test_unique_ids_with_prefix(self):
        entries = [MemoryEntry() for _ in range(20)]
        ids = [e.entry_id for e in entries]
        # All start with ``mem_``
        for eid in ids:
            assert eid.startswith("mem_")
        # All are unique
        assert len(set(ids)) == len(ids)

    def test_is_expired_always_false(self):
        """Expiry is delegated to MemoryGate — the entry itself returns False."""
        entry = MemoryEntry()
        assert entry.is_expired is False


# ===========================================================================
# InMemoryMemoryStore
# ===========================================================================

class TestInMemoryMemoryStore:
    """CRUD operations on InMemoryMemoryStore."""

    @pytest.fixture()
    def store(self) -> InMemoryMemoryStore:
        return InMemoryMemoryStore()

    # ---- write / read / delete / count ------------------------------------

    def test_write_and_read(self, store: InMemoryMemoryStore):
        entry = MemoryEntry(user_id="u1", tool_name="t1", content="hello")
        store.write(entry)
        results = store.read("u1")
        assert len(results) == 1
        assert results[0].content == "hello"

    def test_delete(self, store: InMemoryMemoryStore):
        entry = MemoryEntry(user_id="u1", content="doomed")
        store.write(entry)
        assert store.count("u1") == 1
        store.delete(entry.entry_id)
        assert store.count("u1") == 0

    def test_delete_nonexistent_is_noop(self, store: InMemoryMemoryStore):
        store.delete("mem_does_not_exist")  # should not raise

    def test_count(self, store: InMemoryMemoryStore):
        for _i in range(5):
            store.write(MemoryEntry(user_id="u1", tool_name="t1"))
        assert store.count("u1") == 5
        assert store.count("u1", "t1") == 5
        assert store.count("u1", "other_tool") == 0

    def test_len(self, store: InMemoryMemoryStore):
        store.write(MemoryEntry(user_id="u1"))
        store.write(MemoryEntry(user_id="u2"))
        assert len(store) == 2

    # ---- filters ----------------------------------------------------------

    def test_read_filters_by_user_id(self, store: InMemoryMemoryStore):
        store.write(MemoryEntry(user_id="alice", content="a"))
        store.write(MemoryEntry(user_id="bob", content="b"))
        alice_entries = store.read("alice")
        assert len(alice_entries) == 1
        assert alice_entries[0].content == "a"

    def test_read_filters_by_tool_name(self, store: InMemoryMemoryStore):
        store.write(MemoryEntry(user_id="u1", tool_name="tool_a", content="a"))
        store.write(MemoryEntry(user_id="u1", tool_name="tool_b", content="b"))
        results = store.read("u1", tool_name="tool_a")
        assert len(results) == 1
        assert results[0].content == "a"

    def test_read_no_tool_filter_returns_all(self, store: InMemoryMemoryStore):
        store.write(MemoryEntry(user_id="u1", tool_name="tool_a"))
        store.write(MemoryEntry(user_id="u1", tool_name="tool_b"))
        assert len(store.read("u1")) == 2

    def test_implements_protocol(self, store: InMemoryMemoryStore):
        assert isinstance(store, MemoryStore)


# ===========================================================================
# MemoryGate.authorize_write
# ===========================================================================

class TestAuthorizeWrite:
    """Write authorization checks."""

    @pytest.fixture()
    def gate(self) -> MemoryGate:
        return MemoryGate()

    # ---- allowed writer succeeds ------------------------------------------

    def test_allowed_writer_succeeds(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs())
        assert decision.allowed is True
        assert decision.entry is not None
        assert decision.entry.content == "some safe content"
        assert decision.reason is None

    # ---- denied writer ----------------------------------------------------

    def test_denied_writer(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            writer=MemoryWriter.USER,
            allowed_writers=[MemoryWriter.SYSTEM],
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED
        assert "user" in decision.detail.lower()

    # ---- persistence exceeds allowed --------------------------------------

    def test_persistence_exceeds_allowed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.CROSS_SESSION,
            allowed_persistence=MemoryPersistence.SESSION,
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED
        assert "persistence" in decision.detail.lower()

    # ---- prohibited content: credentials ----------------------------------

    def test_prohibited_credentials(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="Here is the password: s3cret!",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT
        assert "credentials" in decision.detail.lower()

    def test_prohibited_credentials_api_key(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="Use api_key=AKIAIOSFODNN7EXAMPLE to authenticate.",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT

    # ---- prohibited content: PII (SSN) ------------------------------------

    def test_prohibited_pii_ssn_dashed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="SSN is 123-45-6789.",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT
        assert "pii" in decision.detail.lower()

    def test_prohibited_pii_ssn_plain(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="SSN: 123456789",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT

    # ---- prohibited content: financial data (credit card) -----------------

    def test_prohibited_financial_credit_card(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="Card number: 4111 1111 1111 1111",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT
        assert "financial_data" in decision.detail.lower()

    def test_prohibited_financial_credit_card_dashed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="CC: 4111-1111-1111-1111",
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_PROHIBITED_CONTENT

    # ---- max_entries exceeded ---------------------------------------------

    def test_max_entries_exceeded(self, gate: MemoryGate):
        # Fill the store up to the limit first
        for _ in range(3):
            gate.authorize_write(**_make_gate_kwargs(max_entries=100))

        decision = gate.authorize_write(**_make_gate_kwargs(max_entries=3))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_RETENTION_EXCEEDED
        assert "3" in decision.detail

    # ---- require_write_confirmation ---------------------------------------

    def test_require_write_confirmation(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            require_write_confirmation=True,
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_CONFIRMATION_REQUIRED
        assert "confirmation" in decision.detail.lower()

    # ---- entry is persisted in store on success ---------------------------

    def test_entry_persisted_on_success(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(user_id="persist-me"))
        assert decision.allowed is True

        entries = gate.store.read("persist-me")
        assert len(entries) == 1
        assert entries[0].entry_id == decision.entry.entry_id
        assert entries[0].content == "some safe content"

    # ---- no prohibited_content patterns = no content check ----------------

    def test_empty_prohibited_content_skips_check(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            content="password=hunter2",
            prohibited_content=[],
        ))
        assert decision.allowed is True

    # ---- persistence levels at boundary -----------------------------------

    def test_session_persistence_within_session_allowed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.SESSION,
            allowed_persistence=MemoryPersistence.SESSION,
        ))
        assert decision.allowed is True

    def test_none_persistence_always_allowed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.NONE,
            allowed_persistence=MemoryPersistence.NONE,
        ))
        assert decision.allowed is True


# ===========================================================================
# MemoryGate.authorize_read
# ===========================================================================

class TestAuthorizeRead:
    """Read authorization and lazy retention enforcement."""

    @pytest.fixture()
    def gate(self) -> MemoryGate:
        return MemoryGate()

    # ---- allowed reader succeeds ------------------------------------------

    def test_allowed_reader_succeeds(self, gate: MemoryGate):
        decision = gate.authorize_read(
            user_id="u1",
            reader=MemoryWriter.AGENT,
            allowed_readers=[MemoryWriter.AGENT],
        )
        assert decision.allowed is True
        assert decision.reason is None

    # ---- denied reader ----------------------------------------------------

    def test_denied_reader(self, gate: MemoryGate):
        decision = gate.authorize_read(
            user_id="u1",
            reader=MemoryWriter.TOOL,
            allowed_readers=[MemoryWriter.AGENT],
        )
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_READ_DENIED
        assert "tool" in decision.detail.lower()

    # ---- lazy retention: expired entries purged ---------------------------

    def test_lazy_retention_purges_expired_entries(self, gate: MemoryGate):
        # Write an entry with a created_at far in the past
        old_entry = MemoryEntry(
            user_id="u1",
            tool_name="t1",
            content="old",
            created_at=time.time() - 3600,  # 1 hour ago
        )
        gate.store.write(old_entry)

        # Write a fresh entry
        fresh_entry = MemoryEntry(
            user_id="u1",
            tool_name="t1",
            content="fresh",
            created_at=time.time(),
        )
        gate.store.write(fresh_entry)

        assert gate.store.count("u1") == 2

        # Authorize read with max_age of 60 seconds — should purge old entry
        decision = gate.authorize_read(
            user_id="u1",
            reader=MemoryWriter.AGENT,
            tool_name="t1",
            allowed_readers=[MemoryWriter.AGENT],
            max_age_seconds=60,
        )
        assert decision.allowed is True
        remaining = gate.store.read("u1")
        assert len(remaining) == 1
        assert remaining[0].content == "fresh"

    def test_lazy_retention_no_purge_when_max_age_zero(self, gate: MemoryGate):
        """max_age_seconds=0 means no expiry — nothing purged."""
        old_entry = MemoryEntry(
            user_id="u1",
            content="ancient",
            created_at=time.time() - 999999,
        )
        gate.store.write(old_entry)

        gate.authorize_read(
            user_id="u1",
            reader=MemoryWriter.AGENT,
            allowed_readers=[MemoryWriter.AGENT],
            max_age_seconds=0,
        )
        assert gate.store.count("u1") == 1


# ===========================================================================
# Cross-session vs session persistence
# ===========================================================================

class TestPersistenceLevels:
    """Verify persistence level ordering enforcement."""

    @pytest.fixture()
    def gate(self) -> MemoryGate:
        return MemoryGate()

    def test_cross_session_allowed_when_policy_permits(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.CROSS_SESSION,
            allowed_persistence=MemoryPersistence.CROSS_SESSION,
        ))
        assert decision.allowed is True
        assert decision.entry.persistence == MemoryPersistence.CROSS_SESSION

    def test_session_allowed_when_cross_session_permitted(self, gate: MemoryGate):
        """Lower persistence is always fine if a higher level is allowed."""
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.SESSION,
            allowed_persistence=MemoryPersistence.CROSS_SESSION,
        ))
        assert decision.allowed is True

    def test_cross_session_denied_when_only_session_allowed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.CROSS_SESSION,
            allowed_persistence=MemoryPersistence.SESSION,
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED

    def test_session_denied_when_only_none_allowed(self, gate: MemoryGate):
        decision = gate.authorize_write(**_make_gate_kwargs(
            persistence=MemoryPersistence.SESSION,
            allowed_persistence=MemoryPersistence.NONE,
        ))
        assert decision.allowed is False
        assert decision.reason == DenialReason.MEMORY_WRITE_DENIED
