"""Tests for agentlock.context — ContextProvenance and ContextTracker."""

from __future__ import annotations

import hashlib

from agentlock.context import ContextProvenance, ContextState, ContextTracker
from agentlock.schema import (
    ContextPolicyConfig,
    DegradationTrigger,
    SourceAuthorityConfig,
    TrustDegradationConfig,
)
from agentlock.types import ContextAuthority, ContextSource, DegradationEffect

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_policy(
    *,
    source_authorities: list[SourceAuthorityConfig] | None = None,
    triggers: list[DegradationTrigger] | None = None,
    enabled: bool = True,
    minimum_authority: ContextAuthority = ContextAuthority.DERIVED,
    allow_cascade_to_untrusted: bool = False,
) -> ContextPolicyConfig:
    """Build a ContextPolicyConfig with sensible defaults for tests."""
    return ContextPolicyConfig(
        source_authorities=source_authorities or [],
        trust_degradation=TrustDegradationConfig(
            enabled=enabled,
            triggers=triggers or [],
            minimum_authority=minimum_authority,
            allow_cascade_to_untrusted=allow_cascade_to_untrusted,
        ),
    )


# ---------------------------------------------------------------------------
# ContextProvenance
# ---------------------------------------------------------------------------

class TestContextProvenance:

    def test_hash_content_returns_sha256(self):
        content = "hello world"
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert ContextProvenance.hash_content(content) == expected

    def test_hash_content_empty_string(self):
        expected = hashlib.sha256(b"").hexdigest()
        assert ContextProvenance.hash_content("") == expected

    def test_provenance_id_has_cprov_prefix(self):
        prov = ContextProvenance()
        assert prov.provenance_id.startswith("cprov_")

    def test_provenance_id_is_unique(self):
        ids = {ContextProvenance().provenance_id for _ in range(50)}
        assert len(ids) == 50

    def test_default_source_is_tool_output(self):
        prov = ContextProvenance()
        assert prov.source == ContextSource.TOOL_OUTPUT

    def test_default_authority_is_derived(self):
        prov = ContextProvenance()
        assert prov.authority == ContextAuthority.DERIVED


# ---------------------------------------------------------------------------
# ContextTracker — basic CRUD
# ---------------------------------------------------------------------------

class TestContextTrackerBasic:

    def test_get_or_create_creates_state(self):
        tracker = ContextTracker()
        state = tracker.get_or_create("sess-1")
        assert isinstance(state, ContextState)
        assert state.session_id == "sess-1"
        assert state.trust_ceiling == ContextAuthority.AUTHORITATIVE
        assert state.is_degraded is False

    def test_get_or_create_returns_same_state(self):
        tracker = ContextTracker()
        s1 = tracker.get_or_create("sess-1")
        s2 = tracker.get_or_create("sess-1")
        assert s1 is s2

    def test_get_returns_none_for_unknown_session(self):
        tracker = ContextTracker()
        assert tracker.get("nonexistent") is None

    def test_get_returns_state_after_creation(self):
        tracker = ContextTracker()
        tracker.get_or_create("sess-1")
        state = tracker.get("sess-1")
        assert state is not None
        assert state.session_id == "sess-1"

    def test_destroy_removes_session_state(self):
        tracker = ContextTracker()
        tracker.get_or_create("sess-1")
        tracker.destroy("sess-1")
        assert tracker.get("sess-1") is None

    def test_destroy_nonexistent_is_noop(self):
        tracker = ContextTracker()
        tracker.destroy("no-such-session")  # should not raise

    def test_len_returns_count_of_tracked_sessions(self):
        tracker = ContextTracker()
        assert len(tracker) == 0
        tracker.get_or_create("a")
        tracker.get_or_create("b")
        assert len(tracker) == 2
        tracker.destroy("a")
        assert len(tracker) == 1


# ---------------------------------------------------------------------------
# ContextTracker.record_write
# ---------------------------------------------------------------------------

class TestRecordWrite:

    def test_record_write_returns_provenance(self):
        tracker = ContextTracker()
        prov = tracker.record_write(
            "sess-1",
            ContextSource.USER_MESSAGE,
            ContextProvenance.hash_content("hi"),
        )
        assert isinstance(prov, ContextProvenance)
        assert prov.provenance_id.startswith("cprov_")
        assert prov.session_id == "sess-1"
        assert prov.source == ContextSource.USER_MESSAGE

    def test_record_write_appends_to_provenance_log(self):
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.TOOL_OUTPUT, "abc123")
        tracker.record_write("s", ContextSource.USER_MESSAGE, "def456")
        state = tracker.get("s")
        assert state is not None
        assert len(state.provenance_log) == 2

    def test_record_write_with_policy_resolves_authority_from_source_authorities(self):
        policy = _make_policy(
            source_authorities=[
                SourceAuthorityConfig(
                    source=ContextSource.WEB_CONTENT,
                    authority=ContextAuthority.DERIVED,
                ),
            ],
        )
        tracker = ContextTracker()
        prov = tracker.record_write(
            "s",
            ContextSource.WEB_CONTENT,
            "hash",
            policy=policy,
        )
        # Policy maps WEB_CONTENT -> DERIVED instead of the default UNTRUSTED
        assert prov.authority == ContextAuthority.DERIVED

    def test_record_write_with_policy_unmatched_source_gets_untrusted(self):
        policy = _make_policy(
            source_authorities=[
                SourceAuthorityConfig(
                    source=ContextSource.USER_MESSAGE,
                    authority=ContextAuthority.AUTHORITATIVE,
                ),
            ],
        )
        tracker = ContextTracker()
        prov = tracker.record_write(
            "s",
            ContextSource.WEB_CONTENT,
            "hash",
            policy=policy,
        )
        # WEB_CONTENT not in source_authorities -> falls through to UNTRUSTED
        assert prov.authority == ContextAuthority.UNTRUSTED

    def test_record_write_without_policy_uses_default_authority(self):
        tracker = ContextTracker()

        cases = {
            ContextSource.USER_MESSAGE: ContextAuthority.AUTHORITATIVE,
            ContextSource.SYSTEM_PROMPT: ContextAuthority.AUTHORITATIVE,
            ContextSource.TOOL_OUTPUT: ContextAuthority.DERIVED,
            ContextSource.RETRIEVED_DOCUMENT: ContextAuthority.UNTRUSTED,
            ContextSource.WEB_CONTENT: ContextAuthority.UNTRUSTED,
            ContextSource.AGENT_MEMORY: ContextAuthority.DERIVED,
            ContextSource.PEER_AGENT: ContextAuthority.UNTRUSTED,
        }

        for source, expected_authority in cases.items():
            prov = tracker.record_write("s", source, "h")
            assert prov.authority == expected_authority, (
                f"Default authority for {source} should be {expected_authority}, "
                f"got {prov.authority}"
            )

    def test_record_write_preserves_optional_fields(self):
        tracker = ContextTracker()
        prov = tracker.record_write(
            "s",
            ContextSource.TOOL_OUTPUT,
            "hash",
            writer_id="agent-007",
            tool_name="file_read",
            token_id="tok_abc",
            parent_provenance_id="cprov_parent",
            metadata={"path": "/etc/passwd"},
        )
        assert prov.writer_id == "agent-007"
        assert prov.tool_name == "file_read"
        assert prov.token_id == "tok_abc"
        assert prov.parent_provenance_id == "cprov_parent"
        assert prov.metadata == {"path": "/etc/passwd"}


# ---------------------------------------------------------------------------
# Trust degradation
# ---------------------------------------------------------------------------

class TestTrustDegradation:

    def test_untrusted_source_triggers_degradation(self):
        policy = _make_policy(
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write(
            "s",
            ContextSource.WEB_CONTENT,
            "hash",
            policy=policy,
        )
        state = tracker.get("s")
        assert state is not None
        assert state.is_degraded is True
        assert state.degradation_reason == ContextSource.WEB_CONTENT.value
        assert state.degraded_at is not None
        assert DegradationEffect.REQUIRE_APPROVAL in state.active_effects

    def test_trust_never_escalates_within_session(self):
        """After an untrusted source degrades trust, recording an
        authoritative source must NOT restore the ceiling."""
        policy = _make_policy(
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
            ],
        )
        tracker = ContextTracker()

        # First: untrusted write degrades the session
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h1", policy=policy)
        state = tracker.get("s")
        assert state is not None
        assert state.trust_ceiling == ContextAuthority.DERIVED
        assert state.is_degraded is True

        # Second: authoritative write should NOT restore trust
        tracker.record_write("s", ContextSource.USER_MESSAGE, "h2", policy=policy)
        assert state.trust_ceiling == ContextAuthority.DERIVED
        assert state.is_degraded is True

    def test_multiple_degradation_effects_compose(self):
        policy = _make_policy(
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
                DegradationTrigger(
                    source=ContextSource.PEER_AGENT,
                    effect=DegradationEffect.ELEVATE_LOGGING,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h1", policy=policy)
        tracker.record_write("s", ContextSource.PEER_AGENT, "h2", policy=policy)

        state = tracker.get("s")
        assert state is not None
        assert DegradationEffect.REQUIRE_APPROVAL in state.active_effects
        assert DegradationEffect.ELEVATE_LOGGING in state.active_effects
        assert len(state.active_effects) == 2

    def test_same_trigger_does_not_duplicate_effect(self):
        policy = _make_policy(
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h1", policy=policy)
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h2", policy=policy)

        state = tracker.get("s")
        assert state is not None
        assert state.active_effects.count(DegradationEffect.REQUIRE_APPROVAL) == 1

    def test_degradation_disabled_does_not_degrade(self):
        policy = _make_policy(
            enabled=False,
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.WEB_CONTENT, "hash", policy=policy)

        state = tracker.get("s")
        assert state is not None
        assert state.is_degraded is False
        assert state.trust_ceiling == ContextAuthority.AUTHORITATIVE
        assert state.active_effects == []


# ---------------------------------------------------------------------------
# allow_cascade_to_untrusted
# ---------------------------------------------------------------------------

class TestCascadeToUntrusted:

    def test_cascade_false_keeps_ceiling_at_minimum_authority(self):
        """With allow_cascade_to_untrusted=False the ceiling should not
        fall below minimum_authority (DERIVED by default)."""
        policy = _make_policy(
            allow_cascade_to_untrusted=False,
            minimum_authority=ContextAuthority.DERIVED,
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.DENY_WRITES,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h", policy=policy)

        state = tracker.get("s")
        assert state is not None
        assert state.trust_ceiling == ContextAuthority.DERIVED

    def test_cascade_true_allows_ceiling_to_reach_untrusted(self):
        policy = _make_policy(
            allow_cascade_to_untrusted=True,
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.DENY_WRITES,
                ),
            ],
        )
        tracker = ContextTracker()
        tracker.record_write("s", ContextSource.WEB_CONTENT, "h", policy=policy)

        state = tracker.get("s")
        assert state is not None
        assert state.trust_ceiling == ContextAuthority.UNTRUSTED


# ---------------------------------------------------------------------------
# record_unattributed
# ---------------------------------------------------------------------------

class TestRecordUnattributed:

    def test_record_unattributed_increments_count(self):
        tracker = ContextTracker()
        tracker.record_unattributed("s")
        tracker.record_unattributed("s")
        tracker.record_unattributed("s")

        state = tracker.get("s")
        assert state is not None
        assert state.unattributed_count == 3

    def test_record_unattributed_creates_state_if_needed(self):
        tracker = ContextTracker()
        tracker.record_unattributed("new-session")
        state = tracker.get("new-session")
        assert state is not None
        assert state.unattributed_count == 1
