"""v1.4 defer-policy: the commit-time re-decision honors action-class declarations.

Before this change, ``resolve_deferred_commits`` denied every queued action on
session taint alone.  It never consulted ``permissions.action_class``, so
``gate_consequential=False`` was INERT whenever deferred commit was enabled: a
value-carrying write that ``authorize()`` un-gated at call time was silently
re-gated at end of turn.

These tests pin the two enforcement points to the same predicate.
"""

from __future__ import annotations

import hashlib

import pytest

from agentlock.gate import AuthorizationGate
from agentlock.policy import ActionFlags, lineage_gated_action
from agentlock.schema import (
    ActionClassConfig,
    AgentLockPermissions,
    LineagePolicyConfig,
)
from agentlock.types import ContextSource


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _perms(action_class=None, *, gate_consequential: bool) -> AgentLockPermissions:
    return AgentLockPermissions(
        risk_level="medium",
        requires_auth=False,
        allowed_roles=["user"],
        lineage_policy=LineagePolicyConfig(
            enabled=True,
            gate_consequential=gate_consequential,
            decision="step_up",
            require_post_authoritative=True,
        ),
        action_class=action_class,
    )


# The four rows from the pre-flight verification: (tool, declaration, flags).
VALUE_CARRYING = ActionClassConfig(is_value_carrying=True)
DELETION = ActionClassConfig(is_deletion=True)

# Every one of these is a consequential write, as the adapter asserts it.
CONSEQUENTIAL = dict(is_consequential=True)


def _tainted_gate(tools: dict[str, AgentLockPermissions]):
    """Gate with a post-authoritatively tainted session."""
    gate = AuthorizationGate(session_duration=3600)
    for name, perms in tools.items():
        gate.register_tool(name, perms)
    sid = gate.create_session("u", "user").session_id
    gate.notify_context_write(sid, ContextSource.USER_MESSAGE, _h("do my task"))
    gate.notify_context_write(
        sid, ContextSource.WEB_CONTENT, _h("inj"), tool_name="web_read"
    )
    assert gate.context_tracker.lineage_summary(sid)["post_authoritative_taint"]
    return gate, sid


class TestSelectiveGatingAtCommitTime:
    """The regression table: declared value-carrying commits under taint;
    declared value-free stays denied."""

    @pytest.mark.parametrize(
        "tool,declaration,expected",
        [
            ("reserve_hotel", VALUE_CARRYING, "committed"),
            ("create_calendar_event", VALUE_CARRYING, "committed"),
            ("cancel_calendar_event", DELETION, "denied"),
            ("delete_email", DELETION, "denied"),
        ],
    )
    def test_commit_time_honors_declaration(self, tool, declaration, expected):
        perms = _perms(declaration, gate_consequential=False)
        gate, sid = _tainted_gate({tool: perms})
        gate.defer_consequential(
            sid, tool, {"x": 1}, record_action_flags=True, **CONSEQUENTIAL
        )
        resolved = gate.resolve_deferred_commits(sid)
        assert len(resolved) == 1
        assert resolved[0].resolution == expected

    def test_call_time_and_commit_time_agree(self):
        """The whole point: the two enforcement points must not disagree."""
        for tool, declaration in [
            ("reserve_hotel", VALUE_CARRYING),
            ("delete_email", DELETION),
        ]:
            perms = _perms(declaration, gate_consequential=False)
            gate, sid = _tainted_gate({tool: perms})

            call_allowed = gate.authorize(
                tool, user_id="u", role="user", parameters={"x": 1}, **CONSEQUENTIAL
            ).allowed

            gate.defer_consequential(
                sid, tool, {"x": 1}, record_action_flags=True, **CONSEQUENTIAL
            )
            commit_allowed = (
                gate.resolve_deferred_commits(sid)[0].resolution == "committed"
            )
            assert call_allowed == commit_allowed, (
                f"{tool}: call-time allowed={call_allowed} but "
                f"commit-time committed={commit_allowed}"
            )

    def test_value_carrying_still_gated_when_gate_consequential_on(self):
        """Un-gating takes TWO affirmative acts. Declaration alone is not enough."""
        perms = _perms(VALUE_CARRYING, gate_consequential=True)
        gate, sid = _tainted_gate({"reserve_hotel": perms})
        gate.defer_consequential(
            sid, "reserve_hotel", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_membership_change_denied_regardless_of_gate_consequential(self):
        perms = _perms(
            ActionClassConfig(is_membership_change=True), gate_consequential=False
        )
        gate, sid = _tainted_gate({"add_user_to_channel": perms})
        gate.defer_consequential(
            sid, "add_user_to_channel", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_value_carrying_still_gated_by_a_coarse_class(self):
        """is_value_carrying only weakens the residual is_consequential
        disjunct. It must never un-gate an external/financial action."""
        perms = _perms(VALUE_CARRYING, gate_consequential=False)
        gate, sid = _tainted_gate({"share_file": perms})
        gate.defer_consequential(
            sid, "share_file", {}, record_action_flags=True,
            is_consequential=True, is_external=True,
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_untainted_value_free_still_commits(self):
        """The gate is on taint, not on the class. No taint -> commit."""
        gate = AuthorizationGate(session_duration=3600)
        gate.register_tool("delete_email", _perms(DELETION, gate_consequential=False))
        sid = gate.create_session("u", "user").session_id
        gate.notify_context_write(sid, ContextSource.USER_MESSAGE, _h("task"))
        gate.defer_consequential(
            sid, "delete_email", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "committed"


class TestFailClosed:
    def test_unregistered_tool_denied_under_taint(self):
        gate, sid = _tainted_gate({})
        gate.defer_consequential(
            sid, "ghost_tool", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_no_action_flags_recorded_denied_under_taint(self):
        """A caller that queues without recording classes cannot un-gate."""
        perms = _perms(VALUE_CARRYING, gate_consequential=False)
        gate, sid = _tainted_gate({"reserve_hotel": perms})
        gate.defer_consequential(sid, "reserve_hotel", {})  # no flags
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_no_lineage_policy_denied_under_taint(self):
        perms = AgentLockPermissions(
            risk_level="medium", requires_auth=False, allowed_roles=["user"],
            action_class=VALUE_CARRYING,
        )
        gate, sid = _tainted_gate({"reserve_hotel": perms})
        gate.defer_consequential(
            sid, "reserve_hotel", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_disabled_lineage_policy_denied_under_taint(self):
        perms = AgentLockPermissions(
            risk_level="medium", requires_auth=False, allowed_roles=["user"],
            lineage_policy=LineagePolicyConfig(enabled=False, gate_consequential=False),
            action_class=VALUE_CARRYING,
        )
        gate, sid = _tainted_gate({"reserve_hotel": perms})
        gate.defer_consequential(
            sid, "reserve_hotel", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"

    def test_unclassified_consequential_fails_closed(self):
        """No declaration + gate_consequential=False -> STILL gated."""
        perms = _perms(None, gate_consequential=False)
        gate, sid = _tainted_gate({"append_to_file": perms})
        gate.defer_consequential(
            sid, "append_to_file", {}, record_action_flags=True, **CONSEQUENTIAL
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"


class TestNoDeclarationsIsByteIdentical:
    """With no action_class anywhere, the defer path must reduce exactly to the
    pre-v1.4 rule: deny == tainted, for every queued record."""

    @pytest.mark.parametrize("tainted", [True, False])
    @pytest.mark.parametrize("record_flags", [True, False])
    def test_reduces_to_deny_equals_tainted(self, tainted, record_flags):
        perms = _perms(None, gate_consequential=True)
        gate = AuthorizationGate(session_duration=3600)
        for t in ("tool_a", "tool_b"):
            gate.register_tool(t, perms)
        sid = gate.create_session("u", "user").session_id
        gate.notify_context_write(sid, ContextSource.USER_MESSAGE, _h("task"))
        if tainted:
            gate.notify_context_write(
                sid, ContextSource.WEB_CONTENT, _h("inj"), tool_name="web_read"
            )

        kw = dict(record_action_flags=True, **CONSEQUENTIAL) if record_flags else {}
        gate.defer_consequential(sid, "tool_a", {"i": 1}, **kw)
        gate.defer_consequential(sid, "tool_b", {"i": 2}, **kw)

        resolved = gate.resolve_deferred_commits(sid)
        expected = "denied" if tainted else "committed"
        assert [r.tool_name for r in resolved] == ["tool_a", "tool_b"]  # order held
        assert [r.resolution for r in resolved] == [expected, expected]


class TestSharedPredicate:
    """lineage_gated_action is the ONE definition. Guard against re-inlining."""

    def test_predicate_matches_call_time_decision(self):
        perms = _perms(VALUE_CARRYING, gate_consequential=False)
        flags = ActionFlags(is_consequential=True)
        assert lineage_gated_action(perms.lineage_policy, perms, flags) is False

        gated = _perms(VALUE_CARRYING, gate_consequential=True)
        assert lineage_gated_action(gated.lineage_policy, gated, flags) is True

    def test_caller_cannot_assert_value_carrying(self):
        """ActionFlags has no is_value_carrying field: gating-REMOVING signals
        may originate only in the trusted block."""
        assert not hasattr(ActionFlags(), "is_value_carrying")
        with pytest.raises(TypeError):
            ActionFlags(is_value_carrying=True)  # type: ignore[call-arg]

    def test_declaration_or_caller_kwarg_both_add_gating(self):
        """Monotone OR: caller kwarg alone gates even with no declaration."""
        perms = _perms(None, gate_consequential=False)
        flags = ActionFlags(is_deletion=True)
        assert lineage_gated_action(perms.lineage_policy, perms, flags) is True
