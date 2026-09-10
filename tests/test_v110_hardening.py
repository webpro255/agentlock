"""v1.10 integration hardening: the cases the external oracle does not reach.

The review's file, ``tests/test_v110_system_review.py``, is the contract for
this arc and is not edited to add coverage.  What it cannot reach from outside
the engine is pinned here: the mcp 1.x hook (the oracle's mcp case exercises
2.x only), flask tool selection, the autogen adapter, deferral expiry with no
sweep, and the parts of the execution contract that only show up in an
awkwardly shaped signature.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib

import pytest

from agentlock import AgentLockPermissions, AuthorizationGate, ContextSource
from agentlock.exceptions import DeniedError
from agentlock.schema import (
    ActionClassConfig,
    LineagePolicyConfig,
    ModifyPolicyConfig,
    TransformationConfig,
)

SECRET = "Customer SSN 123-45-6789"
SSN = "123-45-6789"


def _redact(field: str) -> ModifyPolicyConfig:
    return ModifyPolicyConfig(
        enabled=True,
        apply_when_hardening_active=False,
        transformations=[
            TransformationConfig(field=field, action="redact_pii", config={}),
        ],
    )


def _perms(**kw) -> AgentLockPermissions:
    kw.setdefault("allowed_roles", ["user"])
    return AgentLockPermissions(risk_level="medium", **kw)


def _gate(**kw) -> tuple[AuthorizationGate, AgentLockPermissions]:
    gate = AuthorizationGate()
    perms = _perms(**kw)
    gate.register_tool("task", perms)
    return gate, perms


class FakeServer:
    """An mcp 1.x ``Server``, reduced to the surface the hook patches.

    The real 1.x SDK is not installed in every environment this suite runs in,
    and the hook's 1.x branch is selected by the presence of ``call_tool``,
    not by the SDK version.  This is the same fixture
    ``test_v15_integration_confirmation.py`` uses.
    """

    def __init__(self) -> None:
        self.handler = None

    def call_tool(self):
        def decorator(fn):
            self.handler = fn
            return fn

        return decorator


class TestMcp1xExecutionContract:
    """E1 over the 1.x hook."""

    def test_output_transformation_reaches_the_client(self):
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"task": perms},
            default_user_id="alice", default_role="user",
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            return SECRET

        assert SSN not in asyncio.run(server.handler("task", {}))

    def test_output_transformation_reaches_text_content(self):
        """The shape an MCP handler actually returns: content blocks."""
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Text:
            def __init__(self, text):
                self.text = text

        class Result:
            def __init__(self, content):
                self.content = content

        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"task": perms},
            default_user_id="alice", default_role="user",
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([Text(SECRET), Text("nothing sensitive")])

        result = asyncio.run(server.handler("task", {}))
        assert SSN not in result.content[0].text
        assert result.content[1].text == "nothing sensitive"

    def test_parameter_transformation_reaches_the_handler(self):
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate, perms = _gate(modify_policy=_redact("body"))
        server = FakeServer()
        seen = []
        AgentLockMCPServer(
            server, gate, {"task": perms},
            default_user_id="alice", default_role="user",
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            seen.append(arguments)
            return "done"

        assert asyncio.run(server.handler("task", {"body": SECRET})) == "done"
        assert SSN not in seen[0]["body"]

    def test_configured_identity_beats_the_client_on_the_1x_hook(self):
        """E4 on the hook the oracle's mcp case does not select."""
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        server = FakeServer()
        ran = []
        AgentLockMCPServer(
            server, gate, {"admin_task": _perms(allowed_roles=["admin"])},
            default_user_id="alice", default_role="user",
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            ran.append(name)
            return "done"

        for spoof in ({"_agentlock_role": "admin"},
                      {"_meta": {"agentlock_role": "admin"}}):
            with pytest.raises(DeniedError):
                asyncio.run(server.handler("admin_task", dict(spoof)))
        assert ran == []

    def test_the_client_is_trusted_when_no_default_is_configured(self):
        """The documented other half of E4, so the fallback stays deliberate."""
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        server = FakeServer()
        ran = []
        AgentLockMCPServer(
            server, gate, {"admin_task": _perms(allowed_roles=["admin"])}
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            ran.append(dict(arguments))
            return "done"

        asyncio.run(server.handler("admin_task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "admin",
        }))
        assert ran == [{}], "the reserved keys must not reach the tool"

    def test_meta_identity_does_not_leak_into_the_tool_arguments(self):
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        server = FakeServer()
        ran = []
        AgentLockMCPServer(server, gate, {"task": _perms()})

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            ran.append(dict(arguments))
            return "done"

        asyncio.run(server.handler("task", {
            "_meta": {"agentlock_user_id": "alice", "agentlock_role": "user"},
            "_agentlock_user_id": "alice",
            "x": 1,
        }))
        assert ran == [{"x": 1}]


class TestFlaskToolSelection:
    """E5 on the flask extension."""

    def _app(self, mapping):
        flask = pytest.importorskip("flask")
        from agentlock.integrations.flask import AgentLockFlask

        gate = AuthorizationGate()
        gate.register_tool("task", _perms())
        gate.register_tool("admin_task", _perms(allowed_roles=["admin"]))

        app = flask.Flask(__name__)
        ran = []

        @app.post("/admin")
        def admin():
            ran.append("ADMIN_ACTION")
            return {"ok": True}

        AgentLockFlask(app, gate, tool_name_from_endpoint=mapping)
        return app, ran

    def test_a_conflicting_tool_header_is_refused(self):
        app, ran = self._app(lambda endpoint, method, path: "admin_task")
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "task",
        })
        assert response.status_code == 403
        assert response.get_json()["detail"]["reason"] == (
            "tool_selection_conflict"
        )
        assert ran == []

    def test_the_mapping_decides_when_no_header_is_sent(self):
        app, ran = self._app(lambda endpoint, method, path: "admin_task")
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice", "X-AgentLock-Role": "user",
        })
        assert response.status_code == 403
        assert ran == []

    def test_an_agreeing_header_is_not_a_conflict(self):
        app, ran = self._app(lambda endpoint, method, path: "admin_task")
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "admin",
            "X-AgentLock-Tool": "admin_task",
        })
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_a_declined_endpoint_passes_through_with_the_header_ignored(self):
        app, ran = self._app(lambda endpoint, method, path: None)
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "admin_task",
        })
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_the_header_is_honored_only_with_no_mapping(self):
        app, ran = self._app(None)
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "admin_task",
        })
        assert response.status_code == 403
        assert ran == []

    def test_an_unverified_bearer_token_is_not_identity(self):
        """Was ``test_a_bearer_token_beats_the_identity_headers``, and E5's
        rule when it was written: an unverified payload naming a subject
        outranked the identity headers, so this token's ``role: user`` beat
        the ``admin`` header and the admin tool was refused.

        1.10.2 removed the unverified read entirely.  This app configures no
        ``jwt_key``, so the token is ignored for identity and the headers
        apply: a role and no user id, which the gate refuses as
        ``not_authenticated``.  The 403 is therefore unchanged and its REASON
        is not, which is why the reason is now pinned.  Left asserting only
        the status, this case would stand green while saying nothing, and
        would go on passing if the unverified read ever came back, since a
        role header alone cannot authorize either way.
        """
        import base64
        import json

        pytest.importorskip("flask")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "alice", "role": "user"}).encode()
        ).decode().rstrip("=")
        app, ran = self._app(lambda endpoint, method, path: "admin_task")
        response = app.test_client().post("/admin", headers={
            "Authorization": f"Bearer header.{payload}.signature",
            "X-AgentLock-Role": "admin",
        })
        assert response.status_code == 403
        assert response.get_json()["detail"]["reason"] == "not_authenticated"
        assert ran == []


class TestAutogenExecutionContract:
    """E1 over the autogen adapter."""

    def _protected(self, monkeypatch, func, **policy):
        from agentlock.integrations import autogen as al_autogen

        monkeypatch.setattr(
            al_autogen, "_check_autogen_available", lambda: None
        )
        gate = AuthorizationGate()
        return al_autogen.protect_functions(
            {"task": func}, gate, {"task": _perms(**policy)}
        )["task"]

    def test_parameter_transformation_reaches_the_callable(self, monkeypatch):
        seen = []

        def task(body):
            seen.append(body)
            return "done"

        guarded = self._protected(
            monkeypatch, task, modify_policy=_redact("body")
        )
        assert guarded(
            body=SECRET, _agentlock_user_id="alice", _agentlock_role="user"
        ) == "done"
        assert SSN not in seen[0]

    def test_a_positional_argument_is_transformed_too(self, monkeypatch):
        """The binding write-back, not just the keyword path."""
        seen = []

        def task(body, /):
            seen.append(body)
            return "done"

        guarded = self._protected(
            monkeypatch, task, modify_policy=_redact("body")
        )
        guarded(SECRET, _agentlock_user_id="alice", _agentlock_role="user")
        assert SSN not in seen[0]

    def test_output_transformation_reaches_the_caller(self, monkeypatch):
        guarded = self._protected(
            monkeypatch, lambda: SECRET, modify_policy=_redact("output")
        )
        result = guarded(_agentlock_user_id="alice", _agentlock_role="user")
        assert SSN not in result


class TestBindingWriteBack:
    """E1: ``apply_effective_parameters`` is the inverse of the flattening."""

    def _bound(self, func, *args, **kwargs):
        from agentlock.binding import bind_call_parameters

        return bind_call_parameters(func, args, kwargs)

    def test_a_var_keyword_key_goes_back_into_the_mapping(self):
        from agentlock.binding import apply_effective_parameters

        def task(a, **extras):
            return a, extras

        params, bound = self._bound(task, 1, note="secret")
        assert params == {"a": 1, "note": "secret"}
        apply_effective_parameters(bound, {"a": 2, "note": "clean"})
        assert task(*bound.args, **bound.kwargs) == (2, {"note": "clean"})

    def test_var_positional_keeps_its_shape(self):
        from agentlock.binding import apply_effective_parameters

        def task(*items):
            return items

        params, bound = self._bound(task, "a", "b")
        assert params == {"items": ("a", "b")}
        apply_effective_parameters(bound, {"items": ("x", "y")})
        assert task(*bound.args, **bound.kwargs) == ("x", "y")

    def test_an_absent_parameter_stays_absent(self):
        from agentlock.binding import apply_effective_parameters

        def task(a, b=None):
            return a, b

        _, bound = self._bound(task, 1)
        apply_effective_parameters(bound, {"a": 9, "c": "invented"})
        assert task(*bound.args, **bound.kwargs) == (9, None)
        assert "c" not in bound.arguments


class TestTokenBoundToEffectiveParameters:
    """E1 at the token, which is where the contract is actually enforced."""

    def test_the_grant_is_bound_to_what_will_run(self):
        gate, _ = _gate(modify_policy=_redact("body"))
        auth = gate.authorize(
            "task", user_id="alice", role="user",
            parameters={"body": SECRET},
        )
        assert auth.allowed
        assert SSN not in auth.effective_parameters["body"]
        assert auth.token.parameters_hash == type(
            auth.token
        ).hash_parameters(auth.effective_parameters)

    def test_presenting_the_requested_parameters_runs_the_granted_call(self):
        gate, _ = _gate(modify_policy=_redact("body"))
        seen = []
        auth = gate.authorize(
            "task", user_id="alice", role="user",
            parameters={"body": SECRET},
        )
        gate.execute(
            "task", lambda body: seen.append(body),
            token=auth.token, parameters={"body": SECRET},
        )
        assert SSN not in seen[0]

    def test_a_substituted_call_is_still_rejected(self):
        from agentlock.exceptions import TokenError

        gate, _ = _gate(modify_policy=_redact("body"))
        seen = []
        auth = gate.authorize(
            "task", user_id="alice", role="user",
            parameters={"body": SECRET},
        )
        with pytest.raises(TokenError):
            gate.execute(
                "task", lambda body: seen.append(body),
                token=auth.token, parameters={"body": "something else"},
            )
        assert seen == []


class TestDeferralTerminalStates:
    """E7, past what the oracle's single case reaches."""

    def test_expiry_is_enforced_with_no_sweep(self):
        from agentlock import DeferralManager

        manager = DeferralManager()
        record = manager.queue_commit("s", "task", {}, taint_at_call={})
        record.created_at -= record.timeout_seconds + 1

        # No check_timeouts() anywhere.
        resolved = manager.resolve_commit_queue("s", deny=False)
        assert resolved == [record]
        assert record.resolution == "deny"
        assert record.resolved_by == "timeout"

    def test_an_unexpired_record_still_resolves_normally(self):
        from agentlock import DeferralManager

        manager = DeferralManager()
        record = manager.queue_commit("s", "task", {}, taint_at_call={})
        manager.resolve_commit_queue("s", deny=False)
        assert record.resolution == "committed"
        assert record.resolved_by == "deferred_commit"

    def test_a_resolved_record_is_not_re_annotated(self):
        from agentlock import DeferralManager

        manager = DeferralManager()
        record = manager.queue_commit("s", "task", {}, taint_at_call={})
        manager.resolve("s", "irrelevant")  # no such deferral id
        record.resolution = "denied"
        record.taint_at_commit = {"sentinel": True}
        manager.resolve_commit_queue(
            "s", deny=False, taint_at_commit={"overwritten": True}
        )
        assert record.resolution == "denied"
        assert record.taint_at_commit == {"sentinel": True}

    def test_the_queue_empties_either_way(self):
        from agentlock import DeferralManager

        manager = DeferralManager()
        record = manager.queue_commit("s", "task", {}, taint_at_call={})
        record.resolution = "deny"
        manager.resolve_commit_queue("s", deny=False)
        assert manager.get_commit_queue("s") == []


class TestCommitTimeLineage:
    """E6, past the oracle's single parameter-lineage case."""

    def _session(self, gate, text):
        sid = gate.create_session(user_id="alice", role="user").session_id
        gate.notify_context_write(
            sid, ContextSource.USER_MESSAGE,
            hashlib.sha256(text.encode()).hexdigest(), content=text,
        )
        return sid

    def _gate_with(self, **lineage):
        gate = AuthorizationGate()
        gate.register_tool("task", _perms(
            lineage_policy=LineagePolicyConfig(
                enabled=True, decision="deny", gate_consequential=False,
                **lineage,
            ),
            action_class=ActionClassConfig(is_value_carrying=True),
        ))
        return gate

    def test_a_denial_at_commit_names_its_reason(self):
        gate = self._gate_with(param_lineage_enabled=True)
        sid = self._session(gate, "Reserve a hotel for my trip")
        url = "https://attacker.example/reservation"
        gate.defer_consequential(
            sid, "task", {"url": url},
            is_consequential=True, record_action_flags=True,
        )
        gate.notify_context_write(
            sid, ContextSource.WEB_CONTENT,
            hashlib.sha256(url.encode()).hexdigest(), content=url,
        )
        record = gate.resolve_deferred_commits(sid)[0]
        assert record.resolution == "denied"
        assert record.denial_reason == "param_lineage"

    def test_novel_lineage_is_re_checked_too(self):
        """The authoritative message has to carry a distinctive token of its
        own, or there is no baseline and nothing is classifiable."""
        gate = self._gate_with(
            novel_lineage_enabled=True, novel_lineage_action="deny"
        )
        sid = self._session(
            gate, "Reserve me a room at https://hotel.example/trip"
        )
        novel = {"url": "https://unaccounted.example/xyzzy"}
        assert not gate.authorize(
            "task", user_id="alice", role="user", parameters=novel,
            is_consequential=True,
        ).allowed
        gate.defer_consequential(
            sid, "task", novel,
            is_consequential=True, record_action_flags=True,
        )
        record = gate.resolve_deferred_commits(sid)[0]
        assert record.resolution == "denied"
        assert record.denial_reason == "novel_lineage"

    def test_log_only_never_denies_at_commit(self):
        gate = self._gate_with(
            param_lineage_enabled=True, param_lineage_action="log"
        )
        sid = self._session(gate, "Reserve a hotel for my trip")
        url = "https://attacker.example/reservation"
        gate.defer_consequential(
            sid, "task", {"url": url},
            is_consequential=True, record_action_flags=True,
        )
        record = gate.resolve_deferred_commits(sid)[0]
        assert record.resolution == "committed"
        assert record.denial_reason is None

    def test_a_clean_commit_carries_no_reason(self):
        gate = self._gate_with(param_lineage_enabled=True)
        sid = self._session(gate, "Reserve a hotel for my trip")
        gate.defer_consequential(
            sid, "task", {"url": "https://hotel.example/trip"},
            is_consequential=True, record_action_flags=True,
        )
        record = gate.resolve_deferred_commits(sid)[0]
        assert record.resolution == "committed"
        assert record.denial_reason is None

    def test_the_queued_parameters_are_snapshotted(self):
        """E6: a caller mutating its own dict cannot move the decision."""
        gate = self._gate_with(param_lineage_enabled=True)
        sid = self._session(gate, "Reserve a hotel for my trip")
        url = "https://attacker.example/reservation"
        parameters = {"url": url}
        gate.defer_consequential(
            sid, "task", parameters,
            is_consequential=True, record_action_flags=True,
        )
        parameters["url"] = "https://hotel.example/trip"
        gate.notify_context_write(
            sid, ContextSource.WEB_CONTENT,
            hashlib.sha256(url.encode()).hexdigest(), content=url,
        )
        assert gate.resolve_deferred_commits(sid)[0].resolution == "denied"


class TestRedPass:
    """The pre-release red pass against the 1.10.0 branch wheel.

    Three findings were reported against the wheel built from
    ``29db1b8``/``4bd3998`` (sha256 ``0d793500``).  Two reproduce and are
    closed by E10 and E11; the third does not reproduce and is pinned here as
    a guard rather than as an expected failure.  Which is which is stated on
    each case.

    Fifteen of these cases were committed as ``xfail(strict=True)`` before the
    code that satisfies them, so the before state is in the history, and the
    markers came off in the commit that closed the findings.  A strict xfail
    that starts passing is a failure, so neither the marker nor the fix could
    be left half applied.

    A SECOND red pass, against the wheel built from ``33d0386``
    (sha256 ``b72739f9``), found three more, and they are carried in the same
    class from the block marked ``Red pass 2`` onward.  F4, MCP structured
    content left unmodified, and F5, sets not walked, reproduce and close
    under E15 and E16 on the same four-xfail-before-the-fix terms.  F6,
    dictionary keys and arbitrary objects not walked, reproduces and is
    STATED rather than closed, so its two cases assert the leak: a limit that
    is pinned is a limit that cannot drift.
    """

    # F1: caller role overrides the session role (REPRODUCED)

    @staticmethod
    def _session_gate() -> AuthorizationGate:
        gate = AuthorizationGate()
        gate.create_session(user_id="alice", role="user")
        gate.register_tool("admin_task", _perms(
            requires_auth=True, allowed_roles=["admin"],
        ))
        gate.register_tool("user_task", _perms(
            requires_auth=True, allowed_roles=["user"],
        ))
        return gate

    def test_a_claimed_role_that_differs_from_the_session_is_denied(self):
        """E10.  alice is authenticated at ``user``.  The caller says
        ``admin``.  Through the branch wheel the claim wins, because
        ``role = session.role`` runs only when no role was supplied, so an
        admin-only tool is authorized over a user's session by anyone who can
        name her.
        """
        from agentlock.types import DenialReason

        gate = self._session_gate()
        result = gate.authorize("admin_task", user_id="alice", role="admin")
        assert not result.allowed
        assert result.denial is not None
        assert result.denial["reason"] == DenialReason.ROLE_MISMATCH.value
        assert "session" in result.denial["detail"].lower()

    def test_role_mismatch_is_a_named_denial_reason(self):
        """E10: a new enum member, not a reused one.  A claimed role that
        contradicts an authenticated session is not the same finding as a role
        the tool does not allow, and an auditor reading the log should not
        have to guess which one happened.
        """
        from agentlock.types import DenialReason

        assert DenialReason.ROLE_MISMATCH.value == "role_mismatch"

    def test_no_role_supplied_still_resolves_from_the_session(self):
        """Control, passing today: E10 changes nothing when the caller
        supplies no role.  ``session.role`` is used, as it always was.
        """
        gate = self._session_gate()
        result = gate.authorize("user_task", user_id="alice")
        assert result.allowed

    def test_a_matching_claimed_role_is_still_allowed(self):
        """Control, passing today: agreement is not a mismatch."""
        gate = self._session_gate()
        result = gate.authorize("user_task", user_id="alice", role="user")
        assert result.allowed

    def test_a_claimed_role_with_no_session_is_trusted_as_before(self):
        """Control, passing today: with no session there is nothing to
        contradict, so the host is trusted to have authenticated the caller.
        E10 says so in the docstring rather than changing it.
        """
        gate = AuthorizationGate()
        gate.register_tool("admin_task", _perms(allowed_roles=["admin"]))
        assert gate.authorize("admin_task", user_id="bob", role="admin").allowed

    def test_an_mcp_client_cannot_claim_a_role_over_a_session(self):
        """F1 through the real mcp 2.x hook with NO default configured.

        E4 made a configured ``default_role`` authoritative over the client.
        With no default the client value is used, which is documented and
        deliberate, but it was never bounded by an authenticated session.  A
        client that names alice and claims ``admin`` therefore runs an
        admin-only tool over her user session.

        Guarded on the 2.x ``Server`` constructor rather than only on the
        package.  ``importorskip("mcp")`` guards the ABSENCE of the SDK, not
        the presence of the wrong major, which is the distinction A1.2
        recorded after the review's own file could not run against 1.30.0.
        The 1.x hook carries the same case in the test below.
        """
        pytest.importorskip("mcp")
        import inspect

        import mcp.types as mt
        from mcp.server import Server

        if "on_call_tool" not in inspect.signature(Server.__init__).parameters:
            pytest.skip("mcp 1.x Server has no on_call_tool constructor")

        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        gate.create_session(user_id="alice", role="user")
        ran = []

        async def handler(ctx, params):
            ran.append("ADMIN_ACTION")
            return mt.CallToolResult(
                content=[mt.TextContent(type="text", text="done")]
            )

        server = Server("local-probe", on_call_tool=handler)
        AgentLockMCPServer(
            server, gate,
            {"admin_task": _perms(requires_auth=True, allowed_roles=["admin"])},
        )
        with contextlib.suppress(DeniedError):
            asyncio.run(server.get_request_handler("tools/call").handler(
                None,
                mt.CallToolRequestParams(name="admin_task", arguments={
                    "_agentlock_user_id": "alice",
                    "_agentlock_role": "admin",
                }),
            ))
        assert ran == []

    def test_an_mcp_1x_client_cannot_claim_a_role_over_a_session(self):
        """E10 over the 1.x ``call_tool`` hook, through the same
        ``FakeServer`` the rest of this file uses.

        The hook's 1.x branch is selected by the presence of ``call_tool``
        rather than by the SDK version, so this runs at either major and is
        what keeps the finding covered where only 1.x is installed.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        gate.create_session(user_id="alice", role="user")
        server = FakeServer()
        ran = []
        AgentLockMCPServer(
            server, gate,
            {"admin_task": _perms(requires_auth=True, allowed_roles=["admin"])},
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            ran.append("ADMIN_ACTION")
            return "done"

        with pytest.raises(DeniedError) as denied:
            asyncio.run(server.handler("admin_task", {
                "_agentlock_user_id": "alice",
                "_agentlock_role": "admin",
            }))
        assert denied.value.reason == "role_mismatch"
        assert ran == []

    # F2: output modification covers str returns only (REPRODUCED)

    RETURNS = {
        "dict": lambda: {"note": SECRET},
        "list": lambda: [SECRET],
        "nested": lambda: {"rows": [{"note": SECRET}]},
        "tuple": lambda: (SECRET,),
        "bytes": lambda: SECRET.encode(),
    }

    @staticmethod
    def _modifying_gate() -> tuple[AuthorizationGate, AgentLockPermissions]:
        gate = AuthorizationGate()
        perms = _perms(modify_policy=_redact("output"))
        gate.register_tool("task", perms)
        return gate, perms

    @pytest.mark.parametrize("shape", sorted(RETURNS))
    def test_the_decorator_modifies_every_shape_of_return(self, shape):
        """E11.  E1 threaded the modifier onto every execution path, so it
        does reach the decorator.  It is then guarded by
        ``isinstance(result, str)``, and a tool that returns a mapping, a
        sequence, or bytes is the ordinary case, so the declared
        transformation was still inert for most tools.
        """
        from agentlock.decorators import agentlock as decorate

        gate, perms = self._modifying_gate()
        wrapped = decorate(gate, name="task", permissions=perms)(
            self.RETURNS[shape]
        )
        assert SSN not in repr(wrapped(_user_id="alice", _role="user"))

    @pytest.mark.parametrize("shape", sorted(RETURNS))
    def test_gate_call_modifies_every_shape_of_return(self, shape):
        """E11 on the one-step path, which applies the modifier inside
        ``gate.execute`` and carries the same guard.
        """
        gate, _ = self._modifying_gate()
        result = gate.call(
            "task", self.RETURNS[shape], user_id="alice", role="user",
        )
        assert SSN not in repr(result)

    def test_bytes_come_back_as_bytes(self):
        """E11: the container type survives the walk.  A modifier that turned
        a bytes return into a str would break the caller as surely as one that
        left the SSN in it.
        """
        gate, _ = self._modifying_gate()
        result = gate.call(
            "task", lambda: SECRET.encode(), user_id="alice", role="user",
        )
        assert isinstance(result, bytes)
        assert SSN not in result.decode()

    def test_a_tuple_comes_back_as_a_tuple(self):
        """E11: likewise for the sequence types, which are not interchangeable
        to a caller that indexes or unpacks them.
        """
        gate, _ = self._modifying_gate()
        result = gate.call("task", lambda: (SECRET,), user_id="alice", role="user")
        assert isinstance(result, tuple)
        assert SSN not in result[0]

    def test_an_unmodifiable_return_is_passed_through(self):
        """Control, passing today: E11 names the types it covers and returns
        everything else unchanged rather than guessing at it.
        """
        marker = object()
        gate, _ = self._modifying_gate()
        assert gate.call(
            "task", lambda: marker, user_id="alice", role="user",
        ) is marker

    def test_a_str_return_is_still_modified(self):
        """Control, passing today: the case E1 closed stays closed."""
        gate, _ = self._modifying_gate()
        result = gate.call("task", lambda: SECRET, user_id="alice", role="user")
        assert SSN not in result

    # F3: route mapping and the header (NOT REPRODUCED)

    @staticmethod
    def _fastapi_app(mapping):
        pytest.importorskip("fastapi")
        import fastapi

        from agentlock.integrations.fastapi import AgentLockMiddleware

        gate = AuthorizationGate()
        gate.register_tool("task", _perms())
        gate.register_tool("admin_task", _perms(allowed_roles=["admin"]))

        app = fastapi.FastAPI()
        ran = []

        @app.post("/admin")
        async def admin():
            ran.append("ADMIN_ACTION")
            return {"ok": True}

        app.add_middleware(
            AgentLockMiddleware, gate=gate, tool_name_from_path=mapping,
        )
        return app, ran

    def test_fastapi_a_declined_route_ignores_the_tool_header(self):
        """F3 as reported: with ``tool_name_from_path`` configured and
        returning ``None`` for the route, the header is said to be consulted
        and to let the client pick the tool.

        Measured against the branch wheel: it is not.  The mapping's ``None``
        is taken as "no tool name" and the request takes the existing
        pass-through path, which is 200 with the handler running and no
        authorization performed.  The header is never read for tool selection
        while a mapping is configured.  That is exactly what E12 requires, so
        this case is a guard on behavior already in the wheel and not an
        expected failure.  It is written down because fastapi had no test for
        the declined-route case, while flask did
        (``TestFlaskToolSelection.test_a_declined_endpoint_passes_through_
        with_the_header_ignored``), and an untested branch is how a finding
        like this one gets reported.
        """
        app, ran = self._fastapi_app(lambda method, path: None)
        from fastapi.testclient import TestClient

        response = TestClient(app).post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "task",
        })
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_fastapi_a_conflicting_tool_header_is_still_refused(self):
        """Plain guard: E5's conflict case, unchanged by E12."""
        app, ran = self._fastapi_app(lambda method, path: "admin_task")
        from fastapi.testclient import TestClient

        response = TestClient(app).post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "task",
        })
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "tool_selection_conflict"
        assert ran == []

    def test_fastapi_the_header_is_honored_with_no_mapping(self):
        """Plain guard: E12 leaves header-only mode alone."""
        app, ran = self._fastapi_app(None)
        from fastapi.testclient import TestClient

        response = TestClient(app).post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "admin_task",
        })
        assert response.status_code == 403
        assert ran == []

    def test_flask_a_declined_endpoint_ignores_the_tool_header(self):
        """The flask half of F3, measured the same way and equally not
        reproduced.  ``TestFlaskToolSelection`` already covers this; the case
        is repeated here so the red pass record is complete on its own.
        """
        flask = pytest.importorskip("flask")
        from agentlock.integrations.flask import AgentLockFlask

        gate = AuthorizationGate()
        gate.register_tool("task", _perms())
        app = flask.Flask(f"{__name__}.redpass")
        ran = []

        @app.post("/admin")
        def admin():
            ran.append("ADMIN_ACTION")
            return {"ok": True}

        AgentLockFlask(
            app, gate, tool_name_from_endpoint=lambda e, m, p: None,
        )
        response = app.test_client().post("/admin", headers={
            "X-AgentLock-User-Id": "alice",
            "X-AgentLock-Role": "user",
            "X-AgentLock-Tool": "task",
        })
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    # Red pass 2, against the wheel built from 33d0386 (sha256 b72739f9).
    # F4 and F5 reproduce and are closed by E15 and E16; F6 reproduces and is
    # stated rather than closed, so its cases are guards on the limit.

    @staticmethod
    def _structured_result_perms() -> AgentLockPermissions:
        return _perms(modify_policy=_redact("output"))

    def test_mcp_2x_structured_content_is_modified(self):
        """F4 through the real mcp 2.x hook.

        E11 taught the MCP applier to walk a result that is not a
        content-carrying model, and taught it to rewrite the ``text`` of every
        content block in one that is.  A 2.x ``CallToolResult`` is both: it
        carries ``content`` AND it carries ``structured_content``, a mapping
        the client reads as the tool's real answer.  The applier stops at the
        first of those, so a handler that puts the SSN in both gets one copy
        redacted and hands the other one over intact.

        Guarded on the 2.x ``Server`` constructor rather than only on the
        package, per A1.2: ``importorskip("mcp")`` guards the ABSENCE of the
        SDK and not the presence of the wrong major.  The 1.x hook carries the
        same finding in the test below, under the SDK's own spelling of the
        field.
        """
        pytest.importorskip("mcp")
        import inspect

        import mcp.types as mt
        from mcp.server import Server

        if "on_call_tool" not in inspect.signature(Server.__init__).parameters:
            pytest.skip("mcp 1.x Server has no on_call_tool constructor")

        from agentlock.integrations.mcp import AgentLockMCPServer

        async def handler(ctx, params):
            return mt.CallToolResult(
                content=[mt.TextContent(type="text", text=SECRET)],
                structured_content={"note": SECRET},
            )

        gate = AuthorizationGate()
        server = Server("local-probe", on_call_tool=handler)
        AgentLockMCPServer(
            server, gate, {"task": self._structured_result_perms()},
        )
        result = asyncio.run(server.get_request_handler("tools/call").handler(
            None,
            mt.CallToolRequestParams(name="task", arguments={
                "_agentlock_user_id": "alice",
                "_agentlock_role": "user",
            }),
        ))
        assert SSN not in result.content[0].text
        assert SSN not in repr(result.structured_content)

    def test_mcp_1x_structured_content_is_modified(self):
        """F4 over the 1.x ``call_tool`` hook, through ``FakeServer``.

        The 1.x SDK spells the field ``structuredContent``, the 2.x SDK spells
        it ``structured_content``, and the applier is one function serving both
        hooks, so it has to know both names.  This case is what covers the
        camelCase name, and it is what keeps the finding covered in an
        environment where only the 1.x SDK is installed and the case above
        skips.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Text:
            def __init__(self, text):
                self.text = text

        class Result:
            def __init__(self, content, structured):
                self.content = content
                self.structuredContent = structured  # noqa: N815

        gate = AuthorizationGate()
        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"task": self._structured_result_perms()},
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([Text(SECRET)], {"note": SECRET})

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert SSN not in result.content[0].text
        assert SSN not in repr(result.structuredContent)

    def test_mcp_1x_a_list_return_is_walked(self):
        """Control, passing today.  E15 says a result that is a plain sequence
        rather than a content-carrying model is walked on the same terms.  The
        1.x handler contract allows a bare list of content items, and that
        shape is already covered; it is pinned here so the structured content
        change cannot quietly cost it.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Text:
            def __init__(self, text):
                self.text = text

        gate = AuthorizationGate()
        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"task": self._structured_result_perms()},
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return [Text(SECRET)]

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert SSN not in result[0].text

    def test_mcp_1x_a_mapping_return_is_walked(self):
        """Control, passing today: the other half of E15's second sentence.
        A handler returning a plain mapping has no ``content`` list, so the
        applier hands it to the walk, which is the behavior E11 added and this
        change must leave alone.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"task": self._structured_result_perms()},
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return {"note": SECRET}

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert SSN not in repr(result)

    # F5: the walk does not cover set or frozenset (REPRODUCED)

    def test_a_set_return_is_modified(self):
        """E16.  E11 named the types it covers and returned everything else
        unchanged, and a ``set`` was one of the things it named as uncovered.
        A set of strings is an ordinary return for a tool that answers with
        distinct values, so naming it as uncovered documented a leak rather
        than bounding one.  The member type is what the walk rebuilds, so the
        return has to come back a ``set``.
        """
        gate, _ = self._modifying_gate()
        result = gate.call("task", lambda: {SECRET}, user_id="alice", role="user")
        assert isinstance(result, set)
        assert SSN not in repr(result)

    def test_a_frozenset_return_is_modified(self):
        """E16, and the container identity half of it: a ``frozenset`` is not
        interchangeable with a ``set`` to a caller that puts it in another set
        or uses it as a key, so the walk rebuilds the type it was given.
        """
        gate, _ = self._modifying_gate()
        result = gate.call(
            "task", lambda: frozenset({SECRET}), user_id="alice", role="user",
        )
        assert isinstance(result, frozenset)
        assert SSN not in repr(result)

    # F6: dict keys and objects are not walked (REPRODUCED, STATED NOT FIXED)

    def test_a_dict_key_is_not_modified(self):
        """F6, pinned as a limit rather than closed.  A key is a field name.
        A transformation that renamed fields would corrupt the payload it was
        asked to sanitize, which is the reason A2.6 already gave for descending
        into values only.  A host that puts secret material in a key is naming
        its records after the secret, and it has to redact that itself.

        This case asserts the leak, so the limit is pinned rather than
        implied: if the walk ever starts modifying keys, this fails and the
        decision gets re-argued instead of drifting.
        """
        gate, _ = self._modifying_gate()
        result = gate.call(
            "task", lambda: {SECRET: "value"}, user_id="alice", role="user",
        )
        assert list(result) == [SECRET]

    def test_an_object_return_is_not_modified(self):
        """F6's other half.  An arbitrary object is returned unchanged even
        when its ``__str__`` carries the secret, because the walk does not
        know how to rebuild a type it was not told about and will not mutate
        one it was handed.  Same conclusion: the host redacts it.
        """

        class Carrier:
            def __str__(self):
                return SECRET

            __repr__ = __str__

        carrier = Carrier()
        gate, _ = self._modifying_gate()
        result = gate.call("task", lambda: carrier, user_id="alice", role="user")
        assert result is carrier
        assert str(result) == SECRET


class TestRecheck:
    """The 1.10.0 recheck: three findings, and the engine-level cases the
    reviewer's oracle does not reach.

    The oracle exercises G1 and G3 through ``gate.call`` and G2 through the
    mcp 2.x hook.  What it cannot reach from outside is pinned here: the same
    G2 shapes over the 1.x ``call_tool`` hook, which is selected by the
    presence of ``call_tool`` and not by the SDK version; the resolved path a
    whitelisted callable actually receives, which the oracle observes only as
    the file that got read; and the recipient edge forms, which decide whether
    the exhaustive parse is usable rather than only safe.
    """

    # G1: whitelist_path normalizes lexically before it resolves (REPRODUCED)

    @staticmethod
    def _whitelist_gate(prefix: str) -> AuthorizationGate:
        gate = AuthorizationGate()
        gate.register_tool("task", _perms(modify_policy=ModifyPolicyConfig(
            enabled=True,
            apply_when_hardening_active=False,
            transformations=[TransformationConfig(
                field="path",
                action="whitelist_path",
                config={"allowed_prefixes": [prefix]},
            )],
        )))
        return gate

    @staticmethod
    def _link_tree(tmp_path):
        """allowed/jump is a directory symlink pointing outside the tree."""
        allowed = tmp_path / "allowed"
        outside = tmp_path / "outside"
        (allowed / "inner").mkdir(parents=True)
        (outside / "child").mkdir(parents=True)
        (allowed / "inside.txt").write_text("PUBLIC")
        (outside / "private.txt").write_text("PRIVATE_SENTINEL")
        (allowed / "jump").symlink_to(outside / "child", target_is_directory=True)
        (allowed / "inner" / "back").symlink_to(allowed, target_is_directory=True)
        return allowed, outside

    def test_the_callable_receives_the_path_that_was_checked(self, tmp_path):
        """G1's second half, which the oracle can only observe indirectly.

        Through 1.10.0 the action returned the caller's original string on
        allow, so the gate checked one path and the host opened another.  A
        composition through a symlink is where those two diverge, and the
        assertion here is on the string the callable was handed rather than on
        what it read, so the divergence is pinned at the point it happens.
        """
        allowed, _ = self._link_tree(tmp_path)
        gate = self._whitelist_gate(str(allowed))
        seen = []

        def read(path):
            seen.append(path)
            return "ok"

        gate.call(
            "task", read,
            parameters={"path": str(allowed / "inner" / "back" / "inside.txt")},
            user_id="alice", role="user",
        )
        assert seen == [str((allowed / "inside.txt").resolve())]

    def test_a_symlink_then_parent_composition_is_denied(self, tmp_path):
        """G1.  ``allowed/jump/../private.txt`` where ``jump`` leads outside.

        A lexical ``normpath`` ahead of ``realpath`` collapses this to
        ``allowed/private.txt`` against the SPELLING of the path, which is
        inside the prefix, and the filesystem is never consulted about
        ``jump``.  ``open()`` does not collapse it lexically, so the tool read
        the file the prefix existed to exclude.
        """
        allowed, outside = self._link_tree(tmp_path)
        gate = self._whitelist_gate(str(allowed))
        target = allowed / "jump" / ".." / "private.txt"
        assert target.resolve() == (outside / "private.txt").resolve()

        with pytest.raises(DeniedError):
            gate.call(
                "task", lambda path: path, parameters={"path": str(target)},
                user_id="alice", role="user",
            )

    def test_a_relative_path_is_blocked(self, tmp_path):
        """A relative path names a different file for every working directory,
        so what it resolves to is a property of the caller's process and not of
        the request.  It was blocked before only because the working directory
        happened to sit outside the prefix; it is blocked structurally now.
        """
        allowed, _ = self._link_tree(tmp_path)
        gate = self._whitelist_gate(str(allowed))

        with pytest.raises(DeniedError):
            gate.call(
                "task", lambda path: path, parameters={"path": "./inside.txt"},
                user_id="alice", role="user",
            )

    def test_mcp_1x_whitelisted_path_reaches_the_handler_resolved(self, tmp_path):
        """G1 over the 1.x hook.  The parameter transformation is applied by
        the gate, so the adapter carries the canonicalized value through to the
        handler like any other effective parameter.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        allowed, _ = self._link_tree(tmp_path)
        gate = self._whitelist_gate(str(allowed))
        server = FakeServer()
        AgentLockMCPServer(server, gate, {})
        seen = []

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            seen.append(arguments["path"])
            return "ok"

        asyncio.run(server.handler("task", {
            "path": str(allowed / "inner" / "back" / "inside.txt"),
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert seen == [str((allowed / "inside.txt").resolve())]

    # G2: MCP output redaction misses two shapes and one policy (REPRODUCED)

    def test_mcp_1x_an_embedded_resource_is_redacted(self):
        """G2(a) over the 1.x hook.  ``getattr(item, "text", None)`` is None on
        an ``EmbeddedResource``, so the item fell through to the general walk,
        which returns a custom object unchanged by its own stated contract.
        The declared transformation never reached the string a client reads.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class TextResource:
            """An ``EmbeddedResource`` holds its text one level down, here."""

            def __init__(self, text):
                self.text = text

        class Embedded:
            def __init__(self, text):
                self.resource = TextResource(text)

        class Result:
            def __init__(self, content):
                self.content = content

        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"task": perms})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([Embedded(SECRET)])

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert SSN not in result.content[0].resource.text

    def test_mcp_1x_a_blob_resource_is_passed_through(self):
        """The stated limit, pinned so it cannot drift.  A resource carrying
        base64 in ``blob`` and no ``text`` comes back untouched: this engine
        does not claim to decode a blob, guess its media type, and redact
        inside it.  A host serving sensitive material that way redacts it at
        the source.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class BlobResource:
            def __init__(self, blob):
                self.blob = blob

        class Embedded:
            def __init__(self, blob):
                self.resource = BlobResource(blob)

        class Result:
            def __init__(self, content):
                self.content = content

        payload = "MTIzLTQ1LTY3ODk="
        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"task": perms})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([Embedded(payload)])

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert result.content[0].resource.blob == payload

    @staticmethod
    def _data_policy_perms() -> AgentLockPermissions:
        from agentlock.schema import DataPolicyConfig

        return _perms(data_policy=DataPolicyConfig(
            prohibited_in_output=["ssn"], redaction="auto",
        ))

    @pytest.mark.parametrize("shape", ["text", "structured", "embedded"])
    def test_mcp_1x_the_data_policy_reaches_every_shape(self, shape):
        """G2(b) over the 1.x hook, and the reason the two policies now share
        one walk.

        Redaction in the adapter was guarded by ``isinstance(result, str)``,
        which is never true of an MCP result, so a tool declaring
        ``prohibited_in_output`` with ``redaction="auto"`` and no modify policy
        had the step skipped entirely and leaked through every shape at once.
        Two policies over the same payload need one definition of what the
        payload is, or the weaker definition decides what leaks.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Text:
            def __init__(self, text):
                self.text = text

        class TextResource:
            def __init__(self, text):
                self.text = text

        class Embedded:
            def __init__(self, text):
                self.resource = TextResource(text)

        class Result:
            def __init__(self, content, structured=None):
                self.content = content
                self.structured_content = structured

        gate = AuthorizationGate()
        perms = self._data_policy_perms()
        gate.register_tool("task", perms)
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"task": perms})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            if shape == "text":
                return Result([Text(SECRET)])
            if shape == "structured":
                return Result([], {"note": SECRET})
            return Result([Embedded(SECRET)])

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        rendered = repr([
            getattr(item, "text", None) or getattr(item.resource, "text", None)
            for item in result.content
        ]) + repr(result.structured_content)
        assert SSN not in rendered

    def test_mcp_1x_an_undeclared_tool_output_is_untouched(self):
        """Control.  Walking unconditionally is only safe because redaction of
        a tool that declared no data policy is the identity.  A plain string
        return with no policy at all comes back exactly as the handler wrote
        it, secret and all, which is the pre-existing contract.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        gate = AuthorizationGate()
        gate.register_tool("task", _perms())
        server = FakeServer()
        AgentLockMCPServer(server, gate, {})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return SECRET

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert result == SECRET

    # G3: restrict_domain validates one address, positionally (REPRODUCED)

    @staticmethod
    def _domain_gate() -> AuthorizationGate:
        gate = AuthorizationGate()
        gate.register_tool("task", _perms(modify_policy=ModifyPolicyConfig(
            enabled=True,
            apply_when_hardening_active=False,
            transformations=[TransformationConfig(
                field="to",
                action="restrict_domain",
                config={"allowed_domains": ["company.test"]},
            )],
        )))
        return gate

    def _send(self, value):
        """Return the recipients the tool was actually invoked with, or None
        if the value was blocked."""
        gate = self._domain_gate()
        seen = []

        def send(to):
            seen.append(to)
            return "simulated sent"

        try:
            gate.call(
                "task", send, parameters={"to": value},
                user_id="alice", role="user",
            )
        except DeniedError:
            return None
        return seen[0]

    @pytest.mark.parametrize("value", [
        "bob@company.test,",
        "bob@company.test;",
        "bob@company.test, ,carol@company.test",
        "Bob <bob@company.test>",
        "bob@COMPANY.TEST",
        "Bob <bob@company.test>, Carol <carol@company.test>",
    ])
    def test_benign_recipient_forms_are_allowed(self, value):
        """The edge forms that decide whether an exhaustive parse is usable
        rather than only safe.

        A trailing separator and a whitespace only piece are formatting, not
        recipients, so they are discarded before the parse requirement rather
        than counted as unparseable pieces.  A display name is accepted because
        the pattern finds the address inside it.  Domains compare case
        insensitively, so a value that differs from the allowlist only in case
        is the same value.
        """
        assert self._send(value) == value

    @pytest.mark.parametrize("value", [
        "bob@company.test, eve@outside.test",
        "eve@outside.test, bob@company.test",
        "bob@company.test;eve@outside.test",
        "bob@company.test, eve@outside.test, carol@company.test",
        "Bob <bob@company.test>, Eve <eve@outside.test>",
        "bob@company.test, not-an-address",
        "bob@company.test eve@outside.test",
    ])
    def test_a_disallowed_or_unparseable_piece_blocks_the_value(self, value):
        """G3.  ``search`` read the FIRST address and nothing after it, so the
        answer was a function of the order the addresses were written in: the
        same recipient set blocked when the outside address came first and
        allowed when it came second.  The pair of orderings at the top of this
        list is that finding; both must block now, and they must block for the
        same reason.

        The unparseable piece cases are the smuggling shape.  Once a value has
        been established as a recipient list by carrying an address, a piece
        the parser cannot read is not evidence of innocence.  The last case has
        no separator at all, which is why addresses are collected per piece
        with ``finditer`` rather than ``search``.
        """
        assert self._send(value) is None

    @pytest.mark.parametrize("value", ["not-an-email", "", "   "])
    def test_a_value_carrying_no_address_is_untouched(self, value):
        """The scope of the exhaustive parse, pinned rather than implied.

        A field with no address in it is not a recipient list, and an allowlist
        over domains can only govern things that have a domain.  This is the
        behavior the engine has always had and
        ``TestRestrictDomain::test_no_email_in_field`` pins the unit half of
        it; this is the gate half.
        """
        assert self._send(value) == value

    def test_a_quoted_display_name_with_a_comma_blocks(self):
        """The stated limit, pinned so it cannot drift.  ``"Doe, Bob"
        <bob@company.test>`` splits into pieces that do not each carry an
        address, so it blocks.  That is a conservative failure and it is
        deliberate: honoring RFC 5322 quoting here would mean writing a mail
        parser, and getting one subtly wrong is how the first match rule
        happened.
        """
        assert self._send('"Doe, Bob" <bob@company.test>') is None


class TestBranchWheelRedPass:
    """The red pass against the 1.10.1 branch wheel, sha256 ``ae231877``.

    1.10.1 closed G3 by parsing the whole recipient value instead of its first
    address.  A red pass against the wheel built from that fix found that the
    parse still decides whether a value IS a recipient list by asking the ASCII
    address pattern, and a value the pattern cannot read was therefore treated
    as carrying no address at all and returned unchanged.  That is G4, and the
    forms it lets through are deliverable addresses rather than curiosities.

    The G4 cases were committed as ``xfail(strict=True)`` before the code that
    satisfies them, so the before state is in the history, and the markers came
    off in the commit that closed the finding.  A strict xfail that starts
    passing is a failure, so neither the marker nor the fix could be left half
    applied.

    The same pass reported two MCP payloads the walker does not descend into.
    Both are STATED rather than closed, and their cases assert the pass
    through: a limit that is pinned is a limit that cannot drift.
    """

    # G4: an address the ASCII pattern cannot read is not "no address"

    @staticmethod
    def _domain_gate() -> AuthorizationGate:
        gate = AuthorizationGate()
        gate.register_tool("task", _perms(modify_policy=ModifyPolicyConfig(
            enabled=True,
            apply_when_hardening_active=False,
            transformations=[TransformationConfig(
                field="to",
                action="restrict_domain",
                config={"allowed_domains": ["company.test"]},
            )],
        )))
        return gate

    def _send(self, value):
        """Return the recipients the tool was invoked with, or None if the
        value was blocked."""
        gate = self._domain_gate()
        seen = []

        def send(to):
            seen.append(to)
            return "simulated sent"

        try:
            gate.call(
                "task", send, parameters={"to": value},
                user_id="alice", role="user",
            )
        except DeniedError:
            return None
        return seen[0]

    @pytest.mark.parametrize("value", [
        "bob@compаny.test",
        "bob@[10.0.0.1]",
        "bob@company.test@evil.test",
    ])
    def test_an_address_the_pattern_cannot_read_is_blocked(self, value):
        """G4.  Through 1.10.1 the exhaustive parse asked the ASCII pattern
        whether the value held an address, and a value the pattern could not
        read was judged to hold none, which returned it unchanged.

        The first case spells its domain with a Cyrillic letter, the second is
        an address literal, and the third carries a second at sign after an
        allowed domain, so the pattern reads the allowed part and stops before
        the rest.  All three are deliverable, and all three passed a domain
        allowlist that exists to decide exactly this.

        What decides now is the at sign, which is the character that makes a
        string an address, and not the pattern, which is one opinion about
        which addresses are well formed.  A piece carrying an at sign that does
        not parse as a single ASCII address blocks the value, so an address the
        engine cannot read is refused rather than waved through.
        """
        assert self._send(value) is None

    @pytest.mark.parametrize("value", ["not-an-email", "Bob Smith", ""])
    def test_a_value_with_no_at_sign_is_untouched(self, value):
        """The scope of the at sign rule, pinned rather than implied.

        A field with no at sign anywhere in it is not a recipient list, and an
        allowlist over domains can only govern things that have a domain.  This
        is the behavior the engine has always had and
        ``TestRestrictDomain::test_no_email_in_field`` pins the unit half of
        it.  A bare local name a mail system may still know how to route is not
        covered, for the same reason: there is no domain in it to compare.
        """
        assert self._send(value) == value

    @pytest.mark.parametrize("value", [
        "Bob <bob@company.test>",
        "bob@COMPANY.TEST",
        "Bob <bob@COMPANY.TEST>",
        "Bob <bob@company.test>, Carol <carol@company.test>",
    ])
    def test_the_benign_forms_the_at_sign_rule_must_not_break(self, value):
        """The controls.  A rule that blocked every value it could not parse
        exactly would close G4 by refusing ordinary recipients, and these are
        the ordinary recipients.

        A display name is accepted, as it was before, because the address
        inside the angle brackets is what the piece is about.  Domains compare
        after casefolding, so a value differing from the allowlist only in case
        is the same value.  Neither of those is a loosening: each of these
        pieces still has to parse as one address whose domain is allowed.
        """
        assert self._send(value) == value

    def test_an_idna_encoded_domain_outside_the_allowlist_is_blocked(self):
        """The lookalike domain in its encoded spelling.

        A domain that is not ASCII reaches the wire encoded, and the encoded
        form is ASCII, parses, and is a different domain from the one on the
        allowlist.  It blocks on the domain comparison rather than on the
        parse, which is the right reason: the engine compares the domain it was
        handed against the domains it was given and does not decode, fold or
        otherwise guess at what a domain resembles.
        """
        assert self._send("bob@xn--compny-4of.test") is None

    # Two MCP payloads the walker does not descend into (STATED)

    def test_a_resource_link_is_passed_through(self):
        """The stated limit.  A resource link carries a URI and a name and no
        content, so it reaches the general walk and comes back untouched, both
        fields included.

        A link is a reference to data rather than the data, and following one
        to redact what it points at would mean fetching it, which is not
        something an authorization decision does.  The name travels with the
        link, so a host that puts sensitive material in either field is
        publishing it and has to redact it at the source.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Link:
            """A ``ResourceLink``: a uri and a name, no text and no resource."""

            def __init__(self, uri, name):
                self.uri = uri
                self.name = name

        class Text:
            def __init__(self, text):
                self.text = text

        class Result:
            def __init__(self, content):
                self.content = content

        link = Link("https://files.test/" + SSN, "report-" + SSN)
        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"task": perms})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([link, Text(SECRET)])

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert result.content[0].uri == "https://files.test/" + SSN
        assert result.content[0].name == "report-" + SSN
        assert SSN not in result.content[1].text

    def test_a_result_meta_is_passed_through(self):
        """The stated limit.  A tool result's metadata field is not walked,
        under either of the spellings the two SDK majors use for it.

        The walker covers the two payloads a client reads as the answer, which
        are the content blocks and the structured content.  Metadata is the
        transport's own channel, carrying things like a progress token and a
        cursor, and rewriting values there would change how a client routes a
        result rather than what it reads out of one.  A handler that puts
        sensitive material in metadata is putting it outside the payload this
        engine claims to cover.
        """
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        class Text:
            def __init__(self, text):
                self.text = text

        class Result:
            def __init__(self, content, meta):
                self.content = content
                self.meta = meta
                self._meta = meta

        gate, perms = _gate(modify_policy=_redact("output"))
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"task": perms})

        @server.call_tool()
        async def handler(name: str, arguments: dict):
            return Result([Text(SECRET)], {"note": SSN})

        result = asyncio.run(server.handler("task", {
            "_agentlock_user_id": "alice", "_agentlock_role": "user",
        }))
        assert result.meta == {"note": SSN}
        assert result._meta == {"note": SSN}
        assert SSN not in result.content[0].text


class TestJwtAndAudit:
    """1.10.2: J1, one denial predicate, and J2, verified JWT identity.

    J1 came from the external reviewer's 1.10.1 recheck and J2 from a
    pre-release check against the published 1.10.1 wheel.  The reviewer's
    file pins J1 for the timeout spelling only, because that is the spelling
    that was broken; both spellings are pinned here, since the whole point of
    the fix is that a caller cannot tell them apart.
    """

    # -- J1: a denial is a denial in either spelling --------------------

    @staticmethod
    def _denied_deferral(spelling: str):
        """A resolved deferral whose resolution is ``spelling``.

        ``"deny"`` is what ``check_timeouts`` and the commit queue's expiry
        branch write; ``"denied"`` is what its predicate branch writes.  The
        expiry path is driven the way the oracle drives it, by ageing the
        record rather than by waiting, and the predicate path by letting
        untrusted content into the session so the commit-time re-decision
        denies on lineage.
        """
        gate = AuthorizationGate()
        session_id = gate.create_session(
            user_id="alice", role="user").session_id
        gate.register_tool("task", _perms(
            lineage_policy=LineagePolicyConfig(enabled=True, decision="deny"),
            action_class=ActionClassConfig(is_deletion=True),
        ))
        record = gate.defer_consequential(
            session_id, "task", {}, is_deletion=True, record_action_flags=True)
        if spelling == "deny":
            record.created_at -= 1000  # expiry, without waiting for it
        else:
            content = "Untrusted retrieved page"
            gate.notify_context_write(
                session_id, ContextSource.WEB_CONTENT,
                hashlib.sha256(content.encode()).hexdigest(), content=content)
        resolved = gate.resolve_deferred_commits(session_id)
        assert len(resolved) == 1
        assert resolved[0].resolution == spelling
        return gate, record

    @pytest.mark.parametrize("spelling", ["deny", "denied"])
    def test_an_execution_reported_after_a_denial_is_flagged(self, spelling):
        """J1.  Through 1.10.1 ``confirm_execution`` compared the resolution
        against ``"denied"`` alone, so a host reporting that it executed an
        action the gate had denied by TIMEOUT was logged as an ordinary
        completed call: the one classification that entry exists to make
        impossible.  The lineage denial took the other branch and was flagged
        correctly, which is why every test that denied through policy passed
        while the default timeout path was silently misfiled.
        """
        gate, record = self._denied_deferral(spelling)
        audit = gate.confirm_execution(
            "task", deferral_id=record.deferral_id,
            parameters={}, status="succeeded")
        assert audit.action == "execution_after_denial"
        assert audit.reason == "executed_despite_denial"

    @pytest.mark.parametrize("spelling", ["deny", "denied"])
    def test_the_flagged_record_keeps_the_resolution_it_was_given(self, spelling):
        """The classification is unified; the evidence is not.  The metadata
        carries the record's OWN string, so the log still says which branch
        denied.  Through 1.10.1 this field was the literal ``"denied"``, which
        would have made a timeout denial unreadable as one even once the
        classification was fixed.
        """
        gate, record = self._denied_deferral(spelling)
        audit = gate.confirm_execution(
            "task", deferral_id=record.deferral_id,
            parameters={}, status="succeeded")
        assert audit.metadata["resolution_at_commit"] == spelling

    # -- J2: a bearer token is identity only once verified ---------------

    KEY = "synthetic-signing-key-for-this-test"
    OTHER_KEY = "a-different-synthetic-key"
    # An identity that cannot reach the admin tool, sent on every request so
    # that a token being honored or ignored is visible in the outcome.
    HEADERS = {
        "X-AgentLock-User-Id": "mallory",
        "X-AgentLock-Role": "guest",
    }
    # An identity that CAN reach the admin tool, for the J3 cases, where what
    # has to be visible is a header being consulted rather than ignored.
    ADMIN_HEADERS = {
        "X-AgentLock-User-Id": "alice",
        "X-AgentLock-Role": "admin",
    }

    @staticmethod
    def _forged_token() -> str:
        """``"alg": "none"``, ``sub`` alice, and bytes that are not a
        signature.  This is the whole attack: on the published 1.10.1 wheel it
        authenticates as alice on both adapters.
        """
        import base64
        import json

        def seg(obj):
            return base64.urlsafe_b64encode(
                json.dumps(obj, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        signature = base64.urlsafe_b64encode(
            b"not-a-signature").rstrip(b"=").decode()
        return (
            f"{seg({'alg': 'none', 'typ': 'JWT'})}."
            f"{seg({'sub': 'alice', 'role': 'admin'})}.{signature}"
        )

    @classmethod
    def _signed_token(cls, key: str = "", exp: int | None = None) -> str:
        from jose import jwt

        claims: dict = {"sub": "alice", "role": "admin"}
        if exp is not None:
            claims["exp"] = exp
        return jwt.encode(claims, key or cls.KEY, algorithm="HS256")

    @staticmethod
    def _gate_with_admin_tool() -> AuthorizationGate:
        gate = AuthorizationGate()
        gate.register_tool("admin_task", _perms(allowed_roles=["admin"]))
        return gate

    @classmethod
    def _fastapi_call(cls, token, jwt_key, *, scheme="Bearer", identity=None):
        pytest.importorskip("fastapi")
        import fastapi
        from fastapi.testclient import TestClient

        from agentlock.integrations.fastapi import AgentLockMiddleware

        app = fastapi.FastAPI()
        ran = []

        @app.post("/admin")
        async def admin():
            ran.append("ADMIN_ACTION")
            return {"ok": True}

        app.add_middleware(
            AgentLockMiddleware, gate=cls._gate_with_admin_tool(),
            tool_name_from_path=lambda method, path: "admin_task",
            jwt_key=jwt_key,
        )
        headers = dict(cls.HEADERS if identity is None else identity)
        if token:
            headers["Authorization"] = f"{scheme} {token}"
        return TestClient(app).post("/admin", headers=headers), ran

    @classmethod
    def _flask_call(cls, token, jwt_key, *, decorator=False,
                    scheme="Bearer", identity=None):
        """The extension hook by default, the route decorator on request.

        Both grew the same two arguments and both have to enforce the same
        rule, so the decorator is not left to a docstring.
        """
        flask = pytest.importorskip("flask")
        from agentlock.integrations.flask import (
            AgentLockFlask,
            agentlock_required,
        )

        gate = cls._gate_with_admin_tool()
        app = flask.Flask(f"{__name__}.jwt")
        ran = []

        if decorator:
            @app.post("/admin")
            @agentlock_required(gate, "admin_task", jwt_key=jwt_key)
            def admin():
                ran.append("ADMIN_ACTION")
                return {"ok": True}
        else:
            @app.post("/admin")
            def admin():
                ran.append("ADMIN_ACTION")
                return {"ok": True}

            AgentLockFlask(
                app, gate,
                tool_name_from_endpoint=lambda e, m, p: "admin_task",
                jwt_key=jwt_key,
            )

        headers = dict(cls.HEADERS if identity is None else identity)
        if token:
            headers["Authorization"] = f"{scheme} {token}"
        return app.test_client().post("/admin", headers=headers), ran

    def test_fastapi_a_forged_unsigned_token_is_refused(self):
        """J2 as reported, on fastapi.  On the published 1.10.1 wheel this
        request is 200 with ``ADMIN_ACTION`` executed, because the payload was
        base64 decoded without a signature check and 1.10.0 made those claims
        outrank the identity headers.  The forged claims must not be read, and
        the headers must not be consulted as a fallback either: this returns
        401, not the 403 the ``mallory``/``guest`` headers would produce.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(self._forged_token(), self.KEY)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_flask_a_forged_unsigned_token_is_refused(self):
        """J2 as reported, on flask.  Same wheel behavior, same fix."""
        pytest.importorskip("jose")
        response, ran = self._flask_call(self._forged_token(), self.KEY)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_fastapi_a_verified_token_carries_the_identity(self):
        """The positive half, and the E5 rule restated as it now holds: a
        token signed with the configured key IS authoritative, and the
        contradicting ``mallory``/``guest`` headers are ignored rather than
        merged with it.  Without this case the fix could be "reject
        everything" and still pass the rejection cases.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(self._signed_token(), self.KEY)
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_flask_a_verified_token_carries_the_identity(self):
        """The same, through the route decorator rather than the hook."""
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            self._signed_token(), self.KEY, decorator=True)
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_fastapi_a_token_signed_with_another_key_is_refused(self):
        """A real signature, over the right claims, by the wrong signer."""
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(
            self._signed_token(self.OTHER_KEY), self.KEY)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_flask_a_token_signed_with_another_key_is_refused(self):
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            self._signed_token(self.OTHER_KEY), self.KEY)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_fastapi_an_expired_token_is_refused(self):
        """Expiry is enforced, so a token that was genuinely issued to alice
        stops being alice.  A verification that checks the signature and not
        the clock turns every leaked token into a permanent credential.
        """
        pytest.importorskip("jose")
        import time

        response, ran = self._fastapi_call(
            self._signed_token(exp=int(time.time()) - 60), self.KEY)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_flask_an_expired_token_is_refused(self):
        pytest.importorskip("jose")
        import time

        response, ran = self._flask_call(
            self._signed_token(exp=int(time.time()) - 60), self.KEY)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_fastapi_without_a_key_the_token_is_ignored_and_headers_apply(self):
        """The default state.  With nothing to verify against, the token is
        not read for identity at all, so the forged ``alice``/``admin`` claims
        do not reach the gate and the ``mallory``/``guest`` headers decide.
        403 for the wrong role, not 200 from the forged claim and not 401,
        because no verification was asked for and none failed.
        """
        response, ran = self._fastapi_call(self._forged_token(), None)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "insufficient_role"
        assert ran == []

    def test_flask_without_a_key_the_token_is_ignored_and_headers_apply(self):
        response, ran = self._flask_call(self._forged_token(), None)
        assert response.status_code == 403
        assert response.get_json()["detail"]["reason"] == "insufficient_role"
        assert ran == []

    def test_fastapi_a_key_without_the_verification_backend_fails_to_build(
        self, monkeypatch
    ):
        """An adapter configured to verify and unable to verify fails at
        CONSTRUCTION.  One that discovered this at its first request would
        have to choose, under load, between refusing every request and
        reading the token anyway, and the second choice is how this finding
        happened the first time.
        """
        pytest.importorskip("fastapi")
        import builtins

        from agentlock.exceptions import IntegrationUnsupportedError
        from agentlock.integrations.fastapi import AgentLockMiddleware

        real_import = builtins.__import__

        def no_jose(name, *args, **kwargs):
            if name == "jose" or name.startswith("jose."):
                raise ImportError("No module named 'jose'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_jose)
        with pytest.raises(IntegrationUnsupportedError):
            AgentLockMiddleware(
                None, self._gate_with_admin_tool(), jwt_key=self.KEY)

    def test_flask_a_key_without_the_verification_backend_fails_to_build(
        self, monkeypatch
    ):
        pytest.importorskip("flask")
        import builtins

        from agentlock.exceptions import IntegrationUnsupportedError
        from agentlock.integrations.flask import AgentLockFlask

        real_import = builtins.__import__

        def no_jose(name, *args, **kwargs):
            if name == "jose" or name.startswith("jose."):
                raise ImportError("No module named 'jose'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_jose)
        with pytest.raises(IntegrationUnsupportedError):
            AgentLockFlask(
                None, self._gate_with_admin_tool(), jwt_key=self.KEY)

    # -- J3: a configured key makes the token the only identity ----------

    @staticmethod
    def _basic_credentials() -> str:
        """A Basic scheme value, so the scheme under test is a real one that
        an ordinary deployment might put in front of this and not a string
        invented to fail a prefix check.
        """
        import base64

        return base64.b64encode(b"alice:not-a-password").decode()

    def test_fastapi_a_configured_key_refuses_a_request_carrying_no_token(self):
        """J3.  Verification is switched ON and the request presents nothing
        to verify.  Through 1.10.2 as released that reached the identity
        headers, so a client that simply omitted the ``Authorization`` header
        was identified by ``X-AgentLock-User-Id`` and ``X-AgentLock-Role`` and
        the admin route ran: verification was enforced only on clients that
        chose to present a token.  A configured key means the token is the
        identity, so a request without one is 401 ``jwt_required`` and the
        headers are not read at all.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(
            None, self.KEY, identity=self.ADMIN_HEADERS)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_required"
        assert ran == []

    def test_flask_a_configured_key_refuses_a_request_carrying_no_token(self):
        """The same on flask, through the extension hook."""
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            None, self.KEY, identity=self.ADMIN_HEADERS)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_required"
        assert ran == []

    def test_fastapi_a_lowercase_bearer_scheme_is_verified(self):
        """RFC 7235 makes the auth scheme case insensitive, and 1.10.2 as
        released matched it with ``startswith("Bearer ")``.  A token spelled
        ``bearer`` was therefore invisible: not a bad token, no token, so the
        identity headers decided.  Here the token is real and signed with the
        configured key while the headers name a guest, so the case fails if
        the token is thrown away for its spelling.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(
            self._signed_token(), self.KEY, scheme="bearer")
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_flask_a_lowercase_bearer_scheme_is_verified(self):
        """The same on flask, through the extension hook."""
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            self._signed_token(), self.KEY, scheme="bearer")
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_fastapi_a_lowercase_bearer_scheme_with_a_forged_token_is_refused(self):
        """The other half of the same rule, and the half that makes it a
        finding rather than an inconvenience.  A forged token under a
        lowercase scheme was not merely ignored: it carried the request past
        the token path entirely and onto the identity headers, which name an
        admin here.  Parsing the scheme case insensitively means this is now
        a bad token, which is 401 ``jwt_invalid``.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(
            self._forged_token(), self.KEY, scheme="bearer",
            identity=self.ADMIN_HEADERS)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_flask_a_lowercase_bearer_scheme_with_a_forged_token_is_refused(self):
        """The same on flask, through the extension hook."""
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            self._forged_token(), self.KEY, scheme="bearer",
            identity=self.ADMIN_HEADERS)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_invalid"
        assert ran == []

    def test_fastapi_a_basic_scheme_does_not_reach_the_identity_headers(self):
        """A scheme that is not bearer at all, which is the general form of
        the same door: any ``Authorization`` value the adapter declines to
        read as a token used to mean no token, and no token used to mean the
        headers decide.  Under a configured key there is no such state.  401
        ``jwt_required``, and the admin headers are not consulted.
        """
        pytest.importorskip("jose")
        response, ran = self._fastapi_call(
            self._basic_credentials(), self.KEY, scheme="Basic",
            identity=self.ADMIN_HEADERS)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "jwt_required"
        assert ran == []

    def test_flask_a_basic_scheme_does_not_reach_the_identity_headers(self):
        """The same through the flask route decorator rather than the hook.
        Both entry points call the one identity function and both have to
        refuse, so the decorator is not left to a docstring.
        """
        pytest.importorskip("jose")
        response, ran = self._flask_call(
            self._basic_credentials(), self.KEY, scheme="Basic",
            identity=self.ADMIN_HEADERS, decorator=True)
        assert response.status_code == 401
        assert response.get_json()["detail"]["reason"] == "jwt_required"
        assert ran == []

    def test_a_key_with_the_token_path_disabled_is_refused_at_build_time(self):
        """``require_agentlock`` takes ``use_jwt``, and with a key configured
        and ``use_jwt=False`` the two arguments contradict: verify tokens with
        this key, and do not read tokens.  Honoring either one silently
        produces the J3 shape, a configured key whose requests are identified
        by header.  The dependency refuses to build instead, at build time
        rather than at the first request, for the same reason a missing
        verification backend does.
        """
        pytest.importorskip("fastapi")
        from agentlock.integrations.fastapi import require_agentlock

        with pytest.raises(ValueError):
            require_agentlock(
                self._gate_with_admin_tool(), "admin_task",
                use_jwt=False, jwt_key=self.KEY)

    def test_fastapi_without_a_key_the_headers_are_still_the_identity(self):
        """The guard on the unchanged half.  J3 is about what a CONFIGURED
        key does; with no key there is nothing to verify and nothing to
        require, so a request carrying no token at all is identified by its
        headers exactly as it was before this fix and before 1.10.0.  This
        case passes both before and after and is here to say that the fix did
        not close the default path along with the door.
        """
        response, ran = self._fastapi_call(
            None, None, identity=self.ADMIN_HEADERS)
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]

    def test_flask_without_a_key_the_headers_are_still_the_identity(self):
        """The same guard on flask."""
        response, ran = self._flask_call(
            None, None, identity=self.ADMIN_HEADERS)
        assert response.status_code == 200
        assert ran == ["ADMIN_ACTION"]
