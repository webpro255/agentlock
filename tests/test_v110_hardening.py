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

    def test_a_bearer_token_beats_the_identity_headers(self):
        """E5: a caller cannot present a token and then override it."""
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
