"""End-to-end recipient enforcement through the in-repo integrations, v1.8 3a.

Increment 1 made pipeline Step 8 enforce.  Increment 2 let the trusted permission
block declare which parameter carries the recipient and had the gate read it.
Neither measured an adapter.  The claim that a declared block reaches Step 8
through a shipped integration was an inference from the shape of those call
sites; these tests make it a measurement for the two integrations that can carry
it, and record why the other two cannot.

Reach, as measured: of the six ``authorize()`` call sites under
``agentlock/integrations/``, two forward the caller's parameter dict
(``autogen.py:119``, ``mcp.py:167``) and four do not (``fastapi.py:197``,
``fastapi.py:290``, ``flask.py:163``, ``flask.py:271``).  The declared recipient
parameter is reachable through the first two and unreachable through the last
four, along with every other parameter-level check the gate performs.  That
limitation is pre-existing, is stated in the CHANGELOG, and is not addressed
here.

Both integrations require a package this suite does not depend on, so both
classes are guarded by ``importorskip``, the idiom
``tests/test_v15_integration_confirmation.py:113`` already uses for ``mcp``.
Neither guard is stubbed out: a stub would report a pass for a wrapper whose own
import check had been defeated.
"""

from __future__ import annotations

import asyncio

import pytest

from agentlock.exceptions import DeniedError
from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions, ScopeConfig
from agentlock.types import RecipientPolicy, RiskLevel

KNOWN = ["bob@company.com"]
HOSTILE = "attacker@evil.com"


def _perms(policy=RecipientPolicy.KNOWN_CONTACTS_ONLY):
    """A block whose only restriction is the recipient, with a declared key."""
    return AgentLockPermissions(
        version="1.5",
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
        scope=ScopeConfig(
            allowed_recipients=policy,
            recipient_parameter="to",
        ),
    )


def _gate():
    """A gate with one session for alice, holding one known contact."""
    gate = AuthorizationGate()
    gate.create_session(
        user_id="alice",
        role="user",
        known_contacts=list(KNOWN),
    )
    return gate


class TestAutogenFunctionMap:
    """``protect_functions`` forwards kwargs, so the gate reads the declared key."""

    def test_recipient_enforcement_through_the_function_map(self):
        pytest.importorskip("autogen")
        from agentlock.integrations.autogen import protect_functions

        calls = {"send_email": 0, "send_anywhere": 0}

        def send_email(**kwargs):
            calls["send_email"] += 1
            return "sent"

        def send_anywhere(**kwargs):
            calls["send_anywhere"] += 1
            return "sent"

        gate = _gate()
        protected = protect_functions(
            {"send_email": send_email, "send_anywhere": send_anywhere},
            gate,
            {
                "send_email": _perms(),
                "send_anywhere": _perms(RecipientPolicy.ANY),
            },
        )
        guarded = protected["send_email"]
        auth = {"_agentlock_user_id": "alice", "_agentlock_role": "user"}

        # A known contact reaches the tool.
        assert guarded(to="bob@company.com", body="hi", **auth) == "sent"
        assert calls["send_email"] == 1

        # A single hostile address denies, and the tool does not run.
        with pytest.raises(DeniedError) as exc:
            guarded(to=HOSTILE, body="hi", **auth)
        assert exc.value.reason == "recipient_not_allowed"
        assert calls["send_email"] == 1

        # A set carrying one bad entry denies on that entry.
        with pytest.raises(DeniedError) as exc:
            guarded(to=["bob@company.com", HOSTILE], body="hi", **auth)
        assert exc.value.reason == "recipient_not_allowed"
        assert calls["send_email"] == 1

        # Control: same wrapper, same declared key, same address, a block that
        # admits any recipient.  It executes.  The gate decided, not the wrapper.
        assert protected["send_anywhere"](to=HOSTILE, body="hi", **auth) == "sent"
        assert calls["send_anywhere"] == 1


class TestMcpServerWrapper:
    """The MCP handler forwards its arguments dict, and the gate reads it."""

    def test_recipient_enforcement_through_the_call_tool_handler(self):
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        seen: list[dict] = []

        class FakeServer:
            """Stands in for an MCP Server: it only has to hand us the
            call_tool decorator the wrapper patches."""

            def __init__(self):
                self.handler = None

            def call_tool(self):
                def decorator(fn):
                    self.handler = fn
                    return fn

                return decorator

        gate = _gate()
        server = FakeServer()
        AgentLockMCPServer(server, gate, {"send_email": _perms()})

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            seen.append(dict(arguments))
            return "sent"

        def _call(to):
            return asyncio.run(
                server.handler(
                    "send_email",
                    {
                        "to": to,
                        "body": "x",
                        "_agentlock_user_id": "alice",
                        "_agentlock_role": "user",
                    },
                )
            )

        # A hostile address denies and the underlying tool never runs.
        with pytest.raises(DeniedError) as exc:
            _call(HOSTILE)
        assert exc.value.reason == "recipient_not_allowed"
        assert seen == []

        # A known contact runs the tool.
        assert _call("bob@company.com") == "sent"
        assert len(seen) == 1

        # What the gate read at mcp.py:171 was the tool's own arguments: the
        # auth keys were consumed by the wrapper and the declared key was not.
        arguments = seen[0]
        assert "_agentlock_user_id" not in arguments
        assert "_agentlock_role" not in arguments
        assert arguments["to"] == "bob@company.com"
