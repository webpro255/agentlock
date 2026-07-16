"""v1.5 evidence -- the in-tree integrations that own execution now report it.

The MCP server wrapper and the async @agentlock decorator both consume the token
themselves and then run the tool, so the gate saw the grant and never the act.
For those callers the absence of an execution record meant nothing at all.  Each
now reports the attempt before running the tool and the outcome after, bound to
the token it was granted.

The synchronous paths (gate.call, the sync decorator, CrewAI, AutoGen) go through
execute() and were already covered there.

The LangChain integration left core in v1.5 and lives in the standalone
``langchain-agentlock`` package; its async evidence coverage belongs there.
"""

from __future__ import annotations

import asyncio

import pytest

from agentlock import AgentLockPermissions, AuthorizationGate, agentlock
from agentlock.audit import InMemoryAuditBackend
from agentlock.exceptions import DeniedError


def _perms() -> AgentLockPermissions:
    return AgentLockPermissions(
        risk_level="medium", requires_auth=False, allowed_roles=["user"]
    )


def _executions(backend):
    return [
        r
        for r in backend.records
        if r.action in ("execution_attempted", "execution_completed")
    ]


class TestAsyncDecorator:
    def test_a_successful_async_tool_is_confirmed(self):
        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        @agentlock(
            gate=gate,
            risk_level="medium",
            requires_auth=False,
            allowed_roles=["user"],
        )
        async def fetch_page(url: str) -> str:
            return f"contents of {url}"

        result = asyncio.run(fetch_page(url="https://example.com", _role="user"))
        assert result == "contents of https://example.com"

        attempt, completed = _executions(backend)
        assert attempt.action == "execution_attempted"
        assert completed.metadata["status"] == "succeeded"
        assert completed.metadata["reported_by"] == "caller"
        assert completed.metadata["attempt_audit_id"] == attempt.audit_id
        # Bound to the grant that authorized it.
        allowed = [r for r in backend.records if r.action == "allowed"][0]
        assert attempt.token_id == allowed.token_id

    def test_a_failing_async_tool_is_recorded_as_failed_and_still_raises(self):
        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        @agentlock(
            gate=gate,
            risk_level="medium",
            requires_auth=False,
            allowed_roles=["user"],
        )
        async def fetch_page(url: str) -> str:
            raise TimeoutError("upstream timed out")

        with pytest.raises(TimeoutError):
            asyncio.run(fetch_page(url="https://example.com", _role="user"))

        completed = _executions(backend)[-1]
        assert completed.metadata["status"] == "failed"
        assert completed.metadata["error_type"] == "TimeoutError"

    def test_a_denied_async_call_confirms_nothing(self):
        """No grant, no execution, no execution record.  Absence with a
        meaning."""
        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        @agentlock(
            gate=gate,
            risk_level="high",
            requires_auth=False,
            allowed_roles=["admin"],
        )
        async def delete_everything() -> str:
            return "gone"

        with pytest.raises(DeniedError):
            asyncio.run(delete_everything(_role="user"))

        assert _executions(backend) == []


class TestMcpServerWrapper:
    def test_the_mcp_handler_reports_its_execution(self):
        """The MCP server owns execution: the gate learns the outcome only
        because the wrapper tells it."""
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

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

        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"read_file": _perms()}, default_role="user"
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            return f"read {arguments['path']}"

        result = asyncio.run(server.handler("read_file", {"path": "/etc/hosts"}))
        assert result == "read /etc/hosts"

        attempt, completed = _executions(backend)
        assert attempt.action == "execution_attempted"
        assert completed.metadata["status"] == "succeeded"
        assert completed.metadata["reported_by"] == "caller"

