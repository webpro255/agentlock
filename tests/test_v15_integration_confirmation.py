"""v1.5 evidence -- the in-tree integrations that own execution now report it.

LangChain async, the MCP server wrapper, and the async @agentlock decorator all
consume the token themselves and then run the tool, so the gate saw the grant and
never the act.  For those callers the absence of an execution record meant
nothing at all.  Each now reports the attempt before running the tool and the
outcome after, bound to the token it was granted.

The synchronous paths (gate.call, the sync decorator, LangChain sync, CrewAI,
AutoGen) go through execute() and were already covered there.
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


class TestLangChainAsync:
    """Driven through ``_authorized_arun``, which is exactly what the wrapped
    tool's ``_arun`` delegates to, against a minimal BaseTool.

    NOT through ``StructuredTool`` or ``BaseTool.arun``. Both fail inside
    langchain_core against the installed version (its ``_arun`` now requires a
    ``config`` kwarg the wrapper does not pass, and ``arun`` raises in its own
    input parsing), and both fail IDENTICALLY on the v1.4.0 baseline. That is a
    pre-existing integration incompatibility with a newer langchain_core, it is
    unrelated to evidence recording, and this milestone does not quietly repair
    it while claiming to change only what is recorded. It is reported instead.
    """

    def _wrapper(self, gate, coroutine):
        from langchain_core.tools import BaseTool

        from agentlock.integrations.langchain import AgentLockToolWrapper

        class MiniTool(BaseTool):
            name: str = "fetch"
            description: str = "fetch a page"

            def _run(self, **kwargs):
                return "sync"

            async def _arun(self, **kwargs):
                return await coroutine(**kwargs)

        return AgentLockToolWrapper(
            MiniTool(), gate, _perms(), default_role="user"
        )

    def test_the_async_wrapper_reports_its_execution(self):
        pytest.importorskip("langchain_core")
        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        async def fetch(url: str) -> str:
            return f"contents of {url}"

        wrapper = self._wrapper(gate, fetch)
        result = asyncio.run(wrapper._authorized_arun(url="https://example.com"))
        assert result == "contents of https://example.com"

        attempt, completed = _executions(backend)
        assert attempt.action == "execution_attempted"
        assert completed.metadata["status"] == "succeeded"
        assert completed.metadata["reported_by"] == "caller"
        assert completed.metadata["attempt_audit_id"] == attempt.audit_id

    def test_a_failing_async_tool_is_recorded_and_still_raises(self):
        pytest.importorskip("langchain_core")
        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        async def fetch(url: str) -> str:
            raise ConnectionError("upstream refused")

        wrapper = self._wrapper(gate, fetch)
        with pytest.raises(ConnectionError):
            asyncio.run(wrapper._authorized_arun(url="https://example.com"))

        completed = _executions(backend)[-1]
        assert completed.metadata["status"] == "failed"
        assert completed.metadata["error_type"] == "ConnectionError"
