"""Model Context Protocol (MCP) integration for AgentLock.

Wraps MCP server tool dispatch with AgentLock authorization so that every
tool call from an MCP client passes through the gate.

Example::

    from mcp.server import Server
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.mcp import AgentLockMCPServer

    gate = AuthorizationGate()
    permissions = {
        "read_file": AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["user", "admin"],
        ),
    }

    server = Server("my-server")
    protected = AgentLockMCPServer(server, gate, permissions)
    # Use protected.server in place of the original server

Requires: ``mcp`` (``pip install mcp``)
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions


def _import_mcp() -> Any:
    """Lazily import the MCP server module."""
    try:
        import mcp.server as mcp_server
        return mcp_server
    except ImportError as exc:
        raise ImportError(
            "The MCP SDK is required for this integration. "
            "Install it with: pip install mcp"
        ) from exc


def _import_mcp_types() -> Any:
    """Lazily import MCP type definitions."""
    try:
        import mcp.types as mcp_types
        return mcp_types
    except ImportError:
        return None


class AgentLockMCPServer:
    """Wraps an MCP ``Server`` with AgentLock authorization on tool dispatch.

    This hooks into the MCP server's tool-call handling so that every
    incoming ``tools/call`` request is authorized before the tool handler
    runs.

    Authorization context is extracted from:
    1. The ``_meta`` field in the tool call arguments (keys
       ``agentlock_user_id``, ``agentlock_role``).
    2. Defaults provided at construction time.

    Args:
        server: An MCP ``Server`` instance.
        gate: An ``AuthorizationGate`` instance.
        permissions_map: Dict mapping tool names to permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
        default_permissions: Permissions for tools not in the map.
    """

    def __init__(
        self,
        server: Any,
        gate: AuthorizationGate,
        permissions_map: dict[str, AgentLockPermissions | dict[str, Any]],
        *,
        default_user_id: str = "",
        default_role: str = "",
        default_permissions: AgentLockPermissions | dict[str, Any] | None = None,
    ) -> None:
        _import_mcp()

        self._server = server
        self._gate = gate
        self._default_user_id = default_user_id
        self._default_role = default_role
        self._permissions_map = permissions_map
        self._default_permissions = default_permissions

        # Register all permissions with the gate
        for tool_name, perms in permissions_map.items():
            gate.register_tool(tool_name, perms)

        # Hook into tool dispatch
        self._install_hook()

    @property
    def server(self) -> Any:
        """Return the underlying MCP server."""
        return self._server

    def _install_hook(self) -> None:
        """Monkey-patch the server's call_tool handler to add authorization.

        MCP servers register tool handlers via ``@server.call_tool()``.  We
        wrap the registered handler (or the dispatch method) so that
        authorization runs first.
        """
        server = self._server

        # The MCP SDK uses a request-handler registry.  We intercept by
        # wrapping the ``call_tool`` decorator so any handler registered
        # through it gets an authorization check.
        original_call_tool = getattr(server, "call_tool", None)
        if original_call_tool is None:
            return

        gate = self._gate
        default_user = self._default_user_id
        default_role = self._default_role
        perm_map = self._permissions_map
        default_perms = self._default_permissions

        original_decorator = original_call_tool

        def patched_call_tool() -> Callable[..., Any]:
            """Replacement for ``@server.call_tool()`` that adds auth."""

            def wrapper(handler: Callable[..., Any]) -> Callable[..., Any]:
                @functools.wraps(handler)
                async def guarded_handler(
                    name: str, arguments: dict[str, Any] | None = None
                ) -> Any:
                    arguments = arguments or {}

                    # Extract auth context from _meta or arguments
                    meta = arguments.pop("_meta", {}) or {}
                    user_id = (
                        meta.get("agentlock_user_id", "")
                        or arguments.pop("_agentlock_user_id", "")
                        or default_user
                    )
                    role = (
                        meta.get("agentlock_role", "")
                        or arguments.pop("_agentlock_role", "")
                        or default_role
                    )

                    # Register tool if not already registered
                    if gate.get_permissions(name) is None:
                        if name in perm_map:
                            gate.register_tool(name, perm_map[name])
                        elif default_perms is not None:
                            gate.register_tool(name, default_perms)

                    # Authorize
                    auth = gate.authorize(
                        name,
                        user_id=user_id,
                        role=role,
                        parameters=arguments or None,
                    )
                    auth.raise_if_denied()
                    assert auth.token is not None

                    # Consume token
                    gate.token_store.validate_and_consume(
                        auth.token.token_id, name, arguments or None
                    )

                    # Delegate to the original handler
                    result = await handler(name, arguments)

                    # Apply redaction
                    if isinstance(result, str):
                        redaction = gate.redact_output(name, result)
                        if redaction.was_redacted:
                            return redaction.redacted

                    return result

                # Register the guarded handler with the original decorator
                registered: Callable[..., Any] = original_decorator()(guarded_handler)
                return registered

            return wrapper

        # Replace the server's call_tool with our version
        server.call_tool = patched_call_tool

    def register_tool(
        self,
        tool_name: str,
        permissions: AgentLockPermissions | dict[str, Any],
    ) -> None:
        """Register additional tool permissions after construction.

        Args:
            tool_name: Tool name as it appears in MCP tool calls.
            permissions: AgentLock permissions for the tool.
        """
        self._permissions_map[tool_name] = permissions
        self._gate.register_tool(tool_name, permissions)
