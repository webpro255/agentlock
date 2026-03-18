"""CrewAI integration for AgentLock.

Wraps CrewAI tool instances with AgentLock authorization so that every
tool execution is gated through the authorization layer.

Example::

    from crewai import Crew, Agent, Task
    from crewai.tools import BaseTool
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.crewai import AgentLockCrewTool, protect_crew_tools

    gate = AuthorizationGate()
    perms = AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    )

    # Wrap a single tool
    protected = AgentLockCrewTool(my_tool, gate, perms, default_user_id="alice")

    # Or protect all tools in a crew
    protect_crew_tools(crew, gate, {"my_tool": perms})

Requires: ``crewai`` (``pip install crewai``)
"""

from __future__ import annotations

import contextlib
from typing import Any

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions


def _import_crewai() -> Any:
    """Lazily import CrewAI and return the tools module."""
    try:
        import crewai.tools as crewai_tools
        return crewai_tools
    except ImportError as exc:
        raise ImportError(
            "CrewAI is required for this integration. "
            "Install it with: pip install crewai"
        ) from exc


def _import_crewai_crew() -> Any:
    """Lazily import the CrewAI Crew class."""
    try:
        from crewai import Crew
        return Crew
    except ImportError as exc:
        raise ImportError(
            "CrewAI is required for this integration. "
            "Install it with: pip install crewai"
        ) from exc


class AgentLockCrewTool:
    """Wraps a CrewAI tool with AgentLock authorization.

    The wrapper proxies the CrewAI tool interface, intercepting ``_run``
    calls to enforce authorization before delegating to the original tool.

    Authorization context is resolved from:
    1. Explicit ``_agentlock_user_id`` / ``_agentlock_role`` in kwargs.
    2. The ``default_user_id`` / ``default_role`` set on the wrapper.

    Args:
        tool: A CrewAI ``BaseTool`` instance.
        gate: An ``AuthorizationGate`` instance.
        permissions: AgentLock permissions for this tool.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
    """

    def __init__(
        self,
        tool: Any,
        gate: AuthorizationGate,
        permissions: AgentLockPermissions | dict[str, Any],
        *,
        default_user_id: str = "",
        default_role: str = "",
    ) -> None:
        crewai_tools = _import_crewai()
        if not isinstance(tool, crewai_tools.BaseTool):
            raise TypeError(
                f"Expected a CrewAI BaseTool instance, got {type(tool).__name__}"
            )

        self._inner_tool = tool
        self._gate = gate
        self._default_user_id = default_user_id
        self._default_role = default_role

        if isinstance(permissions, dict):
            permissions = AgentLockPermissions(**permissions)
        self._permissions = permissions

        self._tool_name = getattr(tool, "name", type(tool).__name__)
        self._gate.register_tool(self._tool_name, self._permissions)

        # Build a dynamic subclass that wraps _run
        wrapper_ref = self
        inner = self._inner_tool

        _base = type(inner)

        class _ProtectedCrewTool(_base):  # type: ignore[misc,valid-type]
            """Dynamically generated CrewAI tool with AgentLock protection."""

            name: str = inner.name
            description: str = inner.description

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                return wrapper_ref._authorized_run(*args, **kwargs)

        # Copy over any extra attributes the original tool might have
        for attr in ("args_schema", "return_direct", "verbose"):
            if hasattr(inner, attr):
                with contextlib.suppress(AttributeError, TypeError):
                    setattr(_ProtectedCrewTool, attr, getattr(inner, attr))

        self._wrapped_tool = _ProtectedCrewTool()

    @property
    def tool(self) -> Any:
        """Return the wrapped CrewAI tool."""
        return self._wrapped_tool

    @property
    def inner_tool(self) -> Any:
        """Return the original unwrapped tool."""
        return self._inner_tool

    @property
    def tool_name(self) -> str:
        """Return the tool name registered with the gate."""
        return self._tool_name

    def _authorized_run(self, *args: Any, **kwargs: Any) -> Any:
        """Run the tool through the authorization gate."""
        user_id = kwargs.pop("_agentlock_user_id", self._default_user_id)
        role = kwargs.pop("_agentlock_role", self._default_role)

        auth = self._gate.authorize(
            self._tool_name,
            user_id=user_id,
            role=role,
            parameters=kwargs or None,
        )
        auth.raise_if_denied()
        assert auth.token is not None

        def _exec(**params: Any) -> Any:
            return self._inner_tool._run(*args, **params)

        return self._gate.execute(
            self._tool_name,
            _exec,
            token=auth.token,
            parameters=kwargs or None,
        )


def protect_crew_tools(
    crew: Any,
    gate: AuthorizationGate,
    permissions_map: dict[str, AgentLockPermissions | dict[str, Any]],
    *,
    default_user_id: str = "",
    default_role: str = "",
    default_permissions: AgentLockPermissions | dict[str, Any] | None = None,
) -> None:
    """Wrap all tools across all agents in a CrewAI ``Crew`` with AgentLock.

    Tools are matched by name against ``permissions_map``.  Tools not found
    in the map use ``default_permissions`` if provided, otherwise they are
    left unwrapped (and will be denied by the gate if called, since they
    have no registered permissions).

    This mutates the crew's agents in place.

    Args:
        crew: A CrewAI ``Crew`` instance.
        gate: Shared authorization gate.
        permissions_map: Mapping of tool names to permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
        default_permissions: Permissions for tools not in the map.
    """
    crew_class = _import_crewai_crew()
    if not isinstance(crew, crew_class):
        raise TypeError(
            f"Expected a CrewAI Crew instance, got {type(crew).__name__}"
        )

    agents = getattr(crew, "agents", [])
    for agent in agents:
        original_tools = getattr(agent, "tools", [])
        protected_tools: list[Any] = []

        for tool in original_tools:
            tool_name = getattr(tool, "name", type(tool).__name__)

            if tool_name in permissions_map:
                perms = permissions_map[tool_name]
            elif default_permissions is not None:
                perms = default_permissions
            else:
                # Leave unwrapped
                protected_tools.append(tool)
                continue

            wrapper = AgentLockCrewTool(
                tool,
                gate,
                perms,
                default_user_id=default_user_id,
                default_role=default_role,
            )
            protected_tools.append(wrapper.tool)

        agent.tools = protected_tools
