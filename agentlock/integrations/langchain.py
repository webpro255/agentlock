"""LangChain integration for AgentLock.

Wraps LangChain ``BaseTool`` instances with AgentLock authorization so that
every tool invocation passes through the gate before execution.

Example::

    from langchain_core.tools import StructuredTool
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.langchain import wrap_tool

    gate = AuthorizationGate()
    perms = AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["user", "admin"],
    )

    my_tool = StructuredTool.from_function(func=my_func, name="my_tool")
    protected = wrap_tool(my_tool, gate, perms)

Requires: ``langchain-core`` (``pip install langchain-core``)
"""

from __future__ import annotations

from typing import Any

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions


def _import_langchain() -> Any:
    """Lazily import LangChain and return the ``langchain_core.tools`` module."""
    try:
        import langchain_core.tools as lc_tools
        return lc_tools
    except ImportError as exc:
        raise ImportError(
            "LangChain is required for this integration. "
            "Install it with: pip install langchain-core"
        ) from exc


def _import_callback_manager() -> Any:
    """Lazily import the LangChain callback manager module."""
    try:
        import langchain_core.callbacks.manager as cb_manager
        return cb_manager
    except ImportError:
        return None


class AgentLockToolWrapper:
    """Wraps a LangChain ``BaseTool`` with AgentLock authorization.

    The wrapper inherits from ``BaseTool`` (resolved at instantiation time)
    and delegates ``_run`` / ``_arun`` through the authorization gate before
    calling the original tool.

    Authorization context (``user_id``, ``role``) is extracted from:
    1. Explicit keys in the ``tool_input`` dict (``_agentlock_user_id``,
       ``_agentlock_role``).
    2. The ``run_manager`` metadata dict (``agentlock_user_id``,
       ``agentlock_role``).
    3. The ``metadata`` set on the wrapper instance as defaults.

    Args:
        tool: The LangChain ``BaseTool`` to protect.
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
        lc_tools = _import_langchain()
        if not isinstance(tool, lc_tools.BaseTool):
            raise TypeError(
                f"Expected a LangChain BaseTool instance, got {type(tool).__name__}"
            )

        self._inner_tool = tool
        self._gate = gate
        self._default_user_id = default_user_id
        self._default_role = default_role

        if isinstance(permissions, dict):
            permissions = AgentLockPermissions(**permissions)
        self._permissions = permissions

        self._gate.register_tool(self._inner_tool.name, self._permissions)

        # Dynamically build a subclass of BaseTool that delegates to us.
        wrapper_ref = self
        inner = self._inner_tool

        _base = lc_tools.BaseTool

        class _WrappedTool(_base):  # type: ignore[misc,valid-type]
            name: str = inner.name
            description: str = inner.description

            @property
            def args_schema(self) -> Any:
                return inner.args_schema

            def _run(
                self,
                *args: Any,
                run_manager: Any = None,
                **kwargs: Any,
            ) -> Any:
                return wrapper_ref._authorized_run(
                    *args, run_manager=run_manager, **kwargs
                )

            async def _arun(
                self,
                *args: Any,
                run_manager: Any = None,
                **kwargs: Any,
            ) -> Any:
                return await wrapper_ref._authorized_arun(
                    *args, run_manager=run_manager, **kwargs
                )

        self._wrapped_tool = _WrappedTool()

    # -- Public access to the LangChain tool object -------------------------

    @property
    def tool(self) -> Any:
        """Return the wrapped LangChain ``BaseTool``."""
        return self._wrapped_tool

    @property
    def inner_tool(self) -> Any:
        """Return the original unwrapped tool."""
        return self._inner_tool

    # -- Context extraction -------------------------------------------------

    def _extract_context(
        self,
        run_manager: Any,
        kwargs: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        """Extract user_id, role, and clean kwargs from multiple sources."""
        user_id = kwargs.pop("_agentlock_user_id", "")
        role = kwargs.pop("_agentlock_role", "")

        # Try run_manager metadata
        if run_manager is not None and not user_id:
            metadata = getattr(run_manager, "metadata", {}) or {}
            user_id = user_id or metadata.get("agentlock_user_id", "")
            role = role or metadata.get("agentlock_role", "")

        # Fall back to defaults
        user_id = user_id or self._default_user_id
        role = role or self._default_role

        return user_id, role, kwargs

    # -- Authorized execution -----------------------------------------------

    def _authorized_run(
        self,
        *args: Any,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Synchronous authorized execution."""
        user_id, role, clean_kwargs = self._extract_context(run_manager, kwargs)
        tool_name = self._inner_tool.name

        auth = self._gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
            parameters=clean_kwargs or None,
        )
        auth.raise_if_denied()
        assert auth.token is not None

        def _exec(**params: Any) -> Any:
            return self._inner_tool._run(*args, **params)

        return self._gate.execute(
            tool_name,
            _exec,
            token=auth.token,
            parameters=clean_kwargs or None,
        )

    async def _authorized_arun(
        self,
        *args: Any,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Asynchronous authorized execution."""
        user_id, role, clean_kwargs = self._extract_context(run_manager, kwargs)
        tool_name = self._inner_tool.name

        auth = self._gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
            parameters=clean_kwargs or None,
        )
        auth.raise_if_denied()
        assert auth.token is not None

        # Consume the token manually so we can call the async inner tool
        self._gate.token_store.validate_and_consume(
            auth.token.token_id, tool_name, clean_kwargs or None
        )

        result = await self._inner_tool._arun(*args, **clean_kwargs)

        # Apply redaction if configured
        redaction = self._gate.redact_output(tool_name, str(result))
        if redaction.was_redacted:
            return redaction.redacted

        return result


class AgentLockToolkit:
    """Wraps multiple LangChain tools with AgentLock authorization.

    Args:
        tools: List of LangChain ``BaseTool`` instances.
        gate: Shared ``AuthorizationGate``.
        permissions: A single ``AgentLockPermissions`` applied to all tools,
            or a dict mapping tool names to individual permissions.
        default_user_id: Fallback user identity for all tools.
        default_role: Fallback role for all tools.
    """

    def __init__(
        self,
        tools: list[Any],
        gate: AuthorizationGate,
        permissions: AgentLockPermissions | dict[str, Any],
        *,
        default_user_id: str = "",
        default_role: str = "",
    ) -> None:
        self._wrappers: list[AgentLockToolWrapper] = []

        # If permissions is a dict with tool-name keys mapping to permission
        # objects, use per-tool permissions.  Otherwise treat as a single
        # AgentLockPermissions (or raw dict for one).
        is_per_tool = (
            isinstance(permissions, dict)
            and all(isinstance(v, (dict, AgentLockPermissions)) for v in permissions.values())
            and all(isinstance(k, str) for k in permissions)
            and any(hasattr(t, "name") and t.name in permissions for t in tools)
        )

        for tool in tools:
            if is_per_tool:
                tool_perms = permissions.get(tool.name, permissions)  # type: ignore[union-attr]
            else:
                tool_perms = permissions

            wrapper = AgentLockToolWrapper(
                tool,
                gate,
                tool_perms,
                default_user_id=default_user_id,
                default_role=default_role,
            )
            self._wrappers.append(wrapper)

    def get_tools(self) -> list[Any]:
        """Return the list of wrapped LangChain tools."""
        return [w.tool for w in self._wrappers]

    def __iter__(self) -> Any:
        return iter(self.get_tools())

    def __len__(self) -> int:
        return len(self._wrappers)


def wrap_tool(
    tool: Any,
    gate: AuthorizationGate,
    permissions: AgentLockPermissions | dict[str, Any],
    *,
    default_user_id: str = "",
    default_role: str = "",
) -> Any:
    """Convenience function to wrap a single LangChain tool.

    Returns the wrapped ``BaseTool`` instance (not the wrapper object).

    Args:
        tool: A LangChain ``BaseTool``.
        gate: Authorization gate.
        permissions: AgentLock permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.

    Returns:
        A new ``BaseTool`` that enforces AgentLock authorization.
    """
    wrapper = AgentLockToolWrapper(
        tool,
        gate,
        permissions,
        default_user_id=default_user_id,
        default_role=default_role,
    )
    return wrapper.tool
