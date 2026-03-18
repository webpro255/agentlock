"""AutoGen integration for AgentLock.

Wraps AutoGen function maps with AgentLock authorization so that every
function call is gated through the authorization layer.

AutoGen agents use ``function_map`` dicts that map function names to
callables.  This integration replaces each callable with a guarded
version that calls ``gate.authorize()`` before executing.

Example::

    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.autogen import protect_functions

    gate = AuthorizationGate()
    perms = {"send_email": AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    )}

    function_map = {"send_email": send_email_func}
    protected = protect_functions(function_map, gate, perms,
                                  default_user_id="alice", default_role="admin")

Requires: ``pyautogen`` (``pip install pyautogen``)
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions


def _check_autogen_available() -> None:
    """Verify that AutoGen is importable."""
    try:
        import autogen  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "AutoGen is required for this integration. "
            "Install it with: pip install pyautogen"
        ) from exc


class AgentLockFunctionMap:
    """Wraps an AutoGen-style function map with AgentLock authorization.

    Each function in the map is replaced with a guarded version that calls
    ``gate.authorize()`` + ``gate.execute()`` before running the original.

    Authorization context is passed via special keyword arguments
    ``_agentlock_user_id`` and ``_agentlock_role``, or falls back to the
    defaults provided at construction time.

    Args:
        function_map: Dict mapping function names to callables.
        gate: An ``AuthorizationGate`` instance.
        permissions_map: Dict mapping function names to permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
        default_permissions: Permissions for functions not in the map.
    """

    def __init__(
        self,
        function_map: dict[str, Callable[..., Any]],
        gate: AuthorizationGate,
        permissions_map: dict[str, AgentLockPermissions | dict[str, Any]],
        *,
        default_user_id: str = "",
        default_role: str = "",
        default_permissions: AgentLockPermissions | dict[str, Any] | None = None,
    ) -> None:
        _check_autogen_available()

        self._gate = gate
        self._default_user_id = default_user_id
        self._default_role = default_role
        self._original_map = dict(function_map)
        self._protected_map: dict[str, Callable[..., Any]] = {}

        for func_name, func in function_map.items():
            if func_name in permissions_map:
                perms = permissions_map[func_name]
            elif default_permissions is not None:
                perms = default_permissions
            else:
                # No permissions -- leave the function as-is.
                # The gate will deny calls to unregistered tools.
                self._protected_map[func_name] = func
                continue

            if isinstance(perms, dict):
                perms = AgentLockPermissions(**perms)

            gate.register_tool(func_name, perms)
            self._protected_map[func_name] = self._wrap_function(
                func_name, func
            )

    def _wrap_function(
        self, func_name: str, func: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Create an authorization-guarded wrapper for a single function."""
        gate = self._gate
        default_user = self._default_user_id
        default_role = self._default_role

        @functools.wraps(func)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            user_id = kwargs.pop("_agentlock_user_id", default_user)
            role = kwargs.pop("_agentlock_role", default_role)

            auth = gate.authorize(
                func_name,
                user_id=user_id,
                role=role,
                parameters=kwargs or None,
            )
            auth.raise_if_denied()
            assert auth.token is not None

            def _exec(**params: Any) -> Any:
                return func(*args, **params)

            return gate.execute(
                func_name,
                _exec,
                token=auth.token,
                parameters=kwargs or None,
            )

        return guarded

    @property
    def map(self) -> dict[str, Callable[..., Any]]:
        """Return the protected function map for use with AutoGen agents."""
        return dict(self._protected_map)

    @property
    def original_map(self) -> dict[str, Callable[..., Any]]:
        """Return the original unprotected function map."""
        return dict(self._original_map)

    def __getitem__(self, key: str) -> Callable[..., Any]:
        return self._protected_map[key]

    def __contains__(self, key: str) -> bool:
        return key in self._protected_map

    def __iter__(self) -> Any:
        return iter(self._protected_map)

    def __len__(self) -> int:
        return len(self._protected_map)

    def items(self) -> Any:
        """Dict-like items() access."""
        return self._protected_map.items()

    def keys(self) -> Any:
        """Dict-like keys() access."""
        return self._protected_map.keys()

    def values(self) -> Any:
        """Dict-like values() access."""
        return self._protected_map.values()


def protect_functions(
    function_map: dict[str, Callable[..., Any]],
    gate: AuthorizationGate,
    permissions_map: dict[str, AgentLockPermissions | dict[str, Any]],
    *,
    default_user_id: str = "",
    default_role: str = "",
    default_permissions: AgentLockPermissions | dict[str, Any] | None = None,
) -> dict[str, Callable[..., Any]]:
    """Convenience function: wrap an AutoGen function map and return a plain dict.

    This returns a standard ``dict[str, Callable]`` suitable for passing
    directly to AutoGen's ``ConversableAgent(function_map=...)``.

    Args:
        function_map: Original function map.
        gate: Authorization gate.
        permissions_map: Per-function permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
        default_permissions: Permissions for functions not in the map.

    Returns:
        A new dict with guarded callables.
    """
    wrapper = AgentLockFunctionMap(
        function_map,
        gate,
        permissions_map,
        default_user_id=default_user_id,
        default_role=default_role,
        default_permissions=default_permissions,
    )
    return wrapper.map
