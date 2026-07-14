"""Decorators for one-line tool protection.

Example::

    from agentlock import agentlock, AuthorizationGate

    gate = AuthorizationGate()

    @agentlock(
        gate,
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
        rate_limit={"max_calls": 5, "window_seconds": 3600},
    )
    def send_email(to: str, subject: str, body: str) -> str:
        # ... send the email ...
        return "sent"

    # Calling the decorated function requires authorization context
    result = send_email(to="bob@co.com", subject="Hi", body="Hello",
                        _user_id="alice", _role="admin")
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import Callable
from typing import Any, TypeVar

from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions

F = TypeVar("F", bound=Callable[..., Any])

_RESERVED_KWARGS = {"_user_id", "_role", "_session_id", "_metadata"}


def agentlock(
    gate: AuthorizationGate,
    *,
    name: str | None = None,
    risk_level: str = "high",
    requires_auth: bool = True,
    allowed_roles: list[str] | None = None,
    rate_limit: dict[str, int] | None = None,
    data_policy: dict[str, Any] | None = None,
    human_approval: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
    audit: dict[str, Any] | None = None,
    session: dict[str, Any] | None = None,
    permissions: AgentLockPermissions | dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Decorator that wraps a function with AgentLock authorization.

    All AgentLock permission fields can be passed as keyword arguments.
    Alternatively, pass a pre-built ``permissions`` object.

    The decorated function accepts special ``_user_id``, ``_role``,
    ``_session_id``, and ``_metadata`` keyword arguments for auth context.
    These are stripped before calling the underlying function.

    Args:
        gate: The AuthorizationGate instance.
        name: Tool name override.  Defaults to function name.
        risk_level: Risk classification.
        requires_auth: Whether authentication is required.
        allowed_roles: Roles permitted to invoke.
        rate_limit: Rate limiting config dict.
        data_policy: Data policy config dict.
        human_approval: Human approval config dict.
        scope: Scope config dict.
        audit: Audit config dict.
        session: Session config dict.
        permissions: Pre-built permissions object (overrides other fields).

    Returns:
        Decorator that protects the function.
    """

    def decorator(func: F) -> F:
        tool_name = name or func.__name__

        # Build permissions
        if permissions is not None:
            if isinstance(permissions, dict):
                perms = AgentLockPermissions(**permissions)
            else:
                perms = permissions
        else:
            perms_dict: dict[str, Any] = {
                "risk_level": risk_level,
                "requires_auth": requires_auth,
            }
            if allowed_roles is not None:
                perms_dict["allowed_roles"] = allowed_roles
            if rate_limit is not None:
                perms_dict["rate_limit"] = rate_limit
            if data_policy is not None:
                perms_dict["data_policy"] = data_policy
            if human_approval is not None:
                perms_dict["human_approval"] = human_approval
            if scope is not None:
                perms_dict["scope"] = scope
            if audit is not None:
                perms_dict["audit"] = audit
            if session is not None:
                perms_dict["session"] = session
            perms = AgentLockPermissions(**perms_dict)

        # Register with gate
        gate.register_tool(tool_name, perms)

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                user_id = kwargs.pop("_user_id", "")
                role = kwargs.pop("_role", "")
                kwargs.pop("_session_id", "")
                meta = kwargs.pop("_metadata", None)

                # Authorize through the gate
                auth_result = gate.authorize(
                    tool_name,
                    user_id=user_id,
                    role=role,
                    parameters=kwargs,
                    metadata=meta,
                )
                auth_result.raise_if_denied()
                assert auth_result.token is not None

                # Execute: await the async function directly, then run
                # through the gate's redaction/audit via execute()
                # We wrap in a sync callable for gate.execute() compatibility
                #
                # E7: this wrapper owns execution (it awaits the coroutine
                # itself), so the gate sees the grant and never the act unless
                # we report it.  The attempt goes out BEFORE the await, so a
                # coroutine that never returns still leaves its trace, and the
                # outcome goes out after.  Neither call can raise.
                attempt = gate.begin_execution(
                    tool_name,
                    token_id=auth_result.token.token_id,
                    parameters=kwargs,
                )
                started = time.time()
                try:
                    captured_result = await func(*args, **kwargs)
                except BaseException as exc:
                    gate.confirm_execution(
                        tool_name,
                        status="failed",
                        token_id=auth_result.token.token_id,
                        parameters=kwargs,
                        duration_ms=(time.time() - started) * 1000,
                        error_type=type(exc).__name__,
                        attempt_audit_id=(attempt.audit_id if attempt else ""),
                    )
                    raise
                gate.confirm_execution(
                    tool_name,
                    status="succeeded",
                    token_id=auth_result.token.token_id,
                    parameters=kwargs,
                    duration_ms=(time.time() - started) * 1000,
                    attempt_audit_id=(attempt.audit_id if attempt else ""),
                )

                # Apply redaction if configured
                redacted = gate.redact_output(tool_name, captured_result) \
                    if isinstance(captured_result, str) else None
                if redacted and redacted.was_redacted:
                    # Consume token and return redacted output
                    gate.token_store.validate_and_consume(
                        auth_result.token.token_id, tool_name, kwargs,
                    )
                    return redacted.redacted

                # Consume token for audit trail
                gate.token_store.validate_and_consume(
                    auth_result.token.token_id, tool_name, kwargs,
                )
                return captured_result

            async_wrapper._agentlock_tool_name = tool_name  # type: ignore[attr-defined]
            async_wrapper._agentlock_permissions = perms  # type: ignore[attr-defined]
            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                user_id = kwargs.pop("_user_id", "")
                role = kwargs.pop("_role", "")
                kwargs.pop("_session_id", "")
                meta = kwargs.pop("_metadata", None)

                return gate.call(
                    tool_name,
                    lambda **p: func(*args, **p),
                    user_id=user_id,
                    role=role,
                    parameters=kwargs,
                    metadata=meta,
                )

            sync_wrapper._agentlock_tool_name = tool_name  # type: ignore[attr-defined]
            sync_wrapper._agentlock_permissions = perms  # type: ignore[attr-defined]
            return sync_wrapper  # type: ignore[return-value]

    return decorator
