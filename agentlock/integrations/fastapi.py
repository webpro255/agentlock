"""FastAPI integration for AgentLock.

Provides ASGI middleware and FastAPI dependency injection for AgentLock
authorization on HTTP endpoints that expose agent tools.

Example::

    from fastapi import FastAPI, Depends
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.fastapi import AgentLockMiddleware, require_agentlock

    gate = AuthorizationGate()
    gate.register_tool("send_email", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ))

    app = FastAPI()
    app.add_middleware(AgentLockMiddleware, gate=gate)

    @app.post("/tools/send_email")
    async def send_email(
        auth=Depends(require_agentlock(gate, "send_email")),
    ):
        # auth.token is available for execution
        ...

Requires: ``fastapi`` and ``starlette`` (``pip install fastapi``)
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from agentlock.gate import AuthorizationGate, AuthResult


def _import_fastapi() -> Any:
    """Lazily import FastAPI."""
    try:
        import fastapi
        return fastapi
    except ImportError as exc:
        raise ImportError(
            "FastAPI is required for this integration. "
            "Install it with: pip install fastapi"
        ) from exc


def _import_starlette() -> tuple[Any, Any, Any]:
    """Lazily import Starlette types needed for ASGI middleware."""
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        return BaseHTTPMiddleware, Request, JSONResponse
    except ImportError as exc:
        raise ImportError(
            "Starlette is required for this integration. "
            "Install it with: pip install fastapi (includes starlette)"
        ) from exc


# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

HEADER_USER_ID = "X-AgentLock-User-Id"
HEADER_ROLE = "X-AgentLock-Role"
HEADER_TOOL = "X-AgentLock-Tool"
HEADER_SESSION_ID = "X-AgentLock-Session-Id"


# ---------------------------------------------------------------------------
# JWT helper
# ---------------------------------------------------------------------------

def _extract_jwt_claims(authorization: str) -> dict[str, Any]:
    """Best-effort JWT claim extraction without verification.

    Full verification should be performed by upstream middleware or an
    auth provider.  This helper decodes the payload for extracting
    ``sub`` (user_id) and ``role`` claims.

    Returns an empty dict if decoding fails.
    """
    if not authorization.startswith("Bearer "):
        return {}
    token = authorization[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        import base64

        # Pad the base64 segment
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        result: dict[str, Any] = json.loads(payload_bytes)
        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

class AgentLockMiddleware:
    """ASGI middleware that enforces AgentLock authorization on requests.

    The middleware extracts tool name, user_id, and role from request
    headers (or JWT ``Authorization`` header) and calls ``gate.authorize()``.
    If authorization fails, a 403 JSON response is returned before the
    endpoint handler runs.

    The tool name is determined from:
    1. The ``X-AgentLock-Tool`` header, if present.
    2. The ``tool_name_from_path`` callback, if provided.
    3. Skipped (the request passes through without authorization).

    If a request does not map to a tool, it passes through unmodified.

    Args:
        app: The ASGI application.
        gate: Authorization gate.
        tool_name_from_path: Optional callback ``(method, path) -> tool_name``
            to derive the tool name from the request path.
        exclude_paths: Paths to skip (e.g., ``["/health", "/docs"]``).
    """

    def __init__(
        self,
        app: Any,
        gate: AuthorizationGate,
        tool_name_from_path: Callable[[str, str], str | None] | None = None,
        exclude_paths: Sequence[str] | None = None,
    ) -> None:
        _import_starlette()  # Validate availability
        self.app = app
        self.gate = gate
        self.tool_name_from_path = tool_name_from_path
        self.exclude_paths = set(exclude_paths or [])

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """ASGI interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        _, request_cls, json_response_cls = _import_starlette()

        request = request_cls(scope, receive)
        path = request.url.path

        # Skip excluded paths
        if path in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        # Resolve tool name
        tool_name = request.headers.get(HEADER_TOOL.lower()) or request.headers.get(HEADER_TOOL)
        if not tool_name and self.tool_name_from_path:
            tool_name = self.tool_name_from_path(request.method, path)

        if not tool_name:
            # No tool identified -- pass through
            await self.app(scope, receive, send)
            return

        # Extract identity
        user_id = (
            request.headers.get(HEADER_USER_ID.lower())
            or request.headers.get(HEADER_USER_ID)
            or ""
        )
        role = (
            request.headers.get(HEADER_ROLE.lower())
            or request.headers.get(HEADER_ROLE)
            or ""
        )

        # Fall back to JWT claims
        if not user_id:
            auth_header = request.headers.get("authorization", "")
            claims = _extract_jwt_claims(auth_header)
            user_id = user_id or claims.get("sub", "")
            role = role or claims.get("role", "")

        # Authorize
        auth = self.gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )

        if not auth.allowed:
            response = json_response_cls(
                status_code=403,
                content={
                    "error": "agentlock_denied",
                    "detail": auth.denial or {},
                    "audit_id": auth.audit_id,
                },
            )
            await response(scope, receive, send)
            return

        # Store auth result in request state for downstream access
        scope.setdefault("state", {})
        scope["state"]["agentlock_auth"] = auth
        scope["state"]["agentlock_user_id"] = user_id
        scope["state"]["agentlock_role"] = role

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------------

def require_agentlock(
    gate: AuthorizationGate,
    tool_name: str,
    *,
    user_id_header: str = HEADER_USER_ID,
    role_header: str = HEADER_ROLE,
    use_jwt: bool = True,
) -> Callable[..., Any]:
    """Create a FastAPI ``Depends()`` dependency that enforces AgentLock.

    Usage::

        @app.post("/tools/send_email")
        async def send_email(
            auth: AuthResult = Depends(require_agentlock(gate, "send_email")),
        ):
            # auth.token is the valid execution token
            ...

    The dependency extracts user_id and role from request headers or JWT
    and calls ``gate.authorize()``.  Raises ``HTTPException(403)`` on denial.

    Args:
        gate: Authorization gate.
        tool_name: The tool to authorize.
        user_id_header: Header name for user identity.
        role_header: Header name for user role.
        use_jwt: Whether to fall back to JWT ``Authorization`` header.

    Returns:
        A FastAPI dependency callable.
    """

    async def dependency(**kwargs: Any) -> AuthResult:
        fastapi_mod = _import_fastapi()

        # FastAPI injects Request automatically when it's a parameter
        request: Any = kwargs.get("request")
        if request is None:
            # Try to get from FastAPI's dependency injection
            raise fastapi_mod.HTTPException(
                status_code=500,
                detail="AgentLock dependency requires a Request object.",
            )

        user_id = (
            request.headers.get(user_id_header.lower())
            or request.headers.get(user_id_header)
            or ""
        )
        role = (
            request.headers.get(role_header.lower())
            or request.headers.get(role_header)
            or ""
        )

        if not user_id and use_jwt:
            auth_header = request.headers.get("authorization", "")
            claims = _extract_jwt_claims(auth_header)
            user_id = user_id or claims.get("sub", "")
            role = role or claims.get("role", "")

        auth = gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )

        if not auth.allowed:
            raise fastapi_mod.HTTPException(
                status_code=403,
                detail={
                    "error": "agentlock_denied",
                    "detail": auth.denial or {},
                    "audit_id": auth.audit_id,
                },
            )

        return auth

    # FastAPI needs the dependency to accept Request as a parameter
    # We create a proper signature for FastAPI's DI system
    _import_fastapi()

    async def _agentlock_dep(request: Any = None) -> AuthResult:
        """AgentLock authorization dependency."""
        return await dependency(request=request)

    # Annotate properly for FastAPI

    try:
        from starlette.requests import Request as StarletteRequest
        _agentlock_dep.__annotations__ = {"request": StarletteRequest, "return": AuthResult}
    except ImportError:
        pass

    return _agentlock_dep
