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

from collections.abc import Callable, Sequence
from typing import Any

from agentlock.exceptions import IntegrationUnsupportedError
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
# JWT verification
# ---------------------------------------------------------------------------
#
# Through 1.10.1 this section held ``_extract_jwt_claims``, which base64
# decoded a bearer token's payload and returned it as identity WITHOUT
# checking a signature.  1.10.0 then made those claims authoritative over the
# identity headers, so a token anyone could type outranked a header a
# deployment could strip at its edge: presenting ``{"sub": "alice"}`` with
# ``"alg": "none"`` and arbitrary signature bytes was authenticating as alice.
# The helper is gone rather than deprecated, because a function whose only
# behavior is to return unverified claims has no correct caller.
#
# Verification is now opt in, and a bearer token carries no identity at all
# unless the deployment configured a key to check it against.

#: Used when the caller configured a key but named no algorithms.
_DEFAULT_JWT_ALGORITHMS = ("HS256",)


class _JwtInvalidError(Exception):
    """A bearer token was presented under a configured key and did not verify.

    Carries no claims by construction: there is nothing trustworthy in a token
    that failed verification, including the reason it names for itself.
    """


def _import_jose() -> Any:
    """Lazily import python-jose, the verification backend.

    Raises ``IntegrationUnsupportedError`` rather than ``ImportError`` so that
    an adapter configured to verify and unable to verify fails at
    CONSTRUCTION.  An adapter that discovers at its first request that it
    cannot check a signature is an adapter that fails open under load.
    """
    try:
        from jose import jwt as jose_jwt
        return jose_jwt
    except ImportError as exc:
        raise IntegrationUnsupportedError(
            "jwt_key was configured but python-jose is not installed, so this "
            "integration cannot verify bearer tokens. Install it with: "
            "pip install 'agentlock[fastapi]' (or pip install "
            "'python-jose[cryptography]'), or leave jwt_key unset, in which "
            "case bearer tokens are ignored for identity entirely."
        ) from exc


def _permitted_algorithms(jwt_algorithms: Sequence[str] | None) -> list[str]:
    """The algorithms a token may be signed with.

    ``"none"`` is dropped whatever the caller passed, in any casing.  The
    unsecured JWS algorithm means "this token is not signed", so accepting it
    under a configured key would restore precisely the bypass this section
    exists to close, by request rather than by oversight.  A list that names
    nothing else falls back to the default rather than to jose's, so the
    outcome of asking for ``["none"]`` is HS256 and never no check at all.
    """
    named = [
        algorithm
        for algorithm in (jwt_algorithms or ())
        if algorithm.strip().casefold() != "none"
    ]
    return named or list(_DEFAULT_JWT_ALGORITHMS)


def _verify_jwt_claims(
    authorization: str,
    jwt_key: str | bytes,
    jwt_algorithms: Sequence[str] | None,
) -> dict[str, Any] | None:
    """Verify a bearer token and return its claims.

    Returns ``None`` when the request carries no bearer token, which is not a
    failure: a deployment may authorize some routes by token and others by
    trusted-upstream header.

    Raises :class:`_JwtInvalidError` when a bearer token IS present and does not
    verify: bad signature, disallowed or unsecured algorithm, expired, or
    malformed.  The caller must refuse the request rather than fall back to
    the identity headers, because falling back on a bad token hands a forger
    the identity the token was there to gate.
    """
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    if not token:
        raise _JwtInvalidError("empty bearer token")

    jose_jwt = _import_jose()
    try:
        claims: dict[str, Any] = jose_jwt.decode(
            token,
            jwt_key,
            algorithms=_permitted_algorithms(jwt_algorithms),
            # Expiry is enforced.  Audience is not, because this integration
            # configures none: a token that carries ``aud`` would otherwise be
            # rejected for naming an audience nobody asked about.
            options={"verify_exp": True, "verify_aud": False},
        )
    except Exception as exc:  # jose raises several unrelated types
        raise _JwtInvalidError(str(exc)) from exc
    return claims


def _jwt_denial(detail: str) -> dict[str, Any]:
    """The 401 body for a bearer token that did not verify."""
    return {
        "error": "agentlock_denied",
        "detail": {
            "status": "denied",
            "reason": "jwt_invalid",
            "detail": (
                f"The bearer token did not verify against the configured "
                f"jwt_key: {detail}. The identity headers are not consulted "
                f"as a fallback for a token that failed verification."
            ),
            "suggestion": (
                "Present a token signed with the configured key and a "
                "permitted algorithm, or send no bearer token at all."
            ),
        },
        "audit_id": "",
    }


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

class AgentLockMiddleware:
    """ASGI middleware that enforces AgentLock authorization on requests.

    The middleware extracts tool name, user_id, and role from request
    headers (or JWT ``Authorization`` header) and calls ``gate.authorize()``.
    If authorization fails, a 403 JSON response is returned before the
    endpoint handler runs.

    Tool selection (E5).  The SERVER's route mapping wins:

    1. When ``tool_name_from_path`` is configured, whatever it returns is the
       tool.  A request carrying an ``X-AgentLock-Tool`` header naming a
       DIFFERENT tool is refused with 403 and reason
       ``tool_selection_conflict``, because a caller that can pick which
       permission block its request is judged against has no permission block.
       A path the mapping declines (returns ``None`` for) passes through with
       the header ignored.
    2. Only when no mapping is configured is ``X-AgentLock-Tool`` honored.
       That trusts the caller to name its own tool, which is appropriate for a
       gateway in front of tools it does not route itself, and for nothing
       else.

    Through 1.9.1 the order was the reverse of this, so a caller reaching an
    admin route could name a low-risk tool in the header and be judged against
    that tool's block while the admin handler ran.

    Identity.  Verification is opt in, and what a bearer token means depends
    entirely on whether this middleware was given a key to check it against:

    * **``jwt_key`` set.** A bearer token is VERIFIED, with expiry enforced
      and ``"none"`` refused as an algorithm however ``jwt_algorithms`` is
      written.  A token that verifies is authoritative: its ``sub`` and
      ``role`` claims are the identity and the ``X-AgentLock-User-Id`` /
      ``X-AgentLock-Role`` headers are ignored, so a caller cannot present a
      token and then override the identity inside it.  A token that does NOT
      verify is **401** with reason ``jwt_invalid``, and the identity headers
      are not consulted as a fallback, because falling back on a bad token
      hands a forger the identity the token existed to gate.
    * **``jwt_key`` unset, the default.** A bearer token is ignored for
      identity ENTIRELY, and the identity headers apply exactly as they did
      before 1.10.0.

    Through 1.10.1 there was no third state: the token's payload was base64
    decoded WITHOUT any signature check and 1.10.0 made those claims
    authoritative over the headers, so any party that could set one request
    header could authenticate as anyone.  That is closed in 1.10.2, and the
    change is not additive for a deployment that was relying on unverified
    claims being read.

    The identity headers are TRUSTED-UPSTREAM inputs in either state.  They
    carry no proof of anything, and a deployment that exposes this middleware
    directly to untrusted clients has to strip client-supplied
    ``X-AgentLock-*`` at its edge, or configure ``jwt_key`` and authenticate
    by token instead.

    If a request does not map to a tool, it passes through unmodified.

    Args:
        app: The ASGI application.
        gate: Authorization gate.
        tool_name_from_path: Optional callback ``(method, path) -> tool_name``
            to derive the tool name from the request path.
        exclude_paths: Paths to skip (e.g., ``["/health", "/docs"]``).
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity.
        jwt_algorithms: Permitted signing algorithms.  Defaults to
            ``["HS256"]``.  ``"none"`` is dropped if listed.

    Raises:
        IntegrationUnsupportedError: if ``jwt_key`` is set and python-jose is
            not installed.  Raised at construction, not at the first request.
    """

    def __init__(
        self,
        app: Any,
        gate: AuthorizationGate,
        tool_name_from_path: Callable[[str, str], str | None] | None = None,
        exclude_paths: Sequence[str] | None = None,
        jwt_key: str | bytes | None = None,
        jwt_algorithms: list[str] | None = None,
    ) -> None:
        _import_starlette()  # Validate availability
        self.app = app
        self.gate = gate
        self.tool_name_from_path = tool_name_from_path
        self.exclude_paths = set(exclude_paths or [])
        self.jwt_key = jwt_key
        self.jwt_algorithms = jwt_algorithms
        if jwt_key is not None:
            _import_jose()  # Fail here, not at the first request.

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

        # Resolve tool name (E5): the route mapping is authoritative.
        header_tool = (
            request.headers.get(HEADER_TOOL.lower())
            or request.headers.get(HEADER_TOOL)
            or ""
        )
        if self.tool_name_from_path is not None:
            tool_name = self.tool_name_from_path(request.method, path)
            if tool_name and header_tool and header_tool != tool_name:
                response = json_response_cls(
                    status_code=403,
                    content={
                        "error": "agentlock_denied",
                        "detail": {
                            "status": "denied",
                            "reason": "tool_selection_conflict",
                            "detail": (
                                f"This route is mapped to tool "
                                f"{tool_name!r}; the request asked to be "
                                f"authorized as {header_tool!r}. The route "
                                f"mapping decides which permission block "
                                f"applies."
                            ),
                            "suggestion": (
                                f"Remove the {HEADER_TOOL} header, or send it "
                                f"with the value {tool_name!r}."
                            ),
                        },
                        "audit_id": "",
                    },
                )
                await response(scope, receive, send)
                return
        else:
            tool_name = header_tool

        if not tool_name:
            # No tool identified -- pass through
            await self.app(scope, receive, send)
            return

        # Extract identity.  A VERIFIED bearer token is authoritative and the
        # identity headers are then ignored entirely rather than merged with
        # it.  With no key configured there is nothing to verify against, so
        # the token is not read for identity at all.
        claims: dict[str, Any] | None = None
        if self.jwt_key is not None:
            try:
                claims = _verify_jwt_claims(
                    request.headers.get("authorization", ""),
                    self.jwt_key,
                    self.jwt_algorithms,
                )
            except _JwtInvalidError as exc:
                response = json_response_cls(
                    status_code=401, content=_jwt_denial(str(exc)),
                )
                await response(scope, receive, send)
                return

        if claims is not None and claims.get("sub"):
            user_id = claims.get("sub", "")
            role = claims.get("role", "")
        else:
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
    jwt_key: str | bytes | None = None,
    jwt_algorithms: list[str] | None = None,
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
        use_jwt: Whether the ``Authorization`` header is read at all.  Only
            consulted when ``jwt_key`` is set; with no key there is no token
            identity to suppress.
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity and the
            identity headers apply.
        jwt_algorithms: Permitted signing algorithms.  Defaults to
            ``["HS256"]``.  ``"none"`` is dropped if listed.

    Identity follows the same rule as :class:`AgentLockMiddleware`, and for
    the same reason: a bearer token is authoritative only once it has been
    VERIFIED against a configured key, a token that fails verification is
    **401** with reason ``jwt_invalid`` and does NOT fall back to the identity
    headers, and with no key configured the token is ignored for identity
    entirely.  The identity headers are trusted-upstream inputs in either
    state.  Through 1.10.1 this dependency read unverified claims and
    preferred them over the headers.

    Returns:
        A FastAPI dependency callable.

    Raises:
        IntegrationUnsupportedError: if ``jwt_key`` is set and python-jose is
            not installed.  Raised when the dependency is built, not when a
            request arrives.
    """
    if jwt_key is not None:
        _import_jose()  # Fail here, not at the first request.

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

        # As in the middleware: a VERIFIED bearer token is authoritative and
        # the identity headers are ignored.  Unverified, it is not identity.
        claims: dict[str, Any] | None = None
        if use_jwt and jwt_key is not None:
            try:
                claims = _verify_jwt_claims(
                    request.headers.get("authorization", ""),
                    jwt_key,
                    jwt_algorithms,
                )
            except _JwtInvalidError as exc:
                raise fastapi_mod.HTTPException(
                    status_code=401, detail=_jwt_denial(str(exc)),
                ) from exc

        if claims is not None and claims.get("sub"):
            user_id = claims.get("sub", "")
            role = claims.get("role", "")
        else:
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
