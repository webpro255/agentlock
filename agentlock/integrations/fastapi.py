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
#
# 1.10.2 as first written left one door in that rule.  A token was verified
# when the request presented one in the recognized form, and ANY other request
# fell through to the identity headers: an absent Authorization header, a
# scheme spelled some other way, a scheme that was not bearer at all.  So the
# check ran only on clients that chose to submit to it.  A configured key now
# means the verified token is the ONLY identity, and a request that presents
# nothing to verify is refused rather than identified some other way.

#: Used when the caller configured a key but named no algorithms.
_DEFAULT_JWT_ALGORITHMS = ("HS256",)


class _JwtIdentityError(Exception):
    """A configured key could not take an identity from this request.

    Carries no claims by construction: there is nothing trustworthy in a token
    that failed verification, including the reason it names for itself, and
    there is nothing at all in a request that presented none.
    """

    #: The denial reason the 401 body reports.
    reason = "jwt_invalid"


class _JwtInvalidError(_JwtIdentityError):
    """A bearer token was presented under a configured key and did not verify."""

    reason = "jwt_invalid"


class _JwtRequiredError(_JwtIdentityError):
    """No bearer credential was presented under a configured key.

    An absent ``Authorization`` header, or one carrying some other scheme, is
    not "nothing to check" but "no identity at all".  With a key configured the
    verified token is the only identity this integration accepts, and the
    identity headers are never consulted to make up the difference.
    """

    reason = "jwt_required"


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
) -> dict[str, Any]:
    """Verify a bearer token and return its claims.

    Called only when a key is configured, and it either returns verified claims
    or raises.  There is no third answer, because a third answer is what the
    identity headers used to be reached through.

    Raises :class:`_JwtRequiredError` when the request carries no bearer
    credential: an absent ``Authorization`` header, an empty one, or one whose
    scheme is something else.  Through 1.10.2 this returned ``None`` and the
    caller read the identity headers instead, so the verification a deployment
    had switched on applied only to clients that chose to present a token.

    Raises :class:`_JwtInvalidError` when a bearer credential IS present and
    does not verify: bad signature, disallowed or unsecured algorithm, expired,
    malformed, or empty.  The caller must refuse the request rather than fall
    back to the identity headers, because falling back on a bad token hands a
    forger the identity the token was there to gate.

    The scheme is matched case insensitively, as RFC 7235 defines it: a
    lowercase ``bearer`` IS a bearer credential.  Matching it exactly, as this
    did through 1.10.2, did not reject such a request; it failed to see the
    token, so a forged one reached the identity headers and a genuine one was
    thrown away for its spelling.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.casefold() != "bearer":
        raise _JwtRequiredError(
            "no bearer token was presented"
            if not authorization.strip()
            else f"the Authorization scheme is {scheme!r}, not Bearer"
        )
    token = token.strip()
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


def _jwt_denial(reason: str, detail: str) -> dict[str, Any]:
    """The 401 body for a request a configured key could not identify."""
    if reason == "jwt_required":
        explanation = (
            f"This integration is configured to verify bearer tokens, so a "
            f"verified token is the only identity it accepts: {detail}. The "
            f"{HEADER_USER_ID} and {HEADER_ROLE} headers are not consulted "
            f"while jwt_key is configured."
        )
        suggestion = (
            "Send an Authorization header of the form 'Bearer <token>' "
            "carrying a token signed with the configured key. The scheme is "
            "matched case insensitively."
        )
    else:
        explanation = (
            f"The bearer token did not verify against the configured "
            f"jwt_key: {detail}. The identity headers are not consulted "
            f"as a fallback for a token that failed verification."
        )
        suggestion = (
            "Present a token signed with the configured key and a "
            "permitted algorithm."
        )
    return {
        "error": "agentlock_denied",
        "detail": {
            "status": "denied",
            "reason": reason,
            "detail": explanation,
            "suggestion": suggestion,
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

    * **``jwt_key`` set.** The verified bearer token is the ONLY identity and
      the ``X-AgentLock-User-Id`` / ``X-AgentLock-Role`` headers are never
      consulted.  A token is verified with expiry enforced and ``"none"``
      refused as an algorithm however ``jwt_algorithms`` is written; the
      scheme is matched case insensitively, so ``bearer`` and ``Bearer`` are
      the same credential.  A token that verifies is authoritative: its
      ``sub`` and ``role`` claims are the identity, so a caller cannot present
      a token and then override the identity inside it.  A token that does NOT
      verify is **401** with reason ``jwt_invalid``.  A request that presents
      no bearer credential at all, whether the ``Authorization`` header is
      absent or carries some other scheme, is **401** with reason
      ``jwt_required``.
    * **``jwt_key`` unset, the default.** A bearer token is ignored for
      identity ENTIRELY, and the identity headers apply exactly as they did
      before 1.10.0.

    Through 1.10.1 there was no third state: the token's payload was base64
    decoded WITHOUT any signature check and 1.10.0 made those claims
    authoritative over the headers, so any party that could set one request
    header could authenticate as anyone.  That is closed in 1.10.2, and the
    change is not additive for a deployment that was relying on unverified
    claims being read.

    1.10.2 as first written closed it only for clients that presented a token.
    Verification ran on a recognized ``Bearer`` value and every other request
    fell through to the identity headers, so omitting the header, or spelling
    the scheme differently, reached the header path under a configured key.
    That is why the ``jwt_required`` refusal exists: with a key configured
    there is no request shape that the headers decide.

    The identity headers are TRUSTED-UPSTREAM inputs, and they are the identity
    input only in the unset state.  They carry no proof of anything, and a
    deployment that exposes this middleware directly to untrusted clients has
    to strip client-supplied ``X-AgentLock-*`` at its edge, or configure
    ``jwt_key`` and authenticate by token instead.

    If a request does not map to a tool, it passes through unmodified.

    Args:
        app: The ASGI application.
        gate: Authorization gate.
        tool_name_from_path: Optional callback ``(method, path) -> tool_name``
            to derive the tool name from the request path.
        exclude_paths: Paths to skip (e.g., ``["/health", "/docs"]``).
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity.  Setting it
            also means the identity headers stop being read.
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

        # Extract identity.  With a key configured the verified bearer token
        # is the only identity: it either verifies, or the request is refused.
        # The headers are not reached from this branch at all, including when
        # a verified token carries no subject, because a window in which they
        # are read is a window a caller can aim for.  With no key configured
        # there is nothing to verify against, so the token is not read for
        # identity at all and the headers are the input.
        if self.jwt_key is not None:
            try:
                claims = _verify_jwt_claims(
                    request.headers.get("authorization", ""),
                    self.jwt_key,
                    self.jwt_algorithms,
                )
            except _JwtIdentityError as exc:
                response = json_response_cls(
                    status_code=401,
                    content=_jwt_denial(exc.reason, str(exc)),
                )
                await response(scope, receive, send)
                return
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
        use_jwt: Whether the ``Authorization`` header is read at all.  It
            cannot be ``False`` while ``jwt_key`` is set: the two say verify
            tokens with this key and do not read tokens, and the only way to
            honor both is to identify a request by header under a configured
            key, which is what this integration no longer does.
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity and the
            identity headers apply.  Setting it also means the identity
            headers stop being read.
        jwt_algorithms: Permitted signing algorithms.  Defaults to
            ``["HS256"]``.  ``"none"`` is dropped if listed.

    Identity follows the same rule as :class:`AgentLockMiddleware`, and for
    the same reason.  With ``jwt_key`` set, the verified bearer token is the
    only identity: the scheme is matched case insensitively, a token that
    fails verification is **401** with reason ``jwt_invalid``, a request
    carrying no bearer credential is **401** with reason ``jwt_required``, and
    the identity headers are never consulted.  With no key configured the
    token is ignored for identity entirely and the headers apply.  Through
    1.10.1 this dependency read unverified claims and preferred them over the
    headers, and through 1.10.2 it read the headers whenever a request
    presented nothing it recognized as a token.

    Returns:
        A FastAPI dependency callable.

    Raises:
        ValueError: if ``jwt_key`` is set and ``use_jwt`` is ``False``.
        IntegrationUnsupportedError: if ``jwt_key`` is set and python-jose is
            not installed.  Raised when the dependency is built, not when a
            request arrives.
    """
    if jwt_key is not None and not use_jwt:
        raise ValueError(
            "require_agentlock was given a jwt_key and use_jwt=False. A "
            "configured key means the verified bearer token is the only "
            "identity, so a dependency that does not read the token has no "
            "identity to authorize and would fall back to the "
            f"{user_id_header} / {role_header} headers, which is what a "
            "configured key exists to prevent. Drop use_jwt=False to verify "
            "tokens, or drop jwt_key to identify by header."
        )
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

        # As in the middleware: with a key configured the verified bearer
        # token is the only identity, and the headers are not reached from
        # this branch.  ``use_jwt`` cannot be False here, because a key and
        # use_jwt=False are refused when the dependency is built.
        if jwt_key is not None:
            try:
                claims = _verify_jwt_claims(
                    request.headers.get("authorization", ""),
                    jwt_key,
                    jwt_algorithms,
                )
            except _JwtIdentityError as exc:
                raise fastapi_mod.HTTPException(
                    status_code=401,
                    detail=_jwt_denial(exc.reason, str(exc)),
                ) from exc
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
