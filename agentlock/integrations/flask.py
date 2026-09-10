"""Flask integration for AgentLock.

Provides a route decorator and a Flask extension for enforcing AgentLock
authorization on Flask endpoints that expose agent tools.

Example::

    from flask import Flask
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.flask import AgentLockFlask, agentlock_required

    gate = AuthorizationGate()
    gate.register_tool("send_email", AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ))

    app = Flask(__name__)
    ext = AgentLockFlask(app, gate)

    @app.route("/tools/send_email", methods=["POST"])
    @agentlock_required(gate, "send_email")
    def send_email():
        # flask.g.agentlock_auth contains the AuthResult
        ...

Requires: ``flask`` (``pip install flask``)
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from agentlock.exceptions import IntegrationUnsupportedError
from agentlock.gate import AuthorizationGate

F = TypeVar("F", bound=Callable[..., Any])


def _import_flask() -> Any:
    """Lazily import Flask."""
    try:
        import flask
        return flask
    except ImportError as exc:
        raise ImportError(
            "Flask is required for this integration. "
            "Install it with: pip install flask"
        ) from exc


# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

HEADER_USER_ID = "X-AgentLock-User-Id"
HEADER_ROLE = "X-AgentLock-Role"
HEADER_TOOL = "X-AgentLock-Tool"
HEADER_SESSION_ID = "X-AgentLock-Session-Id"


# ---------------------------------------------------------------------------
# Identity extraction
# ---------------------------------------------------------------------------

# Through 1.10.1 this section held ``_decode_jwt_claims``, which base64
# decoded a bearer token's payload and returned it as identity WITHOUT
# checking a signature, and ``_extract_identity`` preferred those claims over
# the identity headers.  A token anyone could type therefore outranked a
# header a deployment could strip at its edge.  The helper is gone rather
# than deprecated: a function whose only behavior is to return unverified
# claims has no correct caller.  Verification is now opt in, and a bearer
# token carries no identity at all unless a key was configured to check it
# against.
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
            "pip install 'agentlock[flask]' (or pip install "
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


def _jwt_denial_response(reason: str, detail: str) -> Any:
    """The 401 response for a request a configured key could not identify."""
    flask_mod = _import_flask()
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
    return flask_mod.jsonify({
        "error": "agentlock_denied",
        "detail": {
            "status": "denied",
            "reason": reason,
            "detail": explanation,
            "suggestion": suggestion,
        },
        "audit_id": "",
    }), 401


def _extract_identity(
    user_id_header: str = HEADER_USER_ID,
    role_header: str = HEADER_ROLE,
    jwt_key: str | bytes | None = None,
    jwt_algorithms: Sequence[str] | None = None,
) -> tuple[str, str]:
    """Extract user_id and role from the current Flask request headers.

    Matching the FastAPI middleware, and for the same reason.  With
    ``jwt_key`` configured the VERIFIED bearer token is the only identity: its
    ``sub`` and ``role`` claims are the identity, the scheme is matched case
    insensitively, and the identity headers are never consulted, so a caller
    can neither override the identity inside a token nor step around the token
    by presenting something this does not read as one.  That includes the case
    of a verified token carrying no subject, which yields an empty user id and
    a gate denial rather than a header read.  With no ``jwt_key`` configured
    the token is not read for identity at all and the headers apply, as they
    did before 1.10.0.

    The identity headers are TRUSTED-UPSTREAM inputs, and they are the identity
    input only in the unset state.  They carry no proof of anything, and a
    deployment exposed directly to untrusted clients has to strip
    client-supplied ``X-AgentLock-*`` at its edge, or configure ``jwt_key`` and
    authenticate by token instead.

    Raises:
        _JwtInvalidError: if a bearer token is present under a configured key
            and does not verify.  The caller turns this into a 401.
        _JwtRequiredError: if no bearer credential is present under a
            configured key.  The caller turns this into a 401 as well.

    Returns:
        Tuple of (user_id, role).
    """
    flask_mod = _import_flask()
    request = flask_mod.request

    if jwt_key is not None:
        claims = _verify_jwt_claims(
            request.headers.get("Authorization", ""), jwt_key, jwt_algorithms,
        )
        return claims.get("sub", ""), claims.get("role", "")

    return (
        request.headers.get(user_id_header, ""),
        request.headers.get(role_header, ""),
    )


# ---------------------------------------------------------------------------
# Route decorator
# ---------------------------------------------------------------------------

def agentlock_required(
    gate: AuthorizationGate,
    tool_name: str,
    *,
    user_id_header: str = HEADER_USER_ID,
    role_header: str = HEADER_ROLE,
    jwt_key: str | bytes | None = None,
    jwt_algorithms: list[str] | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces AgentLock authorization on a Flask route.

    On success, the ``AuthResult`` is stored in ``flask.g.agentlock_auth``
    and the wrapped view function is called normally.

    On denial, a 403 JSON response is returned immediately.

    Args:
        gate: Authorization gate.
        tool_name: The tool name to authorize.
        user_id_header: Request header containing the user identity.
        role_header: Request header containing the user role.
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity and the
            identity headers apply.  Setting it also means the identity
            headers stop being read.
        jwt_algorithms: Permitted signing algorithms.  Defaults to
            ``["HS256"]``.  ``"none"`` is dropped if listed.

    Identity follows :func:`_extract_identity`.  With ``jwt_key`` set, the
    verified bearer token is the only identity: the scheme is matched case
    insensitively, a token that fails verification is **401** with reason
    ``jwt_invalid``, a request carrying no bearer credential is **401** with
    reason ``jwt_required``, and the identity headers are never consulted.
    With no key configured the token is ignored for identity entirely.

    Raises:
        IntegrationUnsupportedError: if ``jwt_key`` is set and python-jose is
            not installed.  Raised when the decorator is built, not when a
            request arrives.

    Returns:
        Decorator for Flask view functions.

    Example::

        @app.route("/tools/send_email", methods=["POST"])
        @agentlock_required(gate, "send_email")
        def send_email():
            auth = flask.g.agentlock_auth
            # auth.token is available
            return {"status": "sent"}
    """

    if jwt_key is not None:
        _import_jose()  # Fail here, not at the first request.

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            flask_mod = _import_flask()

            try:
                user_id, role = _extract_identity(
                    user_id_header, role_header, jwt_key, jwt_algorithms,
                )
            except _JwtIdentityError as exc:
                return _jwt_denial_response(exc.reason, str(exc))

            auth = gate.authorize(
                tool_name,
                user_id=user_id,
                role=role,
            )

            if not auth.allowed:
                return flask_mod.jsonify({
                    "error": "agentlock_denied",
                    "detail": auth.denial or {},
                    "audit_id": auth.audit_id,
                }), 403

            # Store auth result for use in the view
            flask_mod.g.agentlock_auth = auth
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Flask extension
# ---------------------------------------------------------------------------

class AgentLockFlask:
    """Flask extension that integrates AgentLock with a Flask application.

    The extension installs a ``before_request`` hook that enforces
    authorization on configured paths.  It also stores the gate on the app for
    access from request handlers.

    Tool selection (E5), matching the FastAPI middleware.  The SERVER's
    endpoint mapping wins:

    1. When ``tool_name_from_endpoint`` is configured, whatever it returns is
       the tool.  A request carrying an ``X-AgentLock-Tool`` header naming a
       DIFFERENT tool is refused with 403 and reason
       ``tool_selection_conflict``.  An endpoint the mapping declines (returns
       ``None`` for) passes through with the header ignored.
    2. Only when no mapping is configured is ``X-AgentLock-Tool`` honored,
       which trusts the caller to name its own tool.

    The hook is installed either way, because case 2 has to be reachable for
    the header to mean anything.  A request that names no tool and matches no
    mapping passes through untouched, which is every request that reached this
    extension unmapped through 1.9.1.

    Args:
        app: A Flask application (or ``None`` for deferred init via
            ``init_app``).
        gate: Authorization gate.
        tool_name_from_endpoint: Optional callback that maps
            ``(endpoint_name, method, path) -> tool_name``.  Return
            ``None`` to skip authorization for that request.
        exclude_paths: Paths to skip (e.g., ``["/health"]``).
        user_id_header: Header name for user identity.
        role_header: Header name for user role.
        jwt_key: Key or secret bearer tokens are verified against.  ``None``,
            the default, means bearer tokens carry no identity.  Setting it
            also means the identity headers stop being read.
        jwt_algorithms: Permitted signing algorithms.  Defaults to
            ``["HS256"]``.  ``"none"`` is dropped if listed.

    Identity, matching the FastAPI middleware.  With ``jwt_key`` set, the
    VERIFIED bearer token is the only identity and the identity headers are
    never consulted: the scheme is matched case insensitively, a token that
    fails verification is **401** with reason ``jwt_invalid``, and a request
    carrying no bearer credential is **401** with reason ``jwt_required``.
    With no key configured a bearer token is ignored for identity entirely,
    the identity headers applying as they did before 1.10.0.  Through 1.10.1
    the token's payload was read without any signature check and preferred
    over the headers, so any party that could set one request header could
    authenticate as anyone.  Through 1.10.2 a request that presented nothing
    the adapter recognized as a token was identified by header even under a
    configured key, so the verification applied only to clients that chose to
    present a token.

    Raises:
        IntegrationUnsupportedError: if ``jwt_key`` is set and python-jose is
            not installed.  Raised at construction, not at the first request.
    """

    def __init__(
        self,
        app: Any = None,
        gate: AuthorizationGate | None = None,
        *,
        tool_name_from_endpoint: Callable[[str, str, str], str | None] | None = None,
        exclude_paths: Sequence[str] | None = None,
        user_id_header: str = HEADER_USER_ID,
        role_header: str = HEADER_ROLE,
        jwt_key: str | bytes | None = None,
        jwt_algorithms: list[str] | None = None,
    ) -> None:
        self.gate = gate
        self.tool_name_from_endpoint = tool_name_from_endpoint
        self.exclude_paths = set(exclude_paths or [])
        self.user_id_header = user_id_header
        self.role_header = role_header
        self.jwt_key = jwt_key
        self.jwt_algorithms = jwt_algorithms
        if jwt_key is not None:
            _import_jose()  # Fail here, not at the first request.

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Initialize the extension with a Flask app.

        This registers a ``before_request`` hook and stores the gate in
        ``app.extensions``.

        Args:
            app: Flask application instance.
        """
        _import_flask()

        if self.gate is None:
            raise ValueError(
                "AgentLockFlask requires a gate. "
                "Pass it to the constructor or set self.gate before init_app."
            )

        app.extensions = getattr(app, "extensions", {})
        app.extensions["agentlock"] = self

        app.before_request(self._before_request_hook)

    def _before_request_hook(self) -> Any:
        """Flask before_request hook that enforces AgentLock authorization."""
        flask_mod = _import_flask()
        request = flask_mod.request

        if request.path in self.exclude_paths:
            return None

        header_tool = request.headers.get(HEADER_TOOL, "")

        if self.tool_name_from_endpoint is not None:
            endpoint = request.endpoint or ""
            tool_name = self.tool_name_from_endpoint(
                endpoint, request.method, request.path
            )
            if tool_name and header_tool and header_tool != tool_name:
                return flask_mod.jsonify({
                    "error": "agentlock_denied",
                    "detail": {
                        "status": "denied",
                        "reason": "tool_selection_conflict",
                        "detail": (
                            f"This route is mapped to tool {tool_name!r}; the "
                            f"request asked to be authorized as "
                            f"{header_tool!r}. The route mapping decides "
                            f"which permission block applies."
                        ),
                        "suggestion": (
                            f"Remove the {HEADER_TOOL} header, or send it "
                            f"with the value {tool_name!r}."
                        ),
                    },
                    "audit_id": "",
                }), 403
        else:
            tool_name = header_tool or None

        if not tool_name:
            return None

        try:
            user_id, role = _extract_identity(
                self.user_id_header, self.role_header,
                self.jwt_key, self.jwt_algorithms,
            )
        except _JwtIdentityError as exc:
            return _jwt_denial_response(exc.reason, str(exc))

        assert self.gate is not None
        auth = self.gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )

        if not auth.allowed:
            return flask_mod.jsonify({
                "error": "agentlock_denied",
                "detail": auth.denial or {},
                "audit_id": auth.audit_id,
            }), 403

        flask_mod.g.agentlock_auth = auth
        return None
