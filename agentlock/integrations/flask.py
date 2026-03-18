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
import json
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

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
HEADER_SESSION_ID = "X-AgentLock-Session-Id"


# ---------------------------------------------------------------------------
# Identity extraction
# ---------------------------------------------------------------------------

def _extract_identity(
    user_id_header: str = HEADER_USER_ID,
    role_header: str = HEADER_ROLE,
) -> tuple[str, str]:
    """Extract user_id and role from the current Flask request headers.

    Returns:
        Tuple of (user_id, role).
    """
    flask_mod = _import_flask()
    request = flask_mod.request

    user_id = request.headers.get(user_id_header, "")
    role = request.headers.get(role_header, "")

    # Fall back to JWT Authorization header (best-effort decode)
    if not user_id:
        auth_header = request.headers.get("Authorization", "")
        claims = _decode_jwt_claims(auth_header)
        user_id = user_id or claims.get("sub", "")
        role = role or claims.get("role", "")

    return user_id, role


def _decode_jwt_claims(authorization: str) -> dict[str, Any]:
    """Best-effort JWT payload decode without signature verification.

    Full verification should be handled by upstream middleware.
    Returns an empty dict on failure.
    """
    if not authorization.startswith("Bearer "):
        return {}
    token = authorization[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        import base64

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
# Route decorator
# ---------------------------------------------------------------------------

def agentlock_required(
    gate: AuthorizationGate,
    tool_name: str,
    *,
    user_id_header: str = HEADER_USER_ID,
    role_header: str = HEADER_ROLE,
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

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            flask_mod = _import_flask()

            user_id, role = _extract_identity(user_id_header, role_header)

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

    The extension optionally installs a ``before_request`` hook that
    enforces authorization on configured paths.  It also stores the gate
    on the app for access from request handlers.

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
    ) -> None:
        self.gate = gate
        self.tool_name_from_endpoint = tool_name_from_endpoint
        self.exclude_paths = set(exclude_paths or [])
        self.user_id_header = user_id_header
        self.role_header = role_header

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

        if self.tool_name_from_endpoint is not None:
            app.before_request(self._before_request_hook)

    def _before_request_hook(self) -> Any:
        """Flask before_request hook that enforces AgentLock authorization."""
        flask_mod = _import_flask()
        request = flask_mod.request

        if request.path in self.exclude_paths:
            return None

        endpoint = request.endpoint or ""
        tool_name = None
        if self.tool_name_from_endpoint:
            tool_name = self.tool_name_from_endpoint(
                endpoint, request.method, request.path
            )

        if not tool_name:
            return None

        user_id, role = _extract_identity(self.user_id_header, self.role_header)

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
