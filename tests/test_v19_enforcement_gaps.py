"""v1.9 enforcement completeness: the three gaps, reproduced as tests.

An external review of the published 1.8.0 wheel found three places where the
engine does not enforce what its own documentation says it enforces. This file
reproduces all three before any fix exists. Every reproduction was marked
``xfail(strict=True)`` at freeze time and measured failing at `d56122d`. The
markers came off as each gap closed; the tests are unchanged otherwise, and are
now the regression guard for the three fixes.

G1. Argument binding. ``agentlock/decorators.py`` and
``agentlock/integrations/autogen.py`` build the gate's ``parameters`` dict out
of ``kwargs`` alone. A positional argument and a function default never reach
the gate, so with ``recipient_parameter="to"`` declared, ``send(to="x")`` is
denied while ``send("x")`` and a bare ``send()`` carrying a hostile default both
execute. X1, X2, X3.

G2. Token binding. ``agentlock/token.py`` issues ``parameters_hash=""`` when the
authorized call carried no parameters, and compares the hash only when both
sides are truthy. A token authorized with no parameters therefore executes with
any parameters at all. X4.

G3. MCP fail open. ``agentlock/integrations/mcp.py`` looks for ``call_tool`` on
the server and returns silently when it is absent. Under mcp 2.x, which the
``mcp`` extra resolves to, ``Server`` has no ``call_tool``: the wrapper installs
nothing and every handler runs ungated. X5 measures that against the real SDK,
X6 measures the 1.x path against the real SDK, X7 measures the fail closed rule.

X8 covers the binding module's own fail closed rule: a callable whose signature
cannot be read cannot be gated, so the wrapper must refuse to be built. X9 was
added at build time and carried no xfail: it covers the mcp 2.x constructor
route, recorded as defect D2 in
``docs/PREDICTIONS_v19_enforcement.md`` before any code was written.

Guards: X5, X6 and X7 need the real MCP SDK and are guarded by
``importorskip("mcp")``, the idiom ``tests/test_v15_integration_confirmation.py``
already uses. X5 and X6 additionally select on the installed major version,
because they measure two different SDK shapes. X3 monkeypatches
``_check_autogen_available`` to a no op so the AutoGen wrapper's own argument
binding can be measured without ``pyautogen`` installed; nothing else about the
wrapper is stubbed, and the gate under it is real.
"""

from __future__ import annotations

import asyncio
import importlib.metadata

import pytest

from agentlock.exceptions import DeniedError
from agentlock.gate import AuthorizationGate
from agentlock.schema import AgentLockPermissions, ScopeConfig
from agentlock.types import RecipientPolicy, RiskLevel

KNOWN = ["bob@company.com"]
CONTACT = "bob@company.com"
HOSTILE = "attacker@evil.com"


def _perms(policy: RecipientPolicy = RecipientPolicy.KNOWN_CONTACTS_ONLY):
    """A block whose only restriction is the recipient, with a declared key."""
    return AgentLockPermissions(
        version="1.5",
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
        scope=ScopeConfig(
            allowed_recipients=policy,
            recipient_parameter="to",
        ),
    )


def _gate() -> AuthorizationGate:
    """A gate with one session for alice, holding one known contact."""
    gate = AuthorizationGate()
    gate.create_session(user_id="alice", role="user", known_contacts=list(KNOWN))
    return gate


def _mcp_major() -> int:
    """Major version of the installed MCP SDK, or 0 when it is absent."""
    try:
        return int(importlib.metadata.version("mcp").split(".")[0])
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# G1: argument binding
# ---------------------------------------------------------------------------


def test_x1_sync_decorator_gates_positional_and_default_arguments():
    """G1 through the sync ``@agentlock`` wrapper.

    Three calls carry the same hostile recipient by three routes: positional,
    function default, keyword. All three must deny, and the body must not run.
    """
    from agentlock.decorators import agentlock as agentlock_decorator

    calls = {"n": 0}
    gate = _gate()

    @agentlock_decorator(gate, name="send_email", permissions=_perms())
    def send_email(to: str = HOSTILE, body: str = "") -> str:
        calls["n"] += 1
        return "sent"

    auth = {"_user_id": "alice", "_role": "user"}

    with pytest.raises(DeniedError) as exc:
        send_email(HOSTILE, **auth)
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        send_email(**auth)
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        send_email(to=HOSTILE, **auth)
    assert exc.value.reason == "recipient_not_allowed"

    assert calls["n"] == 0

    # Control: the same wrapper, the same routes, a recipient the policy admits.
    assert send_email(CONTACT, **auth) == "sent"
    assert send_email(to=CONTACT, **auth) == "sent"
    assert calls["n"] == 2


def test_x2_async_decorator_gates_positional_and_default_arguments():
    """G1 through the async ``@agentlock`` wrapper. Same three routes."""
    from agentlock.decorators import agentlock as agentlock_decorator

    calls = {"n": 0}
    gate = _gate()

    @agentlock_decorator(gate, name="send_email", permissions=_perms())
    async def send_email(to: str = HOSTILE, body: str = "") -> str:
        calls["n"] += 1
        return "sent"

    auth = {"_user_id": "alice", "_role": "user"}

    with pytest.raises(DeniedError) as exc:
        asyncio.run(send_email(HOSTILE, **auth))
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        asyncio.run(send_email(**auth))
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        asyncio.run(send_email(to=HOSTILE, **auth))
    assert exc.value.reason == "recipient_not_allowed"

    assert calls["n"] == 0

    assert asyncio.run(send_email(CONTACT, **auth)) == "sent"
    assert asyncio.run(send_email(to=CONTACT, **auth)) == "sent"
    assert calls["n"] == 2


def test_x3_autogen_guarded_gates_positional_and_default_arguments(monkeypatch):
    """G1 through ``protect_functions``.

    ``_check_autogen_available`` is monkeypatched to a no op so this runs
    without ``pyautogen`` installed. The import check is the only thing
    replaced: the wrapper, the gate and the permission block are all real.
    """
    from agentlock.integrations import autogen as al_autogen

    monkeypatch.setattr(al_autogen, "_check_autogen_available", lambda: None)

    calls = {"n": 0}
    gate = _gate()

    def send_email(to: str = HOSTILE, body: str = "") -> str:
        calls["n"] += 1
        return "sent"

    protected = al_autogen.protect_functions(
        {"send_email": send_email}, gate, {"send_email": _perms()}
    )
    guarded = protected["send_email"]
    auth = {"_agentlock_user_id": "alice", "_agentlock_role": "user"}

    with pytest.raises(DeniedError) as exc:
        guarded(HOSTILE, **auth)
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        guarded(**auth)
    assert exc.value.reason == "recipient_not_allowed"

    with pytest.raises(DeniedError) as exc:
        guarded(to=HOSTILE, **auth)
    assert exc.value.reason == "recipient_not_allowed"

    assert calls["n"] == 0

    assert guarded(CONTACT, **auth) == "sent"
    assert guarded(to=CONTACT, **auth) == "sent"
    assert calls["n"] == 2


# ---------------------------------------------------------------------------
# G2: token binding
# ---------------------------------------------------------------------------


def test_x4_token_authorized_with_no_parameters_is_bound_to_the_empty_call():
    """G2. A token issued for a call carrying nothing must not execute a call
    carrying something. The two positive cases fix the rule in both directions:
    matching parameters still execute, and the empty call still executes."""
    from agentlock.exceptions import TokenInvalidError

    gate = _gate()
    gate.register_tool("send_email", _perms(RecipientPolicy.ANY))

    def _run(**params):
        return "sent"

    # Authorized with an empty dict, executed with parameters.
    auth = gate.authorize(
        "send_email", user_id="alice", role="user", parameters={}
    )
    assert auth.allowed
    with pytest.raises(TokenInvalidError):
        gate.execute(
            "send_email", _run, token=auth.token, parameters={"to": HOSTILE}
        )

    # Authorized with None, executed with parameters.
    auth = gate.authorize(
        "send_email", user_id="alice", role="user", parameters=None
    )
    assert auth.allowed
    with pytest.raises(TokenInvalidError):
        gate.execute(
            "send_email", _run, token=auth.token, parameters={"to": HOSTILE}
        )

    # Authorized and executed with the same parameters: allowed.
    auth = gate.authorize(
        "send_email", user_id="alice", role="user", parameters={"to": CONTACT}
    )
    assert auth.allowed
    assert (
        gate.execute(
            "send_email", _run, token=auth.token, parameters={"to": CONTACT}
        )
        == "sent"
    )

    # Authorized and executed with the empty call: allowed.
    auth = gate.authorize(
        "send_email", user_id="alice", role="user", parameters={}
    )
    assert auth.allowed
    assert gate.execute("send_email", _run, token=auth.token, parameters={}) == "sent"


# ---------------------------------------------------------------------------
# G3: MCP
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_mcp_major() != 2, reason="needs the mcp 2.x SDK")
def test_x5_mcp_2x_handler_is_gated():
    """G3 against the real mcp 2.x SDK.

    Under 2.x a handler is registered with
    ``add_request_handler(method, params_type, handler)`` and is invoked as
    ``handler(ctx, params)``. The wrapper must gate the registration for
    ``tools/call``. Invoked directly off the registry, the guard is the
    outermost layer, so a denial propagates as ``DeniedError``; the 1.x path
    puts the SDK's own decorator outside the guard, which converts the same
    exception into an error result. X6 asserts that shape.
    """
    pytest.importorskip("mcp")
    import mcp.types as types
    from mcp.server import Server

    from agentlock.integrations.mcp import AgentLockMCPServer

    seen: list[dict] = []

    async def handler(ctx, params):
        seen.append(dict(params.arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="sent")]
        )

    gate = _gate()
    server = Server("v19-probe")
    AgentLockMCPServer(server, gate, {"send_email": _perms()})
    server.add_request_handler("tools/call", types.CallToolRequestParams, handler)

    entry = server.get_request_handler("tools/call")
    assert entry is not None

    def _call(to):
        params = types.CallToolRequestParams(
            name="send_email",
            arguments={
                "to": to,
                "body": "x",
                "_agentlock_user_id": "alice",
                "_agentlock_role": "user",
            },
        )
        return asyncio.run(entry.handler(None, params))

    with pytest.raises(DeniedError) as exc:
        _call(HOSTILE)
    assert exc.value.reason == "recipient_not_allowed"
    assert seen == []

    result = _call(CONTACT)
    assert isinstance(result, types.CallToolResult)
    assert len(seen) == 1
    assert "_agentlock_user_id" not in seen[0]
    assert "_agentlock_role" not in seen[0]
    assert seen[0]["to"] == CONTACT


@pytest.mark.skipif(_mcp_major() != 1, reason="needs the mcp 1.x SDK")
def test_x6_mcp_1x_handler_is_gated():
    """The 1.x path, measured through the real SDK rather than a fixture.

    This carries no xfail: the freeze run recorded it passing at 1.8.0, so it
    is a regression guard for the path v1.9 must not break while adding 2.x
    support. The SDK's own ``call_tool`` decorator wraps the guarded handler
    and converts any exception into an error result, so the denial arrives as
    ``isError`` carrying the reason rather than as a raised exception.
    """
    pytest.importorskip("mcp")
    import mcp.types as types
    from mcp.server import Server

    from agentlock.integrations.mcp import AgentLockMCPServer

    seen: list[dict] = []

    gate = _gate()
    server = Server("v19-probe")
    AgentLockMCPServer(server, gate, {"send_email": _perms()})

    @server.call_tool()
    async def handler(name: str, arguments: dict):
        seen.append(dict(arguments))
        return [types.TextContent(type="text", text="sent")]

    registered = server.request_handlers[types.CallToolRequest]

    def _call(to):
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(
                name="send_email",
                arguments={
                    "to": to,
                    "body": "x",
                    "_agentlock_user_id": "alice",
                    "_agentlock_role": "user",
                },
            ),
        )
        return asyncio.run(registered(req))

    denied = _call(HOSTILE)
    assert denied.root.isError is True
    assert "recipient_not_allowed" in denied.root.content[0].text
    assert seen == []

    allowed = _call(CONTACT)
    assert allowed.root.isError is False
    assert len(seen) == 1
    assert "_agentlock_user_id" not in seen[0]
    assert "_agentlock_role" not in seen[0]
    assert seen[0]["to"] == CONTACT


@pytest.mark.skipif(_mcp_major() != 2, reason="needs the mcp 2.x SDK")
def test_x9_mcp_2x_constructor_registered_handler_is_gated():
    """D2, recorded in the freeze document before the build.

    mcp 2.x also accepts a ``tools/call`` handler on the ``Server``
    constructor, which writes the handler registry directly and never reaches
    ``add_request_handler``. Wrapping only the registration function would
    leave that route ungated, which is G3's shape on a different path. The
    hook wraps what is already registered as well.
    """
    pytest.importorskip("mcp")
    import mcp.types as types
    from mcp.server import Server

    from agentlock.integrations.mcp import AgentLockMCPServer

    seen: list[dict] = []

    async def on_call_tool(ctx, params):
        seen.append(dict(params.arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="sent")]
        )

    gate = _gate()
    server = Server("v19-probe", on_call_tool=on_call_tool)

    # Registered before the wrapper exists, and not through the function the
    # wrapper patches.
    assert server.get_request_handler("tools/call") is not None

    AgentLockMCPServer(server, gate, {"send_email": _perms()})
    entry = server.get_request_handler("tools/call")
    assert entry is not None

    def _call(to):
        params = types.CallToolRequestParams(
            name="send_email",
            arguments={
                "to": to,
                "body": "x",
                "_agentlock_user_id": "alice",
                "_agentlock_role": "user",
            },
        )
        return asyncio.run(entry.handler(None, params))

    with pytest.raises(DeniedError) as exc:
        _call(HOSTILE)
    assert exc.value.reason == "recipient_not_allowed"
    assert seen == []

    result = _call(CONTACT)
    assert isinstance(result, types.CallToolResult)
    assert len(seen) == 1
    assert "_agentlock_user_id" not in seen[0]
    assert seen[0]["to"] == CONTACT


def test_x7_unsupported_mcp_server_fails_closed():
    """G3's rule: a server the wrapper cannot hook must not construct."""
    pytest.importorskip("mcp")
    from agentlock.exceptions import IntegrationUnsupportedError
    from agentlock.integrations.mcp import AgentLockMCPServer

    class NotAServer:
        """Neither registration surface the wrapper knows how to hook."""

    with pytest.raises(IntegrationUnsupportedError):
        AgentLockMCPServer(NotAServer(), _gate(), {"send_email": _perms()})


# ---------------------------------------------------------------------------
# Binding module fail closed rule
# ---------------------------------------------------------------------------


def test_x8_uninspectable_callable_refuses_to_wrap():
    """A callable whose signature cannot be read cannot be gated, so the
    wrapper must refuse at wrap time rather than at call time.

    Two callables: ``dict.update``, a real builtin that ``inspect.signature``
    genuinely refuses, and an object that raises when asked to describe itself.
    """
    from agentlock.decorators import agentlock as agentlock_decorator
    from agentlock.exceptions import BindingError

    gate = _gate()

    with pytest.raises(BindingError):
        agentlock_decorator(gate, name="builtin_tool", permissions=_perms())(
            dict.update
        )

    class Uninspectable:
        __name__ = "uninspectable_tool"

        def __call__(self, *args, **kwargs):
            return "ran"

        @property
        def __signature__(self):
            raise ValueError("this callable refuses to describe itself")

    with pytest.raises(BindingError):
        agentlock_decorator(gate, name="opaque_tool", permissions=_perms())(
            Uninspectable()
        )


# ---------------------------------------------------------------------------
# 1.9.1: variadic keyword names that collide with a bound parameter
# ---------------------------------------------------------------------------


class TestBindingCollision:
    """C1 to C3, from the same external review that found G1 to G4.

    ``bind_call_parameters`` flattens a ``VAR_KEYWORD`` mapping onto the
    top-level parameters dict with ``parameters.update(value)``. When a
    flattened key equals the name of another bound parameter, the flattened
    value overwrites the bound one, and the gate is then shown a value the
    function does not receive.

    C1 is the hiding: ``def send(to, /, **extras)`` called as
    ``send(hostile, to=contact)`` shows the gate the contact while the
    function runs with the hostile address. C2 is the same shape over
    ``*args``. C3 is the case that is not a hiding and must keep working:
    ``def g(**kw)`` called as ``g(kw="spoof")`` shows the gate exactly what
    the function receives, because ``kw`` is the variadic parameter itself
    and not another parameter it could shadow.

    XC1 to XC4 were marked ``xfail(strict=True)`` at freeze and measured
    failing against 1.9.0. The markers came off when the collision rule
    landed; the tests are unchanged otherwise and are now the regression guard
    for it. XC5 and XC6 never carried a marker: they are the guards that the
    collision rule itself must not break.
    """

    def test_xc1_sync_decorator_rejects_a_variadic_key_shadowing_a_parameter(self):
        """C1 through the sync ``@agentlock`` wrapper.

        The gate must never be shown ``to=CONTACT`` for a call the function
        will run with ``to=HOSTILE``. The call is refused before ``authorize``
        is reached, so nothing is authorized and nothing executes.
        """
        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0}
        gate = _gate()

        @agentlock_decorator(gate, name="send_email", permissions=_perms())
        def send_email(to, /, **extras):
            calls["n"] += 1
            return "sent"

        with pytest.raises(BindingError) as exc:
            send_email(HOSTILE, to=CONTACT, _user_id="alice", _role="user")
        assert "to" in str(exc.value)
        assert "send_email" in str(exc.value)
        assert calls["n"] == 0

    def test_xc2_async_decorator_rejects_a_variadic_key_shadowing_a_parameter(self):
        """C1 through the async wrapper. Same shape, same refusal."""
        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0}
        gate = _gate()

        @agentlock_decorator(gate, name="send_email", permissions=_perms())
        async def send_email(to, /, **extras):
            calls["n"] += 1
            return "sent"

        with pytest.raises(BindingError) as exc:
            asyncio.run(
                send_email(HOSTILE, to=CONTACT, _user_id="alice", _role="user")
            )
        assert "to" in str(exc.value)
        assert "send_email" in str(exc.value)
        assert calls["n"] == 0

    def test_xc3_autogen_guarded_rejects_a_variadic_key_shadowing_a_parameter(
        self, monkeypatch
    ):
        """C1 through ``protect_functions``.

        ``_check_autogen_available`` is monkeypatched to a no op, as X3 does.
        The wrapper, the gate and the permission block are all real.
        """
        from agentlock.exceptions import BindingError
        from agentlock.integrations import autogen as al_autogen

        monkeypatch.setattr(al_autogen, "_check_autogen_available", lambda: None)

        calls = {"n": 0}
        gate = _gate()

        def send_email(to, /, **extras):
            calls["n"] += 1
            return "sent"

        protected = al_autogen.protect_functions(
            {"send_email": send_email}, gate, {"send_email": _perms()}
        )
        guarded = protected["send_email"]

        with pytest.raises(BindingError) as exc:
            guarded(
                HOSTILE,
                to=CONTACT,
                _agentlock_user_id="alice",
                _agentlock_role="user",
            )
        assert "to" in str(exc.value)
        assert "send_email" in str(exc.value)
        assert calls["n"] == 0

    def test_xc4_variadic_key_shadowing_var_positional_is_rejected(self):
        """C2, measured on the binding function directly.

        ``f(1, 2, args="spoof")`` binds ``args=(1, 2)`` and then flattens
        ``args="spoof"`` over it. The gate would see the string; the function
        receives the tuple.
        """
        from agentlock.binding import bind_call_parameters
        from agentlock.exceptions import BindingError

        def f(*args, **kw):
            return args

        with pytest.raises(BindingError) as exc:
            bind_call_parameters(f, (1, 2), {"args": "spoof"})
        assert "args" in str(exc.value)
        assert "f" in str(exc.value)

    def test_xc5_a_variadic_key_matching_the_variadic_name_still_binds(self):
        """C3, the case that is not a hiding.

        ``def g(**kw)`` has no parameter named ``kw`` that a flattened key
        could shadow: ``kw`` is the variadic itself. The gate and the function
        see the same mapping, so the call is allowed and the flattened view is
        returned unchanged.
        """
        from agentlock.binding import bind_call_parameters

        def g(**kw):
            return kw

        params, bound = bind_call_parameters(g, (), {"kw": "spoof", "to": "x"})
        assert params == {"kw": "spoof", "to": "x"}
        assert g(*bound.args, **bound.kwargs) == {"kw": "spoof", "to": "x"}

    def test_xc6_the_1_9_0_binding_shapes_still_hold(self):
        """Regression guard: the collision rule must not disturb G1's fix.

        The three routes that 1.9.0 closed, positional, function default and
        keyword, still deny a hostile recipient, and a known contact still
        executes by both routes.
        """
        from agentlock.decorators import agentlock as agentlock_decorator

        calls = {"n": 0}
        gate = _gate()

        @agentlock_decorator(gate, name="send_email", permissions=_perms())
        def send_email(to: str = HOSTILE, body: str = "") -> str:
            calls["n"] += 1
            return "sent"

        auth = {"_user_id": "alice", "_role": "user"}

        for call in (
            lambda: send_email(HOSTILE, **auth),
            lambda: send_email(**auth),
            lambda: send_email(to=HOSTILE, **auth),
        ):
            with pytest.raises(DeniedError) as exc:
                call()
            assert exc.value.reason == "recipient_not_allowed"

        assert calls["n"] == 0
        assert send_email(CONTACT, **auth) == "sent"
        assert send_email(to=CONTACT, **auth) == "sent"
        assert calls["n"] == 2


# ---------------------------------------------------------------------------
# 1.9.1 red pass: three more binding gaps, found against the built wheel
# ---------------------------------------------------------------------------


def _perms_without_recipient_parameter(
    policy: RecipientPolicy = RecipientPolicy.KNOWN_CONTACTS_ONLY,
):
    """The same block as ``_perms``, declaring no recipient parameter."""
    return AgentLockPermissions(
        version="1.5",
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
        allowed_roles=["user"],
        scope=ScopeConfig(allowed_recipients=policy),
    )


def _liar(lie: str) -> type:
    """A ``str`` subclass whose methods report ``lie`` and whose data does not.

    ``strip`` and ``casefold`` are what ``_normalize_recipient`` calls, and
    ``__str__`` is what an application calls on its way to the wire. An
    instance built from one address and lying about another is the shape P2
    describes: whichever of the two the gate reads decides what it enforces.
    """

    class Liar(str):
        def strip(self, *chars: object) -> str:
            return lie

        def casefold(self) -> str:
            return lie

        def __str__(self) -> str:
            return lie

    return Liar


class TestBindingRedPass:
    """P1, P2 and P3, from a red pass against the built 1.9.1 wheel.

    The wheel was ``sha256 026c785d``, identical in content to the checkout it
    was built from, so every shape below reproduces in both.

    P1. ``functools.partial``. ``inspect.signature`` of a partial omits the
    parameters the partial has already bound positionally. The gate binds what
    is left, so ``partial(send, HOSTILE)`` called with ``to=CONTACT`` is
    authorized against the contact and runs against the attacker. Pre-bound
    keywords are the same shape.

    P2. ``str`` subclasses. ``_normalize_recipient`` calls ``strip`` and
    ``casefold`` on the value it is given. A subclass that overrides those to
    return a known contact, and ``__str__`` to return the attacker, shows the
    gate one address and the application another.

    P3. Unobservable declared parameters. ``def send(*args, **kw)`` with
    ``recipient_parameter="to"`` declared: a positional call binds ``args``
    and no ``to``, pipeline step 8 skips, and the declaration enforces
    nothing. The declaration can never enforce for positional calls, so the
    callable and the block are incompatible and the wrapper must say so.

    XR1, XR2, XR5, XR6, XR7, XR8 and XR10 were marked ``xfail(strict=True)``
    at freeze and measured failing against the wheel. XR3, XR4, XR9 and XR11
    carry no marker: they passed at freeze and are the guards that the three
    fixes must not break.
    """

    # -- P1: functools.partial -------------------------------------------

    def test_xr1_sync_decorator_binds_through_a_partial(self):
        """P1 through the sync ``@agentlock`` wrapper.

        ``partial(send1, HOSTILE)`` called with ``to=CONTACT``: once the
        partial is unwrapped, ``to`` is bound positionally to the attacker and
        ``to=CONTACT`` lands in ``**extras``, which is the collision the 1.9.1
        shadow rule already refuses. The call never reaches the gate.
        """
        import functools

        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0, "to": None}
        gate = _gate()

        def send1(to, /, **extras):
            calls["n"] += 1
            calls["to"] = to
            return "sent"

        loaded = functools.partial(send1, HOSTILE)
        wrapped = agentlock_decorator(
            gate, name="send_email", permissions=_perms()
        )(loaded)

        with pytest.raises(BindingError) as exc:
            wrapped(to=CONTACT, _user_id="alice", _role="user")
        assert "to" in str(exc.value)
        assert calls["n"] == 0
        assert calls["to"] is None

    def test_xr2_async_decorator_binds_through_a_partial(self):
        """P1 through the async wrapper. Same shape, same refusal."""
        import functools

        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0, "to": None}
        gate = _gate()

        async def send1(to, /, **extras):
            calls["n"] += 1
            calls["to"] = to
            return "sent"

        loaded = functools.partial(send1, HOSTILE)
        wrapped = agentlock_decorator(
            gate, name="send_email", permissions=_perms()
        )(loaded)

        with pytest.raises(BindingError) as exc:
            asyncio.run(wrapped(to=CONTACT, _user_id="alice", _role="user"))
        assert "to" in str(exc.value)
        assert calls["n"] == 0
        assert calls["to"] is None

    def test_xr3_a_partial_pre_binding_the_recipient_by_keyword_never_runs_hostile(self):
        """P1's keyword shape, over the same positional only signature.

        ``partial(send1, to=CONTACT)`` where ``to`` is positional only: the
        pre-bound keyword can only ever reach ``**extras``, so the call is
        refused whichever way it is read. At freeze the refusal came from
        ``inspect.signature``, which rejects the partial outright; after the
        unwrapping it comes from the shadow rule. Either is acceptable here.
        The one thing that must not happen is execution with the attacker.
        """
        import functools

        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0, "to": None}
        gate = _gate()

        def send1(to, /, **extras):
            calls["n"] += 1
            calls["to"] = to
            return "sent"

        loaded = functools.partial(send1, to=CONTACT)

        with pytest.raises((BindingError, TypeError)):
            wrapped = agentlock_decorator(
                gate, name="send_email", permissions=_perms()
            )(loaded)
            wrapped(to=HOSTILE, _user_id="alice", _role="user")

        assert calls["n"] == 0
        assert calls["to"] != HOSTILE

    def test_xr4_a_pre_bound_keyword_reaches_the_returned_parameters(self):
        """A partial's pre-bound keyword is part of the call and must be shown.

        ``partial(deliver, body="loaded")`` called with the recipient
        positionally: the gate sees both the recipient it was passed and the
        body the partial supplied, and the reconstructed call runs with the
        same two values.
        """
        import functools

        from agentlock.binding import bind_call_parameters

        def deliver(to, body=""):
            return (to, body)

        loaded = functools.partial(deliver, body="loaded")
        params, bound = bind_call_parameters(loaded, (CONTACT,), {})

        assert params == {"to": CONTACT, "body": "loaded"}
        assert deliver(*bound.args, **bound.kwargs) == (CONTACT, "loaded")

    # -- P2: str subclasses ------------------------------------------------

    def test_xr5_a_lying_str_subclass_asserted_as_the_recipient_denies(self):
        """P2 through the asserted ``recipient`` argument.

        The value's data is the attacker; its ``strip`` and ``casefold`` say
        the contact. The gate must enforce against the data.
        """
        gate = _gate()
        gate.register_tool("send_email", _perms())

        liar = _liar(CONTACT)(HOSTILE)
        result = gate.authorize(
            "send_email", user_id="alice", role="user", recipient=liar
        )

        assert result.allowed is False
        assert result.decision.value == "deny"
        assert result.denial is not None
        assert result.denial["reason"] == "recipient_not_allowed"

    def test_xr6_a_lying_str_subclass_in_the_declared_parameter_denies(self):
        """P2 through the declared recipient parameter. Same value, same rule."""
        gate = _gate()
        gate.register_tool("send_email", _perms())

        liar = _liar(CONTACT)(HOSTILE)
        result = gate.authorize(
            "send_email", user_id="alice", role="user", parameters={"to": liar}
        )

        assert result.allowed is False
        assert result.decision.value == "deny"
        assert result.denial is not None
        assert result.denial["reason"] == "recipient_not_allowed"

    def test_xr7_a_str_subclass_whose_data_is_a_contact_is_allowed(self):
        """The rule is coercion, not a ban on subclasses.

        This value's data is the known contact and its methods say the
        attacker. Reading the data allows it, which is the same rule XR5 and
        XR6 rely on, applied in the other direction.
        """
        gate = _gate()
        gate.register_tool("send_email", _perms())

        liar = _liar(HOSTILE)(CONTACT)
        result = gate.authorize(
            "send_email", user_id="alice", role="user", parameters={"to": liar}
        )

        assert result.decision.value == "allow"

    # -- P3: unobservable declared parameters ------------------------------

    def test_xr8_a_recipient_parameter_no_signature_can_carry_is_refused_at_wrap_time(self):
        """P3 at wrap time.

        ``def send(*args)`` has no ``to`` and no ``**kwargs`` for one to
        arrive in, so a block declaring ``recipient_parameter="to"`` can never
        be enforced over it. The wrapper refuses to be built.
        """
        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        gate = _gate()

        with pytest.raises(BindingError) as exc:

            @agentlock_decorator(gate, name="send_email", permissions=_perms())
            def send(*args):
                return "sent"

        assert "to" in str(exc.value)

    def test_xr9_a_var_keyword_can_carry_the_declared_parameter(self):
        """``def send(*args, **kw)`` wraps: ``**kw`` can carry ``to``."""
        from agentlock.decorators import agentlock as agentlock_decorator

        gate = _gate()

        @agentlock_decorator(gate, name="send_email", permissions=_perms())
        def send(*args, **kw):
            return "sent"

        assert callable(send)

    def test_xr10_a_positional_call_the_gate_cannot_name_is_refused_at_call_time(self):
        """P3 at call time, on the callable XR9 allows to be wrapped.

        ``send(HOSTILE)`` binds ``args=(HOSTILE,)`` and no ``to``. The gate
        cannot name that argument, and a declared recipient parameter means it
        must not guess, so the call is refused. The keyword routes are
        unaffected: the attacker denies and the contact runs.
        """
        from agentlock.decorators import agentlock as agentlock_decorator
        from agentlock.exceptions import BindingError

        calls = {"n": 0}
        gate = _gate()

        @agentlock_decorator(gate, name="send_email", permissions=_perms())
        def send(*args, **kw):
            calls["n"] += 1
            return "sent"

        auth = {"_user_id": "alice", "_role": "user"}

        with pytest.raises(BindingError) as exc:
            send(HOSTILE, **auth)
        assert "to" in str(exc.value)
        assert calls["n"] == 0

        with pytest.raises(DeniedError) as denial:
            send(to=HOSTILE, **auth)
        assert denial.value.reason == "recipient_not_allowed"
        assert calls["n"] == 0

        assert send(to=CONTACT, **auth) == "sent"
        assert calls["n"] == 1

    def test_xr11_no_declared_recipient_parameter_leaves_variadics_alone(self):
        """A block that declares nothing constrains nothing.

        The same ``def send(*args)`` XR8 refuses wraps and runs normally when
        the block names no recipient parameter. The refusal is about the pair,
        not about variadic signatures.
        """
        from agentlock.decorators import agentlock as agentlock_decorator

        calls = {"n": 0}
        gate = _gate()

        @agentlock_decorator(
            gate, name="send_email", permissions=_perms_without_recipient_parameter()
        )
        def send(*args):
            calls["n"] += 1
            return "sent"

        assert send(HOSTILE, _user_id="alice", _role="user") == "sent"
        assert calls["n"] == 1
