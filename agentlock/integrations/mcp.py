"""Model Context Protocol (MCP) integration for AgentLock.

Wraps MCP server tool dispatch with AgentLock authorization so that every
tool call from an MCP client passes through the gate.

Example::

    from mcp.server import Server
    from agentlock import AuthorizationGate, AgentLockPermissions
    from agentlock.integrations.mcp import AgentLockMCPServer

    gate = AuthorizationGate()
    permissions = {
        "read_file": AgentLockPermissions(
            risk_level="medium",
            requires_auth=True,
            allowed_roles=["user", "admin"],
        ),
    }

    server = Server("my-server")
    protected = AgentLockMCPServer(server, gate, permissions)
    # Use protected.server in place of the original server

Requires: ``mcp`` (``pip install mcp``)
"""

from __future__ import annotations

import contextlib
import functools
import time
from collections.abc import Callable
from typing import Any

from agentlock.exceptions import IntegrationUnsupportedError
from agentlock.gate import AuthorizationGate
from agentlock.modify import apply_output_modifier
from agentlock.schema import AgentLockPermissions

# The JSON-RPC method every MCP tool call arrives on, under both SDK majors.
_CALL_TOOL_METHOD = "tools/call"

# The structured payload of a tool result, under both SDK majors.  mcp 1.x
# spells the attribute ``structuredContent``; mcp 2.x spells it
# ``structured_content`` and carries the camelCase form as a serialization
# alias, which attribute access does not see.  One applier serves both hooks,
# so it has to know both names.
_STRUCTURED_FIELDS = ("structured_content", "structuredContent")


def _mcp_version() -> str:
    """Installed MCP SDK version, for the message when neither hook fits."""
    try:
        import importlib.metadata

        return importlib.metadata.version("mcp")
    except Exception:
        return "unknown"


def _import_mcp() -> Any:
    """Lazily import the MCP server module."""
    try:
        import mcp.server as mcp_server
        return mcp_server
    except ImportError as exc:
        raise ImportError(
            "The MCP SDK is required for this integration. "
            "Install it with: pip install mcp"
        ) from exc


def _import_mcp_types() -> Any:
    """Lazily import MCP type definitions."""
    try:
        import mcp.types as mcp_types
        return mcp_types
    except ImportError:
        return None


def _set_field(obj: Any, name: str, value: Any) -> Any:
    """Write ``value`` to ``obj.name``, copying the model if it will not take it.

    Content models are rewritten in place where they allow it and copied where
    they do not, so a frozen SDK model is handled without assuming which of the
    two the installed version is.  An object that is neither settable nor
    copyable is returned unchanged rather than raising: a transformation is not
    a reason to fail a call the gate already authorized and the tool already
    ran.
    """
    try:
        setattr(obj, name, value)
        return obj
    except Exception:
        model_copy = getattr(obj, "model_copy", None)
        if callable(model_copy):
            return model_copy(update={name: value})
    return obj


class AgentLockMCPServer:
    """Wraps an MCP ``Server`` with AgentLock authorization on tool dispatch.

    This hooks into the MCP server's tool-call handling so that every
    incoming ``tools/call`` request is authorized before the tool handler
    runs.

    Authorization context (E4).  Identity is resolved per field, and the
    HOST wins:

    1. ``default_user_id`` / ``default_role``, when configured.  A configured
       value is authoritative.  Any client-supplied value for that field is
       stripped from the arguments and ignored, and the substitution is
       audited as ``identity_override_ignored``.
    2. Otherwise the client-supplied value, from ``_agentlock_user_id`` /
       ``_agentlock_role`` in the tool call arguments or from
       ``_meta.agentlock_user_id`` / ``_meta.agentlock_role``.  **Taking it
       trusts the transport**: anything that can reach this server can name
       its own identity, so configure a default, or authenticate upstream and
       pass the result in as one, wherever that is not acceptable.

    Through 1.9.1 the order was the reverse of this, so a client that sent
    ``_agentlock_role: admin`` to a server configured ``default_role="user"``
    was authorized as an admin.

    Args:
        server: An MCP ``Server`` instance.
        gate: An ``AuthorizationGate`` instance.
        permissions_map: Dict mapping tool names to permissions.
        default_user_id: Fallback user identity.
        default_role: Fallback role.
        default_permissions: Permissions for tools not in the map.
    """

    def __init__(
        self,
        server: Any,
        gate: AuthorizationGate,
        permissions_map: dict[str, AgentLockPermissions | dict[str, Any]],
        *,
        default_user_id: str = "",
        default_role: str = "",
        default_permissions: AgentLockPermissions | dict[str, Any] | None = None,
    ) -> None:
        _import_mcp()

        self._server = server
        self._gate = gate
        self._default_user_id = default_user_id
        self._default_role = default_role
        self._permissions_map = permissions_map
        self._default_permissions = default_permissions

        # Register all permissions with the gate
        for tool_name, perms in permissions_map.items():
            gate.register_tool(tool_name, perms)

        # Hook into tool dispatch
        self._install_hook()

    @property
    def server(self) -> Any:
        """Return the underlying MCP server."""
        return self._server

    # -- Hook installation --------------------------------------------------

    def _install_hook(self) -> None:
        """Install the authorization hook, or refuse to construct.

        Two SDK generations register tool handlers differently.  1.x exposes a
        ``call_tool`` decorator and invokes handlers as ``(name, arguments)``.
        2.x exposes ``add_request_handler(method, params_type, handler)`` and
        invokes handlers as ``(ctx, params)``.  Both are supported and both are
        tested against the real SDK.

        A server with neither surface cannot be hooked.  Through 1.8.0 that
        case returned silently, which produced an adapter that looked like it
        protected a server and did not: under mcp 2.x every handler ran
        ungated.  It now raises.

        Raises:
            IntegrationUnsupportedError: The server exposes neither
                registration surface.
        """
        server = self._server
        if getattr(server, "call_tool", None) is not None:
            self._install_call_tool_hook()
        elif getattr(server, "add_request_handler", None) is not None:
            self._install_request_handler_hook()
        else:
            raise IntegrationUnsupportedError(
                "Cannot install an AgentLock authorization hook on "
                f"{type(server).__module__}.{type(server).__qualname__}: it "
                "exposes neither 'call_tool' (mcp 1.x) nor "
                "'add_request_handler' (mcp 2.x).  Installed mcp version: "
                f"{_mcp_version()}.  Refusing to construct rather than wrap a "
                "server whose tool calls would not be authorized."
            )

    def _install_call_tool_hook(self) -> None:
        """mcp 1.x: wrap the ``@server.call_tool()`` decorator."""
        server = self._server
        original_decorator = server.call_tool

        def patched_call_tool(*d_args: Any, **d_kwargs: Any) -> Callable[..., Any]:
            """Replacement for ``@server.call_tool()`` that adds auth."""

            def wrapper(handler: Callable[..., Any]) -> Callable[..., Any]:
                @functools.wraps(handler)
                async def guarded_handler(
                    name: str, arguments: dict[str, Any] | None = None
                ) -> Any:
                    arguments = arguments or {}
                    user_id, role = self._extract_auth(arguments)
                    auth = self._authorize(name, arguments, user_id, role)
                    # E1: the handler receives what the gate authorized.
                    effective = self._effective(auth, arguments)
                    return await self._run_reported(
                        name,
                        effective,
                        auth,
                        lambda: handler(name, effective),
                    )

                # Register the guarded handler with the original decorator
                registered: Callable[..., Any] = original_decorator(
                    *d_args, **d_kwargs
                )(guarded_handler)
                return registered

            return wrapper

        # Replace the server's call_tool with our version
        server.call_tool = patched_call_tool

    def _install_request_handler_hook(self) -> None:
        """mcp 2.x: wrap every ``tools/call`` registration."""
        server = self._server
        original_add = server.add_request_handler

        def patched_add_request_handler(
            method: str, params_type: Any, handler: Callable[..., Any]
        ) -> Any:
            if method == _CALL_TOOL_METHOD:
                handler = self._guard_request_handler(handler)
            return original_add(method, params_type, handler)

        server.add_request_handler = patched_add_request_handler

        # A tools/call handler can also arrive through ``Server(on_call_tool=)``,
        # which writes the handler registry directly and never reaches
        # ``add_request_handler``.  This class wraps a server that is already
        # constructed, so such a handler is in place before the hook exists and
        # wrapping the registration function alone would never see it.  Wrap
        # what is already registered too, or the constructor route stays open.
        get_entry = getattr(server, "get_request_handler", None)
        if get_entry is None:
            return
        entry = get_entry(_CALL_TOOL_METHOD)
        if entry is None:
            return
        original_add(
            _CALL_TOOL_METHOD,
            entry.params_type,
            self._guard_request_handler(entry.handler),
        )

    def _guard_request_handler(
        self, handler: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Wrap one mcp 2.x ``(ctx, params)`` handler with authorization."""

        @functools.wraps(handler)
        async def guarded(ctx: Any, params: Any) -> Any:
            name = getattr(params, "name", "")
            # A copy: the params object belongs to the SDK, and the reserved
            # auth keys are stripped from our copy rather than from it.
            arguments = dict(getattr(params, "arguments", None) or {})
            user_id, role = self._extract_auth(arguments)
            auth = self._authorize(name, arguments, user_id, role)
            # E1: the handler receives what the gate authorized.
            effective = self._effective(auth, arguments)
            cleaned = self._with_arguments(params, effective)
            return await self._run_reported(
                name, effective, auth, lambda: handler(ctx, cleaned)
            )

        return guarded

    @staticmethod
    def _with_arguments(params: Any, arguments: dict[str, Any]) -> Any:
        """Return ``params`` carrying ``arguments``, without the reserved keys.

        Pydantic models are immutable often enough that mutation is not an
        option, so the model is copied.  Anything else is set in place.
        """
        model_copy = getattr(params, "model_copy", None)
        if callable(model_copy):
            return model_copy(update={"arguments": arguments})
        params.arguments = arguments
        return params

    # -- Shared decision path -----------------------------------------------

    def _extract_auth(self, arguments: dict[str, Any]) -> tuple[str, str]:
        """Resolve the caller's identity, stripping the reserved keys in place.

        E4, per field: a configured default is authoritative and the client's
        value for that field is discarded; a field with no configured default
        falls back to the client, which trusts the transport.  The reserved
        keys are removed either way, so what the gate authorizes and what the
        tool receives are the same thing: the tool's own arguments.

        Both reserved keys are popped unconditionally.  Popping them inside an
        ``or`` chain, as this did through 1.9.1, left ``_agentlock_user_id``
        in the arguments whenever ``_meta`` had already supplied a value.
        """
        meta = arguments.pop("_meta", {}) or {}
        claimed_user = arguments.pop("_agentlock_user_id", "") or meta.get(
            "agentlock_user_id", ""
        )
        claimed_role = arguments.pop("_agentlock_role", "") or meta.get(
            "agentlock_role", ""
        )

        user_id = self._default_user_id or claimed_user
        role = self._default_role or claimed_role

        ignored = {}
        if self._default_user_id and claimed_user:
            ignored["user_id"] = claimed_user
        if self._default_role and claimed_role:
            ignored["role"] = claimed_role
        if ignored:
            self._audit_identity_override(ignored, user_id, role)

        return user_id, role

    def _audit_identity_override(
        self, ignored: dict[str, str], user_id: str, role: str
    ) -> None:
        """Record a client identity claim that the configured default beat.

        Best effort by construction: a failing audit backend must not break a
        call the gate is about to decide on its own terms anyway.  Nothing
        here is ever read back by ``authorize()``.
        """
        # pragma: no cover on the suppression - evidence never blocks a call
        with contextlib.suppress(Exception):
            self._gate.audit_logger.log(
                tool_name="",
                user_id=user_id,
                role=role,
                action="identity_override_ignored",
                reason="mcp_client_supplied_identity",
                metadata={
                    "ignored_claim": ignored,
                    "effective_user_id": user_id,
                    "effective_role": role,
                },
            )

    def _authorize(
        self,
        name: str,
        arguments: dict[str, Any],
        user_id: str,
        role: str,
    ) -> Any:
        """Register if needed, authorize, and consume the token.

        Raises:
            DeniedError: The gate denied the call.  Nothing has run.
        """
        gate = self._gate

        # Register tool if not already registered
        if gate.get_permissions(name) is None:
            if name in self._permissions_map:
                gate.register_tool(name, self._permissions_map[name])
            elif self._default_permissions is not None:
                gate.register_tool(name, self._default_permissions)

        auth = gate.authorize(
            name,
            user_id=user_id,
            role=role,
            parameters=arguments or None,
        )
        auth.raise_if_denied()
        assert auth.token is not None

        # Consume token, against the parameters the grant is bound to (E1).
        gate.token_store.validate_and_consume(
            auth.token.token_id, name, self._effective(auth, arguments) or None
        )
        return auth

    @staticmethod
    def _effective(auth: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        """The parameters the grant authorizes, defaulting to the request."""
        effective = getattr(auth, "effective_parameters", None)
        return dict(effective) if effective is not None else arguments

    @staticmethod
    def _rewrite_leaf(item: Any, modify: Callable[[str], str]) -> Any:
        """Apply the transformation to one content item.

        Three shapes, in the order they are tried:

        * an item carrying ``text`` directly, which is ``TextContent`` and also
          ``TextResourceContents`` when this is reached through the case below;
        * an item carrying a ``resource``, which is ``EmbeddedResource``.  G2:
          an embedded resource holds its text one level down, at
          ``.resource.text``, and the walk through 1.10.0 read ``.text`` on the
          outer object, found nothing, and handed the whole model to
          ``apply_output_modifier``, which returns a custom object unchanged by
          its own stated contract.  The declared transformation therefore never
          reached the string a client reads.  The resource is now rewritten and
          written back;
        * anything else, which goes to ``apply_output_modifier`` so that a
          handler returning plain strings, a mapping, or bytes rather than SDK
          content blocks is transformed on the same terms as every other
          execution path.

        **What is passed through unchanged, deliberately.**
        ``BlobResourceContents`` carries base64 in ``blob`` and no ``text``, so
        the second case leaves it alone: this engine does not claim to decode a
        blob, guess its media type, and redact inside it.  ``ResourceLink``
        carries a URI and no content at all, so it reaches the third case and
        comes back untouched, because a link is a reference to data rather than
        the data.  A host serving sensitive material as a blob or behind a link
        has to redact it at the source.
        """
        text = getattr(item, "text", None)
        if isinstance(text, str):
            new_text = modify(text)
            if new_text == text:
                return item
            return _set_field(item, "text", new_text)

        resource = getattr(item, "resource", None)
        if resource is not None:
            resource_text = getattr(resource, "text", None)
            if isinstance(resource_text, str):
                new_resource = AgentLockMCPServer._rewrite_leaf(resource, modify)
                if new_resource is resource:
                    return item
                return _set_field(item, "resource", new_resource)
            # BlobResourceContents and anything else without text.
            return item

        return apply_output_modifier(item, modify)

    @staticmethod
    def _walk_payload(result: Any, modify: Callable[[str], str]) -> Any:
        """Apply an output transformation to every text payload in a result.

        This is the ONE walker over an MCP result, and both output policies go
        through it: the declared output transformation and the data policy's
        automatic redaction.  G2: through 1.10.0 they did not share a walk.
        The transformation had this one and the data policy had
        ``isinstance(result, str)``, which is never true of an MCP result, so a
        tool that declared ``prohibited_in_output`` with ``redaction="auto"``
        and no modify policy had its redaction skipped entirely and leaked
        through every shape at once.  Two policies over the same payload need
        one definition of what the payload is, or the weaker definition decides
        what leaks.

        An MCP handler does not return a string.  It returns a
        ``CallToolResult`` carrying a list of content blocks, or that list on
        its own, and the text a client actually reads is the ``text`` field of
        each block.  The shapes covered, and they are the whole list:

        * ``str``: modified, which is the plain return an older handler makes.
        * ``list``: every item walked as a content item.
        * a result with a ``content`` list: every item walked, then the
          structured payload walked as well.  E15: a ``CallToolResult`` carries
          TWO payloads and the content blocks are only one of them.
          ``structured_content`` is the machine-readable answer, which is what
          a client reads it for, and a handler putting the same value in both
          must not get one copy redacted and the other intact.
        * anything else, including a plain mapping or sequence return, which
          the 1.x handler contract allows: handed to ``apply_output_modifier``,
          whose own docstring lists what it covers.

        Content models are rewritten in place where they allow it and copied
        where they do not, so a frozen SDK model is handled without assuming
        which of the two the installed version is.  Both SDK majors are served
        by the same code, which is why the structured field is looked up under
        both of its spellings.
        """
        if isinstance(result, str):
            return modify(result)

        if isinstance(result, list):
            return [
                AgentLockMCPServer._rewrite_leaf(item, modify) for item in result
            ]

        content = getattr(result, "content", None)
        if not isinstance(content, list):
            return apply_output_modifier(result, modify)

        rewritten = [
            AgentLockMCPServer._rewrite_leaf(item, modify) for item in content
        ]
        if rewritten != content:
            result = _set_field(result, "content", rewritten)
        return AgentLockMCPServer._walk_structured(result, modify)

    @staticmethod
    def _walk_structured(result: Any, modify: Callable[[str], str]) -> Any:
        """Apply the walk to a result's structured payload, if it has one.

        E15.  Both field names are tried because the two SDK majors spell it
        differently and one walker serves both hooks.  A payload that is
        ``None`` is left alone: absent is not the same as empty, and writing a
        walked ``None`` back would be a change with nothing behind it.
        """
        for name in _STRUCTURED_FIELDS:
            structured = getattr(result, name, None)
            if structured is None:
                continue
            walked = apply_output_modifier(structured, modify)
            if walked != structured:
                result = _set_field(result, name, walked)
        return result

    async def _run_reported(
        self,
        name: str,
        arguments: dict[str, Any],
        auth: Any,
        run: Callable[[], Any],
    ) -> Any:
        """Run an authorized handler and report the outcome to the gate.

        E7: the MCP server owns execution, so the gate learns the outcome only
        because we report it.  Attempt first, outcome after, so an absent
        completion means "attempted, never returned" rather than nothing.
        Neither call can raise.
        """
        gate = self._gate
        attempt = gate.begin_execution(
            name,
            token_id=auth.token.token_id,
            parameters=arguments or None,
        )
        started = time.time()
        try:
            result = await run()
        except BaseException as exc:
            gate.confirm_execution(
                name,
                status="failed",
                token_id=auth.token.token_id,
                parameters=arguments or None,
                duration_ms=(time.time() - started) * 1000,
                error_type=type(exc).__name__,
                attempt_audit_id=(attempt.audit_id if attempt else ""),
            )
            raise
        gate.confirm_execution(
            name,
            status="succeeded",
            token_id=auth.token.token_id,
            parameters=arguments or None,
            duration_ms=(time.time() - started) * 1000,
            attempt_audit_id=(attempt.audit_id if attempt else ""),
        )

        # E1: the declared output transformation, in the same position
        # ``gate.execute`` applies it: after the call, before redaction.
        modify = getattr(auth, "modify_output_fn", None)
        if modify is not None:
            result = self._walk_payload(result, modify)

        # G2: the data policy's automatic redaction, over the SAME walk.  It
        # was guarded by ``isinstance(result, str)`` through 1.10.0, which is
        # never true of an MCP result, so a tool declaring
        # ``prohibited_in_output`` with ``redaction="auto"`` had this step
        # skipped and leaked through every shape the walk covers.  Redaction of
        # an unconfigured tool is the identity, so walking unconditionally
        # changes nothing for a tool that declared no data policy.
        def redact(text: str) -> str:
            redaction = gate.redact_output(name, text)
            return redaction.redacted if redaction.was_redacted else text

        return self._walk_payload(result, redact)


    def register_tool(
        self,
        tool_name: str,
        permissions: AgentLockPermissions | dict[str, Any],
    ) -> None:
        """Register additional tool permissions after construction.

        Args:
            tool_name: Tool name as it appears in MCP tool calls.
            permissions: AgentLock permissions for the tool.
        """
        self._permissions_map[tool_name] = permissions
        self._gate.register_tool(tool_name, permissions)
