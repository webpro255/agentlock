"""Authorization Gate — Layer 2 of the AgentLock enforcement architecture.

The gate sits between the agent (Layer 1) and tool execution (Layer 3).
It validates permissions, enforces rate limits, manages sessions, issues
single-use execution tokens, and generates audit records.

The agent never bypasses the gate.  The agent never receives tokens.

Example::

    from agentlock import AuthorizationGate, AgentLockPermissions

    gate = AuthorizationGate()

    perms = AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
        rate_limit={"max_calls": 5, "window_seconds": 3600},
    )

    gate.register_tool("send_email", perms)

    # At call time
    result = gate.authorize("send_email", user_id="alice", role="admin")
    # result.allowed is True, result.token is an ExecutionToken
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from agentlock.audit import AuditBackend, AuditLogger, InMemoryAuditBackend
from agentlock.context import ContextProvenance, ContextTracker
from agentlock.exceptions import (
    DeniedError,
    RateLimitedError,
)
from agentlock.memory_gate import MemoryDecision, MemoryGate, MemoryStore
from agentlock.policy import PolicyEngine, RequestContext
from agentlock.rate_limit import RateLimiter
from agentlock.redaction import RedactionEngine, RedactionResult
from agentlock.schema import AgentLockPermissions
from agentlock.session import Session, SessionStore
from agentlock.token import ExecutionToken, TokenStore
from agentlock.types import (
    ContextSource,
    DataBoundary,
    DegradationEffect,
    DenialReason,
    MemoryPersistence,
    MemoryWriter,
)


@dataclass
class AuthResult:
    """Result of an authorization check.

    Attributes:
        allowed: Whether the call is permitted.
        token: Execution token (only when allowed).
        denial: Denial details (only when denied).
        audit_id: Audit record ID for this decision.
    """

    allowed: bool
    token: ExecutionToken | None = None
    denial: dict[str, Any] | None = None
    audit_id: str = ""

    def raise_if_denied(self) -> None:
        """Raise DeniedError if the call was denied."""
        if not self.allowed and self.denial:
            raise DeniedError(
                reason=self.denial.get("reason", "no_permissions"),
                detail=self.denial.get("detail", ""),
                required_role=self.denial.get("required_role"),
                current_role=self.denial.get("current_role"),
                suggestion=self.denial.get("suggestion", ""),
                audit_id=self.audit_id,
            )


class AuthorizationGate:
    """Central authorization enforcement point.

    This is the primary interface for AgentLock.  Register tools with their
    permissions, then call ``authorize()`` on every tool invocation.

    Args:
        audit_backend: Pluggable audit storage.  Defaults to in-memory.
        token_ttl: Execution token lifetime in seconds.
        session_duration: Default session lifetime in seconds.
    """

    def __init__(
        self,
        audit_backend: AuditBackend | None = None,
        token_ttl: int = 60,
        session_duration: int = 900,
        memory_store: MemoryStore | None = None,
    ) -> None:
        self._tools: dict[str, AgentLockPermissions] = {}
        self._policy = PolicyEngine()
        self._rate_limiter = RateLimiter()
        self._token_store = TokenStore(default_ttl=token_ttl)
        self._session_store = SessionStore()
        self._audit = AuditLogger(backend=audit_backend or InMemoryAuditBackend())
        self._redaction_engines: dict[str, RedactionEngine] = {}
        self._context_tracker = ContextTracker()
        self._memory_gate = MemoryGate(store=memory_store)
        self._token_ttl = token_ttl
        self._session_duration = session_duration

    # -- Registration -------------------------------------------------------

    def register_tool(
        self,
        tool_name: str,
        permissions: AgentLockPermissions | dict[str, Any],
    ) -> None:
        """Register a tool with its AgentLock permissions.

        Args:
            tool_name: Unique tool identifier.
            permissions: AgentLockPermissions instance or raw dict.
        """
        if isinstance(permissions, dict):
            permissions = AgentLockPermissions(**permissions)
        self._tools[tool_name] = permissions

        # Pre-build redaction engine if data policy has prohibited types
        dp = permissions.data_policy
        if dp.prohibited_in_output:
            self._redaction_engines[tool_name] = RedactionEngine(
                prohibited=dp.prohibited_in_output
            )

    def get_permissions(self, tool_name: str) -> AgentLockPermissions | None:
        """Get registered permissions for a tool."""
        return self._tools.get(tool_name)

    @property
    def registered_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    # -- Session management -------------------------------------------------

    def create_session(
        self,
        user_id: str,
        role: str,
        data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """Create an authenticated session after out-of-band auth completes.

        This should only be called by the authentication infrastructure,
        never by the agent.

        Args:
            user_id: Verified identity.
            role: Role assigned after authentication.
            data_boundary: Scope of data access for this session.
            metadata: Device info, IP, etc.

        Returns:
            The created session.
        """
        return self._session_store.create(
            user_id=user_id,
            role=role,
            data_boundary=data_boundary,
            max_duration=self._session_duration,
            metadata=metadata,
        )

    def get_session(self, user_id: str) -> Session | None:
        """Get active session for a user."""
        return self._session_store.get_by_user(user_id)

    # -- Authorization ------------------------------------------------------

    def authorize(
        self,
        tool_name: str,
        *,
        user_id: str = "",
        role: str = "",
        parameters: dict[str, Any] | None = None,
        record_count: int = 1,
        recipient: str = "",
        data_boundary: DataBoundary | None = None,
        is_bulk: bool = False,
        is_external: bool = False,
        is_financial: bool = False,
        amount: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authorize a tool call.

        This is the main entry point.  Call it for every tool invocation.

        Args:
            tool_name: The tool being invoked.
            user_id: Authenticated caller identity.
            role: Caller's role.  Auto-resolved from session if omitted.
            parameters: Tool call parameters (for token binding).
            record_count: Number of records requested.
            recipient: Target recipient for outbound tools.
            data_boundary: Requested data scope.
            is_bulk: Whether this is a bulk operation.
            is_external: Whether this sends data externally.
            is_financial: Whether this involves money.
            amount: Financial amount if applicable.
            metadata: Additional context.

        Returns:
            AuthResult with token if allowed, denial details if denied.
        """
        start = time.time()
        permissions = self._tools.get(tool_name)

        # No permissions registered = denied (deny by default)
        if permissions is None:
            record = self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="denied",
                reason="no_permissions",
                risk_level="unknown",
            )
            return AuthResult(
                allowed=False,
                denial={
                    "status": "denied",
                    "reason": DenialReason.NO_PERMISSIONS.value,
                    "detail": f"Tool '{tool_name}' has no AgentLock permissions registered.",
                    "suggestion": "Register the tool with gate.register_tool() first.",
                },
                audit_id=record.audit_id,
            )

        # Resolve session
        session = self._session_store.get_by_user(user_id) if user_id else None
        if session and not role:
            role = session.role
        if session and data_boundary is None:
            data_boundary = session.data_boundary

        # Resolve context state for v1.1
        resolved_session_id = session.session_id if session else ""
        context_state = None
        if permissions.version >= "1.1" and resolved_session_id:
            context_state = self._context_tracker.get(resolved_session_id)
            # Apply restrict_scope effect
            if (
                context_state
                and context_state.is_degraded
                and DegradationEffect.RESTRICT_SCOPE in context_state.active_effects
            ):
                data_boundary = DataBoundary.AUTHENTICATED_USER_ONLY

        # Build request context
        ctx = RequestContext(
            user_id=user_id,
            role=role,
            session_id=resolved_session_id,
            data_boundary=data_boundary or DataBoundary.AUTHENTICATED_USER_ONLY,
            record_count=record_count,
            recipient=recipient,
            is_bulk=is_bulk,
            is_external=is_external,
            is_financial=is_financial,
            amount=amount,
            metadata=metadata or {},
            context_state=context_state,
        )

        # Evaluate policy
        decision = self._policy.evaluate(permissions, ctx)

        # v1.1: Elevate logging if trust is degraded
        effective_log_level = permissions.audit.log_level
        if (
            context_state
            and context_state.is_degraded
            and DegradationEffect.ELEVATE_LOGGING in context_state.active_effects
        ):
            from agentlock.types import AuditLogLevel
            effective_log_level = AuditLogLevel.FULL

        # Rate limiting (checked even if policy passed, before token issuance)
        if decision.allowed and permissions.rate_limit:
            try:
                self._rate_limiter.check(
                    tool_name,
                    user_id or "anonymous",
                    permissions.rate_limit.max_calls,
                    permissions.rate_limit.window_seconds,
                )
            except RateLimitedError as e:
                duration_ms = (time.time() - start) * 1000
                record = self._audit.log(
                    tool_name=tool_name,
                    user_id=user_id,
                    role=role,
                    action="denied",
                    reason="rate_limited",
                    risk_level=permissions.risk_level.value,
                    log_level=effective_log_level,
                    include_parameters=permissions.audit.include_parameters,
                    parameters=parameters,
                    duration_ms=duration_ms,
                    session_id=ctx.session_id,
                )
                return AuthResult(
                    allowed=False,
                    denial=e.to_dict(),
                    audit_id=record.audit_id,
                )

        duration_ms = (time.time() - start) * 1000

        if decision.allowed:
            # Issue execution token
            token = self._token_store.issue(
                tool_name=tool_name,
                user_id=user_id,
                role=role,
                parameters=parameters,
                scope={
                    "data_boundary": ctx.data_boundary.value,
                    "max_records": permissions.scope.max_records,
                },
                ttl=self._token_ttl,
            )

            # Build v1.1 audit metadata
            audit_kwargs: dict[str, Any] = {}
            if context_state:
                audit_kwargs["trust_ceiling"] = context_state.trust_ceiling.value
                audit_kwargs["is_trust_degraded"] = context_state.is_degraded
                if context_state.active_effects:
                    audit_kwargs["degradation_effects"] = [
                        e.value for e in context_state.active_effects
                    ]

            record = self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                role=role,
                action="allowed",
                risk_level=permissions.risk_level.value,
                log_level=permissions.audit.log_level,
                include_parameters=permissions.audit.include_parameters,
                parameters=parameters,
                token_id=token.token_id,
                session_id=ctx.session_id,
                duration_ms=duration_ms,
                **audit_kwargs,
            )

            return AuthResult(
                allowed=True,
                token=token,
                audit_id=record.audit_id,
            )
        else:
            record = self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                role=role,
                action="denied",
                reason=decision.reason.value if decision.reason else "unknown",
                risk_level=permissions.risk_level.value,
                log_level=permissions.audit.log_level,
                include_parameters=permissions.audit.include_parameters,
                parameters=parameters,
                session_id=ctx.session_id,
                duration_ms=duration_ms,
            )

            return AuthResult(
                allowed=False,
                denial={
                    "status": "denied",
                    "reason": decision.reason.value if decision.reason else "unknown",
                    "detail": decision.detail,
                    "required_role": decision.required_role,
                    "current_role": role,
                    "suggestion": decision.suggestion,
                },
                audit_id=record.audit_id,
            )

    # -- Execution ----------------------------------------------------------

    def execute(
        self,
        tool_name: str,
        func: Any,
        *,
        token: ExecutionToken,
        parameters: dict[str, Any] | None = None,
    ) -> Any:
        """Execute a tool via its token (Layer 3).

        Validates and consumes the token, executes the function, applies
        redaction if configured, and returns the result.

        Args:
            tool_name: Tool to execute.
            func: The callable to invoke.
            token: Execution token from authorize().
            parameters: Keyword arguments for the function.

        Returns:
            The (possibly redacted) tool output.
        """
        # Validate and consume token (single-use)
        self._token_store.validate_and_consume(
            token.token_id, tool_name, parameters
        )

        # Execute
        params = parameters or {}
        result = func(**params)

        # Redact output if configured
        engine = self._redaction_engines.get(tool_name)
        if engine and isinstance(result, str):
            redaction = engine.redact(result)
            if redaction.was_redacted:
                self._audit.log(
                    tool_name=tool_name,
                    user_id=token.user_id,
                    role=token.role,
                    action="redacted",
                    risk_level=self._tools[tool_name].risk_level.value,
                    metadata={"redactions": len(redaction.redactions)},
                )
                return redaction.redacted

        return result

    # -- Convenience: authorize + execute in one call -----------------------

    def call(
        self,
        tool_name: str,
        func: Any,
        *,
        user_id: str = "",
        role: str = "",
        parameters: dict[str, Any] | None = None,
        **auth_kwargs: Any,
    ) -> Any:
        """Authorize and execute a tool call in one step.

        Combines ``authorize()`` and ``execute()``.  Raises ``DeniedError``
        if authorization fails.

        Args:
            tool_name: Tool to invoke.
            func: Callable to execute.
            user_id: Authenticated identity.
            role: Caller's role.
            parameters: Function keyword arguments.
            **auth_kwargs: Additional args forwarded to authorize().

        Returns:
            The tool's return value (possibly redacted).

        Raises:
            DeniedError: If authorization fails.
        """
        result = self.authorize(
            tool_name,
            user_id=user_id,
            role=role,
            parameters=parameters,
            **auth_kwargs,
        )
        result.raise_if_denied()
        assert result.token is not None
        return self.execute(
            tool_name, func, token=result.token, parameters=parameters
        )

    # -- Redaction (standalone) ---------------------------------------------

    def redact_output(self, tool_name: str, text: str) -> RedactionResult:
        """Apply redaction to a string using the tool's data policy.

        Args:
            tool_name: Tool whose data policy to use.
            text: Text to redact.

        Returns:
            RedactionResult.
        """
        engine = self._redaction_engines.get(tool_name)
        if engine is None:
            return RedactionResult(original=text, redacted=text, redactions=[])
        return engine.redact(text)

    # -- Memory operations (v1.1) -------------------------------------------

    def authorize_memory_write(
        self,
        tool_name: str,
        *,
        content: str,
        content_hash: str,
        user_id: str,
        writer: MemoryWriter,
        persistence: MemoryPersistence = MemoryPersistence.SESSION,
        provenance: ContextProvenance | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryDecision:
        """Authorize and execute a memory write for a tool.

        Uses the tool's ``memory_policy`` to validate the write.

        Args:
            tool_name: The tool whose memory policy to use.
            content: The content to persist.
            content_hash: SHA-256 hash of the content.
            user_id: Identity of the user whose memory this is.
            writer: Who is writing (system, user, agent, tool).
            persistence: Desired persistence level.
            provenance: Provenance of the content being persisted.
            metadata: Additional context.

        Returns:
            MemoryDecision with the result.
        """
        permissions = self._tools.get(tool_name)
        if permissions is None or permissions.memory_policy is None:
            decision = MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_WRITE_DENIED,
                detail=f"No memory policy configured for tool '{tool_name}'.",
                suggestion="Add memory_policy to the tool's agentlock permissions.",
            )
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="memory_write_denied",
                reason="memory_write_denied",
                memory_operation="write",
            )
            return decision

        mp = permissions.memory_policy
        decision = self._memory_gate.authorize_write(
            content=content,
            content_hash=content_hash,
            user_id=user_id,
            tool_name=tool_name,
            writer=writer,
            persistence=persistence,
            allowed_writers=mp.allowed_writers,
            allowed_persistence=mp.persistence,
            prohibited_content=mp.prohibited_content,
            max_entries=mp.retention.max_entries,
            require_write_confirmation=mp.require_write_confirmation,
            provenance=provenance,
            metadata=metadata,
        )

        if decision.allowed:
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="memory_write",
                memory_operation="write",
                memory_entry_id=decision.entry.entry_id if decision.entry else "",
            )
        else:
            action = "memory_write_denied"
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action=action,
                reason=decision.reason.value if decision.reason else "",
                memory_operation="write",
            )

        return decision

    def authorize_memory_read(
        self,
        tool_name: str,
        *,
        user_id: str,
        reader: MemoryWriter,
    ) -> MemoryDecision:
        """Authorize a memory read for a tool.

        Uses the tool's ``memory_policy`` to validate the read and
        performs lazy retention cleanup.

        Args:
            tool_name: The tool whose memory policy to use.
            user_id: Identity of the user whose memory to read.
            reader: Who is reading (system, user, agent, tool).

        Returns:
            MemoryDecision with the result.
        """
        permissions = self._tools.get(tool_name)
        if permissions is None or permissions.memory_policy is None:
            decision = MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_READ_DENIED,
                detail=f"No memory policy configured for tool '{tool_name}'.",
                suggestion="Add memory_policy to the tool's agentlock permissions.",
            )
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="memory_read_denied",
                reason="memory_read_denied",
                memory_operation="read",
            )
            return decision

        mp = permissions.memory_policy
        decision = self._memory_gate.authorize_read(
            user_id=user_id,
            reader=reader,
            tool_name=tool_name,
            allowed_readers=mp.allowed_readers,
            max_age_seconds=mp.retention.max_age_seconds,
        )

        if decision.allowed:
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="memory_read",
                memory_operation="read",
            )
        else:
            self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                action="memory_read_denied",
                reason=decision.reason.value if decision.reason else "",
                memory_operation="read",
            )

        return decision

    # -- Context tracking (v1.1) --------------------------------------------

    def notify_context_write(
        self,
        session_id: str,
        source: ContextSource,
        content_hash: str,
        *,
        writer_id: str = "",
        tool_name: str | None = None,
        token_id: str | None = None,
        parent_provenance_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ContextProvenance:
        """Report that content has entered the agent's context window.

        Framework integrations MUST call this automatically after every
        tool execution, document retrieval, web fetch, or peer agent
        message reception.

        Args:
            session_id: Session this write belongs to.
            source: What produced this content.
            content_hash: SHA-256 hash of the content.
            writer_id: Identity of the writer.
            tool_name: Tool that produced the content, if any.
            token_id: Execution token, if from an authorized call.
            parent_provenance_id: Parent provenance, if derived.
            metadata: Additional context (URL, filename, etc.).

        Returns:
            The created provenance record.
        """
        # Find the strongest context_policy across registered tools
        # (use the first registered tool's policy that has context_policy set,
        # or None if no tools have context_policy)
        policy = None
        for perms in self._tools.values():
            if perms.context_policy is not None:
                policy = perms.context_policy
                break

        provenance = self._context_tracker.record_write(
            session_id=session_id,
            source=source,
            content_hash=content_hash,
            writer_id=writer_id,
            tool_name=tool_name,
            token_id=token_id,
            parent_provenance_id=parent_provenance_id,
            metadata=metadata,
            policy=policy,
        )

        # Audit the trust degradation if it just happened
        state = self._context_tracker.get(session_id)
        if state and state.is_degraded:
            self._audit.log(
                tool_name=tool_name or "",
                user_id=writer_id,
                action="trust_degraded",
                risk_level="",
                trust_ceiling=state.trust_ceiling.value,
                is_trust_degraded=True,
                degradation_effects=[e.value for e in state.active_effects],
                metadata={"source": source.value, "content_hash": content_hash},
            )

        return provenance

    # -- Introspection ------------------------------------------------------

    @property
    def context_tracker(self) -> ContextTracker:
        return self._context_tracker

    @property
    def memory_gate(self) -> MemoryGate:
        return self._memory_gate

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit

    @property
    def token_store(self) -> TokenStore:
        return self._token_store

    @property
    def session_store(self) -> SessionStore:
        return self._session_store

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate_limiter
