"""AgentLock — Authorization framework for AI agent tool calls.

Your AI agent needs a login screen. AgentLock is that login screen.

AgentLock defines an open standard for authorization in AI agent systems.
It introduces a permissions schema that any tool can implement, any agent
framework can enforce, and any security team can audit.

Quick start::

    from agentlock import AuthorizationGate, AgentLockPermissions, agentlock

    gate = AuthorizationGate()

    # Protect a tool in one line
    @agentlock(gate, risk_level="high", allowed_roles=["admin"])
    def send_email(to: str, subject: str, body: str) -> str:
        return f"Email sent to {to}"

    # Or register manually
    gate.register_tool("read_db", AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["analyst", "admin"],
        scope={"data_boundary": "authenticated_user_only", "max_records": 100},
    ))

    # Authorize every call
    result = gate.authorize("read_db", user_id="alice", role="analyst")
    if result.allowed:
        output = gate.execute("read_db", my_db_func, token=result.token)

Copyright 2026 David Grice
SPDX-License-Identifier: Apache-2.0
"""

__version__ = "1.1.1"

from agentlock.audit import AuditLogger, AuditRecord, FileAuditBackend, InMemoryAuditBackend
from agentlock.context import ContextProvenance, ContextState, ContextTracker
from agentlock.decorators import agentlock
from agentlock.exceptions import (
    AgentLockError,
    ApprovalRequiredError,
    AuthenticationRequiredError,
    ConfigurationError,
    DeniedError,
    InsufficientRoleError,
    MemoryConfirmationRequiredError,
    MemoryProhibitedContentError,
    MemoryReadDeniedError,
    MemoryRetentionExceededError,
    MemoryWriteDeniedError,
    RateLimitedError,
    SchemaValidationError,
    ScopeViolationError,
    SessionExpiredError,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenReplayedError,
    TrustDegradedError,
    UnattributedContextError,
)
from agentlock.gate import AuthorizationGate, AuthResult
from agentlock.memory_gate import InMemoryMemoryStore, MemoryDecision, MemoryEntry, MemoryGate
from agentlock.policy import PolicyDecision, PolicyEngine, RequestContext
from agentlock.rate_limit import RateLimiter
from agentlock.redaction import RedactionEngine, RedactionResult
from agentlock.schema import (
    SCHEMA_VERSION,
    AgentLockPermissions,
    AuditConfig,
    ContextPolicyConfig,
    DataPolicyConfig,
    DegradationTrigger,
    HumanApprovalConfig,
    MemoryPolicyConfig,
    MemoryRetentionConfig,
    RateLimitConfig,
    ScopeConfig,
    SessionConfig,
    SourceAuthorityConfig,
    ToolDefinition,
    TrustDegradationConfig,
)
from agentlock.session import Session, SessionStore
from agentlock.token import ExecutionToken, TokenStore
from agentlock.types import (
    ApprovalChannel,
    ApprovalThreshold,
    AuditLogLevel,
    AuthMethod,
    ContextAuthority,
    ContextSource,
    DataBoundary,
    DataClassification,
    DegradationEffect,
    DenialReason,
    MemoryPersistence,
    MemoryWriter,
    RecipientPolicy,
    RedactionMode,
    RiskLevel,
    TokenStatus,
)

__all__ = [
    # Core
    "AuthorizationGate",
    "AuthResult",
    "AgentLockPermissions",
    "ToolDefinition",
    "agentlock",
    # Schema components
    "ScopeConfig",
    "RateLimitConfig",
    "DataPolicyConfig",
    "SessionConfig",
    "AuditConfig",
    "HumanApprovalConfig",
    "SCHEMA_VERSION",
    # v1.1 schema components
    "ContextPolicyConfig",
    "SourceAuthorityConfig",
    "DegradationTrigger",
    "TrustDegradationConfig",
    "MemoryPolicyConfig",
    "MemoryRetentionConfig",
    # Context tracking (v1.1)
    "ContextProvenance",
    "ContextState",
    "ContextTracker",
    # Memory (v1.1)
    "MemoryGate",
    "MemoryEntry",
    "MemoryDecision",
    "InMemoryMemoryStore",
    # Policy
    "PolicyEngine",
    "PolicyDecision",
    "RequestContext",
    # Tokens
    "ExecutionToken",
    "TokenStore",
    # Sessions
    "Session",
    "SessionStore",
    # Audit
    "AuditLogger",
    "AuditRecord",
    "FileAuditBackend",
    "InMemoryAuditBackend",
    # Rate limiting
    "RateLimiter",
    # Redaction
    "RedactionEngine",
    "RedactionResult",
    # Enums
    "RiskLevel",
    "AuthMethod",
    "DataClassification",
    "DataBoundary",
    "RecipientPolicy",
    "RedactionMode",
    "AuditLogLevel",
    "ApprovalThreshold",
    "ApprovalChannel",
    "ContextSource",
    "ContextAuthority",
    "DegradationEffect",
    "MemoryPersistence",
    "MemoryWriter",
    "DenialReason",
    "TokenStatus",
    # Exceptions
    "AgentLockError",
    "DeniedError",
    "AuthenticationRequiredError",
    "InsufficientRoleError",
    "ScopeViolationError",
    "RateLimitedError",
    "SessionExpiredError",
    "ApprovalRequiredError",
    "TrustDegradedError",
    "UnattributedContextError",
    "MemoryWriteDeniedError",
    "MemoryReadDeniedError",
    "MemoryRetentionExceededError",
    "MemoryProhibitedContentError",
    "MemoryConfirmationRequiredError",
    "TokenError",
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenReplayedError",
    "SchemaValidationError",
    "ConfigurationError",
]
