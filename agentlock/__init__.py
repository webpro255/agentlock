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

__version__ = "1.2.1"

from agentlock.audit import AuditLogger, AuditRecord, FileAuditBackend, InMemoryAuditBackend
from agentlock.chain import GENESIS_HASH, ChainedContextEntry, ContextChain
from agentlock.context import ContextProvenance, ContextState, ContextTracker
from agentlock.decorators import agentlock
from agentlock.defer import DeferralManager, DeferralRecord
from agentlock.exceptions import (
    AgentLockError,
    ApprovalRequiredError,
    AuthenticationRequiredError,
    ConfigurationError,
    DeferredError,
    DeniedError,
    InsufficientRoleError,
    MemoryConfirmationRequiredError,
    MemoryProhibitedContentError,
    MemoryReadDeniedError,
    MemoryRetentionExceededError,
    MemoryWriteDeniedError,
    ModifyAppliedError,
    RateLimitedError,
    SchemaValidationError,
    ScopeViolationError,
    SessionExpiredError,
    StepUpRequiredError,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenReplayedError,
    TrustDegradedError,
    UnattributedContextError,
)
from agentlock.gate import AuthorizationGate, AuthResult
from agentlock.hardening import (
    HardeningConfig,
    HardeningDirective,
    HardeningEngine,
    HardeningSignal,
)
from agentlock.memory_gate import InMemoryMemoryStore, MemoryDecision, MemoryEntry, MemoryGate
from agentlock.modify import ModifyEngine, ModifyResult
from agentlock.policy import (
    InjectionFilter,
    PiiFilter,
    PolicyDecision,
    PolicyEngine,
    RequestContext,
)
from agentlock.rate_limit import RateLimiter
from agentlock.receipts import ReceiptSigner, ReceiptVerifier, SignedReceipt
from agentlock.redaction import RedactionEngine, RedactionResult
from agentlock.schema import (
    SCHEMA_VERSION,
    AgentLockPermissions,
    AuditConfig,
    ContextPolicyConfig,
    DataPolicyConfig,
    DeferPolicyConfig,
    DegradationTrigger,
    HumanApprovalConfig,
    MemoryPolicyConfig,
    MemoryRetentionConfig,
    ModifyPolicyConfig,
    RateLimitConfig,
    ScopeConfig,
    SessionConfig,
    SourceAuthorityConfig,
    StepUpPolicyConfig,
    ToolDefinition,
    TransformationConfig,
    TrustDegradationConfig,
)
from agentlock.session import Session, SessionStore
from agentlock.signals import (
    ComboDetector,
    ComboSignal,
    EchoDetector,
    EchoSignal,
    PromptScanConfig,
    PromptScanner,
    VelocityDetector,
    VelocitySignal,
)
from agentlock.stepup import StepUpManager, StepUpNotifier, StepUpRequest
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
    DecisionType,
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
    "DeferPolicyConfig",
    "ModifyPolicyConfig",
    "StepUpPolicyConfig",
    "TransformationConfig",
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
    "InjectionFilter",
    "PiiFilter",
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
    # DEFER (v1.2)
    "DeferralManager",
    "DeferralRecord",
    "DeferredError",
    # STEP_UP (v1.2)
    "StepUpManager",
    "StepUpRequest",
    "StepUpNotifier",
    "StepUpRequiredError",
    # MODIFY (v1.2)
    "ModifyEngine",
    "ModifyResult",
    # Signed receipts (AARM R5)
    "SignedReceipt",
    "ReceiptSigner",
    "ReceiptVerifier",
    # Hash-chained context (AARM R2)
    "ChainedContextEntry",
    "ContextChain",
    "GENESIS_HASH",
    # Enums
    "DecisionType",
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
    # Hardening
    "HardeningEngine",
    "HardeningDirective",
    "HardeningSignal",
    "HardeningConfig",
    # Signals
    "VelocityDetector",
    "VelocitySignal",
    "ComboDetector",
    "ComboSignal",
    "EchoDetector",
    "EchoSignal",
    "PromptScanner",
    "PromptScanConfig",
    # Exceptions
    "AgentLockError",
    "ModifyAppliedError",
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
