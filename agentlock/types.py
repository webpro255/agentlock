"""AgentLock type definitions and enumerations."""

from __future__ import annotations

from enum import Enum
from typing import Any

__all__ = [
    "RiskLevel",
    "AuthMethod",
    "DataClassification",
    "DataBoundary",
    "RecipientPolicy",
    "RedactionMode",
    "AuditLogLevel",
    "ApprovalThreshold",
    "ApprovalChannel",
    "DenialReason",
    "TokenStatus",
    "ToolName",
    "RoleName",
    "UserId",
    "SessionId",
    "TokenId",
    "AuditId",
    "Permissions",
]


class RiskLevel(str, Enum):
    """Tool risk classification."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthMethod(str, Enum):
    """Supported authentication mechanisms."""

    OAUTH2 = "oauth2"
    MAGIC_LINK = "magic_link"
    MFA = "mfa"
    API_KEY = "api_key"


class DataClassification(str, Enum):
    """Data sensitivity classification."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    MAY_CONTAIN_PII = "may_contain_pii"
    CONTAINS_PII = "contains_pii"
    CONTAINS_PHI = "contains_phi"
    CONTAINS_FINANCIAL = "contains_financial"


class DataBoundary(str, Enum):
    """Scope of data access."""

    AUTHENTICATED_USER_ONLY = "authenticated_user_only"
    TEAM = "team"
    ORGANIZATION = "organization"


class RecipientPolicy(str, Enum):
    """Allowed recipient scope for outbound communication tools."""

    KNOWN_CONTACTS_ONLY = "known_contacts_only"
    SAME_DOMAIN = "same_domain"
    ALLOWLIST = "allowlist"
    ANY = "any"


class RedactionMode(str, Enum):
    """How prohibited data types are handled."""

    AUTO = "auto"
    MANUAL = "manual"
    NONE = "none"


class AuditLogLevel(str, Enum):
    """Audit detail level."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


class ApprovalThreshold(str, Enum):
    """When human approval is triggered."""

    ALWAYS = "always"
    BULK_OPERATIONS = "bulk_operations"
    EXTERNAL_COMMUNICATION = "external_communication"
    FINANCIAL_ABOVE_LIMIT = "financial_above_limit"
    FIRST_INVOCATION_PER_SESSION = "first_invocation_per_session"


class ApprovalChannel(str, Enum):
    """Out-of-band approval delivery channel."""

    PUSH_NOTIFICATION = "push_notification"
    EMAIL = "email"
    SMS = "sms"
    IN_APP = "in_app"


class DenialReason(str, Enum):
    """Standardized denial codes."""

    NO_PERMISSIONS = "no_permissions"
    NOT_AUTHENTICATED = "not_authenticated"
    INSUFFICIENT_ROLE = "insufficient_role"
    SCOPE_VIOLATION = "scope_violation"
    RATE_LIMITED = "rate_limited"
    SESSION_EXPIRED = "session_expired"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DENIED = "approval_denied"
    DATA_POLICY_VIOLATION = "data_policy_violation"
    TOKEN_INVALID = "token_invalid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REPLAYED = "token_replayed"
    RECIPIENT_NOT_ALLOWED = "recipient_not_allowed"
    MAX_RECORDS_EXCEEDED = "max_records_exceeded"


class TokenStatus(str, Enum):
    """Execution token lifecycle states."""

    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


# Type aliases
ToolName = str
RoleName = str
UserId = str
SessionId = str
TokenId = str
AuditId = str
Permissions = dict[str, Any]
