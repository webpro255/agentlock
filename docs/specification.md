# AgentLock Specification v1.0

## Executive Summary

AI agents are being deployed with direct access to tools that can read databases, send emails, execute financial transactions, and modify production systems. Yet these tools have no standardized permission model. Every major agent framework — LangChain, CrewAI, AutoGen, and others — treats tool calls as trusted function invocations with no identity verification, scope constraints, or access control.

AgentLock defines an open standard for authorization in AI agent systems. It introduces a permissions schema that any tool can implement, any agent framework can enforce, and any security team can audit.

This specification is informed by empirical research: 187 multi-turn adversarial attack tests across 35 categories, tested against 6 frontier AI models.

## Design Principles

1. **Deny by default.** No permissions defined = denied. Always.
2. **Tool-level enforcement.** Each tool enforces its own permissions.
3. **Identity-bound access.** Every call associated with verified identity. Agent cannot assert identity — must be verified out-of-band.
4. **Least privilege.** Minimum access for the specific operation.
5. **Framework-agnostic.** Independent of any framework, LLM, or language.
6. **Auditable.** Every call generates an audit record.

## Schema Definition

### Risk Levels

| Level | Use Case | Default Behavior |
|-------|----------|-----------------|
| `none` | Read-only non-sensitive (get time, check weather) | Auto-allow, minimal logging |
| `low` | Read-only potentially sensitive (read own profile) | Auto-allow, standard logging |
| `medium` | Write operations limited scope (update profile) | Allow with auth, full logging |
| `high` | Write to external systems or PII access (send email) | Auth + scope check + full logging |
| `critical` | Financial, destructive, or bulk (transfer funds, delete data) | Auth + approval + full logging |

### Authentication

- `requires_auth` (boolean): Must be authenticated before tool executes.
- `auth_methods` (array): Acceptable mechanisms — `oauth2`, `magic_link`, `mfa`, `api_key`.
- **CRITICAL:** Authentication MUST occur out-of-band from agent conversation. Agent never sees, handles, or stores credentials.

### Authorization

- `allowed_roles` (array): Roles permitted to invoke. Empty = denied to everyone.
- Roles are defined by the deploying organization, not by AgentLock.

### Scope

- `data_boundary`: `authenticated_user_only` (default), `team`, `organization`
- `max_records`: Maximum records per invocation. Prevents bulk exfiltration.
- `allowed_recipients`: `known_contacts_only`, `same_domain`, `allowlist`, `any`

### Rate Limiting

- `max_calls`: Maximum invocations within window.
- `window_seconds`: Time window. Per-user, per-session.

### Data Policy

- `input_classification` / `output_classification`: Data sensitivity level.
- `prohibited_in_output`: Data types that must never appear in output.
- `redaction`: `auto` (pattern-based), `manual` (human review), `none` (public only).

### Session Management

- `max_duration_seconds`: Session lifetime. Must re-auth after expiry.
- `require_reauth_on_scope_change`: Changing data boundary requires re-auth.

### Audit (Not Optional)

- `log_level`: `minimal`, `standard`, `full`
- `include_parameters`: False for tools handling credentials.
- `retention_days`: Minimum retention period.

### Human Approval

- `required`: Whether every invocation needs approval.
- `threshold`: `always`, `bulk_operations`, `external_communication`, `financial_above_limit`, `first_invocation_per_session`
- `channel`: `push_notification`, `email`, `sms`, `in_app` — must be out-of-band.

## Enforcement Architecture

### Three-Layer Model

**Layer 1: Conversation Layer (Agent)**
- Agent reads/writes messages, decides which tool to call
- Agent CANNOT authenticate users, access backends, see credentials

**Layer 2: Authorization Gate (Infrastructure)**
- Receives tool call requests from Layer 1
- Validates AgentLock permissions
- Triggers auth flow if required
- Verifies identity, role, scope, rate limits
- Issues scoped execution token to Layer 3
- Generates audit records

**Layer 3: Tool Execution (Infrastructure)**
- Receives execution token from Layer 2
- Validates token matches requested operation
- Executes tool within scoped boundaries
- Enforces data policy
- Returns results via Layer 2
- Token is single-use, time-limited

**Key Constraint:** Agent never receives execution token. Layer 2 passes directly to Layer 3.

### Denial Response Format

```json
{
  "status": "denied",
  "reason": "insufficient_role",
  "required_role": "admin",
  "current_role": "customer",
  "suggestion": "This operation requires administrator access.",
  "audit_id": "agentlock-2026-03-10-00847"
}
```

## Attack Surface Analysis

| Attack Vector | Mitigation | Residual Risk |
|---------------|-----------|---------------|
| Identity impersonation | Cryptographic verification | None |
| Privilege escalation | Role checked on every call | None |
| Bulk data exfiltration | max_records + rate_limit + data_boundary | Low (slow within limits) |
| Token replay | Single-use, time-limited, operation-bound | None |
| Authenticated abuse | Rate limiting + audit + approval | Medium |
| Phishing via auth flow | Agent can't generate auth URLs | Low |
| Session hijacking | Device/IP binding + short expiry | Low |
| Indirect prompt injection | Infrastructure-enforced permissions | Low |

## Framework Alignment

- **OWASP Top 10 for LLM (2025):** LLM01, LLM05, LLM06
- **OWASP Top 10 for Agentic Apps (2026):** Goal hijacking, excessive agency, unauthorized tool use
- **NIST AI RMF (AI 100-1):** Govern, Map, Measure, Manage
- **NIST SP 800-53 Rev. 5:** AC, AU, IA, SI control families
- **MITRE ATLAS:** AML.T0051, AML.T0054
- **EU AI Act:** Transparency, human oversight, risk classification
