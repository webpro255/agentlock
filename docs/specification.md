# AgentLock Specification v1.2

## Executive Summary

AI agents are being deployed with direct access to tools that can read databases, send emails, execute financial transactions, and modify production systems. Yet these tools have no standardized permission model. Every major agent framework LangChain, CrewAI, AutoGen, and others treats tool calls as trusted function invocations with no identity verification, scope constraints, or access control.

AgentLock defines an open standard for authorization in AI agent systems. It introduces a permissions schema that any tool can implement, any agent framework can enforce, and any security team can audit.

This specification is informed by empirical research: 222 multi-turn adversarial attack tests across 35 categories, tested against frontier AI models.

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

## Decision Types (v1.2)

v1.0 supported ALLOW and DENY. v1.2 adds MODIFY, DEFER, and STEP_UP.

| Decision | When | Effect |
|----------|------|--------|
| ALLOW | Call is authorized | Token issued, tool executes normally |
| DENY | Call is not authorized | No token, structured denial returned |
| MODIFY | Call is authorized but output must be transformed | Token issued, transformations applied before LLM sees output |
| DEFER | Context is ambiguous, gate cannot decide | Action suspended, resolves via human review or timeout (default: DENY) |
| STEP_UP | Session state indicates elevated risk | Action paused, human approval required via configured channel |

### MODIFY Policy

Per-tool output and parameter transformations. Built-in actions: `redact_pii`, `restrict_domain`, `whitelist_path`, `cap_records`. When `whitelist_path` blocks a parameter, the decision escalates from MODIFY to DENY.

### DEFER Policy

Triggers: `first_call_any_risk` (first call in session, any risk level), `first_call_high_risk` (first HIGH/CRITICAL call), `scan_plus_tool` (prompt scanner fired and tool call attempted), `trust_below_threshold` (trust degraded below floor). Sibling deferral: when one tool is deferred in a turn, co-occurring tool calls are also deferred. Prompt scan carry-forward: scan signals defer ALL tools regardless of defer_policy configuration.

### STEP_UP Policy

Triggers: `hardening_elevated_high_risk` (session at elevated+ severity with HIGH/CRITICAL tool), `multi_pii_tool_session` (threshold of PII tools already called), `post_denial_retry` (tool denied earlier, user retrying with different high-risk tool).

## Adaptive Prompt Hardening (v1.2)

When the gate detects suspicious activity, it accumulates signals into a monotonic session risk score and generates defensive system prompt instructions for the agent framework to inject.

### Signal Detectors

| Detector | Signals |
|----------|---------|
| Prompt scanner | Injection phrases, authority claims, instruction planting, encoding, impersonation, format forcing, retrieval, cross-turn repetition |
| Velocity detector | Rapid calls (3+ in 60s), topic escalation (risk jump), burst patterns (same tool 3+ in 30s) |
| Combo detector | 16 suspicious tool pairs, 5 suspicious sequences |
| Echo detector | Attack prompt echoing, tool name disclosure, system prompt leakage |

### Hardening Severity Levels

| Level | Threshold | Effect |
|-------|-----------|--------|
| Warning | Score >= 3 | Targeted instructions injected |
| Elevated | Score >= 6 | Stronger instructions, STEP_UP may fire |
| Critical | Score >= 10 | `enforce_at_critical` blocks HIGH/CRITICAL tools; `enforce_all_at_critical` blocks ALL tools |

### Compound Rules

When multiple signal types co-occur, compound rules add bonus weight. `rapid_exfil` (velocity + combo, +2), `probing_attack` (echo + injection, +3).

## Signed Receipts (v1.2.1, AARM R5)

Every authorization decision can produce a cryptographically signed receipt.

### Receipt Schema

A `SignedReceipt` contains: `receipt_id`, `timestamp`, `decision`, `tool_name`, `user_id`, `role`, `parameters_hash` (SHA-256 of parameters), `reason`, `policy_version_hash`, `context_hash`, `trust_ceiling`, `signing_key_id`, `signature`.

### Signature Methods

- **Ed25519** (default): Fast, small signatures. Requires PyNaCl (`pip install agentlock[crypto]`).
- **HMAC-SHA256** (fallback): Symmetric key. No additional dependencies.

### Verification

`ReceiptVerifier` accepts the public key (Ed25519) or shared secret (HMAC) and verifies the receipt's signature. Tampered receipts fail verification. Receipts are verifiable offline without access to the gate.

## Hash-Chained Context (v1.2.1, AARM R2)

Each context entry includes the hash of the previous entry, forming a tamper-evident append-only chain.

### Chain Structure

- `GENESIS_HASH`: SHA-256 of empty string. The chain's starting point.
- Each `ChainedContextEntry` contains: `entry_id`, `timestamp`, `source`, `authority`, `content_hash`, `previous_hash`, `entry_hash` (SHA-256 of previous_hash + content_hash + metadata).
- `verify_chain()` recomputes every entry's hash and validates the previous_hash linkage. Returns `(True, None)` if intact or `(False, index)` if tampered at `index`.

### Integration with Context Tracking

`ContextProvenance` gains a `previous_hash` field populated automatically when `ContextTracker.record_write()` is called. `ContextTracker.verify_context_chain(session_id)` validates the chain for a given session.

## AARM Conformance

| Requirement | Status |
|-------------|--------|
| R1 (action mediation) | Covered: DENY + DEFER + fail-closed |
| R2 (context accumulation) | Covered: hash-chained, tamper-detected |
| R3 (policy engine) | Covered: immediate deny, context-dependent, pluggable |
| R4 (5 decision types) | Covered: ALLOW, DENY, MODIFY, STEP_UP, DEFER |
| R5 (signed receipts) | Covered: Ed25519, offline verification, tamper detection |
| R7 (drift detection) | Covered: trust degradation + DEFER on novel patterns |
| R9 (least privilege) | Covered: per-tool scoping + deny by default |

## Framework Alignment

- **OWASP Top 10 for LLM (2025):** LLM01, LLM05, LLM06
- **OWASP Top 10 for Agentic Apps (2026):** Goal hijacking, excessive agency, unauthorized tool use
- **NIST AI RMF (AI 100-1):** Govern, Map, Measure, Manage
- **NIST SP 800-53 Rev. 5:** AC, AU, IA, SI control families
- **MITRE ATLAS:** AML.T0051, AML.T0054
- **EU AI Act:** Transparency, human oversight, risk classification
