# Changelog

All notable changes to AgentLock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-30

### Added

- **Adaptive prompt hardening** -- When the gate detects suspicious activity (injection attempts, trust degradation, rate limiting), it generates defensive system prompt instructions for the agent framework to inject before the LLM processes the next turn. Session risk scores are monotonic and session-scoped. Three severity levels: warning, elevated, critical.
- **MODIFY decision type** -- Authorized tool calls can have their outputs transformed before the LLM sees them. Built-in actions: `redact_pii` (strips SSN, email, phone, credit card, API keys from output), `restrict_domain` (blocks external email recipients), `whitelist_path` (restricts file access to allowed directories), `cap_records` (limits output record count). Configured per-tool via `modify_policy`.
- **DEFER decision type** -- Suspends authorization when context is ambiguous. Triggers: first tool call in session is HIGH/CRITICAL risk with no history, prompt scanner fired and tool call attempted in the same turn, trust degraded below threshold. Defaults to DENY on timeout (60s).
- **STEP_UP decision type** -- Dynamically requires human approval based on session state. Triggers: hardening severity at elevated or above with HIGH/CRITICAL risk tool, multiple PII-returning tools already called in session, tool denied earlier and user retrying with a different high-risk tool. Pluggable notification via `StepUpNotifier` protocol.
- **DecisionType enum** -- Five authorization outcomes: `ALLOW`, `DENY`, `DEFER`, `STEP_UP`, `MODIFY`. `AuthResult.decision` field added alongside backward-compatible `AuthResult.allowed`.
- **Gate enforcement at critical severity** -- When session risk score exceeds the critical threshold (10+) and `enforce_at_critical` is enabled, the gate blocks HIGH/CRITICAL risk tools regardless of role authorization. MEDIUM/LOW tools remain allowed.
- **Prompt scanner** (`PromptScanner`) -- Pre-LLM analysis of user messages. Detects injection phrases, authority claims, instruction planting, encoding indicators, agent/system impersonation, format forcing, retrieval exploitation, and cross-turn repetition. Runs before the LLM processes the message, enabling hardening directives on the same turn.
- **Behavioral velocity detector** (`VelocityDetector`) -- Tracks tool call frequency and topic shifts per session. Fires on rapid calls (3+ in 60s), topic escalation (risk jump from low/medium to high/critical), and burst patterns (same tool 3+ in 30s).
- **Tool combination detector** (`ComboDetector`) -- Detects suspicious tool call sequences within a session. Configurable suspicion map with 13 default suspicious pairs and 5 default suspicious sequences covering data exfiltration, account takeover, and tool chain attack patterns.
- **Response echo detector** (`EchoDetector`) -- Framework-side signal that checks LLM responses for attack prompt echoing, tool name disclosure, system prompt leakage, credential-format strings, and compliance language in suspicious contexts.
- **Compound scoring** -- When multiple signal types co-occur, compound rules add bonus weight. `rapid_exfil` (velocity + combo, +2), `probing_attack` (echo + injection, +3).
- **Signal-aware targeted instructions** -- Hardening directives contain instructions specific to the detected signal types instead of generic severity-level text. Format forcing attacks get format-specific instructions, not irrelevant tool-blocking language.
- New schema models: `ModifyPolicyConfig`, `TransformationConfig`, `DeferPolicyConfig`, `StepUpPolicyConfig`
- New exceptions: `DeferredError`, `StepUpRequiredError`, `ModifyAppliedError`
- 276 new tests (745 total, 0 failures)

### Changed

- Schema version updated from `"1.1"` to `"1.2"`
- Package version updated to `1.2.0`
- Phone number redaction pattern expanded to cover 7-digit, US 10-digit, international (+44, +91, +1), and UK local (0-prefixed) formats
- `AuthorizationGate.__init__()` accepts optional `hardening_config`, `velocity_config`, `combo_config`
- `AuthorizationGate.execute()` accepts optional `modify_output_fn` for MODIFY output transformation
- `AuthorizationGate.authorize()` pipeline extended: velocity/combo signals recorded before policy evaluation, DEFER checked before STEP_UP, STEP_UP checked before MODIFY, MODIFY checked before token issuance

### Backward Compatibility

- All v1.0 and v1.1.x `agentlock` permission blocks remain valid
- `AuthResult.allowed` continues to work unchanged for existing callers
- New fields (`decision`, `modify_output_fn`, `deferral_id`, `stepup_request_id`) default to neutral values
- `execute()` works identically without the `modify_output_fn` parameter
- Hardening, velocity, combo, DEFER, STEP_UP, and MODIFY are all disabled by default when their respective config/policy objects are not provided
- All 469 original v1.1.2 tests pass without modification

## [1.1.2] - 2026-03-24

### Added

- **Independent filter pipeline** — Decoupled InjectionFilter and PiiFilter into separate classes on PolicyEngine. Each runs independently with no shared logic or state.
- **InjectionFilter** — Scans tool call parameters for reconnaissance/enumeration, prompt extraction, social engineering, and command injection patterns. Recursively inspects nested dicts and lists.
- **PiiFilter** — Checks caller's max_output_classification against tool's output_classification using 7-level classification hierarchy. Independent from injection filtering.
- 44 new tests (test_filter_pipeline.py)

### Changed

- PolicyEngine.evaluate() refactored into three independent stages: base auth, injection filter, PII filter
- Trust degradation now runs independently of both filters
- Package version updated to 1.1.2

### Fixed

- Injection pass rate recovered from 88.6% (v1.1.1) to 93.4% by restoring behavioral filters without PII interference

## [1.1.1] - 2026-03-24

### Added

- **Gate-level PII classification check** — max_output_classification parameter on authorize() blocks tool execution before data is retrieved when caller clearance is below tool's output classification
- 7-level classification hierarchy: PUBLIC, INTERNAL, CONFIDENTIAL, MAY_CONTAIN_PII, CONTAINS_PII, CONTAINS_PHI, CONTAINS_FINANCIAL
- 16 new tests (test_pii_defense.py)

### Fixed

- PII regression from v1.1: restored input-layer query blocking (100/A) while maintaining output-layer redaction as backup

### Backward Compatibility

- max_output_classification defaults to None. When not provided, check is skipped entirely. No existing callers affected.

## [1.1.0] - 2026-03-20

### Added

- **Context authority model** — `context_policy` block on `AgentLockPermissions` with `source_authorities` mapping context sources (user messages, tool outputs, web content, peer agents, etc.) to authority levels (`authoritative`, `derived`, `untrusted`)
- **Trust degradation** — `TrustDegradationConfig` with per-session trust that monotonically degrades when untrusted content enters context. Effects: `require_approval`, `elevate_logging`, `restrict_scope`, `deny_writes`. Trust never escalates within a session.
- **`allow_cascade_to_untrusted`** flag for security-critical deployments that need maximum restriction after contamination
- **Memory access control** — `memory_policy` block with `allowed_writers`, `allowed_readers`, `prohibited_content`, `retention` limits, and `require_write_confirmation`
- **Provenance tracking** — `ContextProvenance` dataclass with source, authority, writer identity, timestamp, content hash, and token binding for every context write
- **`ContextTracker`** — per-session provenance log and trust state management on the authorization gate
- **`MemoryGate`** — validates memory read/write operations against `MemoryPolicyConfig` with lazy retention enforcement
- **`notify_context_write()`** on `AuthorizationGate` — framework integrations report context entries to the gate
- **`authorize_memory_write()` / `authorize_memory_read()`** on `AuthorizationGate`
- **New enums**: `ContextSource`, `ContextAuthority`, `DegradationEffect`, `MemoryPersistence`, `MemoryWriter`
- **New denial reasons**: `TRUST_DEGRADED`, `UNATTRIBUTED_CONTEXT`, `CONTEXT_AUTHORITY_VIOLATION`, `MEMORY_WRITE_DENIED`, `MEMORY_READ_DENIED`, `MEMORY_RETENTION_EXCEEDED`, `MEMORY_PROHIBITED_CONTENT`, `MEMORY_CONFIRMATION_REQUIRED`
- **New audit actions**: `trust_degraded`, `memory_write`, `memory_write_denied`, `memory_read`, `memory_read_denied`, `memory_expired`, `context_rejected`
- **New audit fields**: `trust_ceiling`, `is_trust_degraded`, `degradation_effects`, `context_provenance_ids`, `memory_operation`, `memory_entry_id`
- **New exception classes**: `TrustDegradedError`, `UnattributedContextError`, `MemoryWriteDeniedError`, `MemoryReadDeniedError`, `MemoryRetentionExceededError`, `MemoryProhibitedContentError`, `MemoryConfirmationRequiredError`
- CLI `validate` and `inspect` commands now display v1.1 context and memory policy fields
- `agentlock init` now generates v1.1 templates
- 142 new tests (409 total)

### Changed

- Schema version default updated from `"1.0"` to `"1.1"`
- Package version updated to `1.1.0`

### Backward Compatibility

- All v1.0 `agentlock` blocks remain valid — new fields are optional with secure defaults
- When `version` is `"1.0"`, the gate skips all v1.1 checks entirely
- All 267 original tests continue to pass without modification

## [1.0.0] - 2026-03-18

### Added

- Core AgentLock permissions schema (v1.0)
- `AuthorizationGate`  central enforcement point with deny-by-default semantics
- `AgentLockPermissions`  Pydantic model for the `agentlock` permissions block
- `@agentlock` decorator for one-line tool protection
- Single-use, time-limited, operation-bound execution tokens
- Session management with expiry and scope tracking
- Sliding-window per-user, per-tool rate limiting
- Automatic data redaction engine with built-in PII patterns
- Policy evaluation engine with 7-step authorization checks
- Pluggable audit logging with file and in-memory backends
- CLI tool: `agentlock validate`, `agentlock schema`, `agentlock init`, `agentlock inspect`, `agentlock audit`
- Framework integrations: LangChain, CrewAI, AutoGen, MCP, FastAPI, Flask
- JSON Schema for tool definition validation
- Comprehensive test suite
- Working examples for all major use cases
- Full documentation
- GitHub Actions CI/CD pipeline
- Apache 2.0 license
