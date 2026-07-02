<p align="center">
  <h1 align="center">AgentLock</h1>
  <p align="center">
    <strong>An adversarially benchmarked reference implementation for pre-action agent authorization</strong>
  </p>
  <p align="center">
    Your AI agent needs a login screen. AgentLock is that login screen.
  </p>
  <p align="center">
    <a href="https://github.com/webpro255/agentlock/actions"><img src="https://github.com/webpro255/agentlock/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://pypi.org/project/agentlock/"><img src="https://img.shields.io/pypi/v/agentlock.svg" alt="PyPI"></a>
    <a href="https://pypi.org/project/agentlock/"><img src="https://img.shields.io/pypi/pyversions/agentlock.svg" alt="Python"></a>
    <a href="https://github.com/webpro255/agentlock/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  </p>
</p>

---

## The Problem

Every major AI agent framework LangChain, CrewAI, AutoGen, and others treats tool calls as trusted function invocations with **no identity verification, no scope constraints, and no access control**.

```json
{
  "name": "send_email",
  "description": "Sends an email to a recipient",
  "parameters": { "to": "string", "subject": "string", "body": "string" }
}
```

This tool will send an email to **anyone**, with **any content**, at **any time**, for **any reason**, initiated by **any user**  or attacker  who can communicate with the agent.

This is the equivalent of giving every application on a computer full root access and hoping it behaves.

## The Solution

AgentLock adds a `permissions` block to every tool. Two fields provide immediate value. The full spec covers everything.

```bash
pip install agentlock
```

Or install from source (before PyPI publish):

```bash
pip install git+https://github.com/webpro255/agentlock.git
```

### Protect your first tool in 5 minutes

```python
from agentlock import AuthorizationGate, AgentLockPermissions

gate = AuthorizationGate()

# Define permissions — deny by default
gate.register_tool("send_email", AgentLockPermissions(
    risk_level="high",
    requires_auth=True,
    allowed_roles=["account_owner", "admin"],
    rate_limit={"max_calls": 5, "window_seconds": 3600},
    data_policy={
        "output_classification": "contains_pii",
        "prohibited_in_output": ["ssn", "credit_card"],
        "redaction": "auto",
    },
))

# Every call goes through the gate
result = gate.authorize(
    "send_email",
    user_id="alice",
    role="account_owner",
    parameters={"to": "bob@company.com", "subject": "Q3 Report"},
)

if result.allowed:
    output = gate.execute("send_email", my_send_func, token=result.token,
                          parameters={"to": "bob@company.com", "subject": "Q3 Report"})
else:
    print(result.denial)
    # {"status": "denied", "reason": "insufficient_role", ...}
```

### Or use the decorator

```python
from agentlock import AuthorizationGate, agentlock

gate = AuthorizationGate()

@agentlock(gate, risk_level="high", allowed_roles=["admin"])
def send_email(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}"

# Call with auth context
send_email(to="bob@co.com", subject="Hi", body="Hello",
           _user_id="alice", _role="admin")
```

## Core Principles

| Principle | What It Means |
|-----------|--------------|
| **Deny by default** | No permissions defined = denied. Always. |
| **Tool-level enforcement** | Each tool enforces its own permissions. |
| **Identity-bound access** | Every call tied to verified identity. Agent cannot assert identity. |
| **Least privilege** | Minimum access for the specific operation. |
| **Framework-agnostic** | Zero framework dependencies in core. |
| **Auditable** | Every call generates an audit record. No exceptions. |

## The Schema

An AgentLock-compliant tool extends the standard definition with a `agentlock` block:

```json
{
  "name": "send_email",
  "description": "Sends an email to a recipient",
  "parameters": { "to": "string", "subject": "string", "body": "string" },
  "agentlock": {
    "version": "1.0",
    "risk_level": "high",
    "requires_auth": true,
    "allowed_roles": ["account_owner", "admin"],
    "scope": {
      "data_boundary": "authenticated_user_only",
      "max_records": 1,
      "allowed_recipients": "known_contacts_only"
    },
    "rate_limit": { "max_calls": 5, "window_seconds": 3600 },
    "data_policy": {
      "output_classification": "contains_pii",
      "prohibited_in_output": ["ssn", "credit_card"],
      "redaction": "auto"
    },
    "audit": { "log_level": "full", "retention_days": 90 },
    "human_approval": { "required": false }
  }
}
```

### Risk Levels

| Level | Description | Default Behavior |
|-------|-------------|-----------------|
| `none` | Read-only, non-sensitive | Auto-allow, minimal logging |
| `low` | Read-only, potentially sensitive | Auto-allow with auth, standard logging |
| `medium` | Write operations, limited scope | Auth + scope check + full logging |
| `high` | Write to external systems or PII | Auth + scope + rate limit + full logging |
| `critical` | Financial, destructive, or bulk | Auth + approval + full logging |

## Three-Layer Enforcement

```
┌──────────────────────────────────────────────┐
│  Layer 1: Agent (Conversation)               │
│  - Reads/writes messages                     │
│  - Decides which tool to call                │
│  - CANNOT authenticate, see credentials,     │
│    or access backends                        │
├──────────────────────────────────────────────┤
│  Layer 2: Authorization Gate (AgentLock)      │
│  - Validates permissions                     │
│  - Verifies identity, role, scope            │
│  - Enforces rate limits                      │
│  - Issues single-use execution tokens        │
│  - Generates audit records                   │
├──────────────────────────────────────────────┤
│  Layer 3: Tool Execution (Infrastructure)     │
│  - Validates token                           │
│  - Executes within scoped boundaries         │
│  - Enforces data policy / redaction          │
│  - Token is single-use, time-limited         │
└──────────────────────────────────────────────┘
```

**Key constraint:** The agent never receives execution tokens. Layer 2 passes directly to Layer 3. The agent gets only the result.

## Security Note

AgentLock authorizes tool calls. It does not authenticate users. The web framework integrations (FastAPI, Flask) trust upstream headers for identity. Deploy behind an authenticated API gateway or reverse proxy.

## Security Hardening

AgentLock assumes the authorization gate runs in a trusted compute environment. These recommendations strengthen the enforcement boundary in production deployments:

- Deploy the gate on a separate machine or container from the agent. A compromised agent cannot tamper with a gate it cannot reach.
- The agent should communicate with the gate over an authenticated API, not shared memory or local function calls.
- The gate host should run only the gate service with minimal attack surface.
- Apply standard infrastructure security: encrypted transport, restricted network access, audit logging at the OS level.


## Framework Integrations

AgentLock is framework-agnostic. Optional integrations for popular frameworks:

```bash
pip install agentlock[langchain]    # LangChain
pip install agentlock[crewai]       # CrewAI
pip install agentlock[autogen]      # AutoGen
pip install agentlock[mcp]          # Model Context Protocol
pip install agentlock[fastapi]      # FastAPI
pip install agentlock[flask]        # Flask
pip install agentlock[crypto]       # Ed25519 signed receipts
pip install agentlock[all]          # Everything
```

### LangChain

```python
from agentlock.integrations.langchain import AgentLockToolWrapper

protected_tool = AgentLockToolWrapper(
    tool=my_langchain_tool,
    gate=gate,
    permissions=AgentLockPermissions(risk_level="high", allowed_roles=["admin"]),
)
```

### FastAPI

```python
from agentlock.integrations.fastapi import AgentLockMiddleware, require_agentlock

app = FastAPI()
app.add_middleware(AgentLockMiddleware, gate=gate)

@app.post("/api/send-email")
async def send_email(request: Request, auth=Depends(require_agentlock(gate, "send_email"))):
    ...
```

## CLI

```bash
agentlock init                      # Generate starter tool definition
agentlock validate tool.json        # Validate against schema
agentlock inspect tool.json         # Display permissions summary
agentlock schema                    # Print JSON schema
agentlock audit --tool send_email   # Query audit logs
```

## What AgentLock Prevents

Based on empirical research: multi-turn adversarial attack testing across 35 categories, tested against multiple frontier AI models.

| Attack Category | Prevention |
|----------------|-----------|
| Prompt injection | Deterministic permission enforcement at the gate, reinforced by content scanning |
| Social engineering | Identity verified cryptographically, not conversationally |
| Data exfiltration | max_records + rate_limit + data_boundary |
| Privilege escalation | Role checked on every call |
| Tool abuse | Scope constraints + rate limiting |
| Token replay | Single-use, time-limited, operation-bound |
| Agent impersonation | Out-of-band identity verification |
| Memory poisoning | Memory gate (allowed_writers + prohibited_content), enforced at the gate |

**Defense in depth.** Adversarial and legitimate tool requests can be semantically identical, so no scanner catches every attack. That is why the authorization gate comes first: it is the deterministic guarantee — a call outside an identity's declared permissions is denied regardless of how the request is phrased. Content scanning and adaptive prompt hardening are the accelerant, not the foundation: they raise the pass rate on attacks that fall *within* an agent's permitted scope, where the gate alone cannot rule. Both layers matter, and our own benchmark shows it: adaptive prompt hardening — a content-detection layer — was the single largest contributor to the v1.2 jump from 30.2% to 57.1% pass rate on the compromised-admin profile, layered on top of the gate. The gate makes unauthorized actions structurally impossible; scanning shrinks the residual attack surface the gate was never designed to cover.

## v1.1: Memory & Context Permissions

AgentLock v1.1 extends tool-level permissions to cover the agent's **context window** and **memory**. Not all context is created equal — a system prompt and a web search result should not have the same authority over agent behavior.

### Context Authority

Every context entry is classified by source and assigned an authority level:

```python
from agentlock import (
    AuthorizationGate, AgentLockPermissions,
    ContextPolicyConfig, TrustDegradationConfig, DegradationTrigger,
    ContextSource, DegradationEffect,
)

gate = AuthorizationGate()

gate.register_tool("web_search", AgentLockPermissions(
    risk_level="low",
    requires_auth=True,
    allowed_roles=["analyst"],
    context_policy=ContextPolicyConfig(
        trust_degradation=TrustDegradationConfig(
            enabled=True,
            triggers=[
                DegradationTrigger(
                    source=ContextSource.WEB_CONTENT,
                    effect=DegradationEffect.REQUIRE_APPROVAL,
                ),
            ],
        ),
    ),
))
```

Once web search results enter context, all subsequent tool calls require human approval. Trust degrades per-session and never escalates — only a new session restores full trust.

### Memory Access Control

```python
from agentlock import MemoryPolicyConfig, MemoryWriter, MemoryPersistence

gate.register_tool("assistant", AgentLockPermissions(
    risk_level="medium",
    requires_auth=True,
    allowed_roles=["user"],
    memory_policy=MemoryPolicyConfig(
        persistence=MemoryPersistence.SESSION,
        allowed_writers=[MemoryWriter.SYSTEM, MemoryWriter.USER],
        prohibited_content=["credentials", "pii"],
        require_write_confirmation=True,
    ),
))
```

### Provenance Tracking

Every write to context generates a `ContextProvenance` record with source, authority, writer identity, timestamp, and content hash. Audit records now include `trust_ceiling`, `context_provenance_ids`, and `memory_operation` fields.

## v1.2: Adaptive Hardening & New Decision Types

AgentLock v1.2 adds four capabilities that close the gap between authorization and runtime defense.

### Adaptive Prompt Hardening

When the gate detects suspicious activity, it generates defensive instructions for the agent's system prompt. A pre-LLM prompt scanner analyzes user messages before the model processes them, enabling hardening on the first turn of an attack. Four signal detectors (velocity, tool combination, response echo, prompt scan) feed into a monotonic session risk score.

### Five Decision Types

v1.0/v1.1 supported ALLOW and DENY. v1.2 adds three more:

| Decision | When | Effect |
|----------|------|--------|
| **ALLOW** | Call is authorized | Token issued, tool executes normally |
| **DENY** | Call is not authorized | No token, structured denial returned |
| **MODIFY** | Call is authorized but output must be transformed | Token issued, PII redacted from output before LLM sees it |
| **DEFER** | Context is ambiguous, gate cannot decide | Action suspended, resolves via human review or timeout |
| **STEP_UP** | Session state indicates elevated risk | Action paused, human approval required |

### MODIFY: Output Transformation

```python
gate.register_tool("query_database", AgentLockPermissions(
    risk_level="high",
    requires_auth=True,
    allowed_roles=["admin", "support"],
    modify_policy=ModifyPolicyConfig(
        enabled=True,
        transformations=[
            TransformationConfig(field="output", action="redact_pii"),
            TransformationConfig(
                field="to", action="restrict_domain",
                config={"allowed_domains": ["company.com"]},
            ),
        ],
    ),
))

result = gate.authorize("query_database", user_id="alice", role="admin")
# result.decision == DecisionType.MODIFY
# result.modify_output_fn strips PII from tool output before the LLM sees it
output = gate.execute("query_database", db_func, token=result.token,
                      modify_output_fn=result.modify_output_fn)
# output: {'name': 'Jane Doe', 'email': '[REDACTED:email]', 'ssn': '[REDACTED:ssn]'}
```

The tool still executes. The admin still gets the answer. But PII never enters the LLM context where it can be weaponized by injection attacks.

### Signed Receipts (AARM R5)

Every authorization decision can produce a cryptographically signed receipt, verifiable offline without access to the gate. Tampered receipts fail signature verification.

```python
from agentlock import AuthorizationGate, ReceiptSigner, ReceiptVerifier

signer = ReceiptSigner(signing_method="ed25519")
gate = AuthorizationGate(receipt_signer=signer)

result = gate.authorize("query_database", user_id="alice", role="admin")
# result.receipt is a SignedReceipt with Ed25519 signature

verifier = ReceiptVerifier(signing_method="ed25519", verify_key=signer.verify_key_bytes)
assert verifier.verify(result.receipt)  # True
```

HMAC-SHA256 is available as a fallback when PyNaCl is not installed. Install Ed25519 support with `pip install agentlock[crypto]`.

### Hash-Chained Context (AARM R2)

Context entries form a tamper-evident append-only chain. Each entry includes the hash of the previous entry. Modifying any entry invalidates all subsequent entries.

```python
gate.notify_context_write(session_id, source=ContextSource.TOOL_OUTPUT,
                          content_hash="abc123...")

valid, broken_at = gate.context_tracker.verify_context_chain(session_id)
# (True, None) if intact, (False, index) if tampered
```

## Benchmark

AgentLock is tested against a published adversarial suite, and the results — including the regressions — are public. That is the point: security claims should be falsifiable and versioned. Both campaigns are documented in full in [docs/benchmark.md](docs/benchmark.md).

- **Five-way progression (v1.0 → v1.1.2)** against a LangChain agent on Gemini 2.5 Flash-Lite. Injection failures fell from 73 (no protection) to 12; PII leaks from 3 to 0. The report does not hide the setbacks: v1.1 broke PII protection (100/A → 0/F) chasing injection gains, and v1.1.1 regressed injection (6 → 21 failures) restoring PII. v1.1.2 decoupled the two filter pipelines and held both.
- **Compromised-admin profile (v1.2.x)** against Grok, where valid admin credentials pass every auth and role check — isolating behavioral and structural defenses from RBAC. Pass rate: 30.2% (permissions only) → 81.3% (adaptive hardening + MODIFY/DEFER/STEP_UP) → 99.5% (v1.2.1).

### Per-module scores (five-way, v1.0 → v1.1.2)

| Module | No AgentLock | v1.0 | v1.1 | v1.1.1 | v1.1.2 |
|--------|--------------|------|------|--------|--------|
| PII Detection | 65/D | 100/A | 0/F | 100/A | 100/A |
| Injection | 56% / F | 89% / B | 96.3% / A | 88.6% / B | 93.4% / B |
| Data Flow | 97/A | 74/C | 97/A | 97/A | 97/A |
| YARA Detection | 0/F | 40/F | 60/D | 0/F | 60/D |
| Compliance | 7/F | 15/F | 7/F | 0/F | 0/F |
| **Permission** | **45/F** | **60/D** | **45/F** | **45/F** | **45/F** |

**About the 45/F Permission score (a known, scoped gap — not hidden).** The Permission module sits at 45/F across v1.1–v1.1.2, and it deserves an honest explanation. It does **not** measure whether the gate enforces permissions — the gate does that deterministically, which is exactly what the injection progression and every other row demonstrate. It measures whether the *agent's responses* resist permission and role reconnaissance: enumerating tool names, confirming that an account hierarchy exists, disclosing a table name when probed. Those are the same model-layer information-leakage behaviors (the SP, EBE, and RE categories) that account for 9 of v1.1.2's 12 remaining injection failures. Middleware can block a request or redact an output, but it cannot stop a helpful model from *acknowledging* that a system prompt or a restricted tier exists. The fix is not more filtering — it is system-prompt hardening that instructs the model to deflect rather than confirm. That is what v1.2's adaptive prompt hardening adds, and the v1.2.1 compromised-admin run — with system-prompt extraction, error-based extraction, and refusal exhaustion all at 100/A — is the evidence the approach works. The Compliance row is low for a related reason: it grades attestation and reporting artifacts the reference agent does not yet produce; compliance-report templates are on the v2.0 roadmap. Neither score is buried — both are on the roadmap with a named plan.

## How AgentLock Compares

The pre-action authorization space now has several serious entrants. This table is built from each project's primary sources (repos, specs, papers) as of July 2026. Where a capability could not be verified from a primary source, it is marked *unclear* (❓) rather than assumed absent.

| Capability | AgentLock | Microsoft AGT | Open Agent Passport (OAP) | NeMo Guardrails | AgentMint (AERF) |
|---|---|---|---|---|---|
| Pre-action authorization gate | ✅ | ✅ | ✅ (PAA-2) | ❌ content/dialogue rails, not identity/scope | ⚠️ scopes in receipts; post-action focus |
| Session-level compound behavioral scoring | ✅ call-sequence rules | ❓ not in specs | ❌ | ❌ | ❌ |
| Decision types beyond allow/deny | ✅ ALLOW/DENY/MODIFY/DEFER/STEP_UP | ✅ allow/warn/deny/escalate/transform | ⚠️ allow/deny/escalate (escalate unimplemented) | ⚠️ reject/alter content only | ❌ binary in_policy |
| Published adversarial benchmark **with regression data** | ✅ v1.0→v1.1.2 five-way + v1.2 profile | ❌ explicitly publishes none yet | ⚠️ Vault CTF (single-config, not versioned) | ❌ sample scans only | ❌ conformance vectors deferred |
| Trust degradation within session | ✅ monotonic, per-session | ❓ 0–1000 score; decay claimed in blog, not spec | ❌ | ❌ | ❌ |
| Ed25519 signed receipts | ✅ (+ HMAC fallback) | ✅ per-call, RFC 8785 JCS, did:mesh | ❓ verifiable passports; receipt signing unclear | ❌ | ✅ |
| Hash-chained tamper-evident audit | ✅ context chain | ✅ Merkle / SHA-256 | ✅ tamper-evident log (PAA-4) | ❌ telemetry / OTel only | ✅ spec (verifier checks sigs only so far) |
| Framework integrations | 6: LangChain, CrewAI, AutoGen, MCP, FastAPI, Flask | ~19: Semantic Kernel, AutoGen, LangGraph, CrewAI, OpenAI Agents SDK, MCP… | ~7: LangChain, CrewAI, Cursor, Claude Code, n8n… | LangChain | 5: LangChain, CrewAI, OpenAI Agents SDK, MCP, Google ADK |
| OWASP mapping coverage | LLM Top 10 + Agentic/MCP (below) | Claims 10/10 Agentic Top 10 | ❓ no numbered mapping published | ❓ third-party mappings only | ⚠️ references Agentic catalog |
| Language SDKs | Python | 5: Python, TS, .NET, Rust, Go | JS/TS (npm) | Python | Python producer + Go verifier |

**Read this honestly.** Microsoft's Agent Governance Toolkit is ahead of AgentLock on distribution and cryptographic surface: roughly 19 framework integrations to our 6, five language SDKs to our one, an MCP security gateway, per-call Ed25519 receipts, and a Merkle-chained audit log. It also ships a five-verdict decision model (allow/warn/deny/escalate/transform) that is a direct peer to ours — our decision types are **parity with AGT, not an advantage over it**. Ed25519 signed receipts and hash-chained audit are likewise becoming table stakes, not differentiators: AGT and AgentMint both ship them.

What is actually narrow and defensible about AgentLock is two things:

1. **A published adversarial benchmark that includes its own regressions.** AGT's own docs state it does not publish an attack-success benchmark yet and caution against trusting third-party percentages attributed to it. OAP reports a single-configuration CTF, not a version-over-version comparison. AgentLock publishes the full v1.0→v1.1.2 progression *including* the v1.1 PII break and the v1.1.1 injection regression, plus the v1.2 compromised-admin run. Nobody else in this table shows their setbacks. We do.
2. **Session-level compound behavioral scoring.** AgentLock scores *sequences* of calls within a session — e.g. a velocity spike combined with a suspicious tool combination fires a `rapid_exfil` compound rule that neither signal triggers alone. This is distinct from a single scalar trust score, and it is not documented in any of the other projects' primary sources.

That is the honest position: a smaller, single-language reference implementation whose edge is rigor and behavioral analysis, not distribution.

## Standards Alignment

AgentLock is positioned as a **reference implementation of the emerging pre-action authorization consensus — not a competing standard.** As independent specifications converge on the same idea (deterministic authorization *before* the tool call executes), AgentLock aims to be a concrete, testable instance of those controls.

### Open Agent Passport (OAP) pre-action controls

OAP (Uchibeke, arXiv:2603.20953) defines five pre-action authorization controls, PAA-1 through PAA-5. AgentLock implements all five:

| OAP control | Requirement | AgentLock |
|---|---|---|
| **PAA-1** | Machine-readable policy for which tool calls are permitted, under what conditions, at what assurance level | `AgentLockPermissions` block per tool (risk_level, allowed_roles, scope, data_policy) |
| **PAA-2** | Platform-level hook enforcing policy synchronously before each tool call, independent of the model | `AuthorizationGate.authorize()` runs before `execute()`; the agent never receives a token |
| **PAA-3** | Verifiable credentials binding agents to authorized scopes | Single-use, SHA-256 parameter-bound execution tokens + Ed25519 signed receipts (capability binding; not W3C VC format) |
| **PAA-4** | Tamper-evident audit log of all authorization decisions | Full audit records + hash-chained context (AARM R2) |
| **PAA-5** | Deny by default in the absence of a valid decision | Deny-by-default is the core principle: no permissions = denied |

### OWASP Top 10 for Agentic Applications (ASI, 2026)

AgentLock does not claim full 10/10 coverage. It maps to the categories a tool-authorization layer can actually enforce:

| ID | Category | AgentLock coverage |
|---|---|---|
| **ASI01** | Agent Goal Hijack | Injection filter + trust degradation once untrusted context enters |
| **ASI02** | Tool Misuse & Exploitation | Per-tool permissions, scope limits, rate limiting |
| **ASI03** | Identity & Privilege Abuse | Role checked on every call; the agent cannot self-elevate |
| **ASI06** | Memory & Context Poisoning | Memory gate (allowed_writers, prohibited_content) + context authority |
| **ASI09** | Human-Agent Trust Exploitation | STEP_UP / human-approval gates on elevated risk |
| **ASI10** | Rogue Agents | Session-level compound scoring + monotonic trust degradation |

Out of scope for an authorization layer: ASI04 (supply chain), ASI05 (unexpected code execution), ASI07 (inter-agent communication), ASI08 (cascading failures). Inter-agent authorization is on the v1.2+ roadmap.

### OWASP MCP Top 10 (2025)

AgentLock addresses 8 of the 10 MCP risks:

| ID | Category | AgentLock coverage |
|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | Out-of-band auth; credentials never touch the conversation |
| **MCP02** | Privilege Escalation via Scope Creep | Declared scope per tool, validated by the gate |
| **MCP03** | Tool Poisoning | Injection filter recursively inspects nested parameters |
| **MCP05** | Command Injection & Execution | Injection filter blocks command-injection payloads |
| **MCP06** | Prompt Injection via Contextual Payloads | Context authority + injection filter |
| **MCP07** | Insufficient Authentication & Authorization | The core function: deny-by-default authorization gate |
| **MCP08** | Lack of Audit and Telemetry | Every call generates an audit record; hash-chained context |
| **MCP10** | Context Injection & Over-Sharing | Trust degradation + data-policy output limits |

Not addressed: MCP04 (supply-chain / dependency tampering) and MCP09 (shadow MCP servers) are deployment-infrastructure concerns outside the authorization layer.

### Other frameworks

| Standard | Coverage |
|----------|----------|
| **OWASP Top 10 for LLM (2025)** | LLM01 Prompt Injection, LLM05 Insecure Output, LLM06 Excessive Agency |
| **NIST AI RMF (AI 100-1)** | Govern, Map, Measure, Manage functions |
| **NIST SP 800-53 Rev. 5** | AC, AU, IA, SI control families |
| **MITRE ATLAS** | AML.T0051 Prompt Injection, AML.T0054 Jailbreak |
| **EU AI Act** | Transparency (audit), human oversight (approval), risk classification |

## Roadmap

| Version | Focus |
|---------|-------|
| **v1.0** | Core schema, tool permissions, enforcement architecture |
| **v1.1** | Memory/context permissions, trust degradation, provenance tracking |
| **v1.2** | Adaptive hardening, MODIFY/DEFER/STEP_UP decisions, signed receipts, hash-chained context (847 tests) |
| **v1.3** | Output destination control, data flow policies |
| **v2.0** | Execution scope, behavioral policy, anomaly detection, compliance templates |

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

```bash
git clone https://github.com/webpro255/agentlock.git
cd agentlock
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Author

**David Grice** — [agentlock.dev](https://agentlock.dev)

---

<p align="center">
  <em>AI tools are the only category of programmable system access in modern computing with no permission model. AgentLock changes that.</em>
</p>
