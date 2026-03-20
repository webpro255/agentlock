<p align="center">
  <h1 align="center">AgentLock</h1>
  <p align="center">
    <strong>Authorization framework for AI agent tool calls</strong>
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

## Framework Integrations

AgentLock is framework-agnostic. Optional integrations for popular frameworks:

```bash
pip install agentlock[langchain]    # LangChain
pip install agentlock[crewai]       # CrewAI
pip install agentlock[autogen]      # AutoGen
pip install agentlock[mcp]          # Model Context Protocol
pip install agentlock[fastapi]      # FastAPI
pip install agentlock[flask]        # Flask
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

Based on empirical research: **187 multi-turn adversarial attack tests** across 35 categories, tested against 6 frontier AI models.

| Attack Category | Prevention |
|----------------|-----------|
| Prompt injection | Permissions enforced at infrastructure layer, not content layer |
| Social engineering | Identity verified cryptographically, not conversationally |
| Data exfiltration | max_records + rate_limit + data_boundary |
| Privilege escalation | Role checked on every call |
| Tool abuse | Scope constraints + rate limiting |
| Token replay | Single-use, time-limited, operation-bound |
| Agent impersonation | Out-of-band identity verification |
| Memory poisoning | Infrastructure-enforced, not content-dependent |

**The central finding:** adversarial and legitimate tool requests are semantically identical — content-based detection cannot reliably distinguish them. The correct defense is **architectural access control**, not smarter AI-based detection.

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

## Standards Alignment

| Standard | Coverage |
|----------|----------|
| **OWASP Top 10 for LLM (2025)** | LLM01 Prompt Injection, LLM05 Insecure Output, LLM06 Excessive Agency |
| **OWASP Top 10 for Agentic Apps (2026)** | Goal hijacking, excessive agency, unauthorized tool use |
| **NIST AI RMF (AI 100-1)** | Govern, Map, Measure, Manage functions |
| **NIST SP 800-53 Rev. 5** | AC, AU, IA, SI control families |
| **MITRE ATLAS** | AML.T0051 Prompt Injection, AML.T0054 Jailbreak |
| **EU AI Act** | Transparency (audit), human oversight (approval), risk classification |

## Roadmap

| Version | Focus |
|---------|-------|
| **v1.0** | Core schema, tool permissions, enforcement architecture |
| **v1.1** | Memory/context permissions, trust degradation, provenance tracking ✅ |
| **v1.2** | Multi-agent permissions, cross-agent identity delegation |
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
