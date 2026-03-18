# Quick Start Guide

## Installation

```bash
pip install agentlock
```

## Protect Your First Tool in 5 Minutes

### Step 1: Create the Gate

```python
from agentlock import AuthorizationGate

gate = AuthorizationGate()
```

The gate is the central enforcement point. All tool calls go through it.

### Step 2: Register a Tool with Permissions

```python
from agentlock import AgentLockPermissions

gate.register_tool("send_email", AgentLockPermissions(
    risk_level="high",
    requires_auth=True,
    allowed_roles=["admin", "support_agent"],
))
```

That's it. Two fields — `risk_level` and `allowed_roles` — provide immediate value.

### Step 3: Authorize Every Call

```python
result = gate.authorize("send_email", user_id="alice", role="admin")

if result.allowed:
    # Execute the tool using the single-use token
    output = gate.execute("send_email", my_email_function,
                          token=result.token,
                          parameters={"to": "bob@co.com"})
else:
    print(result.denial)
```

### Step 4: See What Happens When Denied

```python
# Unauthenticated call → denied
result = gate.authorize("send_email")
print(result.denial)
# {"status": "denied", "reason": "not_authenticated", ...}

# Wrong role → denied
result = gate.authorize("send_email", user_id="eve", role="intern")
print(result.denial)
# {"status": "denied", "reason": "insufficient_role", ...}

# Unregistered tool → denied (deny by default)
result = gate.authorize("delete_database", user_id="alice", role="admin")
print(result.denial)
# {"status": "denied", "reason": "no_permissions", ...}
```

## Using the Decorator

For the simplest integration, use the `@agentlock` decorator:

```python
from agentlock import AuthorizationGate, agentlock

gate = AuthorizationGate()

@agentlock(gate, risk_level="high", allowed_roles=["admin"])
def send_email(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}"

# Pass auth context via special _user_id and _role kwargs
result = send_email(
    to="bob@co.com", subject="Hi", body="Hello",
    _user_id="alice", _role="admin"
)
```

## Adding Rate Limits

```python
gate.register_tool("query_db", AgentLockPermissions(
    risk_level="medium",
    requires_auth=True,
    allowed_roles=["analyst"],
    rate_limit={"max_calls": 100, "window_seconds": 3600},
))
```

## Adding Data Redaction

```python
gate.register_tool("get_customer", AgentLockPermissions(
    risk_level="high",
    requires_auth=True,
    allowed_roles=["support_agent"],
    data_policy={
        "output_classification": "contains_pii",
        "prohibited_in_output": ["ssn", "credit_card"],
        "redaction": "auto",
    },
))
```

Any SSNs or credit card numbers in the tool's output will be automatically replaced with `[REDACTED:ssn]` and `[REDACTED:credit_card]`.

## Next Steps

- [Full Specification](specification.md) — complete schema and architecture
- [Framework Integrations](integrations.md) — LangChain, CrewAI, FastAPI, etc.
- [Examples](../examples/) — working code for every use case
