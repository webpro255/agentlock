#!/usr/bin/env python3
"""Data redaction with AgentLock.

Shows how to configure a tool's data policy so that sensitive data types
(SSNs, credit card numbers, etc.) are automatically stripped from the
tool's output before it reaches the caller.

Run:
    python examples/data_redaction.py
"""

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

gate = AuthorizationGate()

# Register a tool whose output may contain PII.
# The data_policy.prohibited_in_output list tells AgentLock which patterns
# to scan for.  redaction must be set to "auto" (or "manual") when
# prohibited_in_output is non-empty.
gate.register_tool(
    "lookup_customer",
    AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["support", "admin"],
        data_policy={
            "output_classification": "may_contain_pii",
            "prohibited_in_output": ["ssn", "credit_card"],
            "redaction": "auto",
        },
    ),
)


def lookup_customer(customer_id: str) -> str:
    """Simulate a customer lookup that returns raw PII.

    In a real system this might come from a database or API.
    The output contains an SSN and a credit card number that
    AgentLock will automatically redact.
    """
    return (
        f"Customer: {customer_id}\n"
        f"Name: Jane Doe\n"
        f"SSN: 123-45-6789\n"
        f"Credit Card: 4111-1111-1111-1111\n"
        f"Email: jane@example.com\n"
        f"Status: Active"
    )


# ---------------------------------------------------------------------------
# Demo: execute the tool and see redacted output
# ---------------------------------------------------------------------------

print("=== Data Redaction Example ===\n")

# First, show what the raw function returns (no gate involved)
raw_output = lookup_customer(customer_id="CUST-001")
print("[1] Raw function output (before AgentLock):")
for line in raw_output.split("\n"):
    print(f"    {line}")
print()

# Now call through the gate -- output will be automatically redacted
print("[2] Output through AgentLock gate (after redaction):")

redacted_output = gate.call(
    "lookup_customer",
    lookup_customer,
    user_id="support_agent",
    role="support",
    parameters={"customer_id": "CUST-001"},
)

for line in redacted_output.split("\n"):
    print(f"    {line}")
print()

# ---------------------------------------------------------------------------
# You can also use the redaction engine directly for inspection
# ---------------------------------------------------------------------------

print("[3] Redaction details (using gate.redact_output):")

result = gate.redact_output("lookup_customer", raw_output)
print(f"    was_redacted = {result.was_redacted}")
print(f"    redaction count = {len(result.redactions)}")
for r in result.redactions:
    print(f"      type={r['type']!r}  original={r['original']!r}  replacement={r['replacement']!r}")
print()

# ---------------------------------------------------------------------------
# Tool without redaction policy -- output passes through unchanged
# ---------------------------------------------------------------------------

gate.register_tool(
    "get_status",
    AgentLockPermissions(
        risk_level="low",
        requires_auth=True,
        allowed_roles=["support", "admin"],
    ),
)


def get_status() -> str:
    return "System operational. SSN: 987-65-4321 (this would NOT be redacted)"


print("[4] Tool without redaction policy (output passes through as-is):")

output = gate.call(
    "get_status",
    get_status,
    user_id="support_agent",
    role="support",
    parameters={},
)
print(f"    {output}")
