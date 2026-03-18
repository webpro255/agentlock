#!/usr/bin/env python3
"""AgentLock Quickstart -- get up and running in 5 minutes.

This example walks through the core AgentLock workflow:
  1. Create an AuthorizationGate
  2. Register a tool with permissions
  3. Authorize a call (denied case)
  4. Authorize a call (allowed case)
  5. Execute the tool with the token
  6. Inspect the audit trail

Run:
    python examples/quickstart.py
"""

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    DeniedError,
    InMemoryAuditBackend,
)

# ---------------------------------------------------------------------------
# Step 1: Create the authorization gate
# ---------------------------------------------------------------------------
# The gate is the central enforcement point.  Every tool call goes through it.
# We use an InMemoryAuditBackend so audit records stay in RAM (great for demos).
# In production, swap in FileAuditBackend("audit.jsonl") or a custom backend.

audit_backend = InMemoryAuditBackend()
gate = AuthorizationGate(audit_backend=audit_backend)

print("=== AgentLock Quickstart ===\n")
print("[1] Created AuthorizationGate with in-memory audit backend.\n")

# ---------------------------------------------------------------------------
# Step 2: Register a tool with its permissions
# ---------------------------------------------------------------------------
# Every tool needs an AgentLockPermissions block that declares:
#   - risk_level: how dangerous is this tool? ("none", "low", "medium", "high", "critical")
#   - requires_auth: must the caller be authenticated?
#   - allowed_roles: which roles may invoke it?
#
# Deny-by-default: if allowed_roles is empty, nobody can call the tool.

perms = AgentLockPermissions(
    risk_level="high",          # Sending email is a high-risk action
    requires_auth=True,         # Caller must be authenticated
    allowed_roles=["admin"],    # Only admins may send email
)

gate.register_tool("send_email", perms)

print("[2] Registered 'send_email' tool:")
print(f"    risk_level   = {perms.risk_level.value}")
print(f"    requires_auth = {perms.requires_auth}")
print(f"    allowed_roles = {perms.allowed_roles}")
print()

# ---------------------------------------------------------------------------
# Step 3: Denied case -- wrong role
# ---------------------------------------------------------------------------
# Alice is a "viewer".  The tool requires "admin".  Authorization will fail.

print("[3] Attempting authorization as viewer (should be DENIED)...")

result_denied = gate.authorize(
    "send_email",
    user_id="alice",
    role="viewer",
    parameters={"to": "bob@example.com", "subject": "Hello"},
)

print(f"    allowed  = {result_denied.allowed}")
print(f"    denial   = {result_denied.denial}")
print(f"    audit_id = {result_denied.audit_id}")
print()

# You can also use raise_if_denied() to turn denials into exceptions:
try:
    result_denied.raise_if_denied()
except DeniedError as exc:
    print(f"    DeniedError caught: {exc}")
print()

# ---------------------------------------------------------------------------
# Step 4: Allowed case -- correct role
# ---------------------------------------------------------------------------
# Now Alice authenticates as "admin".  Authorization succeeds.

print("[4] Attempting authorization as admin (should be ALLOWED)...")

result_allowed = gate.authorize(
    "send_email",
    user_id="alice",
    role="admin",
    parameters={"to": "bob@example.com", "subject": "Hello"},
)

print(f"    allowed  = {result_allowed.allowed}")
print(f"    token    = {result_allowed.token.token_id if result_allowed.token else None}")
print(f"    audit_id = {result_allowed.audit_id}")
print()

# ---------------------------------------------------------------------------
# Step 5: Execute the tool using the token
# ---------------------------------------------------------------------------
# The token is single-use and time-limited.  Pass it to gate.execute() along
# with the actual function to run.


def send_email(to: str, subject: str) -> str:
    """Simulate sending an email."""
    return f"Email sent to {to} with subject '{subject}'"


print("[5] Executing tool with the token...")

output = gate.execute(
    "send_email",
    send_email,
    token=result_allowed.token,
    parameters={"to": "bob@example.com", "subject": "Hello"},
)

print(f"    result = {output}")
print()

# ---------------------------------------------------------------------------
# Step 6: Inspect the audit trail
# ---------------------------------------------------------------------------
# Every authorization decision (allowed or denied) is recorded.

print("[6] Audit trail:")
records = audit_backend.query()
for rec in records:
    print(f"    [{rec.audit_id}] tool={rec.tool_name} user={rec.user_id} "
          f"action={rec.action} reason={rec.reason}")

print()
print("Done!  Every tool call was authorized and audited.")
