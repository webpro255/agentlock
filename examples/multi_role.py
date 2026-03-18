#!/usr/bin/env python3
"""Multi-role authorization with AgentLock.

Defines tools with different role requirements, creates sessions for
several users with different roles, and prints a full access matrix
showing who can call what.

Run:
    python examples/multi_role.py
"""

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    InMemoryAuditBackend,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

audit_backend = InMemoryAuditBackend()
gate = AuthorizationGate(audit_backend=audit_backend)

# ---------------------------------------------------------------------------
# Register tools with varying role requirements
# ---------------------------------------------------------------------------

tools = {
    "search_docs": AgentLockPermissions(
        risk_level="low",
        requires_auth=True,
        allowed_roles=["viewer", "analyst", "manager", "admin"],
    ),
    "run_report": AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["analyst", "manager", "admin"],
    ),
    "export_data": AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["manager", "admin"],
    ),
    "modify_config": AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ),
    "delete_records": AgentLockPermissions(
        risk_level="critical",
        requires_auth=True,
        allowed_roles=["admin"],
    ),
}

for tool_name, perms in tools.items():
    gate.register_tool(tool_name, perms)

# ---------------------------------------------------------------------------
# Create sessions for users with different roles
# ---------------------------------------------------------------------------

users = {
    "bob":    "viewer",
    "carol":  "analyst",
    "dave":   "manager",
    "alice":  "admin",
}

for user_id, role in users.items():
    gate.create_session(user_id=user_id, role=role)

# ---------------------------------------------------------------------------
# Build and display the access matrix
# ---------------------------------------------------------------------------

print("=== Multi-Role Authorization Example ===\n")

# Header
tool_names = list(tools.keys())
col_width = max(len(t) for t in tool_names) + 2
user_col = 18

header = f"{'User (role)':<{user_col}}"
for t in tool_names:
    header += f"| {t:<{col_width}}"
print(header)
print("-" * len(header))

# Test each user against each tool
for user_id, role in users.items():
    row = f"{user_id} ({role})"
    row = f"{row:<{user_col}}"

    for tool_name in tool_names:
        result = gate.authorize(tool_name, user_id=user_id, role=role)
        status = "ALLOW" if result.allowed else "DENY"
        row += f"| {status:<{col_width}}"

    print(row)

print()

# ---------------------------------------------------------------------------
# Show per-user detail
# ---------------------------------------------------------------------------

print("--- Detailed authorization attempts ---\n")

# Pick a few interesting cases to highlight
test_cases = [
    ("bob", "viewer", "run_report",     "viewer cannot run reports"),
    ("carol", "analyst", "run_report",  "analyst can run reports"),
    ("carol", "analyst", "export_data", "analyst cannot export data"),
    ("dave", "manager", "export_data",  "manager can export data"),
    ("dave", "manager", "modify_config","manager cannot modify config"),
    ("alice", "admin", "delete_records","admin can delete records"),
]

for user_id, role, tool_name, description in test_cases:
    result = gate.authorize(tool_name, user_id=user_id, role=role)
    status = "ALLOWED" if result.allowed else "DENIED"
    reason = ""
    if not result.allowed and result.denial:
        reason = f" ({result.denial.get('reason', '')})"
    print(f"  {user_id}/{role} -> {tool_name}: {status}{reason}")
    print(f"      note: {description}")

print()

# ---------------------------------------------------------------------------
# Audit summary
# ---------------------------------------------------------------------------

print("--- Audit summary ---\n")
records = audit_backend.query(limit=100)
allowed_count = sum(1 for r in records if r.action == "allowed")
denied_count = sum(1 for r in records if r.action == "denied")
print(f"  Total authorization checks: {len(records)}")
print(f"  Allowed: {allowed_count}")
print(f"  Denied:  {denied_count}")
