#!/usr/bin/env python3
"""Using the @agentlock decorator to protect functions.

The decorator is the simplest way to add AgentLock protection.  It
automatically registers the function as a tool and enforces authorization
on every call.

Authorization context is passed via special keyword arguments:
    _user_id  -- the authenticated user identity
    _role     -- the caller's role

These are stripped before the underlying function is called.

Run:
    python examples/decorator_example.py
"""

from agentlock import AuthorizationGate, DeniedError, agentlock

# ---------------------------------------------------------------------------
# Setup: create a gate that all decorated functions will share
# ---------------------------------------------------------------------------

gate = AuthorizationGate()

# ---------------------------------------------------------------------------
# Define three tools with different risk levels and role requirements
# ---------------------------------------------------------------------------


@agentlock(gate, risk_level="low", allowed_roles=["viewer", "analyst", "admin"])
def search_docs(query: str) -> str:
    """Low-risk: anyone can search documentation."""
    return f"Found 12 results for '{query}'"


@agentlock(gate, risk_level="medium", allowed_roles=["analyst", "admin"])
def run_report(report_name: str, date_range: str) -> str:
    """Medium-risk: analysts and admins can run reports."""
    return f"Report '{report_name}' generated for {date_range}"


@agentlock(
    gate,
    risk_level="high",
    allowed_roles=["admin"],
    rate_limit={"max_calls": 3, "window_seconds": 3600},
)
def delete_user(username: str) -> str:
    """High-risk: only admins can delete users, rate-limited to 3/hour."""
    return f"User '{username}' deleted"


# ---------------------------------------------------------------------------
# Demo: call each function with different roles
# ---------------------------------------------------------------------------

print("=== @agentlock Decorator Examples ===\n")

# -- search_docs: accessible to all roles ----------------------------------

print("[1] search_docs as viewer:")
try:
    result = search_docs(query="agentlock setup", _user_id="bob", _role="viewer")
    print(f"    OK: {result}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

print()

# -- run_report: viewer is denied, analyst is allowed ----------------------

print("[2] run_report as viewer (should be DENIED):")
try:
    result = run_report(
        report_name="monthly_sales",
        date_range="2026-01-01/2026-01-31",
        _user_id="bob",
        _role="viewer",
    )
    print(f"    OK: {result}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

print()

print("[3] run_report as analyst (should be ALLOWED):")
try:
    result = run_report(
        report_name="monthly_sales",
        date_range="2026-01-01/2026-01-31",
        _user_id="carol",
        _role="analyst",
    )
    print(f"    OK: {result}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

print()

# -- delete_user: only admin -----------------------------------------------

print("[4] delete_user as analyst (should be DENIED):")
try:
    result = delete_user(username="eve", _user_id="carol", _role="analyst")
    print(f"    OK: {result}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

print()

print("[5] delete_user as admin (should be ALLOWED):")
try:
    result = delete_user(username="eve", _user_id="alice", _role="admin")
    print(f"    OK: {result}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

print()

# -- Summary ---------------------------------------------------------------

print("Access matrix:")
print("  Tool          | viewer | analyst | admin")
print("  ------------- | ------ | ------- | -----")
print("  search_docs   |   OK   |   OK    |  OK")
print("  run_report    | DENIED |   OK    |  OK")
print("  delete_user   | DENIED | DENIED  |  OK")
