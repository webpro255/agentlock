#!/usr/bin/env python3
"""Rate limiting with AgentLock.

Demonstrates per-user, per-tool rate limiting.  The tool is configured to
allow at most 3 calls per 60-second window.  On the 4th call, a
RateLimitedError is raised with a retry_after hint.

Run:
    python examples/rate_limiting.py
"""

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    DeniedError,
    RateLimitedError,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

gate = AuthorizationGate()

# Register a tool with a tight rate limit: 3 calls per 60 seconds
gate.register_tool(
    "send_notification",
    AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["operator", "admin"],
        rate_limit={"max_calls": 3, "window_seconds": 60},
    ),
)


def send_notification(channel: str, message: str) -> str:
    """Simulate sending a notification."""
    return f"Notification sent to #{channel}: {message}"


# ---------------------------------------------------------------------------
# Demo: call the tool up to and beyond the limit
# ---------------------------------------------------------------------------

print("=== Rate Limiting Example ===\n")
print("Tool 'send_notification' is limited to 3 calls per 60 seconds.\n")

for i in range(1, 6):
    print(f"[Call {i}]")
    try:
        # gate.call() combines authorize + execute in one step.
        # It raises DeniedError (including RateLimitedError) on failure.
        output = gate.call(
            "send_notification",
            send_notification,
            user_id="operator_1",
            role="operator",
            parameters={"channel": "alerts", "message": f"Alert #{i}"},
        )
        print(f"    OK: {output}")
    except RateLimitedError as exc:
        # RateLimitedError is a subclass of DeniedError with extra fields
        print(f"    RATE LIMITED!")
        print(f"    reason            = {exc.reason}")
        print(f"    detail            = {exc.detail}")
        print(f"    retry_after_secs  = {exc.retry_after_seconds}")
        print(f"    audit_id          = {exc.audit_id}")
    except DeniedError as exc:
        print(f"    DENIED: {exc}")
    print()

# ---------------------------------------------------------------------------
# Check remaining quota
# ---------------------------------------------------------------------------

remaining = gate.rate_limiter.remaining("send_notification", "operator_1")
print(f"Remaining calls in window: {remaining}")

# ---------------------------------------------------------------------------
# Different users have independent limits
# ---------------------------------------------------------------------------

print("\n--- Different user (operator_2) has a fresh limit ---\n")

try:
    output = gate.call(
        "send_notification",
        send_notification,
        user_id="operator_2",
        role="operator",
        parameters={"channel": "alerts", "message": "First call for operator_2"},
    )
    print(f"    OK: {output}")
except DeniedError as exc:
    print(f"    DENIED: {exc}")

remaining_2 = gate.rate_limiter.remaining("send_notification", "operator_2")
print(f"    Remaining calls for operator_2: {remaining_2}")
