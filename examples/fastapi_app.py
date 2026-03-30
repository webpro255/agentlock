#!/usr/bin/env python3
"""FastAPI integration with AgentLock.

A small FastAPI app that protects three endpoints behind AgentLock
authorization.  The caller's identity and role are read from HTTP headers:

    X-User-Id: alice
    X-User-Role: admin

Endpoints:
    GET  /search?q=...           -- low-risk, any authenticated role
    POST /reports                -- medium-risk, analyst or admin
    POST /admin/delete-user      -- high-risk, admin only

Run:
    pip install fastapi uvicorn
    uvicorn examples.fastapi_app:app --reload --port 8000

Test with curl:
    # Allowed -- viewer can search
    curl -H "X-User-Id: bob" -H "X-User-Role: viewer" \
         "http://localhost:8000/search?q=hello"

    # Denied -- viewer cannot run reports
    curl -X POST -H "X-User-Id: bob" -H "X-User-Role: viewer" \
         -H "Content-Type: application/json" \
         -d '{"report_name": "sales", "date_range": "2026-01"}' \
         "http://localhost:8000/reports"

    # Allowed -- admin can delete users
    curl -X POST -H "X-User-Id: alice" -H "X-User-Role: admin" \
         -H "Content-Type: application/json" \
         -d '{"username": "eve"}' \
         "http://localhost:8000/admin/delete-user"
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    InMemoryAuditBackend,
)

# ---------------------------------------------------------------------------
# AgentLock setup
# ---------------------------------------------------------------------------

audit_backend = InMemoryAuditBackend()
gate = AuthorizationGate(audit_backend=audit_backend)

# Register tools with their permissions
gate.register_tool(
    "search",
    AgentLockPermissions(
        risk_level="low",
        requires_auth=True,
        allowed_roles=["viewer", "analyst", "admin"],
    ),
)

gate.register_tool(
    "run_report",
    AgentLockPermissions(
        risk_level="medium",
        requires_auth=True,
        allowed_roles=["analyst", "admin"],
    ),
)

gate.register_tool(
    "delete_user",
    AgentLockPermissions(
        risk_level="high",
        requires_auth=True,
        allowed_roles=["admin"],
    ),
)

# ---------------------------------------------------------------------------
# FastAPI app and dependency injection
# ---------------------------------------------------------------------------

app = FastAPI(title="AgentLock FastAPI Example")


class AuthContext(BaseModel):
    """Extracted from request headers."""
    user_id: str
    role: str


def get_auth_context(request: Request) -> AuthContext:
    """Dependency that extracts auth context from headers.

    In production this would validate a JWT or session cookie.
    For this demo we trust the headers directly.
    """
    user_id = request.headers.get("X-User-Id", "")
    role = request.headers.get("X-User-Role", "")
    if not user_id or not role:
        raise HTTPException(
            status_code=401,
            detail="Missing X-User-Id or X-User-Role headers",
        )
    return AuthContext(user_id=user_id, role=role)


def agentlock_authorize(
    tool_name: str, auth: AuthContext, parameters: dict[str, Any] | None = None,
) -> None:
    """Helper that authorizes via the gate and raises HTTPException on denial."""
    result = gate.authorize(
        tool_name,
        user_id=auth.user_id,
        role=auth.role,
        parameters=parameters,
    )
    if not result.allowed:
        denial = result.denial or {}
        raise HTTPException(
            status_code=403,
            detail={
                "error": "authorization_denied",
                "reason": denial.get("reason", "unknown"),
                "detail": denial.get("detail", ""),
                "suggestion": denial.get("suggestion", ""),
                "audit_id": result.audit_id,
            },
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/search")
def search(q: str, auth: AuthContext = Depends(get_auth_context)):
    """Search documents -- low risk, any role."""
    agentlock_authorize("search", auth, parameters={"q": q})
    return {"results": [f"Result 1 for '{q}'", f"Result 2 for '{q}'"]}


class ReportRequest(BaseModel):
    report_name: str
    date_range: str


@app.post("/reports")
def run_report(body: ReportRequest, auth: AuthContext = Depends(get_auth_context)):
    """Generate a report -- medium risk, analyst or admin."""
    agentlock_authorize("run_report", auth, parameters=body.model_dump())
    return {
        "status": "generated",
        "report_name": body.report_name,
        "date_range": body.date_range,
        "rows": 42,
    }


class DeleteUserRequest(BaseModel):
    username: str


@app.post("/admin/delete-user")
def delete_user(body: DeleteUserRequest, auth: AuthContext = Depends(get_auth_context)):
    """Delete a user -- high risk, admin only."""
    agentlock_authorize("delete_user", auth, parameters=body.model_dump())
    return {"status": "deleted", "username": body.username}


# ---------------------------------------------------------------------------
# Audit endpoint (bonus)
# ---------------------------------------------------------------------------


@app.get("/audit")
def get_audit(auth: AuthContext = Depends(get_auth_context)):
    """View recent audit records -- admin only."""
    agentlock_authorize("search", auth)  # reuse low-risk check for demo
    records = audit_backend.query(limit=50)
    return [
        {
            "audit_id": r.audit_id,
            "tool": r.tool_name,
            "user": r.user_id,
            "action": r.action,
            "reason": r.reason,
        }
        for r in records
    ]


# ---------------------------------------------------------------------------
# Run directly: python examples/fastapi_app.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    print("Starting AgentLock FastAPI example on http://localhost:8000")
    print("Try: curl -H 'X-User-Id: alice' -H 'X-User-Role: admin' http://localhost:8000/search?q=test")
    uvicorn.run(app, host="0.0.0.0", port=8000)
