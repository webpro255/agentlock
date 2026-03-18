# Framework Integrations

AgentLock is framework-agnostic. The core library has zero framework dependencies.
Optional integrations wrap popular frameworks with AgentLock authorization.

## Installation

```bash
pip install agentlock[langchain]    # LangChain
pip install agentlock[crewai]       # CrewAI
pip install agentlock[autogen]      # AutoGen
pip install agentlock[mcp]          # Model Context Protocol
pip install agentlock[fastapi]      # FastAPI
pip install agentlock[flask]        # Flask
pip install agentlock[all]          # Everything
```

## LangChain

Wrap any LangChain `BaseTool` with AgentLock authorization:

```python
from langchain_core.tools import Tool
from agentlock import AuthorizationGate, AgentLockPermissions
from agentlock.integrations.langchain import AgentLockToolWrapper

gate = AuthorizationGate()

# Your existing LangChain tool
search_tool = Tool(name="search", func=my_search, description="Search the web")

# Wrap with AgentLock
protected_tool = AgentLockToolWrapper(
    tool=search_tool,
    gate=gate,
    permissions=AgentLockPermissions(
        risk_level="low",
        allowed_roles=["user", "admin"],
    ),
    default_user_id="agent_user",
    default_role="user",
)
```

## CrewAI

Protect all tools in a CrewAI crew:

```python
from agentlock import AuthorizationGate, AgentLockPermissions
from agentlock.integrations.crewai import protect_crew_tools

gate = AuthorizationGate()

permissions_map = {
    "search": AgentLockPermissions(risk_level="low", allowed_roles=["researcher"]),
    "write_file": AgentLockPermissions(risk_level="high", allowed_roles=["admin"]),
}

protect_crew_tools(crew, gate, permissions_map)
```

## AutoGen

Wrap AutoGen function maps:

```python
from agentlock.integrations.autogen import protect_functions

protected = protect_functions(
    function_map={"search": search_fn, "calculate": calc_fn},
    gate=gate,
    permissions_map={
        "search": AgentLockPermissions(risk_level="low", allowed_roles=["user"]),
        "calculate": AgentLockPermissions(risk_level="none"),
    },
)
```

## FastAPI

Add AgentLock as middleware or per-route dependency:

```python
from fastapi import FastAPI, Depends, Request
from agentlock import AuthorizationGate
from agentlock.integrations.fastapi import AgentLockMiddleware, require_agentlock

app = FastAPI()
gate = AuthorizationGate()

# Register tools
gate.register_tool("send_email", AgentLockPermissions(...))

# Option 1: Middleware (checks X-AgentLock-Tool header)
app.add_middleware(AgentLockMiddleware, gate=gate)

# Option 2: Per-route dependency
@app.post("/api/email")
async def send_email(
    request: Request,
    auth=Depends(require_agentlock(gate, "send_email")),
):
    ...
```

Headers used:
- `X-AgentLock-User`: User ID
- `X-AgentLock-Role`: Role
- `X-AgentLock-Tool`: Tool name (middleware mode)

## Flask

```python
from flask import Flask
from agentlock.integrations.flask import AgentLockFlask, agentlock_required

app = Flask(__name__)
gate = AuthorizationGate()
AgentLockFlask(app, gate)

@app.route("/api/email", methods=["POST"])
@agentlock_required(gate, "send_email")
def send_email():
    ...
```

## MCP (Model Context Protocol)

```python
from agentlock.integrations.mcp import AgentLockMCPServer

server = AgentLockMCPServer(gate=gate, permissions_map={
    "read_file": AgentLockPermissions(risk_level="medium", allowed_roles=["user"]),
    "write_file": AgentLockPermissions(risk_level="high", allowed_roles=["admin"]),
})
```

## Generic Integration Pattern

For any framework not listed above:

```python
gate = AuthorizationGate()
gate.register_tool("my_tool", permissions)

# Before executing any tool call:
result = gate.authorize("my_tool", user_id=user_id, role=role, parameters=params)
if result.allowed:
    output = gate.execute("my_tool", tool_func, token=result.token, parameters=params)
else:
    return result.denial  # Send denial back to agent
```

The pattern is always the same: **authorize → token → execute → result**.
