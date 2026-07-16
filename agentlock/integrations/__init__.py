"""AgentLock framework integrations.

Each integration module lazily imports its framework dependency and raises
a clear ``ImportError`` when the framework is not installed.

Available integrations:

- :mod:`agentlock.integrations.autogen` -- AutoGen function-map wrapping
- :mod:`agentlock.integrations.mcp` -- Model Context Protocol server hooks
- :mod:`agentlock.integrations.fastapi` -- FastAPI middleware and dependencies
- :mod:`agentlock.integrations.flask` -- Flask decorator and extension

The LangChain and CrewAI integrations were removed from core in v1.5.  They are
published separately as ``langchain-agentlock`` and ``crewai-agentlock``.
"""

from __future__ import annotations

__all__ = [
    "autogen",
    "mcp",
    "fastapi",
    "flask",
]
