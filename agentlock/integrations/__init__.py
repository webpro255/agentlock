"""AgentLock framework integrations.

Each integration module lazily imports its framework dependency and raises
a clear ``ImportError`` when the framework is not installed.

Available integrations:

- :mod:`agentlock.integrations.langchain` -- LangChain tool wrapping
- :mod:`agentlock.integrations.crewai` -- CrewAI tool protection
- :mod:`agentlock.integrations.autogen` -- AutoGen function-map wrapping
- :mod:`agentlock.integrations.mcp` -- Model Context Protocol server hooks
- :mod:`agentlock.integrations.fastapi` -- FastAPI middleware and dependencies
- :mod:`agentlock.integrations.flask` -- Flask decorator and extension
"""

from __future__ import annotations

__all__ = [
    "langchain",
    "crewai",
    "autogen",
    "mcp",
    "fastapi",
    "flask",
]
