"""Audit logging — every tool call generates an audit record.

Audit is not optional in AgentLock.  The default backend writes structured
JSON to a file.  Production deployments should use the ``AuditBackend``
protocol to integrate with SIEM, CloudWatch, Datadog, etc.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agentlock.types import AuditId, AuditLogLevel

logger = logging.getLogger("agentlock.audit")

__all__ = ["AuditRecord", "AuditLogger", "AuditBackend", "FileAuditBackend"]


def _generate_audit_id() -> AuditId:
    ts = time.strftime("%Y-%m-%d", time.gmtime())
    seq = secrets.token_hex(4)
    return f"agentlock-{ts}-{seq}"


@dataclass(slots=True)
class AuditRecord:
    """A single audit entry."""

    audit_id: AuditId = field(default_factory=_generate_audit_id)
    timestamp: float = field(default_factory=time.time)
    tool_name: str = ""
    user_id: str = ""
    role: str = ""
    action: str = ""  # "allowed", "denied", "error"
    reason: str = ""
    risk_level: str = ""
    parameters: dict[str, Any] | None = None
    response_summary: str = ""
    token_id: str = ""
    session_id: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["parameters"] is None:
            del d["parameters"]
        return d


@runtime_checkable
class AuditBackend(Protocol):
    """Protocol for pluggable audit storage."""

    def write(self, record: AuditRecord) -> None: ...
    def query(
        self,
        tool_name: str | None = None,
        user_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]: ...


class FileAuditBackend:
    """Append-only JSON-lines audit log.

    Args:
        path: File path for the audit log.  Created if missing.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            path = Path.home() / ".agentlock" / "audit.jsonl"
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AuditRecord) -> None:
        with open(self._path, "a") as f:
            f.write(json.dumps(record.to_dict(), default=str) + "\n")

    def query(
        self,
        tool_name: str | None = None,
        user_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        if not self._path.exists():
            return []
        results: list[AuditRecord] = []
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if tool_name and d.get("tool_name") != tool_name:
                    continue
                if user_id and d.get("user_id") != user_id:
                    continue
                if since and d.get("timestamp", 0) < since:
                    continue
                results.append(AuditRecord(**{
                    k: v for k, v in d.items()
                    if k in AuditRecord.__dataclass_fields__
                }))
                if len(results) >= limit:
                    break
        return results


class InMemoryAuditBackend:
    """In-memory audit backend for testing."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)

    def query(
        self,
        tool_name: str | None = None,
        user_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        results = []
        for r in self.records:
            if tool_name and r.tool_name != tool_name:
                continue
            if user_id and r.user_id != user_id:
                continue
            if since and r.timestamp < since:
                continue
            results.append(r)
            if len(results) >= limit:
                break
        return results


class AuditLogger:
    """Central audit logger.

    Delegates to a pluggable backend.  Filters records based on the
    tool's configured ``log_level``.
    """

    def __init__(self, backend: AuditBackend | None = None) -> None:
        self._backend = backend or FileAuditBackend()

    @property
    def backend(self) -> AuditBackend:
        return self._backend

    def log(
        self,
        *,
        tool_name: str,
        user_id: str = "",
        role: str = "",
        action: str,
        reason: str = "",
        risk_level: str = "",
        parameters: dict[str, Any] | None = None,
        response_summary: str = "",
        token_id: str = "",
        session_id: str = "",
        duration_ms: float = 0.0,
        log_level: AuditLogLevel = AuditLogLevel.STANDARD,
        include_parameters: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Create and persist an audit record.

        Args:
            tool_name: Name of the tool being invoked.
            user_id: Authenticated user identity.
            role: Role used for authorization.
            action: "allowed", "denied", or "error".
            reason: Denial reason or error description.
            risk_level: Tool's risk classification.
            parameters: Call parameters (omitted if include_parameters is False).
            response_summary: Truncated response for full logging.
            token_id: Execution token identifier.
            session_id: Session identifier.
            duration_ms: Execution duration in milliseconds.
            log_level: The tool's configured audit level.
            include_parameters: Whether to include parameters in the record.
            metadata: Additional context.

        Returns:
            The created audit record.
        """
        record = AuditRecord(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            action=action,
            reason=reason,
            risk_level=risk_level,
            token_id=token_id,
            session_id=session_id,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

        # Filter fields based on log level
        if log_level == AuditLogLevel.MINIMAL:
            # name + timestamp + outcome only
            record.parameters = None
            record.response_summary = ""
            record.user_id = ""
            record.role = ""
        elif log_level == AuditLogLevel.STANDARD:
            # + identity + scope
            record.parameters = None
            record.response_summary = ""
        else:
            # FULL — include everything
            if include_parameters:
                record.parameters = parameters
            record.response_summary = response_summary

        self._backend.write(record)
        logger.debug("audit: %s %s %s → %s", tool_name, user_id, action, record.audit_id)
        return record

    def query(self, **kwargs: Any) -> list[AuditRecord]:
        """Query audit records.  Delegates to backend."""
        return self._backend.query(**kwargs)
