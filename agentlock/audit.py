"""Audit logging -- every tool call generates an audit record.

Audit is not optional in AgentLock.  The default backend writes structured
JSON to a file.  Production deployments should use the ``AuditBackend``
protocol to integrate with SIEM, CloudWatch, Datadog, etc.
"""

from __future__ import annotations

import json
import logging
import queue
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agentlock.types import AuditId, AuditLogLevel

logger = logging.getLogger("agentlock.audit")

__all__ = [
    "AuditRecord",
    "AuditLogger",
    "AuditBackend",
    "FileAuditBackend",
    "AsyncAuditBackend",
]


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
    # v1.1 additions
    trust_ceiling: str | None = None
    is_trust_degraded: bool = False
    degradation_effects: list[str] | None = None
    context_provenance_ids: list[str] | None = None
    memory_operation: str | None = None
    memory_entry_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["parameters"] is None:
            del d["parameters"]
        # Omit None v1.1 fields for backward compat
        for key in ("trust_ceiling", "degradation_effects", "context_provenance_ids",
                     "memory_operation", "memory_entry_id"):
            if d.get(key) is None:
                d.pop(key, None)
        if not d.get("is_trust_degraded"):
            d.pop("is_trust_degraded", None)
        return d


# Metadata keys that carry raw user content rather than a fact about the
# decision.  Evidence completeness and payload disclosure are two axes, not
# one: which gate fired, which parameter carried the value, and which source it
# traced to are decision facts and are recorded at every log level.  The literal
# value is user data (an email, an IBAN, a message fragment), so it follows the
# same disclosure rule as ``parameters`` and is dropped wherever they are.
# Dropping it never weakens the citation: the record still names the gate, the
# parameter, the token, and the source provenance id.
_PAYLOAD_METADATA_KEYS = ("matched_value",)


def _drop_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    """Strip raw user content from ``lineage_evidence``, keeping the facts."""
    evidence = metadata.get("lineage_evidence")
    if not isinstance(evidence, dict):
        return metadata
    if not any(k in evidence for k in _PAYLOAD_METADATA_KEYS):
        return metadata
    stripped = {k: v for k, v in evidence.items() if k not in _PAYLOAD_METADATA_KEYS}
    return {**metadata, "lineage_evidence": stripped}


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


class AsyncAuditBackend:
    """Bounded, non-blocking wrapper around any ``AuditBackend``.

    THE TRADE THIS MAKES, STATED PLAINLY.  The gate's execution records are
    written synchronously by default, because a record that cannot survive a
    crash cannot describe one: the attempt record is on disk *before* the tool
    is invoked, so a process killed mid-execution leaves an attempt with no
    completion, which is exactly the fact a reconstruction needs.

    This wrapper hands records to a bounded queue drained by a background
    thread.  The calling thread never blocks on the backend.  In exchange:

    * records still in the queue when the process dies are LOST, so an action
      that was attempted can leave NO attempt record;
    * a full queue drops records (counted in :attr:`dropped`, never silent).

    So under this backend, the absence of a record is NOT evidence that the
    thing did not happen.  Every record written through it is stamped
    ``writer_mode="async"`` and ``durable_before_execution=False`` so a
    reconstruction reads that limitation out of the log itself rather than out
    of a config file it does not have.

    Call :meth:`flush` on graceful shutdown to drain what is queued.
    """

    def __init__(self, backend: AuditBackend, max_queue: int = 10_000) -> None:
        self._backend = backend
        self._queue: queue.Queue[AuditRecord] = queue.Queue(maxsize=max_queue)
        self._dropped = 0
        self._thread = threading.Thread(
            target=self._drain, name="agentlock-audit", daemon=True
        )
        self._thread.start()

    @property
    def dropped(self) -> int:
        """Records dropped because the queue was full.  Never silent."""
        return self._dropped

    def write(self, record: AuditRecord) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._dropped += 1
            logger.error(
                "agentlock: audit queue full, record DROPPED (%d dropped total). "
                "Evidence is incomplete for this deployment.",
                self._dropped,
            )

    def _drain(self) -> None:
        while True:
            record = self._queue.get()
            try:
                self._backend.write(record)
            except Exception:
                logger.exception(
                    "agentlock: audit backend write failed in async writer"
                )
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        """Drain the queue.  Returns False if it did not finish in time."""
        deadline = time.time() + timeout
        while not self._queue.empty() and time.time() < deadline:
            time.sleep(0.001)
        return self._queue.empty()

    def query(self, **kwargs: Any) -> list[AuditRecord]:
        return self._backend.query(**kwargs)


class AuditLogger:
    """Central audit logger.

    Delegates to a pluggable backend.  Filters records based on the
    tool's configured ``log_level``.

    Two guarantees govern the evidence path, and they are not the same
    guarantee:

    * **Never break, never alter.**  Absolute, and enforced by tests.  Writing
      evidence must never break, and must never change the result of, the thing
      it observes.  ``log_best_effort`` therefore swallows every backend
      exception at the writer boundary, reports it out of band to the
      ``agentlock.audit`` logger, and counts it on
      :attr:`evidence_write_failures`.  A blind evidence layer says so; it does
      not fail quietly and it does not take the tool call down with it.
    * **Never block** is a property of the BACKEND a deployment chooses, not of
      the gate.  A synchronous backend blocks for the duration of its write;
      that is the deployment's trade, and the default, because durability
      before execution is what makes an absent completion record mean
      something.  Deployments that cannot afford the write on the hot path wrap
      their backend in :class:`AsyncAuditBackend` and accept its weaker absence
      semantics, which are stamped into every record it writes.
    """

    def __init__(self, backend: AuditBackend | None = None) -> None:
        self._backend = backend or FileAuditBackend()
        self._evidence_write_failures = 0

    @property
    def backend(self) -> AuditBackend:
        return self._backend

    @property
    def writer_mode(self) -> str:
        """``"sync"`` or ``"async"``.  Stamped into every execution record, so
        a reader knows whether absence is interpretable."""
        return "async" if isinstance(self._backend, AsyncAuditBackend) else "sync"

    @property
    def durable_before_execution(self) -> bool:
        """Whether an attempt record is on the backend before the tool runs."""
        return self.writer_mode == "sync"

    @property
    def evidence_write_failures(self) -> int:
        """Evidence writes that the backend refused or failed to accept.

        A non-zero value means the log is INCOMPLETE: some record that should
        exist does not.  Exposed so a deployment (and a reconstruction) can
        tell a quiet log from a broken one.
        """
        return self._evidence_write_failures

    def log_best_effort(self, **kwargs: Any) -> AuditRecord | None:
        """:meth:`log`, but it can never break its caller.

        Used by every write on the EXECUTION path.  A throwing backend must not
        break, block, or alter a tool call the gate already authorized: the
        decision is made, the tool is running or has run, and an audit failure
        at that point is a failure to observe, never a reason to change what
        happens.  Returns the record, or ``None`` if the write failed.
        """
        try:
            return self.log(**kwargs)
        except Exception:
            self._evidence_write_failures += 1
            logger.exception(
                "agentlock: EVIDENCE WRITE FAILED (%d total). The audit log is "
                "incomplete: a record that should exist does not. The tool call "
                "is unaffected.",
                self._evidence_write_failures,
            )
            return None

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
        # v1.1 fields
        trust_ceiling: str | None = None,
        is_trust_degraded: bool = False,
        degradation_effects: list[str] | None = None,
        context_provenance_ids: list[str] | None = None,
        memory_operation: str | None = None,
        memory_entry_id: str | None = None,
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
            metadata: Additional context.  Raw user content carried under
                ``lineage_evidence`` obeys the same disclosure rule as
                ``parameters``; the decision facts around it do not.

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
            trust_ceiling=trust_ceiling,
            is_trust_degraded=is_trust_degraded,
            degradation_effects=degradation_effects,
            context_provenance_ids=context_provenance_ids,
            memory_operation=memory_operation,
            memory_entry_id=memory_entry_id,
        )

        # Filter fields based on log level
        if log_level == AuditLogLevel.MINIMAL:
            # name, timestamp, outcome, and decision provenance.
            #
            # ``metadata`` survives MINIMAL, as ``trust_ceiling`` already does:
            # both describe *why* a decision came out the way it did, and are
            # bounded, non-sensitive, caller-independent.  MINIMAL sheds the
            # unbounded, caller-controlled fields (parameters, response bodies)
            # and the identity fields -- not the provenance of the decision.
            # ``audit_action_classes()`` reads ``metadata["asserted_classes"]``
            # back out, so stripping it here would silently blind the audit
            # report on any tool logging at MINIMAL.
            record.parameters = None
            record.response_summary = ""
            record.user_id = ""
            record.role = ""
            record.metadata = _drop_payload(record.metadata)
        elif log_level == AuditLogLevel.STANDARD:
            # + identity + scope
            record.parameters = None
            record.response_summary = ""
            record.metadata = _drop_payload(record.metadata)
        else:
            # FULL -- include everything
            if include_parameters:
                record.parameters = parameters
            else:
                record.metadata = _drop_payload(record.metadata)
            record.response_summary = response_summary

        self._backend.write(record)
        logger.debug("audit: %s %s %s → %s", tool_name, user_id, action, record.audit_id)
        return record

    # -- Execution confirmation (E7) ----------------------------------------
    #
    # An "allowed" record is a GRANT.  It is not evidence that anything ran.
    # These two records are what distinguish a permission from an act:
    #
    #   attempt, no completion  -> attempted, never returned (hang, crash, kill)
    #   attempt + completion    -> ran, and the status says how it ended
    #   neither                 -> never attempted
    #
    # That third reading is only sound when the writer is synchronous (an
    # attempt record durable BEFORE the tool runs) and the log is contiguous
    # across the window.  Both conditions are stamped or knowable from the log
    # itself: ``writer_mode`` and ``durable_before_execution`` ride on every
    # execution record.  Never make an absence claim without them.
    #
    # Both writers are best-effort by construction.  See ``log_best_effort``.

    def _execution_meta(self, extra: dict[str, Any]) -> dict[str, Any]:
        return {
            "writer_mode": self.writer_mode,
            "durable_before_execution": self.durable_before_execution,
            **extra,
        }

    def log_execution_attempt(
        self,
        *,
        tool_name: str,
        user_id: str = "",
        role: str = "",
        risk_level: str = "",
        token_id: str = "",
        session_id: str = "",
        parameters: dict[str, Any] | None = None,
        log_level: AuditLogLevel = AuditLogLevel.STANDARD,
        include_parameters: bool = True,
        reported_by: str = "gate",
        deferral_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditRecord | None:
        """The tool is about to be invoked.  Written BEFORE control leaves the
        gate, so that a call which never returns still leaves a trace."""
        extra: dict[str, Any] = {"reported_by": reported_by, **(metadata or {})}
        if deferral_id:
            extra["deferral_id"] = deferral_id
        return self.log_best_effort(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            action="execution_attempted",
            risk_level=risk_level,
            token_id=token_id,
            session_id=session_id,
            parameters=parameters,
            log_level=log_level,
            include_parameters=include_parameters,
            metadata=self._execution_meta(extra),
        )

    def log_execution_completion(
        self,
        *,
        tool_name: str,
        status: str,
        user_id: str = "",
        role: str = "",
        risk_level: str = "",
        token_id: str = "",
        session_id: str = "",
        duration_ms: float = 0.0,
        error_type: str = "",
        attempt_audit_id: str = "",
        log_level: AuditLogLevel = AuditLogLevel.STANDARD,
        reported_by: str = "gate",
        deferral_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditRecord | None:
        """The tool returned or raised.  ``status`` is "succeeded" or "failed".

        Cites the attempt record's ``audit_id``, so the pair joins by id and a
        reader can say exactly which record is missing when one of them is.
        """
        extra: dict[str, Any] = {
            "status": status,
            "reported_by": reported_by,
            **(metadata or {}),
        }
        if error_type:
            extra["error_type"] = error_type
        if attempt_audit_id:
            extra["attempt_audit_id"] = attempt_audit_id
        if deferral_id:
            extra["deferral_id"] = deferral_id
        return self.log_best_effort(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            action="execution_completed",
            reason=status,
            risk_level=risk_level,
            token_id=token_id,
            session_id=session_id,
            duration_ms=duration_ms,
            log_level=log_level,
            metadata=self._execution_meta(extra),
        )

    def query(self, **kwargs: Any) -> list[AuditRecord]:
        """Query audit records.  Delegates to backend."""
        return self._backend.query(**kwargs)
