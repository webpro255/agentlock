"""Memory gate — governs what agents can persist to and read from memory.

Memory operations are gate-mediated actions parallel to tool execution.
Every write is checked against the tool's ``memory_policy`` for allowed
writers, prohibited content, retention limits, and confirmation requirements.

Retention enforcement is lazy (checked on read).
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agentlock.context import ContextProvenance
from agentlock.types import DenialReason, MemoryPersistence, MemoryWriter

__all__ = [
    "MemoryGate",
    "MemoryEntry",
    "MemoryStore",
    "InMemoryMemoryStore",
    "MemoryDecision",
]


def _generate_entry_id() -> str:
    return f"mem_{secrets.token_hex(8)}"


@dataclass
class MemoryEntry:
    """A persisted memory item with provenance."""

    entry_id: str = field(default_factory=_generate_entry_id)
    user_id: str = ""
    tool_name: str = ""
    content: str = ""
    content_hash: str = ""
    persistence: MemoryPersistence = MemoryPersistence.SESSION
    writer: MemoryWriter = MemoryWriter.SYSTEM
    created_at: float = field(default_factory=time.time)
    provenance: ContextProvenance | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if the entry has exceeded its max_age.

        Note: max_age is not stored on the entry — it's checked against
        the policy at read time.
        """
        return False  # Expiry checked by MemoryGate at read time


@dataclass
class MemoryDecision:
    """Result of a memory authorization check."""

    allowed: bool
    reason: DenialReason | None = None
    detail: str = ""
    suggestion: str = ""
    entry: MemoryEntry | None = None


@runtime_checkable
class MemoryStore(Protocol):
    """Protocol for pluggable memory storage."""

    def write(self, entry: MemoryEntry) -> None: ...
    def read(self, user_id: str, tool_name: str | None = None) -> list[MemoryEntry]: ...
    def delete(self, entry_id: str) -> None: ...
    def count(self, user_id: str, tool_name: str | None = None) -> int: ...


class InMemoryMemoryStore:
    """In-memory memory store for testing."""

    def __init__(self) -> None:
        self._entries: dict[str, MemoryEntry] = {}

    def write(self, entry: MemoryEntry) -> None:
        self._entries[entry.entry_id] = entry

    def read(self, user_id: str, tool_name: str | None = None) -> list[MemoryEntry]:
        results = []
        for entry in self._entries.values():
            if entry.user_id != user_id:
                continue
            if tool_name and entry.tool_name != tool_name:
                continue
            results.append(entry)
        return results

    def delete(self, entry_id: str) -> None:
        self._entries.pop(entry_id, None)

    def count(self, user_id: str, tool_name: str | None = None) -> int:
        return len(self.read(user_id, tool_name))

    def __len__(self) -> int:
        return len(self._entries)


# Built-in prohibited content patterns
_PROHIBITED_PATTERNS: dict[str, re.Pattern[str]] = {
    "credentials": re.compile(
        r"(password\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|secret\s*[:=]\s*\S+)",
        re.IGNORECASE,
    ),
    "pii": re.compile(
        r"(\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b)",  # SSN patterns
    ),
    "financial_data": re.compile(
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit card
    ),
}


class MemoryGate:
    """Validates memory read/write requests against MemoryPolicyConfig.

    Args:
        store: Pluggable memory storage. Defaults to in-memory.
    """

    def __init__(self, store: MemoryStore | None = None) -> None:
        self._store = store or InMemoryMemoryStore()

    @property
    def store(self) -> MemoryStore:
        return self._store

    def authorize_write(
        self,
        *,
        content: str,
        content_hash: str,
        user_id: str,
        tool_name: str,
        writer: MemoryWriter,
        persistence: MemoryPersistence,
        allowed_writers: list[MemoryWriter],
        allowed_persistence: MemoryPersistence,
        prohibited_content: list[str],
        max_entries: int,
        require_write_confirmation: bool,
        provenance: ContextProvenance | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryDecision:
        """Authorize a memory write operation.

        Returns:
            MemoryDecision with allowed=True and the entry if approved,
            or allowed=False with denial reason.
        """
        # 1. Check writer authorization
        if writer not in allowed_writers:
            return MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_WRITE_DENIED,
                detail=f"Writer '{writer.value}' not in allowed_writers.",
                suggestion=(
                    f"Only {', '.join(w.value for w in allowed_writers)} "
                    f"can persist memory for this tool's outputs."
                ),
            )

        # 2. Check persistence level
        persistence_order = [
            MemoryPersistence.NONE,
            MemoryPersistence.SESSION,
            MemoryPersistence.CROSS_SESSION,
        ]
        if persistence_order.index(persistence) > persistence_order.index(allowed_persistence):
            return MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_WRITE_DENIED,
                detail=(
                    f"Persistence '{persistence.value}' exceeds allowed "
                    f"'{allowed_persistence.value}'."
                ),
                suggestion=f"Use persistence level '{allowed_persistence.value}' or lower.",
            )

        # 3. Check prohibited content
        for prohibited_type in prohibited_content:
            pattern = _PROHIBITED_PATTERNS.get(prohibited_type)
            if pattern and pattern.search(content):
                return MemoryDecision(
                    allowed=False,
                    reason=DenialReason.MEMORY_PROHIBITED_CONTENT,
                    detail=f"Content contains prohibited type: {prohibited_type}.",
                    suggestion=f"Remove {prohibited_type} before persisting to memory.",
                )

        # 4. Check max_entries
        current_count = self._store.count(user_id, tool_name)
        if current_count >= max_entries:
            return MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_RETENTION_EXCEEDED,
                detail=(
                    f"User has {current_count} entries (limit: {max_entries})."
                ),
                suggestion="Delete existing entries before writing new ones.",
            )

        # 5. Check write confirmation
        if require_write_confirmation:
            return MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_CONFIRMATION_REQUIRED,
                detail="User confirmation required for memory write.",
                suggestion="Approve via the configured confirmation channel.",
            )

        # All checks passed — create and persist entry
        entry = MemoryEntry(
            user_id=user_id,
            tool_name=tool_name,
            content=content,
            content_hash=content_hash,
            persistence=persistence,
            writer=writer,
            provenance=provenance,
            metadata=metadata or {},
        )
        self._store.write(entry)

        return MemoryDecision(allowed=True, entry=entry)

    def authorize_read(
        self,
        *,
        user_id: str,
        reader: MemoryWriter,
        tool_name: str | None = None,
        allowed_readers: list[MemoryWriter],
        max_age_seconds: int = 0,
    ) -> MemoryDecision:
        """Authorize a memory read operation.

        Performs lazy retention enforcement: entries exceeding max_age
        are purged at read time.

        Returns:
            MemoryDecision with allowed=True if access is granted.
            Entries are returned via the store after authorization.
        """
        # Check reader authorization
        if reader not in allowed_readers:
            return MemoryDecision(
                allowed=False,
                reason=DenialReason.MEMORY_READ_DENIED,
                detail=f"Reader '{reader.value}' not in allowed_readers.",
                suggestion=(
                    f"Only {', '.join(r.value for r in allowed_readers)} "
                    f"can read memory for this tool."
                ),
            )

        # Lazy retention: purge expired entries
        if max_age_seconds > 0:
            entries = self._store.read(user_id, tool_name)
            now = time.time()
            for entry in entries:
                if (now - entry.created_at) > max_age_seconds:
                    self._store.delete(entry.entry_id)

        return MemoryDecision(allowed=True)
