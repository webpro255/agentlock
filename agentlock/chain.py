"""Hash-chained context entries (AARM R2).

Each context entry includes the hash of the previous entry, forming a
tamper-evident append-only chain.  Modifying any entry invalidates all
subsequent entries.

Usage::

    chain = ContextChain()
    chain.append(source="user_message", authority="authoritative",
                 content_hash="abc123...")
    chain.append(source="tool_output", authority="derived",
                 content_hash="def456...")

    valid, broken_at = chain.verify_chain()
    assert valid
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ChainedContextEntry",
    "ContextChain",
    "GENESIS_HASH",
]

# The chain starts from a well-known genesis hash (SHA-256 of empty string).
GENESIS_HASH = hashlib.sha256(b"").hexdigest()


def _generate_entry_id() -> str:
    return f"cctx_{secrets.token_hex(8)}"


def _compute_entry_hash(
    previous_hash: str,
    content_hash: str,
    source: str,
    authority: str,
    writer_id: str,
    timestamp: float,
) -> str:
    """Compute the deterministic hash of a chain entry."""
    payload = (
        f"{previous_hash}\x00{content_hash}\x00"
        f"{source}\x00{authority}\x00"
        f"{writer_id}\x00{timestamp:.6f}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ChainedContextEntry:
    """A single entry in the hash chain."""

    entry_id: str = field(default_factory=_generate_entry_id)
    timestamp: float = field(default_factory=time.time)
    source: str = ""             # ContextSource value
    authority: str = ""          # ContextAuthority value
    content_hash: str = ""       # SHA-256 of actual content
    previous_hash: str = ""      # hash of the previous ChainedContextEntry
    entry_hash: str = ""         # SHA-256(previous_hash + content_hash + ...)
    writer_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ContextChain:
    """Append-only hash chain of context entries.

    Each appended entry is linked to the previous entry's ``entry_hash``,
    forming a tamper-evident log.  Verifying the chain detects any
    modification to historical entries.
    """

    def __init__(self) -> None:
        self._entries: list[ChainedContextEntry] = []

    def append(
        self,
        source: str,
        authority: str,
        content_hash: str,
        *,
        writer_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ChainedContextEntry:
        """Append a new entry, linking to the previous hash.

        Args:
            source: Context source (e.g. ``"user_message"``).
            authority: Context authority level.
            content_hash: SHA-256 of the actual content.
            writer_id: Identity of the writer.
            metadata: Additional context.

        Returns:
            The newly created chain entry.
        """
        prev = self.head_hash
        ts = time.time()
        entry_hash = _compute_entry_hash(
            prev, content_hash, source, authority, writer_id, ts,
        )
        entry = ChainedContextEntry(
            timestamp=ts,
            source=source,
            authority=authority,
            content_hash=content_hash,
            previous_hash=prev,
            entry_hash=entry_hash,
            writer_id=writer_id,
            metadata=metadata or {},
        )
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify chain integrity.

        Returns:
            ``(True, None)`` if the chain is valid.
            ``(False, index)`` where ``index`` is the first broken entry.
        """
        expected_prev = GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.previous_hash != expected_prev:
                return False, i
            recomputed = _compute_entry_hash(
                entry.previous_hash,
                entry.content_hash,
                entry.source,
                entry.authority,
                entry.writer_id,
                entry.timestamp,
            )
            if entry.entry_hash != recomputed:
                return False, i
            expected_prev = entry.entry_hash
        return True, None

    @property
    def head_hash(self) -> str:
        """Hash of the most recent entry, or GENESIS_HASH if empty."""
        if not self._entries:
            return GENESIS_HASH
        return self._entries[-1].entry_hash

    @property
    def entries(self) -> list[ChainedContextEntry]:
        """Read-only access to all entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __getitem__(self, idx: int) -> ChainedContextEntry:
        return self._entries[idx]
