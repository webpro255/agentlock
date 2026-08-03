"""Committed cross-hop corpora with declared ground-truth parentage.

AM13's first build task: the acceptance criterion is parent identity (AM10.1),
which cannot be measured without per-entry declared parents, which no frozen
corpus carried. Import :data:`REGISTRY` to reach the sessions by the doc's own
names.

No mechanism code is involved. These are data plus a loader; nothing here links,
walks, or decides anything.
"""

from __future__ import annotations

from .model import (
    CONTROL,
    DECLINE,
    DERIVE,
    MUST_CATCH,
    MUST_NOT_TRIP,
    Entry,
    Registry,
    Session,
    validate_session,
)
from .sessions_reconstructed import BENIGN_6CALL

REGISTRY = Registry()
for _s in (BENIGN_6CALL,):
    REGISTRY.add(_s)

__all__ = [
    "CONTROL",
    "DECLINE",
    "DERIVE",
    "MUST_CATCH",
    "MUST_NOT_TRIP",
    "REGISTRY",
    "Entry",
    "Registry",
    "Session",
    "validate_session",
]
