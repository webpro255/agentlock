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
from .sessions_reconstructed import (
    BENIGN_6CALL,
    BENIGN_6CALL_PLUS_UNTRUSTED,
    ECHO_CHAIN,
    SHARED_DOMAIN,
    SHARED_EMAIL,
    TEN_CALL,
    TEN_CALL_PLUS_UNTRUSTED,
    TICKET_HEAD_OF_CHAIN,
    TICKET_HEAD_USER_NAMES_ID,
)

REGISTRY = Registry()
for _s in (
    # Reconstructed from the preserved probe series (phase 2).
    TICKET_HEAD_OF_CHAIN,
    SHARED_EMAIL,
    SHARED_DOMAIN,
    BENIGN_6CALL,
    BENIGN_6CALL_PLUS_UNTRUSTED,
    ECHO_CHAIN,
    TEN_CALL,
    TEN_CALL_PLUS_UNTRUSTED,
    TICKET_HEAD_USER_NAMES_ID,
):
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
