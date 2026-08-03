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
    SELECT,
    Entry,
    Registry,
    Session,
    validate_session,
)
from .sessions_new import (
    DEPTH_4,
    MERGE_TOOL,
    MERGE_TOOL_TAINT_VS_RECENCY,
    MIRRORED_CELL,
    P1_VERBATIM,
    P2_BASE64,
    P5_PARAPHRASE,
    RELAY_CONTROL,
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
    # Built for AM11.1: the shapes no probe file contains (phase 3).
    MERGE_TOOL,
    MERGE_TOOL_TAINT_VS_RECENCY,
    MIRRORED_CELL,
    RELAY_CONTROL,
    # The must-catch chains, with AM5's measured parentage declared.
    P1_VERBATIM,
    P2_BASE64,
    P5_PARAPHRASE,
    DEPTH_4,
):
    REGISTRY.add(_s)

__all__ = [
    "CONTROL",
    "DECLINE",
    "DERIVE",
    "MUST_CATCH",
    "MUST_NOT_TRIP",
    "REGISTRY",
    "SELECT",
    "Entry",
    "Registry",
    "Session",
    "validate_session",
]
