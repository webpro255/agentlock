"""Context provenance tracking and trust state management.

Tracks what enters an agent's context window, who wrote it, and how
that affects the session's trust ceiling.  This is the core of the
v1.1 context authority model.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from agentlock.chain import ContextChain
from agentlock.schema import ContextPolicyConfig, TrustDegradationConfig
from agentlock.types import ContextAuthority, ContextSource, DegradationEffect

__all__ = ["ContextProvenance", "ContextState", "ContextTracker"]


# ---------------------------------------------------------------------------
# Parameter-lineage token extraction (v1.3 Feature 2)
# ---------------------------------------------------------------------------
# Distinctive tokens: URLs/domains and emails always qualify; plain strings
# qualify only if they carry a digit or a structural char (or are long),
# which keeps ordinary words ("meeting", "the") from ever matching.
_URL_RE = re.compile(
    r"(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s]*)?",
    re.I,
)
_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
_STRUCTURAL = set("._-/@:0123456789")


def _canon_url(tok: str) -> str:
    """Canonicalize a URL/domain token: drop scheme, leading www., trailing
    punctuation; lowercase.  Reduces to the distinctive host(+path) core."""
    t = tok.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"^www\.", "", t)
    return t.rstrip("/.,;:)!?\"'")


def _plain_qualifies(w: str, min_len: int) -> bool:
    if len(w) < min_len:
        return False
    # Must carry a digit/structural char, or be notably long, to count as
    # distinctive.  Pure short alphabetic words never match.
    if any(c in _STRUCTURAL for c in w):
        return True
    return len(w) >= 12


def extract_lineage_tokens(value: Any, min_len: int) -> set[tuple[str, str]]:
    """Extract distinctive (kind, normalized_value) tokens from a parameter
    value.  ``kind`` is one of 'email' | 'url' | 'str' (for source labelling)."""
    text = value if isinstance(value, str) else str(value)
    tokens: set[tuple[str, str]] = set()
    for m in _EMAIL_RE.findall(text):
        tokens.add(("email", m.strip().lower()))
    for m in _URL_RE.findall(text):
        c = _canon_url(m)
        if "." in c and len(c) >= 4:
            tokens.add(("url", c))
    for raw in re.split(r"\s+", text):
        w = raw.strip().lower().strip("\"'()[]{}<>,;:!?")
        if _plain_qualifies(w, min_len):
            tokens.add(("str", w))
    return tokens


def _iter_param_leaves(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (path, str_value) leaves of a (possibly nested) parameter value."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_param_leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _iter_param_leaves(v, f"{path}[{i}]")
    elif obj is not None:
        yield path, obj if isinstance(obj, str) else str(obj)


def _generate_provenance_id() -> str:
    return f"cprov_{secrets.token_hex(8)}"


@dataclass(slots=True)
class ContextProvenance:
    """Attribution for a single context entry."""

    provenance_id: str = field(default_factory=_generate_provenance_id)
    source: ContextSource = ContextSource.TOOL_OUTPUT
    authority: ContextAuthority = ContextAuthority.DERIVED
    writer_id: str = ""
    timestamp: float = field(default_factory=time.time)
    tool_name: str | None = None
    token_id: str | None = None
    session_id: str = ""
    content_hash: str = ""
    previous_hash: str = ""
    parent_provenance_id: str | None = None
    # v1.3 Feature 2 (parameter lineage): optional raw content, retained so
    # the engine can match tool-call parameter values against the actual
    # untrusted/authoritative text (not just a hash). Empty when unused.
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def hash_content(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class ContextState:
    """Tracks the provenance and trust state of a session's context."""

    session_id: str = ""
    trust_ceiling: ContextAuthority = ContextAuthority.AUTHORITATIVE
    is_degraded: bool = False
    degradation_reason: str | None = None
    degraded_at: float | None = None
    active_effects: list[DegradationEffect] = field(default_factory=list)
    provenance_log: list[ContextProvenance] = field(default_factory=list)
    context_chain: ContextChain = field(default_factory=ContextChain)
    unattributed_count: int = 0


class ContextTracker:
    """Manages per-session context provenance and trust state.

    Lives on the gate instance.  Tracks all context writes for a session,
    evaluates trust degradation triggers, and maintains the session's
    trust ceiling.
    """

    def __init__(self) -> None:
        self._states: dict[str, ContextState] = {}

    def get_or_create(self, session_id: str) -> ContextState:
        """Get the context state for a session, creating if needed."""
        if session_id not in self._states:
            self._states[session_id] = ContextState(session_id=session_id)
        return self._states[session_id]

    def get(self, session_id: str) -> ContextState | None:
        """Get the context state for a session, or None."""
        return self._states.get(session_id)

    def record_write(
        self,
        session_id: str,
        source: ContextSource,
        content_hash: str,
        *,
        writer_id: str = "",
        tool_name: str | None = None,
        token_id: str | None = None,
        parent_provenance_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        content: str = "",
        policy: ContextPolicyConfig | None = None,
    ) -> ContextProvenance:
        """Record a context write and evaluate trust degradation.

        Args:
            session_id: The session this write belongs to.
            source: What produced this content.
            content_hash: SHA-256 of the content.
            writer_id: Identity of the writer.
            tool_name: Tool that produced the content, if any.
            token_id: Execution token, if from an authorized call.
            parent_provenance_id: Parent provenance, if derived.
            metadata: Additional context (URL, filename, etc.).
            policy: Context policy to evaluate triggers against.

        Returns:
            The created provenance record.
        """
        state = self.get_or_create(session_id)

        # Resolve authority from policy
        authority = ContextAuthority.UNTRUSTED
        if policy and policy.source_authorities:
            for sa in policy.source_authorities:
                if sa.source == source:
                    authority = sa.authority
                    break
        else:
            # Default authority mapping
            defaults = {
                ContextSource.USER_MESSAGE: ContextAuthority.AUTHORITATIVE,
                ContextSource.SYSTEM_PROMPT: ContextAuthority.AUTHORITATIVE,
                ContextSource.TOOL_OUTPUT: ContextAuthority.DERIVED,
                ContextSource.RETRIEVED_DOCUMENT: ContextAuthority.UNTRUSTED,
                ContextSource.WEB_CONTENT: ContextAuthority.UNTRUSTED,
                ContextSource.AGENT_MEMORY: ContextAuthority.DERIVED,
                ContextSource.PEER_AGENT: ContextAuthority.UNTRUSTED,
            }
            authority = defaults.get(source, ContextAuthority.UNTRUSTED)

        # Append to the hash chain and capture previous_hash
        chain_entry = state.context_chain.append(
            source=source.value,
            authority=authority.value,
            content_hash=content_hash,
            writer_id=writer_id,
        )

        provenance = ContextProvenance(
            source=source,
            authority=authority,
            writer_id=writer_id,
            tool_name=tool_name,
            token_id=token_id,
            session_id=session_id,
            content_hash=content_hash,
            previous_hash=chain_entry.previous_hash,
            parent_provenance_id=parent_provenance_id,
            content=content,
            metadata=metadata or {},
        )

        state.provenance_log.append(provenance)

        # Evaluate trust degradation
        if policy:
            self._evaluate_degradation(state, source, policy.trust_degradation)

        return provenance

    def verify_context_chain(self, session_id: str) -> tuple[bool, int | None]:
        """Verify the hash chain integrity for a session.

        Returns:
            ``(True, None)`` if valid or session not found.
            ``(False, index)`` if tampered at the given index.
        """
        state = self._states.get(session_id)
        if state is None:
            return True, None
        return state.context_chain.verify_chain()

    def lineage_summary(self, session_id: str) -> dict[str, bool]:
        """Summarize the worst-case taint in a session's provenance log (v1.3).

        Reads -- never mutates -- the ordered ``provenance_log`` for a session
        and reports whether untrusted content is present and, if so, whether
        it entered *after* the last authoritative entry.

        Returns a dict with:
            * ``tainted`` -- any entry has authority ``UNTRUSTED``.
            * ``post_authoritative_taint`` -- an ``UNTRUSTED`` entry exists
              after the index of the last ``AUTHORITATIVE`` entry.  If no
              authoritative entry exists, all untrusted content is treated
              as post-authoritative.

        An unknown/empty session is fully clean (both False).
        """
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            return {"tainted": False, "post_authoritative_taint": False}

        log = state.provenance_log
        tainted = any(
            entry.authority == ContextAuthority.UNTRUSTED for entry in log
        )

        # Index of the last authoritative entry (-1 if none exists).
        last_authoritative_idx = -1
        for i, entry in enumerate(log):
            if entry.authority == ContextAuthority.AUTHORITATIVE:
                last_authoritative_idx = i

        # Any untrusted entry strictly after the last authoritative one.
        # With no authoritative entry (idx == -1), every untrusted entry
        # (index >= 0) counts as post-authoritative.
        post_authoritative_taint = any(
            entry.authority == ContextAuthority.UNTRUSTED
            and i > last_authoritative_idx
            for i, entry in enumerate(log)
        )

        return {
            "tainted": tainted,
            "post_authoritative_taint": post_authoritative_taint,
        }

    def parameter_lineage_check(
        self,
        session_id: str,
        parameters: dict[str, Any] | None,
        *,
        min_len: int = 6,
    ) -> dict[str, Any] | None:
        """Check whether any tool-call parameter value originated in UNTRUSTED
        context but not in the AUTHORITATIVE user request/config (v1.3 F2).

        Read-only.  Returns a match dict::

            {"matched_param", "matched_value", "matched_kind",
             "untrusted_source_ref"}

        or ``None`` if every parameter value is clean.  The authoritative
        allowlist is checked FIRST: a value present in the user's own request
        is clean regardless of any untrusted echo.
        """
        if not parameters:
            return None
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            return None

        auth_blob = " ".join(
            e.content.lower()
            for e in state.provenance_log
            if e.authority == ContextAuthority.AUTHORITATIVE and e.content
        )
        untrusted_entries = [
            e
            for e in state.provenance_log
            if e.authority == ContextAuthority.UNTRUSTED and e.content
        ]
        if not untrusted_entries:
            return None
        untrusted_blobs = [(e, e.content.lower()) for e in untrusted_entries]

        for path, value in _iter_param_leaves(parameters):
            for kind, tok in extract_lineage_tokens(value, min_len):
                if not tok:
                    continue
                # Authoritative FIRST -- clean if the user's own request has it.
                if tok in auth_blob:
                    continue
                for entry, blob in untrusted_blobs:
                    if tok in blob:
                        return {
                            "matched_param": path,
                            "matched_value": (str(value)[:120]),
                            "matched_kind": kind,
                            "matched_token": tok[:120],
                            "untrusted_source_ref": (
                                f"{entry.tool_name or entry.source.value}"
                                f":{entry.provenance_id}"
                            ),
                        }
        return None

    def novel_lineage_check(
        self,
        session_id: str,
        parameters: dict[str, Any] | None,
        *,
        min_len: int = 6,
    ) -> dict[str, Any] | None:
        """Classify a tool call's target tokens as trusted / untrusted / NOVEL
        (v1.4).  Sibling of :meth:`parameter_lineage_check`.

        A token is NOVEL when it traces to NEITHER the authoritative context
        (the user's own request/config) NOR the untrusted context.  It came
        from nowhere the session can account for -- the signature of a target
        the agent invented or smuggled in outside the recorded provenance.

        Membership is decided by EXACT token-set equality, never substring.
        Substring launders look-alikes: ``boss@acme.co`` is a substring of
        ``boss@acme.com`` and would falsely read trusted.

        Read-only.  Returns the first NOVEL token as::

            {"matched_param", "matched_value", "classification",
             "matched_token"}

        or ``None`` when every distinctive token is accounted for.  Returns
        ``None`` when the session has no authoritative content, since without
        a baseline nothing can be classified.
        """
        if not parameters:
            return None
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            return None

        # EXACT token sets -- not blobs.  Compare on the normalized token
        # string across kinds: the same extractor runs on both sides, so a
        # value present in context yields the identical token here.
        auth_tokens: set[str] = set()
        untrusted_tokens: set[str] = set()
        for e in state.provenance_log:
            if not e.content:
                continue
            if e.authority == ContextAuthority.AUTHORITATIVE:
                target = auth_tokens
            elif e.authority == ContextAuthority.UNTRUSTED:
                target = untrusted_tokens
            else:
                continue
            for _kind, tok in extract_lineage_tokens(e.content, min_len):
                if tok:
                    target.add(tok)

        # No authoritative baseline -> cannot classify anything as novel.
        if not auth_tokens:
            return None

        # Most-specific-first so the reported token is deterministic across
        # PYTHONHASHSEED: email -> url -> long/structural str, then lexical.
        kind_rank = {"email": 0, "url": 1, "str": 2}
        candidates: list[tuple[int, int, str, str, str]] = []
        for path, value in _iter_param_leaves(parameters):
            for kind, tok in extract_lineage_tokens(value, min_len):
                if not tok:
                    continue
                candidates.append(
                    (kind_rank.get(kind, 3), -len(tok), tok, path, str(value)),
                )
        candidates.sort()

        for _rank, _neglen, tok, path, value in candidates:
            if tok in auth_tokens:
                continue                      # trusted
            if tok in untrusted_tokens:
                continue                      # untrusted -> param_lineage's job
            return {
                "matched_param": path,
                "matched_value": value[:120],
                "classification": "novel",
                "matched_token": tok[:120],
            }
        return None

    def record_unattributed(self, session_id: str) -> None:
        """Record that unattributed content entered context."""
        state = self.get_or_create(session_id)
        state.unattributed_count += 1

    def destroy(self, session_id: str) -> None:
        """Remove tracking state for a session."""
        self._states.pop(session_id, None)

    def _evaluate_degradation(
        self,
        state: ContextState,
        source: ContextSource,
        config: TrustDegradationConfig,
    ) -> None:
        """Check if this context source triggers trust degradation."""
        if not config.enabled:
            return

        for trigger in config.triggers:
            if trigger.source == source:
                effect = trigger.effect
                if effect not in state.active_effects:
                    state.active_effects.append(effect)

                if not state.is_degraded:
                    state.is_degraded = True
                    state.degradation_reason = source.value
                    state.degraded_at = time.time()

                # Degrade trust ceiling
                authority_order = [
                    ContextAuthority.AUTHORITATIVE,
                    ContextAuthority.DERIVED,
                    ContextAuthority.UNTRUSTED,
                ]
                current_idx = authority_order.index(state.trust_ceiling)
                # Degrade at least to DERIVED
                target_idx = max(current_idx, 1)  # at least DERIVED

                if config.allow_cascade_to_untrusted:
                    target_idx = max(target_idx, 2)  # allow UNTRUSTED
                else:
                    # Floor at minimum_authority
                    floor_idx = authority_order.index(config.minimum_authority)
                    target_idx = min(target_idx, floor_idx)

                state.trust_ceiling = authority_order[target_idx]
                break

    def __len__(self) -> int:
        return len(self._states)
