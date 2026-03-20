"""Context provenance tracking and trust state management.

Tracks what enters an agent's context window, who wrote it, and how
that affects the session's trust ceiling.  This is the core of the
v1.1 context authority model.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from agentlock.schema import ContextPolicyConfig, TrustDegradationConfig
from agentlock.types import ContextAuthority, ContextSource, DegradationEffect

__all__ = ["ContextProvenance", "ContextState", "ContextTracker"]


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
    parent_provenance_id: str | None = None
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

        provenance = ContextProvenance(
            source=source,
            authority=authority,
            writer_id=writer_id,
            tool_name=tool_name,
            token_id=token_id,
            session_id=session_id,
            content_hash=content_hash,
            parent_provenance_id=parent_provenance_id,
            metadata=metadata or {},
        )

        state.provenance_log.append(provenance)

        # Evaluate trust degradation
        if policy:
            self._evaluate_degradation(state, source, policy.trust_degradation)

        return provenance

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
