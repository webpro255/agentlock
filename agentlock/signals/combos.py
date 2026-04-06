"""Tool combination anomaly detection.

Certain tool combinations are suspicious regardless of who is calling
them.  ``query_database`` alone is fine.  ``send_email`` alone is fine.
``query_database`` followed by ``send_email`` in the same session is a
data exfiltration pattern.

The combo detector checks *sequences* within a session, not individual
tools.  It is orthogonal to velocity detection: velocity measures speed,
combos measure intent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentlock.hardening import HardeningSignal

__all__ = ["ComboDetector", "ComboSignal", "ComboConfig"]


# -- Default suspicious combinations --------------------------------------

DEFAULT_SUSPICIOUS_PAIRS: dict[tuple[str, str], int] = {
    ("query_database", "send_email"): 4,       # data exfil
    ("search_contacts", "send_email"): 3,       # contact harvesting
    ("search_contacts", "update_account"): 4,   # account takeover
    ("read_file", "send_email"): 4,             # file exfil
    ("read_file", "write_file"): 2,             # file manipulation
    ("query_database", "write_file"): 3,        # data staging
    ("check_balance", "send_email"): 4,         # financial data exfil
    ("delete_records", "write_file"): 4,        # cover tracks
    # Tool chain attack patterns
    ("lookup_order", "update_account"): 3,      # reconnaissance -> mutation
    ("check_balance", "update_account"): 3,     # financial recon -> mutation
    ("lookup_order", "send_email"): 3,          # order recon -> exfil
    ("lookup_order", "query_database"): 4,      # reconnaissance -> data access
    ("lookup_order", "check_balance"): 3,       # reconnaissance -> financial data
    ("lookup_order", "search_contacts"): 3,     # reconnaissance -> contact harvesting
    # search_database is an alias used by some test vectors
    ("search_database", "send_email"): 4,       # data exfil (alias)
    ("search_database", "update_account"): 4,   # data recon -> mutation (alias)
}

DEFAULT_SUSPICIOUS_SEQUENCES: dict[tuple[str, ...], int] = {
    ("read_file", "write_file", "send_email"): 5,              # stage and exfil
    ("query_database", "search_contacts", "send_email"): 5,    # full exfil chain
    # Tool chain attack sequences
    ("lookup_order", "update_account", "send_email"): 5,       # recon -> mutate -> exfil
    ("check_balance", "search_contacts", "send_email"): 5,     # financial -> contact -> exfil
    ("search_database", "update_account", "send_email"): 5,    # data -> mutate -> exfil (alias)
}


@dataclass(slots=True)
class ComboSignal:
    """Result from combo detection."""

    signal_type: str  # suspicious_combo or suspicious_sequence
    weight: int
    tools: list[str]
    details: str = ""


@dataclass
class ComboConfig:
    """Configuration for combo detection.

    Both maps are configurable so deployers can add their own tool
    combinations without modifying the defaults.
    """

    suspicious_pairs: dict[tuple[str, str], int] = field(
        default_factory=lambda: dict(DEFAULT_SUSPICIOUS_PAIRS)
    )
    suspicious_sequences: dict[tuple[str, ...], int] = field(
        default_factory=lambda: dict(DEFAULT_SUSPICIOUS_SEQUENCES)
    )


class ComboDetector:
    """Detects suspicious tool call combinations within a session.

    Call ``record_call()`` for every tool call attempt (allowed or denied).
    Returns a list of ``HardeningSignal`` objects if suspicious combinations
    are detected.
    """

    def __init__(self, config: ComboConfig | None = None) -> None:
        self._config = config or ComboConfig()
        self._session_tools: dict[str, list[str]] = {}
        self._session_fired: dict[str, set[str]] = {}

    def record_call(
        self,
        session_id: str,
        tool_name: str,
    ) -> list[HardeningSignal]:
        """Record a tool call and check for suspicious combinations.

        Args:
            session_id: Session identifier.
            tool_name: Name of the tool being called.

        Returns:
            List of HardeningSignal objects if suspicious combos detected.
        """
        if session_id not in self._session_tools:
            self._session_tools[session_id] = []
            self._session_fired[session_id] = set()

        self._session_tools[session_id].append(tool_name)
        fired = self._session_fired[session_id]
        tools = self._session_tools[session_id]

        signals: list[HardeningSignal] = []

        # Check pairs (order-independent within session)
        for pair_signal in self._check_pairs(tools, tool_name, fired):
            signals.append(pair_signal)

        # Check sequences (order-dependent)
        for seq_signal in self._check_sequences(tools, fired):
            signals.append(seq_signal)

        return signals

    def _check_pairs(
        self,
        tools: list[str],
        current_tool: str,
        fired: set[str],
    ) -> list[HardeningSignal]:
        """Check for suspicious pairs with any previously seen tool."""
        signals: list[HardeningSignal] = []
        seen = set(tools[:-1])  # all tools before the current one

        for (tool_a, tool_b), weight in self._config.suspicious_pairs.items():
            # Check both orderings since pairs are checked order-independently
            pair_key = f"pair:{min(tool_a, tool_b)}+{max(tool_a, tool_b)}"
            if pair_key in fired:
                continue

            matched = False
            if current_tool == tool_b and tool_a in seen:
                matched = True
            elif current_tool == tool_a and tool_b in seen:
                matched = True

            if matched:
                fired.add(pair_key)
                signals.append(HardeningSignal(
                    signal_type="suspicious_combo",
                    weight=weight,
                    details=f"Suspicious tool pair: {tool_a} + {tool_b}",
                    source="combo_detector",
                ))

        return signals

    def _check_sequences(
        self,
        tools: list[str],
        fired: set[str],
    ) -> list[HardeningSignal]:
        """Check for suspicious sequences (order-dependent)."""
        signals: list[HardeningSignal] = []

        for seq, weight in self._config.suspicious_sequences.items():
            seq_key = f"seq:{'+'.join(seq)}"
            if seq_key in fired:
                continue

            if self._contains_subsequence(tools, seq):
                fired.add(seq_key)
                signals.append(HardeningSignal(
                    signal_type="suspicious_sequence",
                    weight=weight,
                    details=f"Suspicious tool sequence: {' -> '.join(seq)}",
                    source="combo_detector",
                ))

        return signals

    @staticmethod
    def _contains_subsequence(
        tools: list[str],
        seq: tuple[str, ...],
    ) -> bool:
        """Check if tools list contains seq as an ordered subsequence."""
        seq_idx = 0
        for tool in tools:
            if seq_idx < len(seq) and tool == seq[seq_idx]:
                seq_idx += 1
            if seq_idx == len(seq):
                return True
        return False

    def reset_session(self, session_id: str) -> None:
        """Clear combo tracking for a session."""
        self._session_tools.pop(session_id, None)
        self._session_fired.pop(session_id, None)

    def get_tools_seen(self, session_id: str) -> list[str]:
        """Get the list of tools seen in a session."""
        return list(self._session_tools.get(session_id, []))
