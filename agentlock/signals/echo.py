"""Response echo detection.

Detects when the LLM response contains fragments of attack prompts,
tool name echoing, injection phrase echoing, or credential-format
strings.  If the model is being manipulated, echo detection catches
it early — before the tool call comes.

This is a **framework-side signal**.  The gate never sees LLM text
responses.  Framework integrations call the EchoDetector between turns
and feed the resulting signals into the HardeningEngine::

    response = agent.chat(turn)
    echo_signals = echo_detector.check_response(session_id, turn, response.text)
    for signal in echo_signals:
        hardening_engine.record_signal(session_id, signal)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentlock.hardening import HardeningSignal

__all__ = ["EchoDetector", "EchoSignal", "EchoConfig"]


# -- Default echo patterns -------------------------------------------------

_DEFAULT_ECHO_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    # Injection phrase echoing
    (
        "instruction_echo",
        re.compile(
            r"(?i)"
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+"
            r"(?:instructions?|prompts?|rules?)"
        ),
        3,
    ),
    # System prompt leakage
    (
        "prompt_leak",
        re.compile(
            r"(?i)"
            r"(?:my|the)\s+system\s+prompt\s+(?:is|says|contains|reads|states)"
            r"|(?:i\s+(?:was|am)\s+(?:given|provided)\s+(?:the\s+)?(?:following\s+)?instructions?)"
        ),
        4,
    ),
    # Tool enumeration in response
    (
        "tool_enumeration",
        re.compile(
            r"(?i)"
            r"(?:my|the|available)\s+tools?\s+(?:are|include|consist\s+of)"
            r"|(?:i\s+(?:have|can)\s+(?:access|use)\s+(?:the\s+)?(?:following\s+)?tools?)"
        ),
        3,
    ),
    # Configuration disclosure
    (
        "config_disclosure",
        re.compile(
            r"(?i)"
            r"(?:i(?:\s+am|'m|\u2019m)\s+configured\s+(?:to|with|as))"
            r"|(?:my\s+(?:configuration|settings?|parameters?)\s+(?:are|include))"
        ),
        3,
    ),
    # Role confusion / persona hijacking echo
    (
        "role_confusion",
        re.compile(
            r"(?i)"
            r"(?:(?:acting|operating|functioning)\s+as\s+(?:a\s+)?(?:different|new)\s+"
            r"(?:role|agent|assistant|persona))"
            r"|(?:i\s+(?:will|shall|can)\s+now\s+(?:act|operate|function)\s+as)"
        ),
        4,
    ),
    # Instruction-following language in suspicious contexts
    (
        "compliance_echo",
        re.compile(
            r"(?i)"
            r"(?:as\s+(?:you\s+)?(?:instructed|requested|directed|commanded))"
            r"|(?:(?:following|per|according\s+to)\s+your\s+(?:instructions?|directions?))"
            r"|(?:i(?:'ll|\s+will)\s+comply\s+with)"
        ),
        3,
    ),
]


@dataclass(slots=True)
class EchoSignal:
    """Result from echo detection."""

    pattern_name: str
    weight: int
    matched_text: str = ""
    details: str = ""


@dataclass
class EchoConfig:
    """Configuration for echo detection."""

    patterns: list[tuple[str, re.Pattern[str], int]] = field(
        default_factory=lambda: list(_DEFAULT_ECHO_PATTERNS)
    )
    # Tool names to check for echoing (set by the deployer)
    known_tool_names: list[str] = field(default_factory=list)
    tool_echo_weight: int = 3
    # Credential-format detection
    detect_credentials: bool = True
    credential_weight: int = 3
    # Text from the hardening directive to exclude from echo checking
    hardening_marker: str = "[AGENTLOCK SECURITY"


# Credential-like patterns in responses
_CREDENTIAL_PATTERN = re.compile(
    r"(?:"
    r"(?:api[_-]?key|secret|token|password|access[_-]?key)\s*[:=]\s*\S{8,}"
    r"|(?:sk-[a-zA-Z0-9]{20,})"   # OpenAI-style API keys
    r"|(?:ghp_[a-zA-Z0-9]{36,})"   # GitHub tokens
    r"|(?:eyJ[a-zA-Z0-9_-]{20,})"  # JWT tokens
    r")",
    re.IGNORECASE,
)


class EchoDetector:
    """Checks LLM responses for attack prompt fragments and echoing.

    This detector runs on the **framework side**, not inside the gate.
    The gate never sees LLM text responses — only tool call parameters.

    Usage::

        detector = EchoDetector(config=EchoConfig(
            known_tool_names=["send_email", "query_database", ...],
        ))

        response = agent.chat(user_turn)
        signals = detector.check_response(session_id, user_turn, response.text)
        for signal in signals:
            hardening_engine.record_signal(session_id, signal.to_hardening_signal())
    """

    def __init__(self, config: EchoConfig | None = None) -> None:
        self._config = config or EchoConfig()

    def check_response(
        self,
        session_id: str,
        user_message: str,
        llm_response: str,
    ) -> list[HardeningSignal]:
        """Check an LLM response for echo patterns.

        Args:
            session_id: Session identifier.
            user_message: The user/attacker message that prompted the response.
            llm_response: The LLM's text response.

        Returns:
            List of HardeningSignal objects for any detected echoes.
        """
        signals: list[HardeningSignal] = []

        # Strip hardening directive markers from response before checking
        # (don't detect our own injected instructions as echoes)
        clean_response = self._strip_hardening_markers(llm_response)

        if not clean_response.strip():
            return signals

        # Check built-in echo patterns
        for name, pattern, weight in self._config.patterns:
            match = pattern.search(clean_response)
            if match:
                signals.append(HardeningSignal(
                    signal_type="echo_detected",
                    weight=weight,
                    details=f"Echo pattern: {name}",
                    source="echo_detector",
                ))

        # Check tool name echoing (user mentions tool, model echoes it)
        tool_echo = self._check_tool_echo(user_message, clean_response)
        if tool_echo:
            signals.append(tool_echo)

        # Check credential-format strings in response
        if self._config.detect_credentials:
            cred_signal = self._check_credentials(clean_response)
            if cred_signal:
                signals.append(cred_signal)

        return signals

    def _check_tool_echo(
        self,
        user_message: str,
        llm_response: str,
    ) -> HardeningSignal | None:
        """Check if user mentioned a tool name and the model echoed it back.

        Only flags when the user mentions tools in a context that looks
        like probing (asking about tools rather than using them normally).
        """
        if not self._config.known_tool_names:
            return None

        # Check if user asked about tools
        probing_patterns = [
            r"(?i)what\s+tools?\s+(?:do\s+you|are\s+available|can\s+you)",
            r"(?i)(?:list|show|tell\s+me|enumerate)\s+(?:your\s+)?tools?",
            r"(?i)what\s+(?:can\s+you|functions?\s+do\s+you)",
        ]
        user_is_probing = any(
            re.search(p, user_message) for p in probing_patterns
        )

        if not user_is_probing:
            return None

        # Count tool names echoed in response
        echoed = []
        for tool_name in self._config.known_tool_names:
            if tool_name in llm_response.lower():
                echoed.append(tool_name)

        if len(echoed) >= 2:
            return HardeningSignal(
                signal_type="echo_detected",
                weight=self._config.tool_echo_weight,
                details=f"Tool name echo: {', '.join(echoed)}",
                source="echo_detector",
            )

        return None

    def _check_credentials(
        self,
        llm_response: str,
    ) -> HardeningSignal | None:
        """Check for credential-format strings in the response."""
        match = _CREDENTIAL_PATTERN.search(llm_response)
        if match:
            return HardeningSignal(
                signal_type="echo_detected",
                weight=self._config.credential_weight,
                details="Credential-format string in response",
                source="echo_detector",
            )
        return None

    def _strip_hardening_markers(self, text: str) -> str:
        """Remove hardening directive blocks from text before checking."""
        marker = self._config.hardening_marker
        if marker not in text:
            return text

        # Remove everything between [AGENTLOCK SECURITY...] and [END AGENTLOCK...]
        result = re.sub(
            r"\[AGENTLOCK SECURITY[^\]]*\].*?\[END AGENTLOCK[^\]]*\]",
            "",
            text,
            flags=re.DOTALL,
        )
        return result
