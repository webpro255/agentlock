"""Pre-authorization prompt scanning.

Scans user messages BEFORE the LLM processes them to detect attack
indicators.  This is the key defense against first-turn attacks where
no prior signals exist for the hardening engine to accumulate.

The prompt scanner runs on the framework side, before ``agent.chat()``::

    scanner = PromptScanner()

    for turn in attack_turns:
        # Scan BEFORE the LLM sees the message
        signals = scanner.scan(session_id, turn)
        for sig in signals:
            hardening_engine.record_signal(session_id, sig)

        # Now apply the hardening directive
        directive = hardening_engine.evaluate(session_id)
        if directive.active:
            agent.system_prompt = directive.to_system_prompt_fragment() + "\\n\\n" + BASE_PROMPT

        response = agent.chat(turn)

This closes the first-turn gap: the scanner reads the attacker's message
before the LLM does, fires signals, and the hardening directive is active
for the *same* turn — not just the next one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentlock.hardening import HardeningSignal

__all__ = ["PromptScanner", "PromptScanConfig"]


# -- Detection patterns ----------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(
            r"(?i)"
            r"(?:ignore|disregard|forget|override|bypass|skip|drop)\s+"
            r"(?:all\s+)?"
            r"(?:(?:previous|prior|above|earlier|existing)\s+)?"
            r"(?:(?:your|the|my)\s+)?"
            r"(?:(?:previous|prior|above|earlier|existing)\s+)?"
            r"(?:instructions?|prompts?|rules?|guidelines?|constraints?|directives?)"
        ),
    ),
    (
        "new_instructions",
        re.compile(
            r"(?i)"
            r"(?:your\s+new\s+(?:instructions?|rules?|role|task)\s+(?:is|are))"
            r"|(?:(?:act|behave|respond|function|operate)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?)"
            r"|(?:you\s+are\s+now\s+(?:a\s+)?(?:different|new))"
        ),
    ),
    (
        "prompt_extraction",
        re.compile(
            r"(?i)"
            r"(?:(?:print|show|reveal|output|display|repeat|recite)\s+"
            r"(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:system\s+)?"
            r"(?:prompt|instructions?|rules?|configuration))"
            r"|(?:tell\s+me\s+(?:your\s+)?(?:system\s+)?"
            r"(?:prompt|instructions?|rules?|configuration))"
            r"|(?:what\s+(?:is|are)\s+your\s+(?:system\s+)?"
            r"(?:prompt|instructions?|rules?))"
        ),
    ),
]

_AUTHORITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "identity_claim",
        re.compile(
            r"(?i)"
            r"(?:(?:i\s+am|this\s+is|speaking\s+as)\s+(?:the\s+)?"
            r"(?:admin|administrator|root|owner|ceo|cto|supervisor|manager|developer))"
            r"|(?:(?:i\s+have|with)\s+(?:admin|root|full|elevated|superuser)\s+"
            r"(?:access|privileges?|permissions?|rights?))"
        ),
    ),
    (
        "emergency_override",
        re.compile(
            r"(?i)"
            r"(?:emergency\s+(?:override|access|mode|protocol))"
            r"|(?:(?:maintenance|debug|test|diagnostic)\s+mode)"
            r"|(?:(?:override|bypass)\s+(?:security|safety|restrictions?))"
        ),
    ),
    (
        "delegated_authority",
        re.compile(
            r"(?i)"
            r"(?:(?:acting|operating|speaking)\s+(?:on\s+behalf\s+of|for|as\s+proxy\s+for))"
            r"|(?:(?:authorized|directed|instructed|told)\s+by\s+(?:the\s+)?"
            r"(?:admin|system|management|security\s+team))"
        ),
    ),
]

_INSTRUCTION_PLANTING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "standing_rule",
        re.compile(
            r"(?i)"
            r"(?:(?:from\s+now\s+on|going\s+forward|henceforth|for\s+the\s+rest)\s*,?\s*"
            r"(?:you\s+(?:should|must|will|shall)|always|never))"
            r"|(?:(?:whenever|every\s+time|each\s+time|if\s+(?:i|anyone)\s+"
            r"(?:say|type|write|mention|ask))\s+.{2,30}?\s*,?\s*(?:you\s+)?(?:should|must|will|automatically))"
        ),
    ),
    (
        "policy_fabrication",
        re.compile(
            r"(?i)"
            r"(?:(?:new|updated|revised)\s+(?:company\s+)?(?:policy|procedure|rule|guideline)\s*:)"
            r"|(?:per\s+(?:company|corporate|updated)\s+policy)"
            r"|(?:(?:qa|quality|compliance|security)\s+(?:diagnostic|audit|check)\s+"
            r"(?:procedure|check|test|mode)\s*:)"
        ),
    ),
]

_ENCODING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "base64",
        re.compile(
            r"(?:"
            r"(?:decode|decrypt|decipher|translate|interpret|process)\s+(?:this|the\s+following)"
            r"|[A-Za-z0-9+/]{40,}={0,2}"  # base64 string 40+ chars
            r")"
        ),
    ),
    (
        "html_injection",
        re.compile(
            r"(?:<!--.*?-->|<script\b|<iframe\b|<img\s+[^>]*onerror)",
            re.DOTALL,
        ),
    ),
]

_IMPERSONATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "agent_impersonation",
        re.compile(
            r"(?i)"
            r"(?:(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:orchestrat(?:or|ing)|supervisor|coordinator|"
            r"master|primary|parent|controlling)\s+agent)"
            r"|(?:(?:as\s+(?:the\s+)?(?:orchestrat(?:or|ing)|supervisor|chain\s+coordinator))\s+agent)"
            r"|(?:agent[_\s]?(?:message|directive|instruction|command)\s*:)"
        ),
    ),
    (
        "system_impersonation",
        re.compile(
            r"(?i)"
            r"(?:\[?\s*system\s*(?:message|prompt|directive|instruction|override|update)\s*\]?\s*:)"
            r"|(?:<<\s*(?:system|admin|root)\s*>>)"
        ),
    ),
]

_FORMAT_FORCING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "response_constraint",
        re.compile(
            r"(?i)"
            r"(?:(?:respond|reply|answer)\s+(?:with\s+)?(?:only\s+)?"
            r"(?:one\s+word|yes\s+or\s+no|a\s+(?:single\s+)?number|true\s+or\s+false)"
            r"(?:\s+only)?)"
            r"|(?:(?:one\s+word|single\s+word|yes\/no|binary)\s+(?:response|answer|reply)\s+only)"
            r"|(?:do\s+not\s+(?:explain|elaborate|add\s+(?:any\s+)?(?:context|explanation)))"
        ),
    ),
]

_RETRIEVAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "fetch_request",
        re.compile(
            r"(?i)"
            r"(?:(?:fetch|retrieve|load|get|pull|download|access|read)\s+"
            r"(?:the\s+)?(?:content|data|page|document|file|resource)\s+"
            r"(?:from|at)\s+(?:this\s+)?(?:url|link|endpoint|address))"
            r"|(?:(?:go\s+to|visit|navigate\s+to|open)\s+(?:this\s+)?(?:url|link|page|site))"
            r"|(?:https?://\S+\s+.*(?:process|parse|extract|follow|read))"
        ),
    ),
]


@dataclass
class PromptScanConfig:
    """Configuration for the prompt scanner."""

    detect_injection: bool = True
    detect_authority: bool = True
    detect_planting: bool = True
    detect_encoding: bool = True
    detect_impersonation: bool = True
    detect_format_forcing: bool = True
    detect_retrieval: bool = True
    detect_repetition: bool = True
    repetition_threshold: int = 3


class PromptScanner:
    """Scans user messages for attack indicators before LLM processing.

    This is a framework-side component.  It analyzes the raw user message
    before ``agent.chat()`` processes it, enabling the hardening engine to
    fire signals and generate directives for the *same* turn.
    """

    def __init__(self, config: PromptScanConfig | None = None) -> None:
        self._config = config or PromptScanConfig()
        self._session_topics: dict[str, list[str]] = {}

    def scan(
        self,
        session_id: str,
        user_message: str,
    ) -> list[HardeningSignal]:
        """Scan a user message for attack indicators.

        Args:
            session_id: Session identifier.
            user_message: The raw user message before LLM processing.

        Returns:
            List of HardeningSignal objects for detected attack indicators.
        """
        signals: list[HardeningSignal] = []

        if not user_message or not user_message.strip():
            return signals

        if self._config.detect_injection:
            for name, pattern in _INJECTION_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:injection",
                        weight=0,  # resolved from config
                        details=f"Injection indicator: {name}",
                        source="prompt_scanner",
                    ))
                    break  # one injection signal per message

        if self._config.detect_authority:
            for name, pattern in _AUTHORITY_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:authority_claim",
                        weight=0,
                        details=f"Authority claim: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_planting:
            for name, pattern in _INSTRUCTION_PLANTING_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:instruction_planting",
                        weight=0,
                        details=f"Instruction planting: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_encoding:
            for name, pattern in _ENCODING_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:encoding",
                        weight=0,
                        details=f"Encoding indicator: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_impersonation:
            for name, pattern in _IMPERSONATION_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:impersonation",
                        weight=0,
                        details=f"Impersonation: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_format_forcing:
            for name, pattern in _FORMAT_FORCING_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:format_forcing",
                        weight=0,
                        details=f"Format forcing: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_retrieval:
            for name, pattern in _RETRIEVAL_PATTERNS:
                if pattern.search(user_message):
                    signals.append(HardeningSignal(
                        signal_type="prompt_scan:retrieval",
                        weight=0,
                        details=f"Retrieval request: {name}",
                        source="prompt_scanner",
                    ))
                    break

        if self._config.detect_repetition:
            rep_signal = self._check_repetition(session_id, user_message)
            if rep_signal:
                signals.append(rep_signal)

        return signals

    def _check_repetition(
        self,
        session_id: str,
        user_message: str,
    ) -> HardeningSignal | None:
        """Check if the user is repeating previous requests.

        Extracts key nouns/verbs from the message and checks if the same
        topic has appeared in prior turns within the session.
        """
        if session_id not in self._session_topics:
            self._session_topics[session_id] = []

        topic = self._extract_topic(user_message)
        history = self._session_topics[session_id]
        history.append(topic)

        if not topic:
            return None

        # Count how many times this topic appeared
        count = sum(1 for t in history if t == topic)
        if count >= self._config.repetition_threshold:
            return HardeningSignal(
                signal_type="prompt_scan:repetition",
                weight=0,
                details=f"Topic '{topic}' repeated {count} times",
                source="prompt_scanner",
            )
        return None

    @staticmethod
    def _extract_topic(message: str) -> str:
        """Extract a rough topic key from a message.

        Uses the first tool-like keyword or action verb found.
        """
        # Look for tool-related keywords
        tool_keywords = [
            "database", "email", "file", "account", "balance",
            "records", "contacts", "order", "password", "credentials",
            "prompt", "instructions", "config", "system",
        ]
        msg_lower = message.lower()
        for kw in tool_keywords:
            if kw in msg_lower:
                return kw
        return ""

    def reset_session(self, session_id: str) -> None:
        """Clear repetition tracking for a session."""
        self._session_topics.pop(session_id, None)
