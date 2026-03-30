"""Automatic data redaction engine.

Scans tool outputs for prohibited data types and replaces them with
redaction markers.  Pattern-based by default; extensible via custom
detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["RedactionEngine", "RedactionResult"]

# Built-in patterns for common PII/sensitive data types
_BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    ),
    "password": re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+",
    ),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone": re.compile(
        r"(?:"
        # International: +44 7700 900000, +91-9876543210, +1-555-123-4567
        r"\+\d{1,3}[-.\s]?\d[\d\-.\s]{6,14}\d"
        # US with area code: (555) 123-4567, 555-123-4567, 555.123.4567, 5551234567
        r"|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
        # Local with leading zero: 07700 900000, 0800-123-456
        r"|\b0\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
        # 7-digit: 555-0199, 123-4567
        r"|\b\d{3}[-.\s]\d{4}\b"
        r")"
    ),
    "api_key": re.compile(
        r"(?i)(?:api[_-]?key|token|secret)\s*[:=]\s*['\"]?\S{16,}['\"]?"
    ),
    "ip_address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
}


@dataclass(slots=True)
class RedactionResult:
    """Result of a redaction pass."""

    original: str
    redacted: str
    redactions: list[dict[str, str]]  # [{"type": "ssn", "original": "...", "replacement": "..."}]

    @property
    def was_redacted(self) -> bool:
        return len(self.redactions) > 0


class RedactionEngine:
    """Pattern-based redaction engine.

    Args:
        prohibited: List of data type names to redact (e.g. ["ssn", "credit_card"]).
        custom_patterns: Additional regex patterns keyed by type name.
        placeholder: Format string for redaction markers. ``{type}`` is replaced.
    """

    def __init__(
        self,
        prohibited: list[str] | None = None,
        custom_patterns: dict[str, re.Pattern[str] | str] | None = None,
        placeholder: str = "[REDACTED:{type}]",
    ) -> None:
        self._prohibited = set(prohibited or [])
        self._placeholder = placeholder
        self._patterns: dict[str, re.Pattern[str]] = {}

        # Load built-in patterns for prohibited types
        for dtype in self._prohibited:
            if dtype in _BUILTIN_PATTERNS:
                self._patterns[dtype] = _BUILTIN_PATTERNS[dtype]

        # Add custom patterns
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                if isinstance(pattern, str):
                    pattern = re.compile(pattern)
                self._patterns[name] = pattern
                self._prohibited.add(name)

    def redact(self, text: str) -> RedactionResult:
        """Scan text and replace prohibited data patterns.

        Args:
            text: The string to redact.

        Returns:
            RedactionResult with the cleaned text and a list of redactions applied.
        """
        redactions: list[dict[str, str]] = []
        result = text

        for dtype, pattern in self._patterns.items():
            replacement = self._placeholder.format(type=dtype)

            def _replacer(match: re.Match[str], dt: str = dtype, rep: str = replacement) -> str:
                redactions.append({
                    "type": dt,
                    "original": match.group(),
                    "replacement": rep,
                })
                return rep

            result = pattern.sub(_replacer, result)

        return RedactionResult(
            original=text,
            redacted=result,
            redactions=redactions,
        )

    def add_pattern(self, name: str, pattern: re.Pattern[str] | str) -> None:
        """Register an additional redaction pattern at runtime."""
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        self._patterns[name] = pattern
        self._prohibited.add(name)

    @property
    def prohibited_types(self) -> set[str]:
        return self._prohibited.copy()
