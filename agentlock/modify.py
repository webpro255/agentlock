"""MODIFY decision type — parameter and output transformations.

When a tool call is authorized but the output or parameters should be
transformed before the LLM sees them, the MODIFY engine applies
declared transformations.  The tool still runs.  The admin still gets
an answer.  But PII, external domains, and sensitive paths are sanitized.

Built-in actions:

- ``redact_pii``: Uses the existing ``RedactionEngine`` to strip SSNs,
  emails, phones, credit cards, API keys from tool output strings.
- ``restrict_domain``: Rewrites ``send_email``'s ``to`` parameter to
  block external domains.  Config: ``{"allowed_domains": ["company.com"]}``.
- ``whitelist_path``: Blocks ``read_file``'s ``path`` parameter if
  outside allowed directory prefixes.  Config: ``{"allowed_prefixes": ["/data/"]}``.
- ``cap_records``: Limits output to a maximum number of records.
  Config: ``{"max_records": 10}``.

Usage::

    from agentlock.modify import ModifyEngine

    engine = ModifyEngine()

    # Redact PII from a tool output
    result = engine.apply_output("query_database", output_text, [
        TransformationConfig(field="output", action="redact_pii"),
    ])
    # result.modified_output has PII replaced with [REDACTED]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agentlock.redaction import RedactionEngine

__all__ = [
    "ModifyEngine",
    "ModifyResult",
]

# All PII types for the default redact_pii action
_DEFAULT_PII_TYPES = ["ssn", "email", "phone", "credit_card", "api_key"]


@dataclass
class ModifyResult:
    """Result of applying MODIFY transformations."""

    modified: bool = False
    original_params: dict[str, Any] | None = None
    modified_params: dict[str, Any] | None = None
    original_output: str | None = None
    modified_output: str | None = None
    transformations_applied: list[str] = field(default_factory=list)


class ModifyEngine:
    """Applies parameter and output transformations.

    The engine is stateless — it applies transformations based on the
    configuration passed to each call.  It does not track sessions or
    accumulate state.
    """

    def __init__(self) -> None:
        self._pii_engine = RedactionEngine(prohibited=_DEFAULT_PII_TYPES)
        self._action_handlers: dict[str, Callable[..., Any]] = {
            "redact_pii": self._action_redact_pii,
            "restrict_domain": self._action_restrict_domain,
            "whitelist_path": self._action_whitelist_path,
            "cap_records": self._action_cap_records,
        }

    def apply_output(
        self,
        tool_name: str,
        output: str,
        transformations: list[Any],
    ) -> ModifyResult:
        """Apply output transformations to a tool's result string.

        Only processes transformations where ``field == "output"``.

        Args:
            tool_name: Name of the tool (for logging).
            output: The raw tool output string.
            transformations: List of TransformationConfig-like objects
                with ``field``, ``action``, ``config`` attributes.

        Returns:
            ModifyResult with original and modified output.
        """
        result = ModifyResult(original_output=output)
        current = output

        for t in transformations:
            t_field = t.field if hasattr(t, "field") else t.get("field", "")
            t_action = t.action if hasattr(t, "action") else t.get("action", "")
            t_config = t.config if hasattr(t, "config") else t.get("config", {})

            if t_field != "output":
                continue

            handler = self._action_handlers.get(t_action)
            if handler is None:
                continue

            new_value = handler(current, t_config)
            if new_value != current:
                result.modified = True
                result.transformations_applied.append(t_action)
                current = new_value

        result.modified_output = current
        return result

    def apply_params(
        self,
        tool_name: str,
        params: dict[str, Any],
        transformations: list[Any],
    ) -> ModifyResult:
        """Apply parameter transformations before tool execution.

        Processes transformations where ``field`` matches a parameter name.

        Args:
            tool_name: Name of the tool.
            params: The tool call parameters.
            transformations: List of TransformationConfig-like objects.

        Returns:
            ModifyResult with original and modified parameters.
        """
        result = ModifyResult(original_params=dict(params))
        current = dict(params)

        for t in transformations:
            t_field = t.field if hasattr(t, "field") else t.get("field", "")
            t_action = t.action if hasattr(t, "action") else t.get("action", "")
            t_config = t.config if hasattr(t, "config") else t.get("config", {})

            if t_field == "output" or t_field not in current:
                continue

            handler = self._action_handlers.get(t_action)
            if handler is None:
                continue

            old_value = current[t_field]
            if isinstance(old_value, str):
                new_value = handler(old_value, t_config)
                if new_value != old_value:
                    result.modified = True
                    result.transformations_applied.append(f"{t_action}:{t_field}")
                    current[t_field] = new_value

        result.modified_params = current
        return result

    def build_output_modifier(
        self,
        tool_name: str,
        transformations: list[Any],
    ) -> Callable[[str], str] | None:
        """Build a callable that applies output transformations.

        Returns None if no output transformations are configured.
        Used by the gate to attach a modifier to the execution path.
        """
        output_transforms = [
            t for t in transformations
            if (t.field if hasattr(t, "field") else t.get("field", "")) == "output"
        ]
        if not output_transforms:
            return None

        def modifier(output: str) -> str:
            result = self.apply_output(tool_name, output, output_transforms)
            return result.modified_output if result.modified_output is not None else output

        return modifier

    # -- Built-in transformation actions -----------------------------------

    def _action_redact_pii(self, value: str, config: dict[str, Any]) -> str:
        """Redact PII patterns from a string value."""
        redaction = self._pii_engine.redact(value)
        return redaction.redacted

    def _action_restrict_domain(self, value: str, config: dict[str, Any]) -> str:
        """Restrict email addresses to allowed domains."""
        allowed = config.get("allowed_domains", [])
        if not allowed:
            return value

        # Check if value looks like an email
        email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b"
        )
        match = email_pattern.search(value)
        if match:
            domain = match.group(1).lower()
            if domain not in [d.lower() for d in allowed]:
                return "[BLOCKED: external domain not allowed]"
        return value

    def _action_whitelist_path(self, value: str, config: dict[str, Any]) -> str:
        """Block file paths outside allowed prefixes."""
        allowed_prefixes = config.get("allowed_prefixes", [])
        if not allowed_prefixes:
            return value

        # Normalize path
        normalized = value.replace("\\", "/")
        for prefix in allowed_prefixes:
            if normalized.startswith(prefix):
                return value

        return "[BLOCKED: path outside allowed directories]"

    def _action_cap_records(self, value: str, config: dict[str, Any]) -> str:
        """Limit output to max_records entries.

        Looks for list-like patterns in the output and truncates.
        """
        max_records = config.get("max_records", 10)
        if max_records <= 0:
            return value

        # Try to find JSON-like array entries: [{...}, {...}, ...]
        # Count occurrences of '}, {' or '}\n{' patterns
        entries = re.findall(r"\{[^{}]*\}", value)
        if len(entries) > max_records:
            truncated = ", ".join(entries[:max_records])
            return f"[{truncated}] ... ({len(entries) - max_records} records redacted, {max_records} shown)"

        return value
