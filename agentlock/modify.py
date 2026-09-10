"""MODIFY decision type -- parameter and output transformations.

When a tool call is authorized but the output or parameters should be
transformed before the LLM sees them, the MODIFY engine applies
declared transformations.  The tool still runs.  The admin still gets
an answer.  But PII, external domains, and sensitive paths are sanitized.

Built-in actions:

- ``redact_pii``: Uses the existing ``RedactionEngine`` to strip SSNs,
  emails, phones, credit cards, API keys from tool output strings.
- ``restrict_domain``: Rewrites ``send_email``'s ``to`` parameter to
  block external domains.  Config: ``{"allowed_domains": ["company.com"]}``.
- ``whitelist_path``: Blocks ``read_file``'s ``path`` parameter if it does not
  RESOLVE inside one of the allowed directories.  Config:
  ``{"allowed_prefixes": ["/data/"]}``.
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

import os
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentlock.redaction import RedactionEngine

__all__ = [
    "ModifyEngine",
    "ModifyResult",
    "apply_output_modifier",
]

# All PII types for the default redact_pii action
_DEFAULT_PII_TYPES = ["ssn", "email", "phone", "credit_card", "api_key"]


def apply_output_modifier(
    value: Any, modify: Callable[[str], str]
) -> Any:
    """Apply an output transformation to every string a tool returned.

    E11.  ``build_output_modifier`` produces a ``str -> str`` callable, and
    every path that applied it did so behind ``isinstance(result, str)``.  A
    tool that returns a mapping, a sequence, or bytes is the ordinary case
    rather than the exotic one, so a declared transformation was inert for
    most of the tools that declared it: the modifier reached the call and was
    then dropped on the way back out.

    The types covered, and they are the whole list:

    * ``str``: modified.
    * ``dict``, ``list``, ``tuple``: walked recursively; every ``str`` leaf is
      modified and the container type is preserved, because a caller that
      indexes or unpacks a tuple is as broken by getting a list back as by
      getting the SSN.  Dictionary KEYS are not modified: a key is a field
      name, changing it renames the field, and a transformation that renamed
      fields would corrupt the payload it was asked to sanitize.  A NAMED
      tuple is rebuilt through ``_make`` and keeps its own type; a ``dict`` or
      ``list`` SUBCLASS is rebuilt as a plain ``dict`` or ``list``, because
      there is no general way to call an arbitrary subclass's constructor.
    * ``set``, ``frozenset``: members are walked and the type is rebuilt, so a
      ``set`` comes back a ``set`` and a ``frozenset`` comes back a
      ``frozenset``.  E16.  A set of strings is an ordinary return for a tool
      that answers with distinct values, and naming it as uncovered, which is
      what this docstring did through the first red pass, documented a leak
      rather than bounding one.  A SUBCLASS of either is rebuilt as the plain
      type, on the same reasoning as ``dict`` and ``list`` above.
    * ``bytes``: decoded as UTF-8 with ``errors="replace"``, modified, and
      re-encoded as UTF-8.  The replace is deliberate: a transformation that
      cannot read the bytes must not be a reason to hand them back unread,
      and undecodable input is not a shape a redaction pattern was going to
      match anyway.
    * anything else: returned unchanged, including ``bytearray``,
      ``memoryview``, and every custom object, whatever its ``__str__`` says.
      The engine does not guess at a type it was not told how to rebuild, and
      it does not mutate one it was handed.

    A caller returning a shape this does not cover gets no transformation and
    no error, which is why the list is stated rather than implied.

    **What this does not modify.** Three limits, stated here because a limit a
    caller has to discover for itself is a limit that leaks:

    * **Dictionary KEYS.**  A key is a field name.  Renaming fields would
      corrupt the payload the transformation was asked to sanitize, so the
      walk descends into values only.  A mapping keyed by secret material is
      naming its records after the secret.
    * **Objects.**  A custom object is returned as it came, and an object
      whose ``__str__`` or ``__repr__`` carries the secret carries it out.
    * **Bytes that are not valid UTF-8.**  The undecodable sequences are
      replaced with U+FFFD before the transformation ever sees them, so the
      transformation cannot match on that part, and what comes back is a UTF-8
      re-encoding rather than the original bytes.  The readable part of such a
      value IS transformed; the unreadable part is neither transformed nor
      preserved.

    A host that returns any of those three has to redact it itself.  The gate
    cannot do it here without either renaming the caller's fields or guessing
    at a type it was not told how to rebuild.

    Args:
        value: Whatever the tool returned.
        modify: The ``str -> str`` transformation to apply to each leaf.

    Returns:
        The value with every covered string leaf transformed.
    """
    if isinstance(value, str):
        return modify(value)
    if isinstance(value, bytes):
        return modify(value.decode("utf-8", errors="replace")).encode("utf-8")
    if isinstance(value, dict):
        return {k: apply_output_modifier(v, modify) for k, v in value.items()}
    if isinstance(value, list):
        return [apply_output_modifier(v, modify) for v in value]
    if isinstance(value, tuple):
        walked = [apply_output_modifier(v, modify) for v in value]
        make = getattr(type(value), "_make", None)
        return make(walked) if callable(make) else tuple(walked)
    if isinstance(value, (set, frozenset)):
        members = {apply_output_modifier(v, modify) for v in value}
        return frozenset(members) if isinstance(value, frozenset) else set(members)
    return value


@dataclass
class ModifyResult:
    """Result of applying MODIFY transformations."""

    modified: bool = False
    original_params: dict[str, Any] | None = None
    modified_params: dict[str, Any] | None = None
    original_output: str | None = None
    modified_output: str | None = None
    transformations_applied: list[str] = field(default_factory=list)
    blocked_fields: list[str] = field(default_factory=list)


class ModifyEngine:
    """Applies parameter and output transformations.

    The engine is stateless -- it applies transformations based on the
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
                    # Track fields that were blocked (not just modified)
                    if new_value.startswith("[BLOCKED:"):
                        result.blocked_fields.append(t_field)

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
        """Block a file path that does not RESOLVE inside an allowed directory.

        E3.  Through 1.9.1 this compared the raw string against the prefix with
        ``startswith``, which is a test of how a path is spelled and not of
        where it leads.  ``/allowed/../private.txt`` starts with ``/allowed/``
        and a symlink at ``/allowed/link.txt`` starts with ``/allowed/`` no
        matter what it points at, so both were permitted and the tool then read
        the file the prefix existed to exclude.

        The check now resolves both sides and compares them as paths:
        backslashes are normalized, the candidate is lexically normalized,
        both it and each prefix are put through :func:`os.path.realpath`, which
        collapses ``..`` and follows symlinks, and the candidate is allowed
        only when :func:`os.path.commonpath` of the pair IS the prefix.  That
        last comparison is what makes ``/data-private`` fail against a
        ``/data`` prefix, which a string prefix test would have passed.

        Any exception blocks.  A path that cannot be resolved is a path whose
        destination is unknown, and an unknown destination is not an allowed
        one.

        **This is canonicalization at authorization time, not a race resistant
        filesystem sandbox.**  It reports where a path led when the gate looked.
        Between that moment and the host's ``open()`` a component of the path
        can be replaced, and nothing decided here can prevent that.  A host
        that needs to be safe against an actively hostile filesystem must open
        the file safely itself, with ``O_NOFOLLOW`` or an ``openat`` sequence
        anchored to a directory descriptor it already holds.
        """
        allowed_prefixes = config.get("allowed_prefixes", [])
        if not allowed_prefixes:
            return value

        blocked = "[BLOCKED: path outside allowed directories]"
        try:
            candidate = os.path.realpath(
                posixpath.normpath(value.replace("\\", "/"))
            )
        except Exception:
            return blocked

        for prefix in allowed_prefixes:
            try:
                resolved_prefix = os.path.realpath(
                    posixpath.normpath(str(prefix).replace("\\", "/"))
                )
                if (
                    os.path.commonpath([candidate, resolved_prefix])
                    == resolved_prefix
                ):
                    return value
            except Exception:
                continue

        return blocked

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
            hidden = len(entries) - max_records
            return f"[{truncated}] ... ({hidden} records redacted, {max_records} shown)"

        return value
