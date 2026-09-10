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

# G3.  One address, and the domain it belongs to as group 1.  Held verbatim
# from the pre 1.10.1 action so that what counts as an address is unchanged by
# this fix; only how many of them are checked changes.
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b"
)

# G3.  A recipient field separates addresses with either of these.
_RECIPIENT_SEPARATORS = re.compile(r"[,;]")


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
        """Restrict a recipient field to addresses in allowed domains.

        G3.  Through 1.10.0 this called ``search`` and read ``group(1)``, which
        is the FIRST address in the value and nothing after it.
        ``"bob@company.test, eve@outside.test"`` was judged on ``company.test``
        alone, passed, and the tool was invoked with both recipients intact.
        The decision was a function of the order the addresses were written in:
        the same recipient set blocked when the outside address came first and
        allowed when it came second.  A restriction whose answer depends on
        spelling order is not a restriction.

        The whole value is parsed now.  It is split on both comma and
        semicolon, each piece is stripped, pieces that are empty after
        stripping are discarded, and then EVERY remaining piece must carry at
        least one address and EVERY domain found in EVERY piece must be
        allowed.  One unparseable piece or one disallowed domain blocks the
        value.  Order cannot change the answer, because no piece is privileged
        over any other.

        Addresses are collected per piece with ``finditer`` rather than
        ``search``, so a piece holding more than one address has all of them
        checked and none can shelter behind the first.  The display name form
        ``Bob <bob@company.test>`` is accepted, because the pattern finds the
        address inside it.  Domains compare case insensitively.

        **The scope, stated rather than left to be discovered.**  A value that
        carries no address ANYWHERE is returned unchanged.  A field with no
        address in it is not a recipient list, and an allowlist over domains
        can only govern things that have a domain.  This is the behavior the
        engine has always had and it is what
        ``TestRestrictDomain::test_no_email_in_field`` pins.  Once the value
        carries even one address, every remaining piece is held to the standard
        above, so the smuggling shape the finding is about, an allowed address
        followed by anything else, blocks.

        Two limits follow from parsing this way, and both fail closed.  A
        display name containing a comma, as in ``"Doe, Bob"
        <bob@company.test>``, splits into pieces that do not each carry an
        address and is therefore BLOCKED; honoring RFC 5322 quoting here would
        mean writing a mail parser, and getting one subtly wrong is how the
        first match rule happened.  A bare local name with no domain, which a
        mail system may still know how to route, is not covered, for the same
        reason as the no address case.
        """
        allowed = config.get("allowed_domains", [])
        if not allowed:
            return value

        allowed_lower = {str(d).lower() for d in allowed}
        blocked = "[BLOCKED: external domain not allowed]"

        pieces = [
            piece.strip()
            for piece in _RECIPIENT_SEPARATORS.split(value)
        ]
        pieces = [piece for piece in pieces if piece]

        found_any = False
        unparseable = False
        for piece in pieces:
            domains = [m.group(1).lower() for m in _EMAIL_PATTERN.finditer(piece)]
            if not domains:
                # A piece with no address is only a problem once some other
                # piece has established that this value IS a recipient list.
                unparseable = True
                continue
            found_any = True
            if any(domain not in allowed_lower for domain in domains):
                return blocked

        if not found_any:
            return value
        if unparseable:
            return blocked
        return value

    def _action_whitelist_path(self, value: str, config: dict[str, Any]) -> str:
        """Block a file path that does not RESOLVE inside an allowed directory.

        E3.  Through 1.9.1 this compared the raw string against the prefix with
        ``startswith``, which is a test of how a path is spelled and not of
        where it leads.  ``/allowed/../private.txt`` starts with ``/allowed/``
        and a symlink at ``/allowed/link.txt`` starts with ``/allowed/`` no
        matter what it points at, so both were permitted and the tool then read
        the file the prefix existed to exclude.

        G1.  Through 1.10.0 the fix was incomplete in a way that reintroduced
        the same hole for one composition.  A lexical ``normpath`` ran BEFORE
        ``realpath``, so ``..`` was collapsed against the SPELLING of the path
        rather than against where the path leads.  With a directory symlink at
        ``allowed/jump`` pointing outside the tree,
        ``allowed/jump/../private.txt`` was rewritten to
        ``allowed/private.txt`` before the filesystem was consulted at all, and
        that rewritten path is genuinely inside the prefix.  The gate allowed.
        The host then opened the ORIGINAL string, ``open()`` walked ``jump`` as
        a link and did not collapse the ``..`` lexically, and the file outside
        the prefix was read.  The checked path and the opened path were two
        different files.

        Both halves of that are closed here.  Resolution now uses filesystem
        semantics FIRST: backslashes are normalized and nothing else is, and
        the raw value goes straight into :func:`os.path.realpath`, which walks
        the components left to right, follows each symlink as it meets it, and
        resolves ``..`` against what it has resolved so far rather than against
        the text.  Each prefix is resolved the same way.  The candidate is
        allowed only when :func:`os.path.commonpath` of the pair IS the
        resolved prefix, which is what makes ``/data-private`` fail against a
        ``/data`` prefix where a string prefix test would have passed.

        **On allow the RESOLVED path is returned, not the caller's string.**
        The parameter value is canonicalized, so the callable opens exactly the
        path that was checked and the two cannot diverge.  A caller that needs
        the spelling it sent has it in the audit record of the original
        parameters.

        A path that is not absolute is blocked outright.  A relative path names
        a different file for every working directory, so what it resolves to is
        a property of the caller's process and not of the request.

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
        raw = value.replace("\\", "/")
        if not os.path.isabs(raw):
            return blocked
        try:
            candidate = os.path.realpath(raw)
        except Exception:
            return blocked

        for prefix in allowed_prefixes:
            try:
                resolved_prefix = os.path.realpath(str(prefix).replace("\\", "/"))
                if (
                    os.path.commonpath([candidate, resolved_prefix])
                    == resolved_prefix
                ):
                    return candidate
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
