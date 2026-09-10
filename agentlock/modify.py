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

# G3.  A recipient field separates RECIPIENTS with either of these.  Whitespace
# separates the parts of ONE recipient, which is how a display name is written,
# so it is not a peer of these two and gets its own split below.
_RECIPIENT_SEPARATORS = re.compile(r"[,;]")


def _address_domain(token: str) -> str | None:
    """The domain of a token that is exactly one address, or ``None``.

    G4.  The pattern is used as a FULL match here, not as a search.  A search
    asks whether some substring of the token is an address, which is how
    ``bob@company.test@evil.test`` was judged on ``company.test`` and allowed:
    the pattern read the part it recognized and stopped before the rest.  A
    full match asks whether the token IS an address, so anything the pattern
    cannot account for in its entirety is refused rather than partly read.

    Angle brackets around the address are stripped first, because that is how a
    display name is written and the address inside them is what the token is
    about.  The bracketed form is taken from the LAST ``<`` so that
    ``Bob<bob@company.test>``, written without a space, is read the same way as
    ``Bob <bob@company.test>``.
    """
    inner = token
    if inner.endswith(">") and "<" in inner:
        inner = inner[inner.rindex("<") + 1:-1]
    match = _EMAIL_PATTERN.fullmatch(inner)
    return match.group(1) if match else None


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
        The decision was a function of the order the addresses were written in.
        1.10.1 made the parse exhaustive over the pieces of the value, which
        closed that.

        G4.  What 1.10.1 left unchanged was how the value is recognized as a
        recipient list at all: it asked ``_EMAIL_PATTERN`` whether it could
        find an address anywhere, and if it could not, the value was held to
        carry none and returned unchanged.  That is correct for a field holding
        something that is not a recipient, and wrong for a field holding a
        recipient the pattern cannot read.  ``_EMAIL_PATTERN`` is ASCII only
        and wants a dotted domain, so ``bob@compаny.test`` spelled with a
        Cyrillic letter and the address literal ``bob@[10.0.0.1]`` both failed
        it and both passed a domain allowlist.  Both are deliverable.
        ``bob@company.test@evil.test`` passed for the neighboring reason: the
        pattern recognized the leading part, and what a mail system does with
        the rest was never decided.

        **The at sign decides, not the pattern.**  An at sign is what makes a
        string an address; the pattern is one opinion about which addresses are
        well formed, and an engine that refuses to decide about the addresses
        its own pattern cannot read is deciding in the caller's favor.  So:

        1. A value with no ``@`` anywhere is returned unchanged.  A field with
           no at sign in it is not a recipient list, and an allowlist over
           domains can only govern things that have a domain.  This is the
           behavior the engine has always had and it is what
           ``TestRestrictDomain::test_no_email_in_field`` pins.
        2. Otherwise the value is split on comma and semicolon into pieces,
           each piece is stripped, and pieces empty after stripping are
           discarded.  That is what makes a trailing separator and a whitespace
           only piece benign.
        3. Every remaining piece must carry at least one whitespace separated
           token containing an ``@``.  A piece with none blocks the value:
           once a value has been established as a recipient list, a piece the
           parser cannot read is not evidence of innocence.
        4. Every token containing an ``@``, in every piece, must parse as
           exactly one ASCII address, and its domain must be on the allowlist
           after casefold.  A token that does not parse blocks the value.

        The two separators do different jobs, which is what they already are.
        A comma or a semicolon separates RECIPIENTS.  Whitespace separates the
        parts of one recipient, which is how ``Bob <bob@company.test>`` is
        written, so the display name form is accepted: the token carrying the
        at sign parses once its angle brackets come off, and the tokens that
        carry no at sign are the name.  Domains compare after casefolding, so a
        value differing from the allowlist only in case is the same value.

        Order cannot change the answer, because no piece and no token is
        privileged over any other.

        Two limits, both fail closed, both stated rather than left to be
        discovered.  A display name containing a comma, as in ``"Doe, Bob"
        <bob@company.test>``, splits into pieces that do not each carry an
        address and is therefore BLOCKED; honoring RFC 5322 quoting here would
        mean writing a mail parser, and getting one subtly wrong is how the
        first match rule happened.  A bare local name with no domain, which a
        mail system may still know how to route, is not covered, for the same
        reason as the no at sign case: there is no domain in it to compare.
        """
        allowed = config.get("allowed_domains", [])
        if not allowed:
            return value

        if "@" not in value:
            return value

        allowed_folded = {str(d).casefold() for d in allowed}
        blocked = "[BLOCKED: external domain not allowed]"

        pieces = [
            piece.strip()
            for piece in _RECIPIENT_SEPARATORS.split(value)
        ]

        for piece in pieces:
            if not piece:
                continue
            tokens = [token for token in piece.split() if "@" in token]
            if not tokens:
                return blocked
            for token in tokens:
                domain = _address_domain(token)
                if domain is None or domain.casefold() not in allowed_folded:
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
