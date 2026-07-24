"""Context provenance tracking and trust state management.

Tracks what enters an agent's context window, who wrote it, and how
that affects the session's trust ceiling.  This is the core of the
v1.1 context authority model.
"""

from __future__ import annotations

import base64
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

# ---------------------------------------------------------------------------
# v1.6 family 1 -- value-identity canonical-form recognizers
# ---------------------------------------------------------------------------
# Each recognizer matches a value that is IN a known surface form and returns
# its canonical form.  None of them inspects scope or classifies what a value
# is 'for'; they normalize every value identically.  The family split (benign
# clears, attack attributes) is produced entirely downstream, by whether a
# canonical form matches an authoritative or an untrusted token.

# Defang markers only.  Fires solely when a marker is present, so clean domains
# are untouched (the raw floor already covers those).
_DEFANG_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I)

# Date: tightly anchored FULL dates only.  ISO YYYY-MM-DD and slash D/D/YYYY.
# Bare years and loose hyphen groups never match (two hyphens with a valid
# month and day are required), so UUID and order-ID segments do not
# canonicalize into dates.
_DATE_ISO_RE = re.compile(r"(?<!\d)(\d{4})-(\d{2})-(\d{2})(?!\d)")
_DATE_SLASH_RE = re.compile(r"(?<!\d)(\d{1,2})/(\d{1,2})/(\d{4})(?!\d)")

# Phone: a run of digits joined only by phone separators (space, dash, dot,
# parens, plus).  Comma and slash are NOT separators, so amounts and dates
# cannot be read as phones.  Digit count is validated after extraction.
_PHONE_RE = re.compile(r"(?<![\w+])(\+?\d[\d\s().\-]{7,}\d)(?![\w])")

# Amount: currency-anchored only.  Requires a currency symbol, OR a
# thousands-grouped number, OR a two-decimal-place number.  A bare integer is
# NOT an amount (it is too generic to canonicalize onto a source).
_AMOUNT_RE = re.compile(
    r"[$€£]\s?\d[\d,]*(?:\.\d+)?"
    r"|(?<![\d.])\d{1,3}(?:,\d{3})+(?:\.\d+)?"
    r"|(?<![\d.])\d+\.\d{2}(?!\d)"
)


def _canon_url(tok: str) -> str:
    """Canonicalize a URL/domain token: drop scheme, leading www., trailing
    punctuation; lowercase.  Reduces to the distinctive host(+path) core."""
    t = tok.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"^www\.", "", t)
    return t.rstrip("/.,;:)!?\"'")


def _canon_date(year: str, month: str, day: str) -> str | None:
    """Canonicalize a validated (year, month, day) to ISO ``YYYY-MM-DD``.
    Returns ``None`` if the month or day is out of range."""
    mi, di = int(month), int(day)
    if not (1 <= mi <= 12 and 1 <= di <= 31):
        return None
    return f"{int(year):04d}-{mi:02d}-{di:02d}"


def _canon_date_slash(a: str, b: str, year: str) -> str | None:
    """Canonicalize a slash date to ISO.  Disambiguates US ``MM/DD`` from EU
    ``DD/MM`` only when one field is unambiguously a day (> 12).  A genuinely
    ambiguous string (both fields <= 12) is left UNCANONICALIZED, per the
    design: guessing the locale would collapse two distinct dates."""
    ai, bi = int(a), int(b)
    if ai > 12 and bi <= 12:        # first field must be the day -> DD/MM
        month, day = bi, ai
    elif bi > 12 and ai <= 12:      # second field must be the day -> MM/DD
        month, day = ai, bi
    else:                           # both <= 12 (ambiguous) or both > 12
        return None
    return _canon_date(year, str(month), str(day))


def _canon_phone(match: str) -> str | None:
    """Canonicalize a phone match to E.164 (``+<countrycode><number>``).

    E.164, not last-10-digits: the country code is retained when present, so
    ``+1 (555) 123-4567`` and ``+44 555 123 4567`` do not collapse together.
    A bare 10-digit number with no country code is assumed NANP (``+1``); the
    A5 residual (a 10-digit account number colliding with a domestic phone)
    is documented in the predictions doc, not solved here."""
    has_plus = match.lstrip().startswith("+")
    digits = re.sub(r"\D", "", match)
    if has_plus:
        return "+" + digits if 10 <= len(digits) <= 15 else None
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    return None


def _canon_amount(match: str) -> str | None:
    """Canonicalize a currency amount to its bare numeric value: strip the
    currency symbol and thousands separators, and drop trailing-zero decimals.
    ``$1,000.00`` -> ``1000``; ``$14,207.50`` -> ``14207.5``."""
    cleaned = re.sub(r"[^\d.]", "", match)
    if not cleaned or cleaned.count(".") > 1:
        return None
    if "." in cleaned:
        cleaned = cleaned.rstrip("0").rstrip(".")
    return cleaned or None


def _defang_forms(text: str) -> set[tuple[str, str]]:
    """URL/domain tokens recovered from bracket-style defanging (``evil[.]com``
    -> ``evil.com``).  Only fires when a defang marker is present."""
    if not _DEFANG_RE.search(text):
        return set()
    de = _DEFANG_RE.sub(".", text)
    out: set[tuple[str, str]] = set()
    for m in _URL_RE.findall(de):
        c = _canon_url(m)
        if "." in c and len(c) >= 4:
            out.add(("url", c))
    return out


def _plain_qualifies(w: str, min_len: int) -> bool:
    if len(w) < min_len:
        return False
    # Must carry a digit/structural char, or be notably long, to count as
    # distinctive.  Pure short alphabetic words never match.
    if any(c in _STRUCTURAL for c in w):
        return True
    return len(w) >= 12


def _base_lineage_tokens(value: Any, min_len: int) -> set[tuple[str, str]]:
    """The v1.3 distinctive-token extraction: emails, URLs/domains, and
    qualifying plain strings.  This is the RAW-token floor.

    v1.6 family 1 layers canonical forms ON TOP of this floor (additive
    emission, invariant A1); it never removes a token this function produced.
    Keeping the floor in its own function is what lets the invariant test
    assert the subset relation structurally: whatever this returns must remain
    a subset of :func:`extract_lineage_tokens`."""
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


def _canonical_lineage_tokens(value: Any, min_len: int) -> set[tuple[str, str]]:
    """Value-identity canonical forms (v1.6 family 1).

    Returns ADDITIONAL (kind, canonical_value) tokens for format conversions
    and representation variants: the same value in a different surface form.
    ``kind`` is one of 'date' | 'phone' | 'url' (defang) | 'amount'.

    This is the whole family-1 mechanism.  It does NOT inspect scope or
    classify what a value 'is for': it normalizes every value identically, and
    the family split (benign clears, attack attributes) is produced entirely by
    whether a canonical form matches an authoritative or untrusted token.  It
    is emitted ALONGSIDE the raw floor, never instead of it (invariant A1).

    Interstitial character insertion (``e-v-i-l.com``) is DEFERRED and is not
    handled here (predictions doc, AMENDMENT 1, A3).  Filename decomposition is
    a separate sub-phase and is not handled here."""
    text = value if isinstance(value, str) else str(value)
    out: set[tuple[str, str]] = set()

    # Defang -> URL/domain.  Distinctive by construction; gated like the raw
    # URL floor (len >= 4), not by min_len.
    out |= _defang_forms(text)

    # Dates -> ISO.  min_len-gated like every canonical string token.
    for m in _DATE_ISO_RE.finditer(text):
        c = _canon_date(*m.groups())
        if c and len(c) >= min_len:
            out.add(("date", c))
    for m in _DATE_SLASH_RE.finditer(text):
        c = _canon_date_slash(*m.groups())
        if c and len(c) >= min_len:
            out.add(("date", c))

    # Phone -> E.164.
    for m in _PHONE_RE.finditer(text):
        c = _canon_phone(m.group(1))
        if c and len(c) >= min_len:
            out.add(("phone", c))

    # Amount -> bare numeric value.  Per A6 the common case (``$1,000.00`` ->
    # ``1000``) canonicalizes BELOW min_len and is dropped here; that is the
    # pre-registered at-risk behavior, not worked around.
    for m in _AMOUNT_RE.finditer(text):
        c = _canon_amount(m.group(0))
        if c and len(c) >= min_len:
            out.add(("amount", c))

    return out


def extract_lineage_tokens(value: Any, min_len: int) -> set[tuple[str, str]]:
    """Extract distinctive (kind, normalized_value) tokens from a parameter
    value.  ``kind`` is one of 'email' | 'url' | 'str' (raw v1.3 floor) or a
    v1.6 canonical kind ('date' | 'phone' | 'amount').

    ADDITIVE EMISSION (invariant A1): the result is the raw-token floor UNION
    the canonical forms, never a replacement.  Canonicalization can only ADD
    match opportunities, so no catch that existed before family 1 can be
    deleted by it.  Both the parameter side and the context side run through
    this one function, so ``novel_lineage_check`` gets its symmetry for free."""
    return _base_lineage_tokens(value, min_len) | _canonical_lineage_tokens(
        value, min_len
    )


def _canonical_blob_suffix(content: str, min_len: int) -> str:
    """Canonical forms of a context blob's content, as a text suffix (v1.6).

    Symmetry: param_lineage compares parameter tokens against the raw untrusted
    and authoritative blobs by substring, but the raw blob is not canonicalized,
    so a defanged untrusted ``evil[.]com`` never matches a clean ``evil.com``
    parameter.  novel_lineage already canonicalizes context (its token sets run
    through :func:`extract_lineage_tokens`); this closes the same gap on the
    param side.

    ADDITIVE, never replacement: the suffix is appended to the raw lowercased
    content, so the raw form stays and param_lineage keeps its INDEPENDENT raw
    substring catch.  A canonical-only (replacement) blob would drop a clean
    untrusted token that has no canonical of its own (``evil.com`` produces
    none), making param_lineage miss it; combined with novel-side leaf
    clearance that is what surfaces the ``evil.com report 03/14/2026``
    DENY-to-ALLOW flip (AMENDMENT 4, D2).  Additive keeps both the raw catch and
    the canonical reach."""
    cs = sorted(t for _kind, t in _canonical_lineage_tokens(content, min_len))
    return (" " + " ".join(cs)) if cs else ""


# ---------------------------------------------------------------------------
# v1.6 family 2 -- directional-encoding forward emission
# ---------------------------------------------------------------------------
# FORWARD-ENCODE, never reverse-decode (PREDICTIONS_v16_family2.md, section 1).
# Each recorded UNTRUSTED token is run FORWARD through the known encodings and
# the encoded forms are ADDED to the untrusted blob, alongside the raw content
# and the family-1 canonical suffix.  parameter_lineage_check then substring-
# matches a raw parameter token against them, exactly as it matches the raw and
# canonical forms.  No parameter value is ever decoded or inverted: the entire
# false-positive argument is that a benign value is only ever COMPARED against a
# known encoded-untrusted string, never read backwards (AM1.3; section 1's
# rejection of reverse-decode on the probe-2 UUID).  There is no decode
# primitive in this module, and none may be added; a test asserts their
# absence so one cannot be slipped in silently.
#
# Placement is the UNTRUSTED blob only.  The authoritative blob is untouched, so
# the auth-first short-circuit (parameter_lineage_check, ``tok in auth_blob``)
# clears a legitimately user-supplied encoded value before any untrusted scan
# (AM5.2, the positive control).

# Natural-URL percent-encoding of the STRUCTURALLY SIGNIFICANT characters only
# (AM1.2): the dot/at/colon/slash a natural encoder targets, leaving
# alphanumerics bare.  Adversarial per-character enumeration (``%65`` for 'e')
# is the deferred frontier, not emitted here.  Percent codes are written
# lowercase so they fold with the extractor's lowercase (AM2.2, symmetric fold).
_URL_SIGNIFICANT = {".": "%2e", "@": "%40", ":": "%3a", "/": "%2f"}

# Length floor on the ENCODED form (AM2.2), NOT on the plaintext token.  Value
# chosen = 8, justified against the near-min_len folded-entropy hazard:
#
#   * The plaintext distinctiveness gate is min_len=6 over the folded 36-symbol
#     lowercase-alphanumeric alphabet, about 31 bits.
#   * Folding a base64 form collapses its 64-symbol alphabet to about 38
#     (log2 ~ 5.25 bits/char), so RAW length OVERSTATES a folded form's entropy.
#     Recovering the plaintext gate's 31 bits under folding needs ceil(31/5.25)
#     = 6 folded chars, and AM2.2 flags exactly that 6-char band as where a
#     folded encoded form is a weaker discriminator than its length suggests.
#   * A floor of 8 clears that band with margin (8 folded chars ~ 42 bits, about
#     11 bits / ~2000x above the plaintext gate) while admitting every counted
#     row: the shortest counted encoded form is the natural-URL ``evil%2ecom``
#     at 10 chars, so 8 rejects the low-entropy near-min_len emissions without
#     dropping a counted catch.
#
# A collision at short lengths therefore reads as a floor set too low, a named
# spec decision, not an unpredicted failure.
_ENCODED_MIN_LEN = 8


def _natural_url_encode(tok: str) -> str:
    """Percent-encode the structurally significant characters of ``tok`` and
    leave everything else bare (AM1.2 natural-encoder form)."""
    return "".join(_URL_SIGNIFICANT.get(c, c) for c in tok)


def _encoded_forms(tok: str) -> set[str]:
    """The forward encodings of one untrusted plaintext token: base64 (standard
    alphabet and padding), hex, and natural-URL, each folded lowercase (AM2.2),
    admitted only if the ENCODED form meets the length floor (AM2.2).

    Encode only.  There is no decode path here and none may be added: a decode
    would reintroduce the reverse-decode false-positive surface section 1
    rejects on the probe-2 UUID.  One round per encoding; nesting is the
    deferred depth frontier (R3), not emitted here."""
    raw = tok.encode("utf-8")
    forms = {
        base64.b64encode(raw).decode("ascii").lower(),
        raw.hex().lower(),
        _natural_url_encode(tok).lower(),
    }
    return {f for f in forms if len(f) >= _ENCODED_MIN_LEN}


def _encoded_blob_suffix(content: str, min_len: int) -> str:
    """Forward-encoded forms of a context blob's UNTRUSTED tokens, as a text
    suffix (v1.6 family 2).

    Source (AM5.1): the plaintext set is exactly ``extract_lineage_tokens``
    of the content, the same context-side tokenization ``novel_lineage_check``
    already runs, so family 2's catch surface is the IMAGE of family 1's
    tokenization under the encoding set -- it can only encode what family 1
    already sees.

    ADDITIVE, never replacement: the caller appends this AFTER the raw lowercased
    content and the family-1 canonical suffix, so the raw and canonical catches
    are untouched and only encoded match opportunities are added.  Emitted into
    the UNTRUSTED blob only; the auth blob is never extended (AM5.2, AM5.3)."""
    forms: set[str] = set()
    for _kind, tok in extract_lineage_tokens(content, min_len):
        if tok:
            forms |= _encoded_forms(tok)
    return (" " + " ".join(sorted(forms))) if forms else ""


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


def _note_outcome(
    outcome: dict[str, Any] | None,
    result: str,
    qualifier: str = "",
) -> None:
    """Record WHY a lineage check returned what it returned (E10).

    Write-only, into a caller-supplied dict.  Nothing in the engine reads this
    back, and no check consults it: it is evidence, on the far side of the
    value the policy engine actually decides on.  It adds no computation to the
    decision path.  Every branch it records was already being taken; the fact
    was simply thrown away at the ``return``.

    ``result`` is one of ``match``, ``no_match``, ``not_classifiable``.  The
    distinction that matters is between a ``no_match`` with no qualifier (the
    check ran its comparison and nothing matched, which is the strong claim)
    and one with a qualifier (the check had nothing to compare, which is not a
    claim about the arguments at all).
    """
    if outcome is None:
        return
    outcome["ran"] = True
    outcome["result"] = result
    if qualifier:
        outcome["qualifier"] = qualifier


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
        outcome: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Check whether any tool-call parameter value originated in UNTRUSTED
        context but not in the AUTHORITATIVE user request/config (v1.3 F2).

        Read-only.  Returns a match dict::

            {"matched_param", "matched_value", "matched_kind",
             "untrusted_source_ref"}

        or ``None`` if every parameter value is clean.  The authoritative
        allowlist is checked FIRST: a value present in the user's own request
        is clean regardless of any untrusted echo.

        ``outcome`` (E10) is an optional out-dict recording WHY this returned
        what it returned.  The return value is unchanged, so no decision can
        move; this only stops discarding a fact the method already had.  It
        exists because ``None`` here is overloaded: it means "compared the
        parameters against untrusted context and nothing traced to it", but it
        ALSO means "there was nothing to compare against".  A grant record that
        reported both as a clean result would be asserting a cleanliness the
        check never established.  A bare ``no_match`` is therefore the strong
        claim; every vacuous case carries a qualifier that says so.
        """
        if not parameters:
            _note_outcome(outcome, "no_match", "no_parameters")
            return None
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            _note_outcome(outcome, "no_match", "no_provenance_log")
            return None

        # Symmetry (v1.6 family 1): each blob carries its content's canonical
        # forms too, appended additively (see _canonical_blob_suffix).  Both
        # sides hold canonical forms, so a defanged untrusted ``evil[.]com`` is
        # reachable by a clean ``evil.com`` parameter.  Additive, not
        # replacement: the raw form stays so param_lineage keeps its independent
        # raw catch (D2).
        #
        # The auth blob carries ONLY the family-1 canonical suffix.  It is NOT
        # extended with the family-2 encoded suffix: forward-encode emits into
        # untrusted blobs only (AM5.2, AM5.3), which is what keeps the auth-first
        # short-circuit below the positive control -- a legitimately
        # user-supplied encoded value is an authoritative token and clears there
        # before any untrusted comparison.
        auth_blob = " ".join(
            e.content.lower() + _canonical_blob_suffix(e.content, min_len)
            for e in state.provenance_log
            if e.authority == ContextAuthority.AUTHORITATIVE and e.content
        )
        untrusted_entries = [
            e
            for e in state.provenance_log
            if e.authority == ContextAuthority.UNTRUSTED and e.content
        ]
        if not untrusted_entries:
            _note_outcome(outcome, "no_match", "no_untrusted_context")
            return None
        # Untrusted blobs additionally carry the family-2 encoded suffix: the
        # forward encodings of their own untrusted tokens (base64/hex/natural-URL
        # of ``evil.com`` and friends).  Additive on top of the raw content and
        # the canonical suffix, so a raw parameter token that is an encoded form
        # of a known untrusted value substring-matches here (AM5.3).
        untrusted_blobs = [
            (
                e,
                e.content.lower()
                + _canonical_blob_suffix(e.content, min_len)
                + _encoded_blob_suffix(e.content, min_len),
            )
            for e in untrusted_entries
        ]

        # Most-specific-first, like ``novel_lineage_check``, and for the same
        # reason: ``extract_lineage_tokens`` returns a SET, so iterating it
        # directly reports whichever token happened to come out first, which
        # varies with PYTHONHASHSEED across processes.  The DECISION never did
        # (a match is a match, and its existence is order independent), but the
        # cited token did, and a citation that changes between runs is not one.
        # Ordering is total: kind, then length, then the token, then the path.
        kind_rank = {"email": 0, "url": 1, "str": 2}
        candidates: list[tuple[int, int, str, str, str, str]] = []
        for path, value in _iter_param_leaves(parameters):
            for kind, tok in extract_lineage_tokens(value, min_len):
                if not tok:
                    continue
                candidates.append(
                    (kind_rank.get(kind, 3), -len(tok), tok, path, kind, str(value)),
                )
        candidates.sort()

        if not candidates:
            # The parameters carry no token distinctive enough to trace.  The
            # loop below would return None anyway; saying so is the difference
            # between "nothing traced" and "nothing was traceable".
            _note_outcome(outcome, "no_match", "no_tokens")
            return None

        # Authoritative-first precedence, PER TOKEN.  A token that appears in
        # the user's own request is clean; a token that does not is scanned
        # against untrusted context below.  This is deliberately per-token, NOT
        # per-leaf, and it is deliberately DIFFERENT from novel_lineage_check's
        # leaf-granular clearance a few methods down.  The two checks answer
        # different questions:
        #
        #   * param_lineage substring-matches the raw untrusted content.  A raw
        #     untrusted token must be caught on its own merits, regardless of a
        #     clean sibling in the same leaf.  Lifting the auth-clean to the leaf
        #     here (the A2 attempt, reverted per AMENDMENT 2 / AMENDMENT 3) let
        #     an authoritative sibling launder an untrusted token in a composite
        #     value -- e.g. ``evil.com_2026-03-14.pdf`` cleared on the date.
        #     Per-token clearance closes that: ``evil.com`` is denied on itself.
        #
        #   * novel_lineage_check needs leaf granularity for the OPPOSITE reason:
        #     a benign format conversion's CANONICAL form must be allowed to
        #     clear the leaf even though its raw form is unseen.  That check does
        #     not substring-scan untrusted content, so it cannot launder an
        #     untrusted token the way a per-leaf clear does here.
        #
        # The asymmetry is intentional; it is not an inconsistency.
        for _rank, _neglen, tok, path, kind, value in candidates:
            # Authoritative FIRST, per token.
            if tok in auth_blob:
                continue
            for entry, blob in untrusted_blobs:
                if tok in blob:
                    _note_outcome(outcome, "match")
                    return {
                        "matched_param": path,
                        "matched_value": value[:120],
                        "matched_kind": kind,
                        "matched_token": tok[:120],
                        "untrusted_source_ref": (
                            f"{entry.tool_name or entry.source.value}"
                            f":{entry.provenance_id}"
                        ),
                        # The id on its own, so an evidence consumer can
                        # join this match to the taint-introduction record
                        # without parsing ``untrusted_source_ref``.
                        "untrusted_provenance_id": entry.provenance_id,
                    }
        # Compared every traceable token against the untrusted context and none
        # of them traced to it.  This, and only this, is the strong result: it
        # carries no qualifier.
        _note_outcome(outcome, "no_match")
        return None

    def untrusted_sources(self, session_id: str) -> list[dict[str, Any]]:
        """The untrusted entries in a session's provenance log, in order.

        Read-only, and read by the audit path only: this is the evidence
        behind a session-taint denial, never an input to one.  Each entry is
        reported as its provenance id, a human-readable source ref, its
        content hash, and whether it entered after the last authoritative
        entry (the fact ``post_authoritative_taint`` is computed from).
        """
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            return []

        log = state.provenance_log
        last_authoritative_idx = -1
        for i, entry in enumerate(log):
            if entry.authority == ContextAuthority.AUTHORITATIVE:
                last_authoritative_idx = i

        return [
            {
                "provenance_id": entry.provenance_id,
                "source_ref": (
                    f"{entry.tool_name or entry.source.value}"
                    f":{entry.provenance_id}"
                ),
                "source": entry.source.value,
                "content_hash": entry.content_hash,
                "post_authoritative": i > last_authoritative_idx,
            }
            for i, entry in enumerate(log)
            if entry.authority == ContextAuthority.UNTRUSTED
        ]

    def novel_lineage_check(
        self,
        session_id: str,
        parameters: dict[str, Any] | None,
        *,
        min_len: int = 6,
        outcome: dict[str, Any] | None = None,
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

        ``outcome`` (E10) is an optional out-dict recording WHY.  The return
        value is unchanged, so no decision can move.  It matters more here than
        it does for :meth:`parameter_lineage_check`, because the no-baseline
        case above is the check DECLINING TO CLASSIFY, and it returns the same
        ``None`` as a clean result.  It is reported as ``not_classifiable``,
        never as ``no_match``: a grant record must not claim the target was
        accounted for when nothing could be classified at all.
        """
        if not parameters:
            _note_outcome(outcome, "no_match", "no_parameters")
            return None
        state = self._states.get(session_id)
        if state is None or not state.provenance_log:
            _note_outcome(outcome, "no_match", "no_provenance_log")
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
            _note_outcome(outcome, "not_classifiable", "no_authoritative_baseline")
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

        if not candidates:
            _note_outcome(outcome, "no_match", "no_tokens")
            return None

        # A2' composite-aware clearance -- SUPERSEDES A2 any-form-clears
        # (AMENDMENT 4, D4).  EVERY value-bearing token in a leaf must account
        # for itself: a token is accounted if it, OR one of its own canonical
        # forms, is in the authoritative or the untrusted set.  A leaf is NOVEL
        # if any of its tokens is unaccounted.
        #
        # On a SINGLE-value leaf this is identical to any-form-clears (a benign
        # date's raw ``03/14/2026`` clears because its own canonical
        # ``2026-03-14`` is authoritative).  It DIVERGES only on multi-value
        # leaves, where A2 let one accounted sibling launder an untrusted token
        # (``evil.com 2026-03-14`` cleared on the date) and A2' does not:
        # ``evil.com`` must account for itself.
        #
        # min_len is load-bearing HERE too (D3): a benign component below the
        # distinctiveness gate (``alice`` in report_alice_2026-03-14.pdf) is
        # never emitted as a token, so it is not a value-bearing token that must
        # account for itself, and its leaf can still clear on the tokens that
        # ARE emitted.  Lowering min_len would turn such short components into
        # tokens that A2' then requires to be attributable, which is the
        # RESTRICTIVE direction; raising it would drop real targets.
        accounted = auth_tokens | untrusted_tokens

        def _token_accounted(tok: str) -> bool:
            if tok in accounted:
                return True
            own = {t for _kind, t in _canonical_lineage_tokens(tok, min_len)}
            return bool(own & accounted)

        for _rank, _neglen, tok, path, value in candidates:
            if _token_accounted(tok):
                continue
            _note_outcome(outcome, "match")
            return {
                "matched_param": path,
                "matched_value": value[:120],
                "classification": "novel",
                "matched_token": tok[:120],
            }
        # Every distinctive token was accounted for, against a real baseline.
        _note_outcome(outcome, "no_match")
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
