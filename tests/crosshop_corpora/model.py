"""Corpus representation for cross-hop multi-hop sessions, with DECLARED
ground-truth parentage.

Why this file exists (AM10.1 / AM13 of ``docs/PREDICTIONS_crosshop.md``): the
cross-hop acceptance criterion is PARENT IDENTITY, not link count. AM3 measured
a graph that passes a link-count criterion and is two thirds wrong (6 links for
6 true derivations, 2 correct parents, 4 wrong, ``:810-813``). Measuring parent
identity requires per-entry ground truth, and no frozen corpus carried any. This
is that ground truth.

Two fields are deliberately kept apart, and conflating them is the mistake this
representation exists to prevent:

``true_parents``
    A FACT about the session, declared by hand from how the session was
    constructed. The definition is the doc's own (FL3, ``:481``): a genuine
    input-to-prior-output derivation, that is, a prior entry whose OUTPUT
    content this entry's INPUT carries. A tool call whose argument came from
    outside the provenance log (a ticket id from the ticket system, a URL the
    user typed) has NO true parent, even though something caused it. That is
    the definition AM3's ``true_derivations=6`` counted under, and the one
    AM5's link counts are comparable to.

``expect``
    A SPEC CLAIM about what the linker should record, which is not always the
    same thing. AM10.3 requires the linker to DECLINE on the mirrored cell even
    though real carriage candidates exist there. Declining is a decision about
    what may be asserted, not a claim that no derivation happened, so it is
    modelled as an expectation override carrying its own reason, never by
    deleting the true parents.

Ground truth is hand-declared everywhere. Nothing in this module infers a
parent from content; :func:`validate_session` only checks internal consistency
of what a human wrote.

Fan-in (FL5, ``:496-511``): ``parent_provenance_id`` is single-valued and the
selection rule records ONE parent. Where an entry has several true parents, any
one of them is a correct recording, and the corpus says so by listing them all.
The doc calls this sound but incomplete attribution; it is a known limitation of
the field, not a defect of the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentlock.types import ContextSource

# ``expect`` values.
DERIVE = "derive"
"""Record one of ``true_parents``; or ``None`` when ``true_parents`` is empty."""

DECLINE = "decline"
"""Record ``None`` DESPITE real carriage candidates, because the selection rule
declines to assert an edge it cannot attribute (AM5 ``:936-941``, AM10.3)."""


@dataclass(frozen=True)
class Entry:
    """One call in a session, plus what its parentage truly is.

    ``label`` is the short name the probe series and the doc's tables use
    (``B(relay)``, ``C5``, ``N(sink)``), so a measured row can be read against
    the doc without a translation step.
    """

    label: str
    tool: str
    params: dict[str, Any]
    output: str
    source: ContextSource
    true_parents: tuple[str, ...] = ()
    expect: str = DERIVE
    expect_reason: str = ""
    provisional: bool = False

    def acceptable_parents(self) -> frozenset[str | None]:
        """The set of recordings that count as CORRECT for this entry.

        ``None`` is a member when the entry has no true parent, or when the
        expectation is an explicit DECLINE. Otherwise every true parent is
        acceptable, which is FL5's single-valued-field allowance.
        """
        if self.expect == DECLINE or not self.true_parents:
            return frozenset({None})
        return frozenset(self.true_parents)


@dataclass(frozen=True)
class Session:
    """A multi-hop session: ordered entries plus declared expectations."""

    name: str
    kind: str
    doc_ref: str
    entries: tuple[Entry, ...]
    aliases: tuple[str, ...] = ()
    expect_tainted: tuple[str, ...] = ()
    notes: str = ""
    provisional: bool = False

    def labels(self) -> tuple[str, ...]:
        return tuple(e.label for e in self.entries)

    def by_label(self, label: str) -> Entry:
        for e in self.entries:
            if e.label == label:
                return e
        raise KeyError(f"{self.name}: no entry labelled {label!r}")

    def true_derivation_count(self) -> int:
        """Entries that genuinely derive from a prior entry's output.

        This is the number AM3 reported as ``true_derivations``. It is NOT the
        acceptance criterion (AM10.1 replaced counting with identity); it is
        retained only so a reconstructed session can be checked against the
        figure the scratch probe printed.
        """
        return sum(1 for e in self.entries if e.true_parents)

    def declined(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.entries if e.expect == DECLINE)


# Session kinds.
MUST_CATCH = "must_catch"
MUST_NOT_TRIP = "must_not_trip"
CONTROL = "control"


def validate_session(s: Session) -> list[str]:
    """Internal-consistency problems in a hand-declared session.

    Checks the human, not the mechanism. It never derives a parent; it only
    reports declarations that cannot be true (a parent that is not an earlier
    entry, a DECLINE with nothing to decline, an unexplained provisional cell).
    """
    problems: list[str] = []
    seen: set[str] = set()

    if not s.entries:
        problems.append(f"{s.name}: session has no entries")

    for i, e in enumerate(s.entries):
        where = f"{s.name}[{i}] {e.label!r}"
        if e.label in seen:
            problems.append(f"{where}: duplicate label")
        for p in e.true_parents:
            if p == e.label:
                problems.append(f"{where}: declares itself as its own parent")
            elif p not in seen:
                problems.append(
                    f"{where}: true parent {p!r} is not an EARLIER entry "
                    "(a parent link may only point backwards in the log)"
                )
        if e.expect not in (DERIVE, DECLINE):
            problems.append(f"{where}: unknown expect {e.expect!r}")
        if e.expect == DECLINE and not e.true_parents:
            problems.append(
                f"{where}: DECLINE with no true parents is indistinguishable "
                "from having no parent; declare the carriage candidates"
            )
        if e.expect == DECLINE and not e.expect_reason:
            problems.append(f"{where}: DECLINE must carry a reason")
        if e.provisional and not e.expect_reason:
            problems.append(f"{where}: provisional cell must carry a reason")
        if e.source is ContextSource.USER_MESSAGE and e.true_parents:
            problems.append(
                f"{where}: a user message is authoritative input, it cannot "
                "derive from a prior tool output"
            )
        seen.add(e.label)

    for label in s.expect_tainted:
        if label not in seen:
            problems.append(
                f"{s.name}: expect_tainted names {label!r}, not an entry label"
            )

    if s.kind not in (MUST_CATCH, MUST_NOT_TRIP, CONTROL):
        problems.append(f"{s.name}: unknown kind {s.kind!r}")

    if s.provisional and not s.notes:
        problems.append(f"{s.name}: provisional session must carry notes")

    return problems


@dataclass
class Registry:
    """The committed corpus set, keyed by the doc's own session names."""

    sessions: dict[str, Session] = field(default_factory=dict)

    def add(self, s: Session) -> Session:
        if s.name in self.sessions:
            raise ValueError(f"duplicate session name {s.name!r}")
        self.sessions[s.name] = s
        return s

    def get(self, name: str) -> Session:
        return self.sessions[name]

    def of_kind(self, kind: str) -> tuple[Session, ...]:
        return tuple(s for s in self.sessions.values() if s.kind == kind)

    def all(self) -> tuple[Session, ...]:
        return tuple(self.sessions.values())
