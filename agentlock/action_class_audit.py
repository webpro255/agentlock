"""Action-class audit -- the on-demand replacement for the register-time warning.

A ``UserWarning`` at ``register_tool()`` could not see how a tool is actually
called, so it guessed from name and risk level and fired in every importing
application.  This module answers the same question with evidence, when an
operator asks: *which of my tools have an action class the gate cannot infer,
and what should I declare for them?*

Everything here is **pure data over a snapshot**.  ``audit_action_classes()``
reads the tool registry and the audit log, mutates nothing, and is never
called from ``authorize()`` or any other hot path.  The audit log is the only
place caller-asserted classes are recorded, and it is read back exactly once
per report -- never during a decision.

Coverage is defined to match ``policy.py`` exactly, not approximately.  Three
structural facts drive it, and the report would lie if it ignored any of them:

1. The lineage block is skipped entirely when the permission block predates
   v1.3, however the policy is configured.  Such a tool is ``inert``.
   Compared NUMERICALLY via ``schema.version_at_least`` -- never as strings.
2. ``session_write_gate=False`` computes the decision but never blocks -- it
   records a shadow and falls through.  Such a tool is ``shadow``.
3. ``is_value_carrying`` weakens ONLY the residual ``is_consequential``
   disjunct, ``C ∧ (G ∨ ¬V)``.  A value-carrying tool is still taint-gated
   when ``gate_consequential`` is on.  Coverage of a declared class is
   therefore a per-class question, not a per-tool one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from agentlock.schema import version_at_least

if TYPE_CHECKING:  # pragma: no cover
    from agentlock.audit import AuditRecord
    from agentlock.schema import AgentLockPermissions

__all__ = [
    "ActionClassFinding",
    "ActionClassAudit",
    "classify_tool",
    "describe",
    "declared_classes",
    "tally_observations",
    "suggest",
    "Suggestion",
    "lexical_classes",
    "lexical_value_carrying",
    "FindingStatus",
    "SuggestionBasis",
    "Confidence",
    "LineageMode",
    "VALUE_CARRYING_QUESTION",
    "format_action_class_audit",
]


#: The question a human must answer before declaring ``is_value_carrying``.
#: Lifted from ``ActionClassConfig``'s contract in schema.py, because a
#: suggestion that omits it invites a rubber-stamp of a fail-open declaration.
VALUE_CARRYING_QUESTION = (
    "Is this tool's consequential effect FULLY determined by an "
    "attacker-choosable parameter value, such that parameter/novel lineage "
    "already covers it and session taint need not?"
)


class FindingStatus(str, Enum):
    """Where a tool sits in the partition.  Disjoint and exhaustive over
    every tool with ``lineage_policy.enabled``.

    ``NOT_COVERED`` takes priority over the declaration axis: when the gate
    structurally cannot block a tool, what it declares is moot.
    """

    #: Declares no action class.  The population the removed warning aimed at,
    #: reported for every tool regardless of ``gate_consequential``.
    UNDECLARED = "undeclared"
    #: Declares at least one action class that is taint-gated as configured.
    DECLARED = "declared"
    #: The session write-gate cannot deny this tool at all -- the permission
    #: block predates v1.3, or ``session_write_gate`` is off.  Declaration
    #: changes nothing until that is fixed.
    NOT_COVERED = "not_covered"


class LineageMode(str, Enum):
    """How the lineage policy treats this tool's residual bucket."""

    #: The permission block predates v1.3 (numeric compare) -- policy.py skips
    #: the lineage block entirely.
    INERT = "inert"
    #: ``session_write_gate=False`` -- decision computed, never enforced.
    SHADOW = "shadow"
    #: ``gate_consequential=True`` -- every consequential call is taint-gated.
    UNIFORM = "uniform"
    #: ``gate_consequential=False`` -- only declared/asserted classes are gated.
    SELECTIVE = "selective"


class SuggestionBasis(str, Enum):
    """What a suggestion rests on.  Populated in Phase 4."""

    #: Name/risk heuristic only.  Weakest.
    LEXICAL = "lexical"
    #: Read back from the audit log: callers were seen asserting this.
    OBSERVED = "observed"
    #: Readback works, and this tool has zero recorded assertions.
    OBSERVED_NONE = "observed_none"
    #: The gate issued decisions but the log read back empty.  Not the same as
    #: ``OBSERVED_NONE``, and must never be silently reported as it.
    OBSERVATION_UNAVAILABLE = "observation_unavailable"


class Confidence(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ActionClassFinding:
    """One tool's action-class standing.  Immutable, side-effect free.

    Phase 4's suggestion engine populates ``suggestion`` / ``confidence`` /
    ``basis`` / ``rationale`` / ``requires_human_decision`` without reshaping
    anything above them.

    ``suggestion`` is a tuple of ``ActionClassConfig`` field names, so the
    polarity guard is a plain membership test: if ``"is_value_carrying"`` is
    in it, ``requires_human_decision`` MUST be True.  A wrong gating-ADDING
    suggestion over-gates (safe); a wrong gating-REMOVING one under-gates
    (fail-open), and no heuristic is ever allowed to make that call alone.
    """

    tool_name: str
    risk_level: str
    lineage_mode: LineageMode
    status: FindingStatus
    #: Action-class flags the trusted permission block declares.
    declared: tuple[str, ...] = ()
    #: Flag name -> number of audited decisions on which a caller asserted it.
    #: Counts AUDIT RECORDS, not authorize() calls: a single authorize() can
    #: emit more than one record on some paths.
    observed: dict[str, int] = field(default_factory=dict)

    # -- Populated by Phase 4's suggestion engine ---------------------------
    suggestion: tuple[str, ...] | None = None
    confidence: Confidence = Confidence.UNKNOWN
    basis: SuggestionBasis | None = None
    rationale: str = ""
    #: Fail-safe default.  Only a gating-ADDING suggestion may clear it.
    requires_human_decision: bool = True

    @property
    def suggests_value_carrying(self) -> bool:
        return bool(self.suggestion) and "is_value_carrying" in (
            self.suggestion or ()
        )

    def __post_init__(self) -> None:
        # The polarity invariant, enforced at construction so no code path --
        # not Phase 4, not a future contributor -- can produce a finding that
        # quietly recommends un-gating without a human in the loop.
        if self.suggests_value_carrying and not self.requires_human_decision:
            raise ValueError(
                f"POLARITY VIOLATION for tool {self.tool_name!r}: a finding "
                f"suggesting is_value_carrying (gating-REMOVING) may never "
                f"set requires_human_decision=False. Wrong gating-adding "
                f"suggestions over-gate and are safe; wrong value-carrying "
                f"suggestions under-gate and fail OPEN."
            )


class ActionClassAudit(list[ActionClassFinding]):
    """The findings, plus the report-level facts a per-tool finding cannot hold.

    A ``list`` subclass so the documented ``-> list[ActionClassFinding]``
    contract holds for every caller that just iterates.  The extra attributes
    are read defensively by ``format_action_class_audit`` via ``getattr``, so
    a plain list of findings formats fine too.
    """

    def __init__(
        self,
        findings: list[ActionClassFinding] | None = None,
        *,
        decisions_issued: int = 0,
        observation_available: bool = True,
        unregistered_observations: dict[str, int] | None = None,
    ) -> None:
        super().__init__(findings or [])
        #: Monotonic count of decisions the gate believes it has logged.
        self.decisions_issued = decisions_issued
        #: False when decisions were issued but the log read back empty.
        self.observation_available = observation_available
        #: tool_name -> audited decisions carrying asserted classes, for tools
        #: NOT in the registry.  Reported as one summary line, never as
        #: per-tool findings: the report's subject is the registry.
        self.unregistered_observations = unregistered_observations or {}


# ---------------------------------------------------------------------------
# Classification -- pure functions over a permission block.
# ---------------------------------------------------------------------------


#: Declared class -> the lineage_policy flag that decides whether it is gated.
#: is_value_carrying maps to gate_consequential because V only weakens the
#: residual disjunct C ∧ (G ∨ ¬V); with G on, the action is still gated.
_CLASS_COVERAGE_FLAG: dict[str, str] = {
    "is_deletion": "gate_deletion",
    "is_membership_change": "gate_membership_change",
    "is_value_carrying": "gate_consequential",
}


def declared_classes(permissions: AgentLockPermissions) -> tuple[str, ...]:
    """The action-class flags the trusted block sets True, in schema order."""
    ac = permissions.action_class
    if ac is None:
        return ()
    return tuple(
        name
        for name in ("is_deletion", "is_membership_change", "is_value_carrying")
        if getattr(ac, name, False)
    )


def _lineage_mode(permissions: AgentLockPermissions) -> LineageMode:
    lp = permissions.lineage_policy
    assert lp is not None  # caller filters on lp.enabled
    if not _version_ok(permissions):
        return LineageMode.INERT
    if not lp.session_write_gate:
        return LineageMode.SHADOW
    return LineageMode.UNIFORM if lp.gate_consequential else LineageMode.SELECTIVE


def _version_ok(permissions: AgentLockPermissions) -> bool:
    """Does the gate consider this permission block v1.3+?

    Calls the SAME ``version_at_least`` the gate calls.  The report must never
    claim coverage the gate does not provide, so this shares the predicate
    rather than reimplementing it -- a second implementation is a second thing
    to drift.

    (This function once deliberately mirrored a lexicographic string compare,
    bug and all, because a report that "helpfully" parsed versions would have
    told operators a v1.10 tool was taint-gated while the gate skipped it.
    The gate is fixed; the mirror now points at the fix.)
    """
    return version_at_least(permissions.version, (1, 3))


def describe(
    permissions: AgentLockPermissions,
    mode: LineageMode,
    status: FindingStatus,
    declared: tuple[str, ...],
) -> str:
    """A factual, suggestion-free explanation of the finding's status.

    Phase 3 populates ``rationale`` with this because ``NOT_COVERED`` is not
    self-explanatory: it holds for a tool deliberately un-gated via
    ``is_value_carrying`` *and* for one accidentally stranded by an old schema
    version.  A report that renders both as bare "NOT COVERED" tells the
    operator to panic about the first or ignore the second.
    """
    lp = permissions.lineage_policy
    assert lp is not None

    if mode is LineageMode.INERT:
        return (
            f"permission block declares version {permissions.version!r}; "
            f"policy.py skips the lineage block entirely below '1.3', so this "
            f"tool's lineage_policy has no effect at all"
        )
    if mode is LineageMode.SHADOW:
        return (
            "session_write_gate=False: the taint decision is computed and "
            "recorded as a shadow, but never enforced (v1.3 ablation)"
        )

    if status is FindingStatus.NOT_COVERED:
        if declared == ("is_value_carrying",):
            return (
                "declares is_value_carrying with gate_consequential=False -- "
                "DELIBERATELY un-gated. Session taint does not block it; "
                "parameter/novel lineage is the covering control. This is the "
                "intended configuration, not a defect"
            )
        ungated = ", ".join(
            f"{name} (needs {_CLASS_COVERAGE_FLAG[name]}=True)"
            for name in declared
        )
        return (
            f"declares {ungated}, but every declared class has its gate flag "
            f"switched off, so the declaration currently buys no gating"
        )

    if status is FindingStatus.UNDECLARED:
        if mode is LineageMode.SELECTIVE:
            return (
                "no action_class, and gate_consequential=False. A call that "
                "asserts no class at all matches no disjunct and is never "
                "taint-gated. This is the residual hazard"
            )
        return (
            "no action_class, but gate_consequential=True, so consequential "
            "calls are still taint-gated today. The declaration matters the "
            "moment this deployment un-gates the residual bucket"
        )

    covered = ", ".join(
        name
        for name in declared
        if getattr(lp, _CLASS_COVERAGE_FLAG[name], False)
    )
    return f"declared and taint-gated via {covered}"


def classify_tool(permissions: AgentLockPermissions) -> tuple[LineageMode, FindingStatus]:
    mode = _lineage_mode(permissions)
    if mode in (LineageMode.INERT, LineageMode.SHADOW):
        return mode, FindingStatus.NOT_COVERED

    declared = declared_classes(permissions)
    if not declared:
        return mode, FindingStatus.UNDECLARED

    lp = permissions.lineage_policy
    assert lp is not None
    covered = any(
        getattr(lp, _CLASS_COVERAGE_FLAG[name], False) for name in declared
    )
    return mode, (FindingStatus.DECLARED if covered else FindingStatus.NOT_COVERED)


# ---------------------------------------------------------------------------
# Observation readback.
# ---------------------------------------------------------------------------


def tally_observations(
    records: list[AuditRecord],
) -> dict[str, dict[str, int]]:
    """tool_name -> {flag: count of audited decisions asserting it}.

    Counts records, not ``authorize()`` calls.  Some paths emit two records
    for one call, so the report says "asserted on >=N audited decisions".
    """
    tally: dict[str, dict[str, int]] = {}
    for rec in records:
        meta: dict[str, Any] = rec.metadata or {}
        asserted = meta.get("asserted_classes")
        if not asserted:
            continue
        per_tool = tally.setdefault(rec.tool_name, {})
        for flag in asserted:
            per_tool[flag] = per_tool.get(flag, 0) + 1
    return tally


# ---------------------------------------------------------------------------
# Suggestions -- two tiers.  Tier B (observed) beats Tier A (lexical).
#
# Suggestions are EVIDENCE PRESENTED TO A HUMAN.  Nothing here ever feeds a
# gating decision: the gate reads `permissions.action_class`, which only a
# human can write.  Tier B tallies what callers asserted; it does not make
# those assertions authoritative.
#
# THE POLARITY ASYMMETRY governs every default below.  A wrong gating-ADDING
# suggestion (is_deletion / is_membership_change) over-gates: the operator
# loses some utility and nothing fails open.  A wrong gating-REMOVING one
# (is_value_carrying) under-gates: it silently un-gates a value-free action
# for which session taint was the only available signal.  So gating-adding
# suggestions may be paste-ready, and value-carrying suggestions may never be.
# ---------------------------------------------------------------------------

#: Verbs that destroy existing state.
_DELETION_VERBS = frozenset(
    {"delete", "destroy", "drop", "purge", "wipe", "erase", "remove",
     "truncate", "rm", "del"}
)

#: Verbs that move a principal across a boundary, on their own.
_STANDALONE_MEMBERSHIP_VERBS = frozenset(
    {"invite", "kick", "ban", "unban", "subscribe", "unsubscribe",
     "join", "leave"}
)

#: Verbs that change membership only when applied to a principal noun.
_MEMBERSHIP_VERBS = frozenset(
    {"add", "remove", "delete", "grant", "revoke", "assign", "unassign",
     "set", "update"}
)

#: Principal nouns.  Deliberately EXCLUDES container nouns like "channel" and
#: "group": `delete_channel` destroys a container, it does not change a
#: membership, and `add_user_to_channel` is already caught by "user".
_PRINCIPAL_NOUNS = frozenset(
    {"user", "users", "member", "members", "membership", "principal",
     "role", "roles", "acl", "permission", "permissions", "collaborator",
     "collaborators", "owner", "admin"}
)

#: Verbs whose effect is determined by an attacker-choosable parameter value.
_VALUE_CARRYING_VERBS = frozenset(
    {"reserve", "book", "schedule", "create", "transfer", "pay", "charge",
     "purchase", "order", "allocate", "submit", "issue", "provision"}
)

#: Tier A fires only for these risk levels.  MEMBERSHIP TEST, never an
#: ordering test: RiskLevel is a plain str-Enum, so `risk >= "high"` compares
#: LEXICOGRAPHICALLY and "critical" < "high" would silently exclude the
#: highest-risk tools.  Same trap class as the lexicographic version compare
#: that `schema.version_at_least` now exists to prevent.
_ELEVATED_RISK = frozenset({"high", "critical"})

#: Named (gating-ADDING) classes, in schema order.
_NAMED_CLASSES = ("is_deletion", "is_membership_change")


def _name_tokens(tool_name: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", tool_name.lower()) if t}


def lexical_classes(tool_name: str) -> tuple[str, ...]:
    """Named, gating-adding classes implied by a tool's name.  Never
    ``is_value_carrying`` -- that is gating-removing and needs a human.

    Collisions are intentional: ``remove_user`` is BOTH a deletion and a
    membership change, and ``ActionClassConfig`` permits both together (they
    are both gating-adding).  Suggest both rather than picking one.
    """
    t = _name_tokens(tool_name)
    out: list[str] = []
    if t & _DELETION_VERBS:
        out.append("is_deletion")
    if (t & _STANDALONE_MEMBERSHIP_VERBS) or (
        (t & _MEMBERSHIP_VERBS) and (t & _PRINCIPAL_NOUNS)
    ):
        out.append("is_membership_change")
    return tuple(out)


def lexical_value_carrying(tool_name: str) -> bool:
    return bool(_name_tokens(tool_name) & _VALUE_CARRYING_VERBS)


@dataclass(frozen=True, slots=True)
class Suggestion:
    """A suggestion plus everything needed to judge it."""

    suggestion: tuple[str, ...] | None
    confidence: Confidence
    basis: SuggestionBasis
    requires_human_decision: bool
    rationale: str


def suggest(
    *,
    tool_name: str,
    risk_level: str,
    observed: dict[str, int],
    observation_available: bool,
) -> Suggestion:
    """Suggest an action class for an UNDECLARED tool.

    Tier B (observed) beats Tier A (lexical): what callers actually asserted
    is evidence; what a tool is named is a guess.
    """
    # Three-state basis.  A broken readback is NOT "no observations" -- one is
    # a missing instrument, the other is a reading of zero.  Conflating them
    # would let a dead audit backend masquerade as a clean bill of health.
    if not observation_available:
        lex = lexical_classes(tool_name)
        return Suggestion(
            suggestion=lex or None,
            confidence=Confidence.LOW,
            basis=SuggestionBasis.OBSERVATION_UNAVAILABLE,
            # Nothing is paste-ready when the evidence channel is broken.
            requires_human_decision=True,
            rationale=(
                "the audit log read back empty despite decisions having been "
                "issued, so no observed evidence is available; this rests on "
                "NAMING ALONE"
            ),
        )

    # -- Tier B: observed ---------------------------------------------------
    observed_named = tuple(c for c in _NAMED_CLASSES if observed.get(c))
    if observed_named:
        evidence = "; ".join(
            f"{c} on >={observed[c]} audited decision"
            f"{'s' if observed[c] != 1 else ''}"
            for c in observed_named
        )
        return Suggestion(
            suggestion=observed_named,
            confidence=Confidence.HIGH,
            basis=SuggestionBasis.OBSERVED,
            requires_human_decision=False,  # gating-adding: safe if wrong
            rationale=f"callers were observed asserting {evidence}",
        )

    if observed.get("is_consequential"):
        n = observed["is_consequential"]
        seen = (
            f"callers were observed asserting is_consequential on >={n} "
            f"audited decision{'s' if n != 1 else ''}, the RESIDUAL bucket "
            f"rather than a named class"
        )
        # The name can say WHICH value-free class the residual bucket holds.
        # That is still a gating-adding suggestion, so it stays safe if wrong,
        # and the observation -- not the name -- is what triggered it.
        lex = lexical_classes(tool_name)
        if lex:
            return Suggestion(
                suggestion=lex,
                confidence=Confidence.MEDIUM,
                basis=SuggestionBasis.OBSERVED,
                requires_human_decision=False,
                rationale=(
                    f"{seen}. The tool's name identifies the class as "
                    f"{', '.join(lex)}"
                ),
            )
        # Nothing named it.  The residual bucket is exactly the question
        # is_value_carrying answers -- and answering it wrong FAILS OPEN.
        return Suggestion(
            suggestion=("is_value_carrying",),
            confidence=Confidence.LOW,
            basis=SuggestionBasis.OBSERVED,
            requires_human_decision=True,  # enforced again in __post_init__
            rationale=(
                f"{seen}. No name token identifies a value-free class, so "
                f"this may be a value-carrying write -- but only a human can "
                f"say so, and saying so wrongly un-gates it"
            ),
        )

    # -- Tier A: lexical ----------------------------------------------------
    # Membership test on risk, never an ordering test.
    if risk_level in _ELEVATED_RISK:
        lex = lexical_classes(tool_name)
        if lex:
            return Suggestion(
                suggestion=lex,
                confidence=Confidence.LOW,
                basis=SuggestionBasis.LEXICAL,
                requires_human_decision=False,  # gating-adding
                rationale=(
                    f"no observed assertions; the tool's name implies "
                    f"{', '.join(lex)} at {risk_level} risk"
                ),
            )
        if lexical_value_carrying(tool_name):
            return Suggestion(
                suggestion=("is_value_carrying",),
                confidence=Confidence.LOW,
                basis=SuggestionBasis.LEXICAL,
                requires_human_decision=True,
                rationale=(
                    f"no observed assertions; the tool's name suggests a "
                    f"value-carrying write at {risk_level} risk. A NAME IS "
                    f"NOT EVIDENCE for a gating-removing declaration"
                ),
            )

    return Suggestion(
        suggestion=None,
        confidence=Confidence.UNKNOWN,
        basis=SuggestionBasis.OBSERVED_NONE,
        requires_human_decision=True,
        rationale=(
            "no observed assertions and no name/risk signal; a human must "
            "classify this tool"
        ),
    )


# ---------------------------------------------------------------------------
# Formatting.
# ---------------------------------------------------------------------------

_STATUS_ORDER = (
    FindingStatus.UNDECLARED,
    FindingStatus.NOT_COVERED,
    FindingStatus.DECLARED,
)

_STATUS_HEADING = {
    FindingStatus.UNDECLARED: (
        "UNDECLARED -- no action_class in the trusted permission block"
    ),
    FindingStatus.NOT_COVERED: (
        "NOT COVERED -- the session write-gate cannot block these tools"
    ),
    FindingStatus.DECLARED: "DECLARED -- action class on the trusted side",
}


def _format_observed(observed: dict[str, int]) -> str:
    if not observed:
        return ""
    parts = [
        # ">=" because one authorize() can emit more than one audit record.
        f"{flag} on >={count} audited decision{'s' if count != 1 else ''}"
        for flag, count in sorted(observed.items())
    ]
    return "; ".join(parts)


def format_action_class_audit(
    findings: list[ActionClassFinding],
) -> str:
    """Human-readable rendering of an action-class audit."""
    lines: list[str] = []
    lines.append("AgentLock action-class audit")
    lines.append("=" * 60)

    if not findings:
        lines.append("")
        lines.append("No tools with lineage_policy.enabled are registered.")
        lines.append("Nothing to audit: the session write-gate is not in use.")
        return "\n".join(lines)

    observation_available = getattr(findings, "observation_available", True)
    decisions_issued = getattr(findings, "decisions_issued", 0)
    unregistered = getattr(findings, "unregistered_observations", {})

    if not observation_available:
        lines.append("")
        lines.append("!! OBSERVATION UNAVAILABLE")
        lines.append(
            f"   The gate has issued {decisions_issued} audited decision(s), "
            f"but the audit log read back empty."
        )
        lines.append(
            "   Suggestions below rest on NAMING ALONE. This is not the same "
            "as a tool having no observed assertions."
        )
        lines.append("   Check the audit backend before trusting this report.")

    by_status: dict[FindingStatus, list[ActionClassFinding]] = {}
    for f in findings:
        by_status.setdefault(f.status, []).append(f)

    for status in _STATUS_ORDER:
        bucket = by_status.get(status)
        if not bucket:
            continue
        lines.append("")
        lines.append(_STATUS_HEADING[status])
        lines.append("-" * 60)
        for f in sorted(bucket, key=lambda x: x.tool_name):
            lines.extend(_format_finding(f))

    lines.append("")
    lines.append("-" * 60)
    counts = {s: len(by_status.get(s, [])) for s in _STATUS_ORDER}
    lines.append(
        f"{len(findings)} tool(s) audited: "
        f"{counts[FindingStatus.UNDECLARED]} undeclared, "
        f"{counts[FindingStatus.NOT_COVERED]} not covered, "
        f"{counts[FindingStatus.DECLARED]} declared."
    )

    if unregistered:
        total = sum(unregistered.values())
        lines.append(
            f"Note: {total} audited decision(s) across "
            f"{len(unregistered)} tool(s) NOT in the registry carried asserted "
            f"action classes ({', '.join(sorted(unregistered))}). Not audited "
            f"here -- this report's subject is the tool registry."
        )

    return "\n".join(lines)


def _format_finding(f: ActionClassFinding) -> list[str]:
    out: list[str] = []
    out.append("")
    out.append(f"  {f.tool_name}  [{f.risk_level} risk, {f.lineage_mode.value}]")

    if f.declared:
        out.append(f"    declared:  {', '.join(f.declared)}")

    obs = _format_observed(f.observed)
    if obs:
        out.append(f"    observed:  {obs}")

    if f.rationale:
        out.append(f"    why:       {f.rationale}")

    if f.suggestion:
        basis = f.basis.value if f.basis else "none"
        out.append(
            f"    suggest:   {', '.join(f.suggestion)}  "
            f"(basis={basis}, confidence={f.confidence.value})"
        )
        if f.suggests_value_carrying:
            # Never paste-ready.  Wrong here means fail-OPEN.
            out.append("    >> REQUIRES HUMAN CONFIRMATION")
            out.append(f"       {VALUE_CARRYING_QUESTION}")
        elif f.requires_human_decision:
            out.append("    >> REQUIRES HUMAN DECISION")
        else:
            out.append(
                f"    paste:     action_class=ActionClassConfig("
                f"{', '.join(f'{s}=True' for s in f.suggestion)})"
            )
    elif f.requires_human_decision and f.status is FindingStatus.UNDECLARED:
        out.append("    >> REQUIRES HUMAN DECISION (no suggestion available)")

    return out
