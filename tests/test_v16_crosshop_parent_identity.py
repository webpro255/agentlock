"""Cross-hop acceptance criterion: PARENT IDENTITY, not link count (AM10.1).

``docs/PREDICTIONS_crosshop.md`` section 6 originally accepted a link graph when
"parent links set must equal the true derivation count exactly" (``:596-598``).
AM3 then measured a graph that passes that and is two thirds wrong: 6 links for
6 true derivations, 2 correct parents, 4 wrong (``:810-813``). AM10.1 replaced
the criterion with parent identity. This file is that criterion, executable.

Three things are kept strictly apart here, because conflating any two of them
would make the suite lie about the state of the build:

1. **The corpus is real and non-vacuous.** Checked unconditionally. If the
   ground truth were emptied, or the registry lost its sessions, these tests
   fail whether or not any mechanism exists.
2. **The old criterion is not what is being tested.** Checked unconditionally,
   against AM3's actual measured graph: the link count matches and the parent
   identities do not, and this file's scorer must say so.
3. **The mechanism does not exist yet.** AM7 items 1 to 5 are unbuilt. The
   acceptance tests skip on that, and the discriminator is the presence of the
   linker SYMBOL in the engine source, never the shape of the output.

Why the symbol and not the output: a linker that wrongly declines everything
produces all-``None`` parents, which is exactly what no linker at all produces.
Treating all-``None`` as "not built yet" would turn the total-failure case into
a green skip, which is the failure mode this file exists to prevent. The same
rule the AgentDojo harness used with ``_encoded_blob_suffix`` applies: ask the
source whether the mechanism is there, then judge its output on the merits.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import agentlock.context as ctx
from agentlock import AuthorizationGate
from agentlock.types import ContextSource
from tests.crosshop_corpora import (
    MUST_CATCH,
    MUST_NOT_TRIP,
    REGISTRY,
    validate_session,
)

# ---------------------------------------------------------------------------
# THE DISCRIMINATOR. One edit when the linker lands.
# ---------------------------------------------------------------------------
# AM7 does not fix the symbol name (item 3 names the predicate, not its
# identifier), so the name below is a placeholder and is EXPECTED to be edited
# once. Point it at the containment linker's function or constant in
# ``agentlock/context.py`` and every acceptance test in this file switches from
# skip to judged, with no other change.
LINKER_SYMBOL = "_containment_parent"

# ``notify_context_write`` has no parameter for the call's input arguments
# (AM7 item 2, ``gate.py:2450``), and the linker cannot run without one. The
# name it lands under is not fixed either, so it is the second edit point.
INPUT_ARGS_KWARG = "parameters"

_ENGINE_SOURCE = Path(ctx.__file__)


def linker_present() -> bool:
    """Whether the cross-hop linker exists in the engine.

    Source inspection, deliberately. Nothing about the produced graph is
    consulted, because every wrong graph a built linker can produce is also a
    graph an absent linker produces.
    """
    return LINKER_SYMBOL in _ENGINE_SOURCE.read_text()


SKIP_REASON = (
    f"cross-hop linker not built: {LINKER_SYMBOL!r} is absent from "
    f"{_ENGINE_SOURCE.name}. AM7's frozen build spec is unimplemented: "
    "match-before-write ordering (item 1), input arguments at ingestion "
    "(item 2), the containment link predicate (item 3), the transitive "
    "cycle-guarded walk (item 4), and the reachability taint predicate "
    "(item 5). This is a MISSING MECHANISM, not a failing one."
)

needs_linker = pytest.mark.skipif(not linker_present(), reason=SKIP_REASON)

SESSIONS = REGISTRY.all()
SESSION_IDS = [s.name for s in SESSIONS]


# ---------------------------------------------------------------------------
# Scoring. Parent identity, per entry.
# ---------------------------------------------------------------------------


def score(session, recorded: dict[str, str | None]) -> dict[str, object]:
    """Judge a recorded graph against the session's declared ground truth.

    ``recorded`` maps entry label to the label of the parent that was recorded,
    or ``None``. The verdict is per ENTRY: a recording is correct when it is one
    of the entry's acceptable parents (FL5 allows any true parent where the
    entry has several; SELECT narrows that to one when a rule picks; DECLINE
    requires ``None``).

    ``links_set`` is reported because the OLD criterion counted it, and
    :func:`test_link_count_criterion_is_not_what_is_tested` needs both numbers
    from one place to show they disagree.
    """
    correct: list[str] = []
    wrong: list[str] = []
    missed: list[str] = []
    for e in session.entries:
        got = recorded.get(e.label)
        acceptable = e.acceptable_parents()
        if got in acceptable:
            correct.append(e.label)
        elif got is None:
            missed.append(f"{e.label}: recorded None, acceptable {sorted(acceptable)}")
        else:
            wrong.append(
                f"{e.label}: recorded {got!r}, acceptable "
                f"{sorted(str(a) for a in acceptable)}"
            )
    return {
        "correct": correct,
        "wrong": wrong,
        "missed": missed,
        "links_set": sum(1 for v in recorded.values() if v is not None),
        "true_derivations": session.true_derivation_count(),
    }


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def _record(gate: AuthorizationGate, sid: str, entry):
    """Report one entry as a context write, passing the call's input arguments.

    The kwarg is passed by name from :data:`INPUT_ARGS_KWARG`. If the engine
    does not accept it while :data:`LINKER_SYMBOL` IS present, that is a real
    failure and it is raised as one: a linker that never sees the call's inputs
    cannot establish a link, and AM7 item 2 is the part of the spec that was
    skipped.
    """
    kwargs = {
        "writer_id": entry.tool,
        "tool_name": entry.tool if entry.source is not ContextSource.USER_MESSAGE else None,
        "content": entry.output,
    }
    accepted = inspect.signature(gate.notify_context_write).parameters
    if INPUT_ARGS_KWARG not in accepted:
        raise AssertionError(
            f"{LINKER_SYMBOL!r} is present in {_ENGINE_SOURCE.name} but "
            f"notify_context_write does not accept {INPUT_ARGS_KWARG!r}. AM7 "
            "item 2 (input arguments at ingestion) is unimplemented, so no "
            "link can be established. Update INPUT_ARGS_KWARG if the "
            "parameter landed under another name."
        )
    kwargs[INPUT_ARGS_KWARG] = dict(entry.params)
    return gate.notify_context_write(
        sid,
        entry.source,
        ctx.ContextProvenance.hash_content(entry.output),
        **kwargs,
    )


def replay(session) -> dict[str, str | None]:
    """Replay a session through the gate and read back the recorded parentage.

    No linking logic lives here. The corpus is data; this function only reports
    the writes in order and translates provenance ids back to labels.
    """
    gate = AuthorizationGate()
    sess = gate.create_session(user_id="alice", role="analyst")
    ids: dict[str, str] = {}
    recorded: dict[str, str | None] = {}
    for entry in session.entries:
        prov = _record(gate, sess.session_id, entry)
        ids[prov.provenance_id] = entry.label
        recorded[entry.label] = prov.parent_provenance_id
    return {
        label: (ids.get(pid) if pid else None) for label, pid in recorded.items()
    }


# ---------------------------------------------------------------------------
# 1. The corpus is real. These run whether or not the mechanism exists.
# ---------------------------------------------------------------------------


def test_registry_is_populated():
    assert len(SESSIONS) == 17, "corpus lost or gained sessions unnoticed"
    assert len(REGISTRY.of_kind(MUST_NOT_TRIP)) == 8
    assert len(REGISTRY.of_kind(MUST_CATCH)) == 7


@pytest.mark.parametrize("session", SESSIONS, ids=SESSION_IDS)
def test_session_ground_truth_is_internally_consistent(session):
    assert validate_session(session) == []


def test_ground_truth_is_not_empty():
    """Non-vacuity floor.

    Counts the entries whose CORRECT recording is a real parent rather than
    ``None``. If the ground truth were deleted, or every expectation flipped to
    DECLINE, the acceptance tests below would still pass on an all-``None``
    graph. They cannot, because this number is pinned.
    """
    demanding = [
        (s.name, e.label)
        for s in SESSIONS
        for e in s.entries
        if None not in e.acceptable_parents()
    ]
    assert len(demanding) == 49, (
        "the number of entries that DEMAND a non-None parent changed; if that "
        "is intended, the acceptance criterion moved and the change belongs in "
        "a dated amendment, not in a test edit"
    )


def test_declared_parents_reproduce_the_am3_true_derivation_count():
    """AM3's ``true_derivations=6`` on the 10-call session (``:813``).

    The reconstruction is only comparable to the AM5 zeros if it declares the
    same derivations the scratch probe declared.
    """
    assert REGISTRY.get("10-call session").true_derivation_count() == 6
    assert REGISTRY.get("benign 6-call").true_derivation_count() == 4
    assert REGISTRY.get("ticket head-of-chain").true_derivation_count() == 3


def test_the_provisional_cell_is_marked_provisional():
    """AM10.3's decline is PROVISIONAL and coupled to AM11.1 (AM12.1).

    If this expectation is ever silently promoted to settled, the corpus would
    be asserting a decision the doc records as unmeasured.
    """
    mirrored = REGISTRY.get("mirrored cell")
    assert mirrored.provisional
    declined = mirrored.declined()
    assert len(declined) == 1
    assert declined[0].provisional
    assert "AM10.3" in declined[0].expect_reason


# ---------------------------------------------------------------------------
# 2. The old criterion is not what is being tested.
# ---------------------------------------------------------------------------

# AM3's measured linker-B graph on the 10-call session, transcribed from the
# probe series (``probes/crosshop-am3-am5/run6.py``, replayed). It is the graph
# that produced ":810-813": six links for six true derivations, of which two
# name the correct parent.
AM3_MEASURED_TEN_CALL_GRAPH = {
    "U": None,
    "C1": None,
    "C2": None,
    "C3": "C1",
    "C4": None,
    "C5": "C4",
    "C6": "C4",
    "C7": "C4",
    "C8": "C4",
    "C9": "C3",
}


def test_link_count_criterion_is_not_what_is_tested():
    """The guard AM10.1 exists for.

    On AM3's measured graph the OLD criterion passes exactly: links set equals
    the true derivation count. The NEW criterion must fail it, naming four
    wrong parents. A suite that cannot tell these two graphs apart is scoring
    the thing AM10.1 discarded.
    """
    session = REGISTRY.get("10-call session")
    result = score(session, AM3_MEASURED_TEN_CALL_GRAPH)

    # The old criterion, evaluated here only to show it passes on a wrong graph.
    assert result["links_set"] == result["true_derivations"] == 6

    # The new criterion, on the same graph.
    assert len(result["wrong"]) == 4, result["wrong"]
    assert result["missed"] == []
    wrong_children = {w.split(":")[0] for w in result["wrong"]}
    assert wrong_children == {"C6", "C7", "C8", "C9"}


def test_scorer_rejects_an_all_none_graph():
    """All-``None`` is a FAILURE, not an absence.

    A built linker that declines everything produces this graph. It must score
    as parent-identity failure, which is what makes the symbol check (rather
    than an output check) the only safe discriminator for skipping.
    """
    session = REGISTRY.get("depth-4")
    result = score(session, {e.label: None for e in session.entries})
    assert result["links_set"] == 0
    assert len(result["missed"]) == 4
    assert result["wrong"] == []


# ---------------------------------------------------------------------------
# 3. The acceptance criterion itself. Skipped only on a missing mechanism.
# ---------------------------------------------------------------------------


@needs_linker
@pytest.mark.parametrize("session", SESSIONS, ids=SESSION_IDS)
def test_parent_identity(session):
    """AM10.1: every entry's recorded parent must be an acceptable one.

    Not a link count. A session passes only when every entry, including the
    ones whose correct recording is ``None``, matches its declaration.
    """
    result = score(session, replay(session))
    assert not result["wrong"] and not result["missed"], (
        f"{session.name}: parent identity failed. "
        f"wrong={result['wrong']} missed={result['missed']} "
        f"(doc reference: {session.doc_ref})"
    )


@needs_linker
def test_am3_ten_call_session_is_repaired_by_the_built_linker():
    """The specific regression AM10.1 was written from.

    AM3 measured 2 correct parents of 6 on this session with a token linker.
    The containment rule (AM5) is expected to name every one. A build that
    reproduces AM3's 2-of-6 while passing a link-count check has rebuilt the
    graph the criterion was changed to reject.
    """
    session = REGISTRY.get("10-call session")
    result = score(session, replay(session))
    assert len(result["correct"]) == len(session.entries), result
