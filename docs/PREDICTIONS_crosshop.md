# Pre-registered prediction: cross-hop provenance linking (derivation taint)
# Date: August 1, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing

No probe of the cross-hop MECHANISM has run and no cross-hop mechanism code
exists. This document is written after the cross-hop Phase 0 terrain map (a
read-only scope probe over `agentlock/context.py`, `agentlock/gate.py`, and the
two working single-hop adapters at `~/crewai-agentlock` and `~/mcp-agentlock`)
and before any linking logic is added to the engine. Every AFTER column below is
a prediction, not a measurement.

Two classes of cell are distinguished throughout, as in
`PREDICTIONS_v16_family2.md`. Cells marked MEASURED are facts the scope probe
read out of the shipped code. Cells marked PREDICTED are unconfirmed and must be
turned into measurements by a cross-hop BEFORE probe before any AFTER column is
judged.

This work is NOT part of the v1.6 release scope. `RELEASE_SCOPE_v16.md` ships
families 1 and 2; its roadmap (item 7) carries the IP composite cut, Defect A,
and per-character URL enumeration. Cross-hop is a separate family, sequenced
after that release, and nothing in this document gates v1.6.

---

## CORRECTION TO THE STARTING FACTS (recorded before anything else)

This section exists because the task that commissioned this document supplied
four starting facts, and one of them is false. It is recorded here, at the top,
rather than silently corrected downstream, on the same footing as AM2.1 and
AM4.1 in `PREDICTIONS_v16_family2.md`: a pre-registration whose starting facts
are wrong is worse than no pre-registration, because it launders an assumption
into the record as a measurement.

**The falsified fact.** The commissioning brief states, as ESTABLISHED BY THE
SCOPE PROBE, that "the engine ALREADY walks the parent chain:
`_collect_provenance_ids` does a transitive cycle-guarded BFS over
`parent_provenance_id` to any depth," and concludes from it that this is a
MEDIUM build (populate links, do not build the walk).

`_collect_provenance_ids` does not exist. Verified four ways:

```
$ grep -rn "_collect_provenance_ids" . ~/crewai-agentlock ~/mcp-agentlock
(no output)

$ git grep -n "_collect_provenance_ids" $(git rev-list --all)
(no output; absent from all 11 branches and all reachable history)

$ grep -rn "_collect_provenance_ids" /home/n1trolab --include=*.py --include=*.md
(no output)

$ grep -rn "\.parent_provenance_id" agentlock/ ~/crewai-agentlock/src ~/mcp-agentlock/src
(exit 1; zero attribute reads anywhere in the engine or either adapter)
```

**What the scope probe actually established.** `parent_provenance_id` is
write-only. It has exactly seven references in the engine, and all seven are
declarations, keyword parameters, docstrings, or the one assignment:

| Location | What it is |
|---|---|
| `agentlock/context.py:551` | field declaration on `ContextProvenance` |
| `agentlock/context.py:609,623` | keyword parameter and docstring on `record_write` |
| `agentlock/context.py:669` | the assignment into the dataclass |
| `agentlock/gate.py:2459,2476,2498` | the same three, one layer up in `notify_context_write` |

No consumer. The only reads anywhere are two round-trip assertions in
`tests/test_context.py:216,222` and the two adapter boundary tests, which assert
the field is `None`. The only chain that exists in the codebase is
`ContextChain` / `previous_hash` (`chain.py`, `context.py:682`), a tamper-evident
sequential hash chain that records ORDER, not DERIVATION. There is no ancestor
traversal, cycle-guarded or otherwise, anywhere in the repo.

**The second-order consequence, which is the part that matters.** The walk being
absent is the cheap half of the correction. A BFS over parent links is small. The
expensive half is that the taint predicate all three lineage readers share is a
FLAT authority test over the log, and it discards exactly the entries a parent
link would live on.

`parameter_lineage_check` (`context.py:795`):

```
untrusted_entries = [
    e
    for e in state.provenance_log
    if e.authority == ContextAuthority.UNTRUSTED and e.content
]
```

`novel_lineage_check` (`context.py:1043`):

```
if e.authority == ContextAuthority.AUTHORITATIVE:
    target = auth_tokens
elif e.authority == ContextAuthority.UNTRUSTED:
    target = untrusted_tokens
else:
    continue                    # DERIVED entries dropped outright
```

`lineage_summary` (`context.py:715`) is the same shape: a flat index scan for
`authority == UNTRUSTED` against the index of the last `AUTHORITATIVE`.

An intermediate hop's output is recorded as `TOOL_OUTPUT`, which the default
authority map (`context.py:640-648`) resolves to `DERIVED`. So the entry that would
CARRY a parent link is filtered out of every lineage haystack before the link
could ever be consulted. **Populating parent links, on the shipped engine,
changes no decision.** The link is inert until "tainted" stops meaning
`authority == UNTRUSTED` and starts meaning reachability to an UNTRUSTED
ancestor.

**Restated build classification.** Cross-hop is a THREE-COMPONENT build, not a
one-component one:

1. **Populate links at ingestion.** Reuse the existing match. Genuinely cheap.
   This is the component the brief correctly identified, and its payoff argument
   (below) survives the correction untouched.
2. **Build the walk.** Transitive, cycle-guarded traversal over
   `parent_provenance_id`. Small in isolation, but it does not exist and must be
   written, including its cycle guard.
3. **Change the shared taint predicate to reachability.** Three call sites in
   `context.py` share one definition. This is the component with blast radius,
   because it changes the meaning of "untrusted context" for `param_lineage`,
   `novel_lineage`, and `lineage_summary` at once, and that definition is the one
   every frozen family-1 and family-2 corpus was measured against.

Component 3 is why the honest classification is closer to the brief's option (c)
than its option (b). Not because the work is large in lines, but because it moves
a definition two closed families are pinned to. Every no-regression floor in this
document exists to bound that.

**The three starting facts that SURVIVE.** Recorded so the correction is not read
as invalidating the brief wholesale:

- Establishing a parent link is the same token-matching the single-hop check
  already does, run at INGESTION time rather than DECISION time. CONFIRMED, and
  the code that makes it true is quoted in section 1.
- Families 1 and 2 therefore apply to linking for free. CONFIRMED, and it is the
  payoff. Section 2's P2 is the pre-registered form of this claim.
- There is a hard ceiling where no matchable form survives. CONFIRMED as a real
  and permanent boundary, but the brief draws it in the wrong place. Section 3
  states where it actually falls, and the correction makes the capability claim
  STRONGER, not weaker.

---

## Hypothesis

A parent link established at INGESTION time, by matching a tool call's INPUT
arguments against the accumulated provenance log with the existing lineage-token
matching, plus a transitive walk over those links, plus a taint predicate
redefined as reachability, extends single-hop provenance enforcement to chains of
arbitrary depth WITHOUT adding any new matching primitive.

The claim is deliberately narrow. It is about VALUE PROPAGATION THROUGH TOOL
BOUNDARIES: a value that enters some tool's input in a form the existing matcher
can see. It says nothing about propagation the gate cannot observe, and section 3
pre-registers that boundary as an explicit, permanent non-capability so that a
failure there counts as a measured boundary rather than a defect.

---

## 1. THE MECHANISM (stated, not designed)

Stated at the level of what is reused and what is new, so the doc determines the
spec without designing it. No mechanism code exists.

**Ingestion-time linking.** Today, both adapters record a tool's output with no
parent. CrewAI (`wrapper.py:219-226`) and MCP (`wrapper.py:456-463`) both call
`_maybe_record_provenance` from inside the wrapper body, where the call's input
arguments are still in scope, and neither passes anything derived from them. The
mechanism: at the moment a tool's output is recorded, match that tool's INPUT
arguments against the accumulated provenance log; when a prior entry's token is
found in the input, record that entry as the `parent_provenance_id` of the new
output entry.

**Confirmed: this reuses the existing matcher, not a new one.** The match already
takes the exact inputs a linker needs, and already returns the exact identifier a
link is made of. `parameter_lineage_check` (`context.py:880-893`) returns:

```
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
```

`untrusted_provenance_id` IS the parent id. The method already takes
`(session_id, parameters, min_len)` and already walks the log. The gate already
invokes it on the current call's parameters at `gate.py:807-816`. Cross-hop
changes the CONSUMER of that match, not the match.

Note on naming: the shared extractor is `extract_lineage_tokens`
(`context.py:236`), public, no leading underscore. The brief's
`_extract_lineage_tokens` does not exist under that name.

**What is new, enumerated so nothing hides:**

- A call to the matcher on the INPUT side at ingestion, which requires
  `notify_context_write` to receive the call's input arguments. That is a public
  API surface (`gate.py:2450`) documented for framework integrations to call, and
  both adapters must be changed to pass them.
- The transitive cycle-guarded walk (does not exist, see the correction).
- The reachability taint predicate, replacing the flat `authority == UNTRUSTED`
  test at three call sites.

**Spec line, recorded now: the denial must name the CHAIN, not only the proximate
parent.** In a three-hop chain the matcher at hop C matches against hop B's
content, so the cited `untrusted_provenance_id` is B. A cross-hop denial that
cites only B understates the finding: the claim of this family is that the value
traces to A. The E5 evidence machinery already exists (`gate.py:297-332`,
`audit.py:105-121` with its raw-content stripping), so the walk's output must be
surfaced through it as an ordered chain, and the AFTER probe must assert the
ORIGIN entry is named, not merely some tainted ancestor. A denial that names only
the proximate parent does NOT satisfy the must-catch column.

---

## 2. FROZEN MUST-CATCH column

Session shape: one authoritative writer (`user_message`, `alice`), one untrusted
writer (`web_content`, `fetch_url`) carrying `evil.com` / `mallory@evil.com`, and
one or more intermediate `tool_output` writers forming the chain. Lineage policy
under test: `param_lineage_enabled=True`, `param_lineage_action="deny"`,
`min_len=6`, evaluated under both `novel_lineage_enabled=True` and the shipped
`novel_lineage_enabled=False` default.

BEFORE cells are the shipped single-hop engine. The MEASURED cell is the one the
adapters already pin; every other BEFORE cell is PREDICTED and must be confirmed
by the cross-hop BEFORE probe.

```
row  | chain                                              | before                  | predicted after
-----+----------------------------------------------------+-------------------------+----------------------------------
P1   | A(untrusted) -> B(verbatim relay) -> C(sink)        | ALLOW (MEASURED)        | DENY:param_lineage, chain names A
P2   | A(untrusted) -> B(base64-encodes it) -> C(sink)     | PREDICTED ALLOW         | DENY:param_lineage, chain names A
P3   | A -> B -> C -> D(sink), depth 3                     | PREDICTED ALLOW         | DENY:param_lineage, chain names A
P4   | A -> B -> C -> D -> E(sink), depth 4                | PREDICTED ALLOW         | DENY:param_lineage, chain names A
P5   | A(untrusted) -> B(tool paraphrases) -> C(sink)      | PREDICTED ALLOW         | DENY:param_lineage, chain names A
```

### P1. Verbatim multi-hop

The untrusted value flows A to B to C unchanged. B's input contains A's value, so
the link A to B is established by a bare direction-(B) token match. C's parameter
contains the value, which under the reachability predicate is now reachable
through B's tainted-by-ancestry entry.

**Note on the existing boundary tests.** Both adapters pin this gap today
(`crewai-agentlock/tests/test_provenance.py:182`,
`mcp-agentlock/tests/test_provenance.py:290`), but neither constructs P1. Both
call the relay with `text="ignored"` (crewai `:203`, MCP `:194`), so the
untrusted text never enters the relay's INPUT at all. Those two tests instantiate
section 3's uncatchable case, not this one. **They are therefore predicted
UNCHANGED by this work**, and they must keep passing. A cross-hop build that
flips them has done something other than what this document predicts, and the
correct response is an audit of the measurement, not acceptance. P1 needs a new
test that actually routes the value through the relay's input.

### P2. Encoding-transformed multi-hop (THE PAYOFF)

**This is the prediction the family is worth building for, and it is named
explicitly as such.** The intermediate hop base64-, hex-, or URL-encodes the
value before passing it on. The link is still established, because the ingestion
match is the SAME `parameter_lineage_check` that families 1 and 2 hardened:
`_canonical_blob_suffix` (`context.py:251`) supplies family 1's canonical forms
on both sides, `_encoded_blob_suffix` (`context.py:345`) supplies family 2's
forward encodings into untrusted blobs, and `_encoded_scan_needles`
(`context.py:478`) supplies the direction-(A) raw substring scan.

A linker that calls this method inherits all of it at zero marginal cost. A hop
that defangs `evil.com` to `evil[.]com` links for the same reason family 1's
defang catch denies. A hop that base64-encodes it links for the same reason
family 2's forward-encode catch denies.

This is the concrete return on the families 1 and 2 investment, and it is the
reason cross-hop is sequenced after them rather than before. Falsifier: if an
encoded-at-the-intermediate-hop chain misses while its verbatim sibling (P1)
catches, the free-inheritance claim is falsified and linking needs its own
matcher, which would change the cost of this family substantially.

**Inherited limits, recorded so a miss reads correctly.** P2 inherits family 2's
boundaries exactly, per AM5.1's coverage-inheritance rule. A hop that produces a
COMPOSITE encoded form is predicted to MISS, because all composites are deferred
(AM3.5), and `_SCAN_KINDS = frozenset({"url", "email"})` (`context.py:408`)
excludes `str` from the direction-(A) scan (AM7.1). Those misses are INHERITED,
not cross-hop defects, and fixing them is family 2 roadmap work.

### P3, P4. Depth

The walk, once built, is depth-unbounded by construction. But depth is not the
binding constraint and this document will not claim it is: **a depth-N chain
requires N-1 independently successful link establishments**, each of which is a
separate match that can miss. Chain survival is the conjunction of its links, not
a property of the traversal.

So the honest prediction is: the WALK handles 3+ hops with no additional
mechanism, and P3/P4 catch if and only if every hop in them is individually
linkable. P3 and P4 are constructed with verbatim hops precisely to isolate the
traversal from the matching, so a P3 miss with P1 catching indicts the walk,
while a P3 miss alongside a P1 miss indicts the matching.

### P5. Tool-mediated semantic rewrite (a capability, not a boundary)

**This row is the correction to the brief's ceiling, and it moves in the
capability direction.** The brief pre-registers semantic paraphrase as UNCAUGHT.
That is too broad, and pre-registering a non-capability that the mechanism
actually delivers is as damaging to a pre-registration as claiming one it does
not: it would let a genuine catch read as a scope leak.

The reason: **the link is established from hop B's INPUT, not from its OUTPUT.**
If B is called with the untrusted text and returns a total paraphrase in which no
token survives, the link A to B is set at ingestion regardless, because the match
ran against B's input, upstream of the rewrite. B's output entry is then
tainted-by-ancestry in full, and C's use of the paraphrase denies against B's
content under the reachability predicate. The rewrite is irrelevant to a link
established upstream of it.

P5 is therefore PREDICTED CAUGHT, and it is the strongest single claim in this
document, because summarization and paraphrase hops are exactly what a realistic
laundering chain looks like. Falsifier: if P5 misses while P1 catches, the
ingestion match is being run against the wrong side (output rather than input),
which is a mechanism defect with a named diagnosis.

---

## 3. FROZEN MUST-NOT-CLAIM column (the boundary, as an explicit non-capability)

Pre-registered as PREDICTED UNCAUGHT so the eventual test MEASURES the boundary
rather than hiding it. These rows must NOT move. A catch here is investigated as
a measurement fault before it is accepted as a capability, the AM4.4 discipline.

```
row  | chain                                                    | predicted after
-----+----------------------------------------------------------+--------------------------
N1   | A(untrusted) -> [model paraphrases in context] -> C(sink)| UNCHANGED (ALLOW / unattributed)
N2   | A(untrusted) -> B(input carries no matchable form) -> C  | UNCHANGED (ALLOW / unattributed)
```

### N1. Model-mediated rewrite

The model reads the untrusted text out of its own context window and emits a
paraphrase directly into a later call. No intervening tool carries the value.
There is no tool input to match, therefore no link to establish, therefore
nothing for the walk to traverse.

This is not a coverage gap to close in a later cut. It is a boundary of
value-matching provenance itself. A gate observes tool boundaries; a
transformation that occurs entirely inside the model's reasoning between two tool
calls is not at a tool boundary and is not observable by any provenance mechanism
operating at that layer. Closing it would require either instrumenting the
model's intermediate reasoning (a different architecture) or content-classifying
the parameter against the untrusted set (the exact thing the core thesis rejects,
and the thing `PREDICTIONS_v16_family2.md` section 1 rejected reverse-decode
over).

**This is where the brief's hard ceiling actually falls.** Not at "the value was
rewritten," but at "no tool call's arguments ever contained a matchable form of
the value." P5 and N1 differ only in whether a tool was in the loop for the
rewrite, and that difference is the entire boundary.

### N2. No matchable form in any tool input

The general statement of which N1 is the common instance. If the value reaches
the sink without any tool call's arguments having contained it in a form the
matcher can see, there is no link at any hop.

Two sub-cases inherited rather than novel: a value below the `min_len=6`
distinctiveness floor, and a value the shared extractor does not tokenize (AM7.1
names localhost, db01, abcde, and purely alphabetic values with no structural
character). Both are family-1 tokenizer inheritances, not cross-hop failures, and
both are fixed in the extractor if they are fixed at all.

### Transport independence (stated for the eventual writeup)

N1 and N2 are TRANSPORT-INDEPENDENT. They hold identically on `crewai-agentlock`,
on `mcp-agentlock`, and on any future adapter, because the limitation is not in
what a given framework exposes. Both adapters see exactly the same thing at a
tool call: name, input arguments, output, session id, token id, and a statically
declared `context_source` (crewai `wrapper.py:96`, MCP `wrapper.py:87`). Neither
framework supplies a derivation signal, and no framework can supply one for a
transformation that never crossed its boundary. A future adapter that appears to
close N1 has either gained model-internal instrumentation or is content
classifying, and either is a different claim requiring its own pre-registration.

The limitations section of any writeup must state N1 in this register: a
permanent boundary of the approach, named and measured, not a known gap awaiting
a later cut. This is the F5 two-registers discipline from
`PREDICTIONS_v16_family1.md`.

---

## 4. FROZEN MUST-NOT-TRIP column (the false-link surface, the real risk)

**This is the risk that makes cross-hop qualitatively more dangerous than
families 1 and 2, and it deserves the most careful floor in this document.**

In families 1 and 2 a matching error produces one wrong verdict on one call. At
ingestion time a matching error produces a wrong LINK, and a wrong link is
persistent and amplifying: every descendant of the falsely-linked entry inherits
the taint for the remainder of the session. One bad match poisons a subtree, not
a call.

```
row  | case                                                   | predicted after
-----+--------------------------------------------------------+------------------
FL1  | benign chain, token coincidentally in untrusted entry   | NO link set
FL2  | chain through purely trusted tools only                 | NO untrusted ancestor
FL3  | long benign session, many tools, no untrusted content   | link count exactly correct
FL4  | hop input is authoritative (user's own value)            | NO untrusted parent
FL5  | hop input carries two distinct untrusted entries         | see structural note
FL6  | tool that echoes its own input; self-referential chains  | terminates, no cycle
```

### FL1. Coincidental collision at linking time

A legitimate value that coincidentally matches a token in an unrelated untrusted
entry gets falsely linked to it. This is the same collision surface families 1
and 2 addressed with floors, now relocated to ingestion where its consequences
compound.

**What keeps linking precise, pre-registered as the answer:** the existing floors
carry over unchanged, because the matcher carries over unchanged.

- The `min_len=6` distinctiveness floor (`schema.py:373`) gates which plaintext
  tokens are traceable at all.
- `_ENCODED_MIN_LEN = 8` (`context.py:318`) gates emitted encoded forms, the
  family-2 AM2.2 line, fixed and justified at 8 in AM6.2.
- The `_SCAN_KINDS = frozenset({"url", "email"})` curation (`context.py:408`)
  keeps the direction-(A) scan off the low-distinctiveness `str` net.

Prediction: these three floors are sufficient for linking precision at the same
level they deliver decision precision, because the operation is identical. The
falsifier is FL3's link count.

**Standing hazard, extended.** `min_len` was already load-bearing in two opposite
directions (family-1 E5) and gained a third surface in family 2 (AM2.2). Linking
is a FOURTH: lowering it now also increases false links, which amplify. `min_len`
must not be changed without re-measuring amount attribution, composite-aware
benign clearance, encoded-form entropy, AND link precision together.

### FL2. Trusted-only chains

A value flowing through purely trusted tools must NOT acquire an untrusted parent
because a token coincidentally matched. Predicted: no untrusted ancestor is
reachable from any entry in such a chain. This is the direct analogue of family
2's must-not-trip column and carries the same zero-delta requirement.

### FL3. Over-linking and taint saturation

**The most important row in this column.** If ingestion matching is too loose,
everything links to everything, the walk always finds an untrusted ancestor, and
the gate denies everything. This is the linking analogue of the novelty branch's
over-firing (family-1 F1/F4).

The terminal failure is specific and worth naming: total saturation collapses
cross-hop into the pre-existing session-taint gate. `lineage_summary` already
denies on `post_authoritative_taint` for any session that has seen untrusted
content. A cross-hop mechanism that taints every entry delivers exactly that
verdict with more machinery and worse attribution, and its per-value citations
become meaningless because everything cites the same origin. **Saturation would
not read as a failure in a pass/fail attack corpus.** Every attack row would
catch. It is only visible against a benign corpus and a direct link count, which
is why FL3 is measured by counting links, not by reading verdicts.

Predicted: on a benign multi-hop session with no untrusted content, the number of
parent links set is exactly the number of genuine input-to-prior-output
derivations, and zero entries are reachable to an untrusted ancestor.

### FL4. Authoritative-first at linking time (an open spec question, named)

`parameter_lineage_check` short-circuits on `tok in auth_blob` before scanning
any untrusted blob (`context.py:875-877`). At DECISION time that means "the
user's own value, clean, allow." At INGESTION time its meaning is not automatic:
does an authoritative match mean "no parent," or "an authoritative parent"?

Named, not solved. It is recorded because the two answers differ observably on
FL4 and because inheriting the short-circuit without deciding would be inheriting
a decision made for a different question. The AM5.2 positive control applies: the
legit-user-supplied-value row must be re-run as a positive control, and a flip
there means linking leaked into the authoritative side.

### FL5. Fan-in (a structural limitation, pre-registered)

A hop whose input carries values from two distinct untrusted entries has TWO real
parents. `parent_provenance_id: str | None` (`context.py:551`) is single-valued
and the matcher short-circuits on the first match (`context.py:877-880`), returning
one entry. So the recorded link is one of the true parents, chosen by the
`kind_rank` ordering (`context.py:833`), which family 1 made deterministic
precisely so citations do not vary across runs.

Predicted consequence: SOUND but INCOMPLETE attribution. Taint still propagates
(one true parent suffices to reach an untrusted ancestor), so no attack escapes
on fan-in alone. But the cited chain names one origin where two exist, so a
multi-origin incident is under-reported in the audit record. Pre-registered as a
known limitation of the single-valued field, not as a defect to be discovered
later. Widening the field to a list is a schema change with its own blast radius
and is out of scope here.

### FL6. Cycles and echo chains

The walk must terminate. Two distinct sources of non-termination: a genuine cycle
in the link graph, and an echo tool whose output contains its own input, which
produces long legitimate chains rather than cycles. The cycle guard the brief
assumed exists does not (see the correction) and must be built. Predicted: the
walk terminates on every corpus, and a self-echo chain produces a finite chain of
length equal to the number of echo hops.

---

## 5. SESSION PREREQUISITE: CONFIRMED, with one asymmetry to fix

The prerequisite is that the provenance log accumulates across calls within one
session and does not reset per call, so a parent from call 1 is visible at call 3.

**CONFIRMED by read, not assumed.** `ContextTracker._states` is a
`dict[str, ContextState]` held on the gate instance (`context.py:588`).
`record_write` appends to the state returned by `get_or_create`
(`context.py:674`). The only removal path is `ContextTracker.destroy(session_id)`
(`context.py:1118`), and grepping both adapter source trees for `destroy`,
`clear_session`, `reset`, and `_context_tracker` returns only contextvar
`reset_active_context` hits, never a tracker reset. Order is preserved by the
append-only list, which `lineage_summary` already depends on for its
`post_authoritative_taint` index arithmetic.

**One asymmetry, recorded as a prerequisite to fix before building.** The two
adapters address their provenance writes to the session id differently, and only
one of them enforces agreement with the gate.

- MCP resolves the write target the same way the gate does, through
  `_provenance_session_id` (`wrapper.py:236-252`), which re-resolves via
  `gate.get_session(ctx.user_id)` because `authorize` resolves with
  `_session_store.get_by_user(user_id)` (`gate.py:758`). Pinned by
  `test_provenance_lands_in_the_session_the_gate_resolves`.
- CrewAI passes `ctx.session_id` straight through (`wrapper.py:220`) and relies
  on the caller having supplied the gate-created session id. That agreement is a
  CALLER CONVENTION, not an enforced invariant.

This does not block cross-hop, and it is a latent single-hop issue too. But
cross-hop makes it sharper: a chain whose links land in a session the gate never
reads is a chain that silently does not exist, and the failure mode is a
vacuously passing test suite, which is the failure MCP's session mapping was
written to prevent. Fix the crewai side to resolve the same way before building,
or the depth rows cannot be trusted.

---

## 6. SUCCESS CRITERIA (numeric, falsifiable)

All figures are the frozen cross-hop probe (must-catch, must-not-claim,
must-not-trip) plus the full family-1 and family-2 corpora replayed on the
cross-hop engine.

### Attributed cross-hop catch count (must-catch, five rows)

Attributed = `DENY:param_lineage` whose surfaced chain NAMES THE ORIGIN entry,
per the section 1 spec line. A deny that names only the proximate parent does not
count.

- Before: **0/5** (P1 measured ALLOW; P2 through P5 predicted ALLOW, to be
  confirmed by the BEFORE probe).
- Predicted after, in BOTH the novel-on and novel-off configurations: **5/5**.
- P2 is the payoff row. A measured result of 4/5 that misses exactly P2 falsifies
  the free-inheritance claim and is the single most consequential possible
  falsification in this document, because it changes the cost of the family.
- A P3 or P4 miss with P1 catching indicts the walk. A P5 miss with P1 catching
  indicts the match side (input versus output).

### Boundary measurement (must-not-claim, two rows)

- Predicted after: **0/2 caught**. N1 and N2 stay exactly where the single-hop
  engine leaves them.
- This is a SUCCESS criterion, not a failure to tolerate. The boundary being
  measured and holding is what licenses stating it in the writeup as a permanent
  limit.
- A catch on N1 or N2 triggers an AUDIT OF THE MEASUREMENT (AM4.4 discipline): it
  is a structural impossibility given that no tool input carried the value, so it
  indicates a mis-seeded probe or a mechanism doing something other than
  input-matching, before it indicates a capability.

### Link precision (must-not-trip, the FL3 floor)

- On a benign multi-hop corpus with no untrusted content: parent links set must
  equal the true derivation count **exactly**, and entries reachable to an
  untrusted ancestor must be **0**.
- Measured by counting links directly, not by reading verdicts. A verdict-only
  measurement cannot see saturation (FL3).
- Any nonzero false-link count falsifies the FL1 floor-sufficiency prediction and
  opens the min_len fourth-surface question.

### No-regression floor (families 1 and 2 corpora)

- Every row of every frozen family-1 corpus (probes 1 through 4, and the probe-7
  and probe-8 configurations) and every row of the family-2 must-catch and
  must-not-trip columns must be **byte-identical** before and after.
- **This floor is the load-bearing one and it is at genuine risk**, because
  component 3 changes the taint predicate those corpora were measured against.
  Families 1 and 2 could hold a byte-equality floor cheaply, since forward-encode
  only added strings to untrusted blobs. Cross-hop widens WHICH ENTRIES are
  untrusted, which is a change of a different kind.
- Prediction: byte-identical, because on a single-hop corpus no entry has a parent
  link, so reachability degenerates to exactly the flat `authority == UNTRUSTED`
  test it replaces. A single family-1 or family-2 row changing verdict falsifies
  that degeneracy argument and means the predicate change is not conservative.
- Single-hop adapter suites must also pass unchanged, including both existing
  `test_two_hop_laundering_slips` tests, which per section 2 are section 3 cases
  and are predicted UNCHANGED.

---

## CONDITIONS

- Frozen baseline engine: the family-2 engine at this branch's tip, the one whose
  corpora are frozen in `PREDICTIONS_v16_family1.md` and
  `PREDICTIONS_v16_family2.md`.
- BEFORE tables to be produced by a scratch cross-hop probe calling only
  `parameter_lineage_check`, `novel_lineage_check`, `notify_context_write`, and
  `authorize()`, with no linking logic added to produce the BEFORE state. That
  probe has NOT been run at time of writing; every BEFORE cell except P1 is
  unconfirmed.
- Session shape: one authoritative writer (`user_message`, `alice`), one untrusted
  writer (`web_content`, `fetch_url`) carrying `evil.com` / `mallory@evil.com`,
  and one or more `tool_output` intermediate writers.
- Lineage policy under test: `param_lineage_enabled=True`,
  `param_lineage_action="deny"`, `min_len=6`, under both
  `novel_lineage_enabled=True` and the shipped `novel_lineage_enabled=False`
  default.
- Prerequisite before any depth row is trusted: the crewai session-id resolution
  asymmetry of section 5.
- After engine: the cross-hop linking mechanism on branch
  `v1.6-derivation-taint`. This document is the pre-registered prediction of
  record and is not to be edited once the cross-hop run is launched; any deviation
  is recorded in a dated amendment, as with families 1 and 2.
- Verification method: A/B replay diff. Cross-hop columns judged against their
  predicted AFTER cells; families 1 and 2 corpora judged for byte-equality; link
  precision judged by direct link count on a benign corpus.

---

## Reproduction of the cross-hop status

No probe of the mechanism has run. No cross-hop mechanism code exists. What has
run is a read-only scope probe over the shipped engine and the two working
single-hop adapters, and its findings are the MEASURED cells and the code
citations above. One of the four starting facts supplied to this document was
falsified by that probe and is corrected on the record at the top rather than
carried forward. The BEFORE states other than P1 are predictions, and the
cross-hop BEFORE probe is what turns them into measurements. This file is the
prediction of record.

---

# AMENDMENT 1 (2026-08-01): mechanism probe results, and the frozen build spec

Everything above this line is the original prediction of record and is unedited.
This amendment records what a read-only mechanism probe series MEASURED against
the shipped engine, and freezes the build spec that follows from it. All probe
code was scratch, outside the repo, and no mechanism code exists at time of
writing.

## AM1.0 CORRECTION TO THE COMMISSIONING CLAIMS

This section exists for the same reason the CORRECTION block at the top of the
original document exists, and is placed first for the same reason. The task that
commissioned this amendment supplied six findings to record. Four are
contradicted by the measurements, and one of those re-asserts the precise fact
the original document was written to correct. They are corrected here rather
than carried into the spec.

**C1. "The engine's existing BFS walks the chain, no engine walk work needed."**
FALSE, and this is the original document's own falsified starting fact returning
verbatim. `_collect_provenance_ids` does not exist; the correction at the top of
this file verifies its absence four ways and classifies the walk as component 2
of a three-component build. The probe wrote a cycle-guarded BFS in scratch to
evaluate reachability; that scratch BFS is not engine code and nothing about it
shipped. **The walk must still be built.**

**C2. "Short/common-token over-linking is cut by the inherited family-2 min_len
floors and kind curation, which transfer to linking unchanged."** FALSE in three
separate ways, measured:

  * `min_len` is family-1/v1.3 machinery (`schema.py:373`), not family 2.
  * The family-2 controls are `_SCAN_FLOORS` and `_SCAN_KINDS` (`context.py:407-408`).
    They govern only `_encoded_scan_needles`, the direction-(A) needle set.
    **100% of measured false links were direction-(B) whole-token blob matches**,
    which those controls do not govern. The family-2 controls cut none of the
    over-linking, because they never engaged on any false link.
  * The floors do not cut common tokens either. Every measured collision token
    passes `min_len=6`: `ticket-88213` (12), `po-2026-0042` (12), `confirmation`
    (12), `acknowledgement` (15), `security@corp.example.com` (25). Separately,
    `_plain_qualifies` (`context.py:152-159`) treats `.` as structural and the
    token strip set (`:180`) does not strip a trailing period, so sentence-final
    English words are emitted as traceable tokens: measured emissions include
    `report.`, `notice.`, `breakdown.`, `assigned.`, `resolved.`, `details.`.
    An ordinary 200-character benign tool output emitted 11 tokens, 7 of kind
    `str`.

  The floors DO transfer unchanged, and they DO correctly exclude short and
  undistinctive tokens (measured: `po-42`, `abcde`, `report`, `localhost`,
  `totals`, `priority` all emit nothing). The false claim is that this cuts the
  over-linking. It does not.

**C3. "The Reading B selection rule is the fix (measured)."** PARTIALLY FALSE.
Reading B was implemented and measured, and it is a real improvement that is not
sufficient. See AM3 for the numbers. Recording it as the fix would pre-register
a control the probe measured failing.

**C4. "Ceiling (P4/P5): semantic and model-mediated rewrite uncatchable,
pre-registered as non-capability."** FALSE, and it inverts the original
document. Section 2 predicts P5 CAUGHT and states at lines 316-337 that
pre-registering semantic paraphrase as a non-capability would be as damaging as
claiming a capability the mechanism lacks. P4 is a depth row, also predicted
CAUGHT. The ceiling is N1 and N2, model-mediated rewrite and no-matchable-form,
and it is unchanged. The probe MEASURED P5 and depth-4 caught (AM4). Moving P5
into the ceiling would discard the strongest measured result in the series.

**C5. Verdict letter.** The mechanism probe returned **(c)**, an over-linking
problem that must be solved before the build is viable, and identified a control
that moves it to (b). Recording (b) is defensible ONLY with that control named
and adopted. It is named and adopted in AM5. Recording (b) while attributing the
fix to the family-2 floors (C2) or to Reading B (C3) would be recording a
viability that no measurement supports.

**What survives unchanged.** The R4 self-linking finding and its
match-before-write fix are confirmed exactly as commissioned (AM2). The
three-component build classification at the top of this document survives. The
family-1 and family-2 floors transfer unchanged (they are simply not the control
that resolves the residual).

## AM1.1 VERDICT

**Cross-hop linking is VIABLE, verdict (b): sound, requiring precision controls,
all of which are now identified and specified.** The qualifier that makes this
(b) rather than (c) is that the link predicate is REPLACED, not tuned. Token
overlap does not survive as the linking condition. See AM5.

Corpora were hand-built and small. Every figure below is an existence proof of a
behavior, not a rate.

## AM2 TRAP 1: R4 SELF-LINKING. CONFIRMED, FIX CONFIRMED

**Measured.** Match-before-write produced **0 self-links across all 8 corpora**.
Write-before-match produced self-links wherever a tool's output contains its own
input: 3/3 on the echo chain, 1/1 on the P1 relay.

**The consequence is worse than a spurious edge.** On P1 the self-link REPLACED
the true parent and the catch disappeared: entries reachable to an untrusted
ancestor went from `['B(relay)']` to `none`. Write-before-match is silently
catch-destroying on any relay or echo tool.

**Ordering confirmed slottable.** `record_write` (`context.py:600`) takes
`parent_provenance_id` as a caller keyword (`:609`), constructs the dataclass
with it (`:669`), and appends at `:674`. `notify_context_write` (`gate.py:2450`)
is a pass-through, calling `record_write` at `:2491` and forwarding at `:2498`.
Nothing between the public entry point and the append reads the log. **A match
inserted anywhere before `context.py:674` sees prior entries only.**

FROZEN: the match runs inside `record_write` or `notify_context_write`, strictly
before the append. Not in an adapter that records first and links after.

## AM3 TRAP 2: THE OVER-LINKING RESIDUAL, AND WHY READING B IS NOT THE FIX

Two token-based linkers were simulated against the shipped matcher. Linker A
reuses `parameter_lineage_check` verbatim (UNTRUSTED-only haystack, which is what
that method scans, `context.py:795-799`). Linker B generalizes the haystack to
every prior entry, which a link over a DERIVED intermediate hop requires.

**Reading A (any untrusted token match wins), measured over-linking on
legitimate trusted-only chains:**

```
corpus (collision token)                      linker A      linker B
ticket workflow ('ticket-88213')              4/4 tainted   4/4 tainted
benign 6-call ('po-2026-0042')                4/4 tainted   0
benign 6-call, untrusted FIRST                4/4 tainted   0
10-call session ('confirmation')              5/9 tainted   1/9 tainted
incident chain ('security@corp.example.com')  3/4 tainted   3/4 tainted
expense chain (shared domain, distinct paths) 0             0
```

Linker B's zeroes are `kind_rank` luck, not a control: it escaped only where a
higher-ranked email or url token happened to point at the correct benign parent
before the ordering reached the colliding `str` token.

**The shared-email row is the important one.** `kind_rank` (`context.py:833`)
places `email` at 0 and `url` at 1, above every `str`. An email or bare-domain
collision is therefore selected in preference to every other token in the leaf,
and no kind outranks it, so the rank-luck escape structurally cannot occur.
Reading A is at its worst on exactly the shared-address case. A shared domain
with distinct paths did NOT collide, because `_canon_url` retains the path
(`docs.example.com/policy/travel` versus `docs.example.com/shared/invoice-9912`);
the collision requires a bare-domain mention or a shared path. An address is
atomic and has no such escape.

**Link precision against declared ground truth, 10-call benign session, linker
B: 6 links set for 6 true derivations, of which 2 named the correct parent and 4
did not.** The link COUNT matched exactly, which is the FL3 success criterion as
originally pre-registered. **FL3 must therefore be re-specified as parent
identity, not link count**, or it will certify a graph that is two thirds wrong,
the same way a verdict-only measurement cannot see saturation.

**Reading B, implemented and measured.** Definition used, which is the only
implementable reading at this layer: a token is trust-explained iff some prior
entry with `authority != UNTRUSTED` and non-empty `content` contains it, under
the same blob construction and substring test the untrusted side uses. Iterate
candidate tokens in `kind_rank` order; prefer any trust-explained entry as
parent; fall to untrusted only when no non-untrusted entry contains the token.

```
shared email (MID-chain collision)     3/4 tainted -> 0 tainted     FIXED
P5 paraphrase (must-catch)             still caught                  HELD
ticket (HEAD-of-chain collision)       4/4 tainted -> 4/4 tainted    NOT FIXED
```

**Reading B fixes mid-chain collisions and does not fix head-of-chain
collisions, and one poisoned head link taints the whole chain through the walk.**
The head case exactly:

```
T1  params {"id": "ticket-88213"}
    prior log = [ U(auth) "please work the open ticket", A(untrusted) ]
    -> T1 parent=A(untrusted)   tok='ticket-88213'
    T2, T3, N(sink) then inherit.  4/4 tainted.
```

At T1 no trusted entry contains the token, because T1 is the first entry to carry
it and its true origin is the ticket system, OUTSIDE the provenance log.

**This limit is structural and cannot be tuned away.** It follows from the
transport-independence fact already pre-registered at section 3 of this document:
both adapters see only tool name, input arguments, output, session id, token id,
and a static `context_source`, and no framework supplies a derivation signal.
There is no way to record "this identifier came from the tool's own backend", so
"a trusted origin ACCOUNTS FOR the token" is undecidable for any value entering
from outside the log, which is the normal case for identifiers tools return.

**Recorded as a definitional finding, because the commissioning brief asked for
the distinction: at this layer there is no implementable difference between a
trusted entry that ACCOUNTS FOR a token and one that merely CONTAINS it.** The
brief's requested definition does not exist and could not be written. That is the
finding, not an omission.

**Not A2', confirmed.** A2' (`PREDICTIONS_v16_family1.md:994-997`,
`context.py:1091-1097`) pools authoritative and untrusted into one set,
`accounted = auth_tokens | untrusted_tokens`, because novelty does not care which
side accounted a token. Untrusted membership ACCOUNTS a token under A2'. It is a
novelty predicate over a token, not an attribution over an edge, and applying it
at link time would decline to link on exactly the tokens that carry taint. Once
unpooled, nothing of A2' remains but `extract_lineage_tokens`, which is the
surface generating the false links rather than constraining them. Additionally
`_token_accounted` is a closure inside `novel_lineage_check` (`context.py:1093`)
and is not callable from a linker without extraction.

## AM4 TRAP 3: THE PAYOFF ROWS DO NOT ISOLATE CROSS-HOP AS WRITTEN

**Measured on the shipped single-hop engine, no linking:**

```
P1 sink send_payment  -> MATCH, cites fetch_url, tok 'mallory@evil.com', direction (B)
P2 sink post_webhook  -> MATCH, cites fetch_url, needle 'bwfsbg9yeubldmlslmnvb',
                                match_direction='raw_substring_scan'
P5 sink send_email    -> None (no_match)
depth-4 sink          -> None (no_match)
```

P1's and P2's BEFORE cells in section 2 are corrected: both measure **DENY**, not
ALLOW, whenever the sink's own parameters carry the untrusted value or an encoded
form of it. P1's original `MEASURED ALLOW` came from the two adapter boundary
tests, which call the relay with `text="ignored"` so the value never enters the
relay's input; section 2 already notes those are section-3 cases. P2 is caught by
family 2's direction-(A) phase interiors at decision time.

**Consequence for the payoff argument.** The rows that genuinely isolate
cross-hop are those where the sink carries NO matchable form of the untrusted
value, only the intermediate hop's content. Those are P5 and the depth rows, and
both measure `no_match` on the shipped engine. **P5 and P3/P4 are the real
must-catch set. P1 and P2 as constructed are family-1 and family-2 rows.**

The free-inheritance claim itself holds mechanically: the encoded hop links, in
both directions, under both simulated linkers. But note for the writeup that
under the frozen control (AM5) the encoded link does not come from family 2 at
all: C links to B because B's output IS the base64 blob and C's input carries it
verbatim. Family 2 remains load-bearing for the single-hop DECISION and is not
load-bearing for the LINK.

## AM5 THE FROZEN SELECTION RULE (the one new piece)

The residual in AM3 is not a floor set too low. `ticket-88213` and
`po-2026-0042` are 12 characters, correctly extracted, above every floor, and
genuinely present in both a trusted and an untrusted entry. **Token overlap is
not derivation evidence when the haystack is ordinary prose**, because benign
tool outputs share vocabulary and identifiers with each other and with attacker
text by default. No token-side control separated the false links from the real
catches: curating to url/email kinds took the ticket collision from 4/4 to 0 and
simultaneously took P5 and depth-4 to `parent=None`, because their carrying token
was `acknowledgement`.

FROZEN: the link predicate is REPLACED by whole-content carriage, in two tiers.

**Tier 1, candidacy (containment).** At ingestion, before the append at
`context.py:674`, with `leaves = [v.lower() for _p, v in _iter_param_leaves(params)]`:
a prior entry `e` is a CANDIDATE PARENT iff `c = (e.content or "").strip().lower()`
satisfies `len(c) >= CONTAIN_MIN` and `c` is a substring of at least one leaf.

**Tier 2, selection.** Let `C` be the candidate set. Partition by whether a
candidate is UNTRUSTED or has an untrusted ancestor through already-set links
(computable at ingestion, since prior parents are resolved).

  1. If any candidate is taint-reachable, select from that subset.
  2. Otherwise select from the full candidate set.
  3. Within the selected subset: most recent by log index, then longest
     `content`, then lexically by `provenance_id`.
  4. If `C` is empty, `parent_provenance_id = None`.

**Binding side conditions.** Reverse-order iteration is required, not cosmetic:
forward order attaches to the oldest containing ancestor and flattens the chain.
No auth short-circuit at ingestion: inheriting `parameter_lineage_check`'s
`tok in auth_blob` skip (`context.py:875-877`) was measured deleting true edges
(with the user naming the ticket id, T1 and T2 got no parent at all and the real
T2 -> T1 derivation was suppressed). This answers the FL4 open question in
section 4: containment does not need the short-circuit, because coincidental
overlap no longer sets a link.

**Under this rule the AM3 conflict case dissolves.** A token present in both a
trusted and an untrusted entry sets NO link from either. The honest answer to
"did this value derive from the trusted or the untrusted origin" is that the
token does not say, and a parent link is a permanent claim of fact amplified over
every descendant. The rule declines to assert an edge rather than guessing one.

**Measured, same corpora:**

```
MUST-CATCH   P1 verbatim         B->A linked; C(sink) parent=None (extraction hop,
                                 already denied single-hop, see AM4)
             P2 base64 hop       C->B->A, all correct
             P5 paraphrase       C->B->A, all correct
             depth-4             D->B3->B2->B1->A, all four correct
MUST-NOT-TRIP ticket head-of-chain  3 links, all correct, 0 tainted
             shared email           3 links, all correct, 0 tainted
             shared domain          3 links, all correct, 0 tainted
             benign 6-call          4 links, all correct, 0 tainted
             benign 6-call + untrusted page  4 links, all correct, 0 tainted
             echo chain             terminates, 0 tainted
```

Zero false links on every must-not-trip corpus, correct parents throughout, and
the encoded hop still crosses.

**Reuse: none.** Containment uses `_iter_param_leaves` (`context.py:494`) and the
`ContextProvenance.content` field (`context.py:555`). It does NOT use
`extract_lineage_tokens`, `_canonical_blob_suffix`, `_encoded_blob_suffix`,
`_encoded_scan_needles`, `_SCAN_FLOORS`, `_SCAN_KINDS`, `_ENCODED_MIN_LEN`,
`min_len`, or `kind_rank`. It is a fourth comparison orientation: prior content
as needle, param leaf as haystack, no tokenization. This is genuinely new code.

## AM6 ERROR DIRECTION, pre-registered as a security decision

**The rule errs toward MISSED links, which is the direction in which an attack
slips.** Stated plainly rather than argued away. Measured and structural misses:
extraction hops (P1's sink, `parent=None`), outputs below `CONTAIN_MIN`, and any
re-serialization, whitespace collapse, truncation, or reformatting that breaks
the substring.

The justification is not that missing is preferable in the abstract. It is that
containment is not deployed alone: the shipped single-hop check still runs at
decision time and covers precisely the extraction case (AM4 measures P1 and P2
denying there). Token matching catches chains where a matchable form SURVIVES to
the sink; containment catches chains where the value is TRANSFORMED beyond
matching but the whole payload is relayed. The composite covers both.

**The choice being made:** prefer under-linking in the linker and recover through
the decision-time check that already ships, rather than prefer over-linking and
take the amplifying failure. A false link is not one wrong verdict. It is
persistent, inherited by every descendant for the remainder of the session, and
at saturation collapses cross-hop into the pre-existing `post_authoritative_taint`
gate while producing citations that all name the same origin, which is this
document's FL3 terminal failure and is invisible to a pass/fail attack corpus.

**Where fail-closed DOES fire, and why the reversal is consistent.** Tier 2 step
1 prefers the taint-reachable candidate. That is safe for a reason that does not
hold at token level: **every carriage candidate is a true parent**, so preferring
the tainted one adds no false edge, it only chooses which true edge the
single-valued `parent_provenance_id` (`context.py:551`) records. This is FL5's
pre-registered incompleteness resolved fail-closed. At token level, candidacy
itself is uncertain, so a fail-closed preference manufactures edges. The
principle: **fail-closed selection is correct when candidacy is certain and wrong
when candidacy is what is in doubt.**

**NEW MUST-NOT-CLAIM ROW, pre-registered as uncaught.** A chain whose
intermediate hop BOTH transforms the text (breaking containment) AND drops every
matchable token (breaking single-hop). Concretely, transform-then-extract: B
paraphrases the untrusted page, then C forwards one extracted sentence of B's
paraphrase. Neither predicate fires. This is NOT N1: a tool was in the loop for
both steps, so it does not fall inside the permanent boundary of section 3. It is
a genuine coverage gap of this control and is recorded here as row N3.

## AM7 THE COMPLETE FROZEN BUILD SPEC

1. **Match-before-write ordering.** Inside `record_write` or
   `notify_context_write`, strictly before `context.py:674`. Resolves R4.
2. **Input arguments at ingestion.** `notify_context_write` (`gate.py:2450`) has
   no parameter for the call's input arguments and neither adapter passes any.
   New public API surface plus changes to both adapters.
3. **The containment link predicate**, tier 1 and tier 2 as frozen in AM5,
   including reverse order, no auth short-circuit, and `CONTAIN_MIN`.
4. **The transitive cycle-guarded walk. MUST BE BUILT.** It does not exist. See
   C1 and the correction at the top of this document.
5. **The reachability taint predicate**, replacing the flat
   `authority == UNTRUSTED` test at three call sites in `context.py`. Unchanged
   from component 3 of the original classification, and still the component with
   blast radius.
6. **Families 1 and 2 unchanged.** Their floors and curation transfer unchanged
   and remain load-bearing for the single-hop DECISION. They are not the control
   that resolves the linking residual, and no family-1 or family-2 code is
   modified.

Payoff: encoded multi-hop links, measured (AM4, AM5), with the attribution
correction that the link comes from carriage rather than from family 2.
Ceiling: N1 and N2, unchanged, plus the new N3 of AM6. **P4 and P5 are NOT the
ceiling; they are measured must-catch rows (AM4, AM5).**

## AM8 OPEN, TO BE DECIDED BEFORE THE BUILD, NOT DURING IT

1. **The mirrored-content ambiguity.** Two prior entries with identical content,
   one trusted and one untrusted, both carried into a later input. Nothing
   distinguishes which the value derived from. Tier 2 step 1 resolves it
   fail-closed. Consequence to accept or reject explicitly: **an attacker who
   mirrors legitimate content into an untrusted entry can induce taint on a chain
   that genuinely derived from the trusted copy.** Cheap to trigger. The
   alternative, declining to link when candidates are content-identical across
   authorities, has the opposite failure mode.
2. **Tier 2 is unmeasured.** No corpus produced a multi-candidate ingestion. The
   tie-break is reasoned, not measured. Needs its own rows, specifically the
   merge-tool shape.
3. **`CONTAIN_MIN`.** Run at 24. Chosen, not calibrated. Needs the treatment
   `_ENCODED_MIN_LEN = 8` received at `context.py:300-317`. It is separate from
   `min_len` and does not extend that standing hazard.
4. **Normalization before comparison.** Raw, whitespace-collapsed, or unicode-
   normalized? Decides whether a JSON re-serialization keeps or loses a link.
   Unmeasured; the probe compared `.strip().lower()` only.
5. **Nested-content candidacy.** In an append-style chain where a later entry's
   content contains an earlier one's, both are candidates. Benign for taint,
   both being true ancestors, but it determines the cited proximate parent, and
   citation stability was a family-1 requirement. Unmeasured.
6. **FL3 re-specification.** Parent identity, not link count. See AM3.

## AM9 STATUS AT TIME OF WRITING

No mechanism code exists. Nothing in the engine or either adapter was modified by
this probe series; all simulation was scratch, outside the repo. The section 5
prerequisite is MET: the crewai session-id asymmetry is fixed, `_provenance_session_id`
at `crewai-agentlock/src/.../wrapper.py:38` used at `:244`, commit `1b69b6d`,
resolving the same way MCP does. The next step is the build against the frozen
spec in AM7, with the AM8 decisions made first.

---

# AMENDMENT 2 (2026-08-03): the AM8 decisions, resolved

Everything above this line is the prediction of record plus AMENDMENT 1, both
unedited. This amendment resolves the six AM8 items. It is written from a
read-only verification pass over this document, `agentlock/context.py`,
`agentlock/gate.py`, the frozen family-2 guard tests, and both adapters. No
mechanism code exists at time of writing and nothing in the engine or either
adapter was modified.

The resolution below is NOT the split the commissioning proposal supplied
("decide 1 and 4 now, defer 2, 3, 5, 6"). Two items move. Decision 6 cannot be
deferred, because it changes the acceptance criterion rather than the mechanism.
Decision 1 cannot be ratified, because the case that defines it falsifies the
premise the existing rule is justified on. Both corrections are recorded in the
same register as AM1.0: the split is corrected here rather than carried into the
build.

## AM10 DECIDED BEFORE THE BUILD

### AM10.1 DECISION 6 (FL3 success criterion). DECIDED. Must land before build.

**Re-specified: the acceptance criterion is PARENT IDENTITY, not link count.**

The section 6 link-precision criterion (`:596-598`) requires that "parent links
set must equal the true derivation count exactly". AM3 measured a graph that
passes it and is two thirds wrong: on the 10-call benign session, linker B set
**6 links for 6 true derivations, of which 2 named the correct parent and 4 did
not** (`:810-813`). A criterion that certifies that graph is not a criterion. It
fails for the same reason a verdict-only measurement cannot see saturation: it
counts the right number of the wrong thing.

**This is not mechanism work and it is not a constant. It is the gate the build
is judged against**, and it carries pre-build corpus work that does not exist
yet: **every benign corpus row needs per-entry DECLARED GROUND-TRUTH PARENTS**.
AM3's 2-of-6 figure was obtainable only because ground truth was declared for
that one hand-built session. No frozen corpus carries it. Measuring parent
identity is impossible until it does.

Recorded plainly: **changing a success criterion after the build launches is the
exact drift the CORRECTION block at the top of this document and AM1.0 both
exist to prevent.** Deferring this item to "spec cleanup during the build" would
mean launching against a gate already measured to pass a wrong graph, then
re-specifying the gate once results are in hand. That is the shape of the
failure, independent of intent.

### AM10.2 DECISION 4 (normalization). CEILING DECIDED, level deferred.

FROZEN: **one symmetric pure normalization helper, applied identically to the
candidate content and to the parameter leaf, no decode primitives, no parsing.**

**Safe core, adopted for the first cut:** strip, case fold, whitespace-run
collapse. Whitespace collapse is admitted because it does not alter token
content, so it closes reformatting without widening what can collide.

**HARD CEILING, code-enforced, not a preference.** Percent-decoding and
hex-decoding are structurally forbidden:
`tests/test_v16_family2_base64composite.py:360-370` and
`tests/test_v16_family2_encoding.py:282` grep the whole of `context.py` for
`unquote` and `fromhex` (among other decode primitives) and fail if any is
present. A URL-normalizing or hex-normalizing containment implemented in
`context.py` breaks a frozen family-2 guard. This is a shipped constraint on the
normalization choice, discovered by reading the tests, and it bounds the option
space before any measurement is run.

**JSON canonicalization is OUT.** It requires deciding that an opaque content
string is JSON, which is content-type inference, which is content classification.
That is the thing the core thesis rejects and the thing
`PREDICTIONS_v16_family2.md` section 1 rejected reverse-decode over. It also adds
a parse surface on attacker-controlled content at ingestion.

**NFKC is guard-permitted but DEFERRED to a false-link measurement**, not adopted.
It is the one candidate normalization that is coupled to decision 1: see AM12.2.

**Re-serialization evasion is recorded as a KNOWN MISS, not as a new open risk.**
AM6 (`:974-976`) already froze "any re-serialization, whitespace collapse,
truncation, or reformatting that breaks the substring" as a structural miss in
the chosen error direction. The consequence is bounded and should be stated at
its true width: JSON key reorder and whitespace change break CONTAINMENT while
leaving the lineage tokens intact, so the decision-time single-hop check still
denies at the sink. What is lost is the link and the chain citation, not the
denial. A full escape needs re-serialization PLUS token loss, which is the
already-pre-registered N3 of AM6.

### AM10.3 DECISION 1 (mirrored content). RE-SPECIFIED AND PROVISIONAL.

**Tier 2 step 1 is NOT ratified for this cell.**

AM6 licenses step 1 on one premise: "every carriage candidate is a true parent,
so preferring the tainted one adds no false edge" (`:995-1000`). In the mirrored
case, two prior entries with identical content, **at most one is the true
parent**. The case falsifies the premise the rule is justified on. AM6's own
stated principle resolves it in the opposite direction: "fail-closed selection is
correct when candidacy is certain and wrong when candidacy is what is in doubt",
and which of two identical-content candidates the value derived from is precisely
what is in doubt. AM5 (`:936-941`) already applied that principle at token level
and DECLINED to assert an edge. Ratifying fail-closed here would be recording a
control on a premise the case itself defeats, which is the C3 error of AM1.0 in a
new place.

FROZEN, in two parts:

1. **General multi-candidate case (candidates differ in content): Tier 2 step 1
   STANDS.** AM6's premise holds there, every candidate genuinely carries, and
   preferring the taint-reachable one only chooses which true edge the
   single-valued `parent_provenance_id` (`context.py:551`) records.
2. **Mirrored cell (content-identical candidates that DISAGREE on
   taint-reachability): DECLINE to link.** No parent is set from either.

**Correction to this document's own alternative wording.** AM8 item 1 states the
alternative as "declining to link when candidates are content-identical across
authorities". As written that is wrong and would break must-catch rows: a
verbatim relay produces an UNTRUSTED entry and a DERIVED entry with IDENTICAL
content, which is content-identical across authorities, and both are
taint-reachable, so the chain must still link (by recency, to the proximate
relay). The correct scope is **disagreement on TAINT-REACHABILITY, not on
authority**. Under that scope the relay case is untouched and only the genuinely
ambiguous cell declines.

**What declining costs, measured against the code.** It costs attribution, not
denial. `parameter_lineage_check` scans every UNTRUSTED entry with content
independently of any link (`context.py:795-799`), and the mirror's tokens are
identical to its trusted twin's, so a matchable form reaching the sink still
denies at decision time. This is AM6's composite argument applied to this cell,
and it is why "decline" is under-linking in the direction AM6 already froze,
rather than a laundering bypass.

**Two things the fail-closed reading understates, recorded so the trade is not
mis-stated in a writeup.** First, the induced-taint failure is not only
availability: it writes a FALSE DERIVATION into the audit record, asserting the
value came from the untrusted mirror when it came from the trusted copy. Second,
that falseness is NOT visible, because the two contents are identical by
construction, so the citation reads as correct to an operator. AM3's definitional
finding (`:850-854`) states why no downstream check recovers it: at this layer
there is no implementable difference between a trusted entry that ACCOUNTS FOR
content and one that merely CONTAINS it. The magnitude is measured: one poisoned
head link took the chain to **4/4 tainted** (AM3 `:832-837`).

**One interaction with the shipped engine, recorded because it decides where the
induced-taint failure bites.** AM5 removes the auth short-circuit at ingestion
(`:930-935`) while `context.py:875` keeps it per-token at decision time. So
descendants of an induced link that carry the value VERBATIM still clear at
decision time, while descendants whose content was TRANSFORMED do not. The
mirrored failure therefore concentrates on transformed chains, which are exactly
the chains cross-hop is being built to catch.

**Status: PROVISIONAL.** Tier 2 has zero measurements (AM8 item 2). This cell is
resolved by reasoning and by the falsified premise, and it is finalized by the
merge-tool corpus of AM11.1. Marked provisional so that a measurement contradicting
it reads as a measurement, not as a re-litigation.

### AM10.4 DECISION 5 (nested-content candidacy). CLOSED.

**AM5 step 3 already decides it: most recent by log index.** In an append-style
chain the containing entry is always the later one, so recency selects the
correct proximate parent, deterministically, and family 1's citation-stability
requirement holds without further specification.

One interaction, recorded rather than left implicit: **step 1 runs before step 3**,
so nested candidates that disagree on taint-reachability get the taint preference
and may cite a non-proximate ancestor. Taint remains correct (the ancestor is a
true ancestor); proximate attribution degrades. Under AM10.3 the content-identical
sub-case of that disagreement declines instead.

Item 5 is no longer carried as open, and it needs no measurement.

## AM11 DEFERRED TO BUILD-TIME MEASUREMENT, each with its condition

### AM11.1 DECISION 2 (Tier 2 unmeasured). Deferred. NOT independent of decision 1.

The merge-tool corpus is the right shape and building it during the build is
fine. **But 1 and 2 are ONE question, not two.** Decision 1 IS Tier 2 step 1, and
the merge-tool corpus that measures item 2 is the evidence that finalizes item 1.
The original split, which ratified 1 by reasoning while conceding 2 is unmeasured,
ratified the exact rule it simultaneously recorded as having no evidence.

Deferring 2 is coherent here only because 1 is marked PROVISIONAL in AM10.3. The
corpus must produce genuine multi-candidate ingestions, including the mirrored
cell (content-identical candidates disagreeing on taint-reachability) and the
merge-tool shape AM8 named.

### AM11.2 DECISION 3 (`CONTAIN_MIN` = 24). Number deferred, two conditions.

**(a) Recalibration invalidates the measured zeros.** Every must-not-trip zero in
AM5 (`:951-957`), 0 false links across six corpora, was measured AT 24. A change
to `CONTAIN_MIN` requires **RE-RUNNING ALL SIX corpora**, not adding rows to
them. The zeros are conditional results, not standing ones.

**(b) The `_ENCODED_MIN_LEN` derivation does not transfer.** That justification
(`context.py:300-317`) is a bits-per-character argument over a folded 36 to 38
symbol alphabet, roughly 5.25 bits per character. English prose carries on the
order of ten times less entropy per character, so an analogous derivation for
whole-content prose carriage lands nowhere near 24. "Calibrate it the way
`_ENCODED_MIN_LEN` was calibrated" names the right discipline and the wrong
arithmetic; the derivation must be redone for the alphabet actually being
compared.

**Pre-registered falsifier, because `CONTAIN_MIN` is the ONLY Tier 1 precision
control.** If calibration finds a false-candidacy class that no threshold
separates, standard error strings, boilerplate, legal footers, anything that
exceeds any length one would pick and appears verbatim across unrelated outputs,
then that is a **SHAPE finding, not a constant**: length is the wrong predicate
for prose distinctiveness and the candidacy test needs a different control. A
larger number would not be the fix and recording one would hide the finding.

## AM12 TWO COUPLINGS, recorded because the original split treated them as independent

### AM12.1 Decisions 1 and 2 are one question.

See AM11.1. Decision 1 is Tier 2 step 1; decision 2 is the measurement of Tier 2.
They cannot be resolved on different schedules except by marking 1 provisional,
which AM10.3 does.

### AM12.2 Decisions 1 and 4 are coupled through normalization aggressiveness.

**Normalization directly controls how often decision 1's ambiguous cell occurs.**
The more aggressive the normalization, the more distinct contents collapse to
identical normal forms, and the mirrored cell fires on identity of the NORMALIZED
content, not of the raw bytes. NFKC folds width variants, ligatures, and
compatibility forms, so adopting it converts the mirrored case from exotic to
routine, and it does so silently, since nothing in the link record shows which
normalization step produced the collision.

This is why AM10.2 defers NFKC to a false-link measurement rather than adopting
it with the safe core. The measurement is not only "does NFKC add false links";
it is also "how many additional content-identical candidate pairs does NFKC
create", which is decision 1's frequency.

## AM13 CORRECTED PRE-BUILD CHECKLIST

1. **Decision 6, fully** (AM10.1), including the per-entry ground-truth parent
   annotations added to every benign corpus.
2. **Decision 4, ceiling** (AM10.2): symmetric pure helper, no decode primitives,
   no parsing, safe core adopted, NFKC and JSON canonicalization out of the first
   cut.
3. **Decision 1, re-specified and provisional** (AM10.3): step 1 stands for the
   general case, declines for the mirrored cell scoped on taint-reachability
   disagreement, finalized by AM11.1's corpus.
4. **Decision 5, closed** (AM10.4). No further work.

Deferred with conditions attached: decision 2 (AM11.1), decision 3 (AM11.2),
decision 4's level (AM10.2, AM12.2).

**FIRST BUILD TASK: add per-entry declared ground-truth parents to the benign
corpora.** It is decision 6's prerequisite and it is first because the build
cannot be JUDGED without it. Every other build task in AM7 produces a graph whose
correctness is unmeasurable until the ground truth exists, and the criterion that
would pass in its absence is the link count AM3 already measured certifying a
two-thirds-wrong graph.

## AM14 STATUS AT TIME OF WRITING

No mechanism code exists. Nothing in the engine or either adapter was modified by
this verification pass. One build-spec fact confirmed along the way and recorded
because AM7 does not state it: both adapters ALREADY populate untruncated output
content on their provenance writes (`crewai-agentlock/src/crewai_agentlock/wrapper.py:85`,
`content=str(output)`; `mcp-agentlock/src/mcp_agentlock/wrapper.py:280`,
`content=text`), so Tier 1's needle side needs no adapter change. AM7 item 2's new
public API surface is the INPUT side only.

---

# AMENDMENT 3 (2026-08-11): provisional decision 1, RESOLVED by measurement

Everything above this line is the prediction of record plus AMENDMENT 1 and
AMENDMENT 2, all unedited. This amendment records that decision 1, frozen
PROVISIONAL in AM10.3, is now resolved by measurement rather than by reasoning.
It is written after the increment 2 build (commit `38a4bb6`), which was
pre-registered in `docs/PREDICTIONS_crosshop_increment2.md` (frozen at `26ef567`)
and measured against that freeze.

Nothing above is edited. AM10.3 stays exactly as written, including its
PROVISIONAL marking, because it was correct at the time it was written and the
record of what was reasoned before the evidence existed is the point of freezing
it. This amendment supersedes the marking; it does not revise the text.

## AM15 THE RESOLUTION

**Decision 1, the mirrored-content tie-break, is RESOLVED.** All three parts
below are load-bearing and are recorded in full, because a reimplementation that
matches two of them and not the third does not reproduce the measured behavior.

### AM15.1 Trigger: a condition on the candidate-set CONFIGURATION

The decline fires when the Tier 1 candidate set contains content-identical
candidates (identical normalized content) that DISAGREE on taint-reachability.
The trigger is a property of the candidate set, not of the selection outcome:
it is enough that such a pair EXISTS among the candidates.

**Textual basis, recorded because the alternative reading would have been
plausible and unfalsifiable.** AM10.3 part 2 states the trigger as a property of
the candidates themselves ("content-identical candidates that DISAGREE on
taint-reachability"). Nothing in the frozen text, in part 2 or anywhere else in
AM10.3, refers to what WOULD BE SELECTED. The outcome-dependent reading, under
which a pair declines only when it would decide the selection, requires importing
a run-selection-first-then-check step that appears nowhere in the frozen text, so
it has no textual basis. The existence reading is what increment 2 implemented
and shipped.

The committed corpus cannot distinguish the two readings: no session produces a
candidate set where they differ. The resolution rests on the frozen text, and
that is recorded here rather than left implicit, so a later measurement that
distinguishes them reads as new evidence against a stated basis rather than as a
re-litigation.

### AM15.2 Reachability: the transitive definition, shared

Taint-reachability is: the candidate's own authority is UNTRUSTED, OR it chains
to an untrusted ancestor through recorded `parent_provenance_id` links. The walk
is cycle-guarded.

Two properties are part of the resolution:

- It is computed over the links the MECHANISM RECORDED earlier in the same
  session, never over declared ground-truth parentage. A linker that read the
  declarations it is scored against would be grading its own exam.
- It is ONE definition, shared identically by the decline and by Tier 2 step 1.
  Not two definitions that happen to agree.

### AM15.3 Ordering: decline over the FULL candidate set, BEFORE step 1

The decline is evaluated over the full Tier 1 candidate set, strictly before
step 1's taint subsetting. If it fires, `parent_provenance_id = None` is recorded
and selection stops. Step 1 and steps 3 and 4 run only when no decline fires.

**This is part of the resolution and not an implementation detail.** If step 1
subsets first, the mirrored cell's taint-reachable subset holds only the
untrusted member of the pair, the content-identical pair no longer coexists in
the working set, no disagreement is visible, the decline never fires, and the
mirrored cell wrongly links to the untrusted mirror. A reimplementation matching
AM15.1 and AM15.2 exactly, but ordering the decline after subsetting, breaks the
measured behavior on the one cell decision 1 is about.

## AM16 THE EVIDENCE

AM11.1 states what finalizing decision 1 required:

> **But 1 and 2 are ONE question, not two.** Decision 1 IS Tier 2 step 1, and
> the merge-tool corpus that measures item 2 is the evidence that finalizes item 1.
> The original split, which ratified 1 by reasoning while conceding 2 is unmeasured,
> ratified the exact rule it simultaneously recorded as having no evidence.
>
> Deferring 2 is coherent here only because 1 is marked PROVISIONAL in AM10.3. The
> corpus must produce genuine multi-candidate ingestions, including the mirrored
> cell (content-identical candidates disagreeing on taint-reachability) and the
> merge-tool shape AM8 named.

That corpus exists, is committed, and is measured. **Both directions are
measured, which is what makes this a resolution rather than a confirmation.**

- **The FIRE case.** `mirrored cell :: B(mirror-consumer)` declines: the
  mechanism records `None`, where the declared acceptable recording is `{None}`.
  The two candidates are content-identical at normalized length 125 and disagree
  on taint-reachability.
- **The MUST-NOT-FIRE case.** `relay control :: C(consumer)` does NOT decline:
  the mechanism records `B(relay)`, where the declared acceptable recording is
  `{B(relay)}`. Its two candidates are also content-identical, at normalized
  length 128, and they AGREE on taint-reachability under the transitive walk,
  because the relay reaches the untrusted entry through its recorded link.

A rule measured only on the fire case would be indistinguishable from one that
declines on every content-identical pair, which is precisely the alternative
AM10.3's own scope correction rejected as breaking must-catch rows.

The genuine multi-candidate ingestions AM11.1 required are also measured:
`merge-tool multi-candidate :: M(merged)` and
`merge-tool, taint preference against recency :: M(merged)` both record `W(web)`,
each against a declared acceptable set of `{W(web)}`, and the second is the row
where recency alone would have selected `P(policy)`, so step 1 is measured firing
against recency rather than merely agreeing with it.

Measured totals at commit `38a4bb6`:

```
tests/test_v16_crosshop_parent_identity.py    41 passed, 0 failed, 0 skipped
all 17 committed sessions                     every entry's parent correct
full repo suite                               1405 passed, 0 failed, 0 skipped
```

## AM17 THE LOAD-BEARING FINDING, AND THE SCOPE INVERSION THAT PRODUCED IT

**The decline's correctness REQUIRES the transitive reachability definition. A
direct-authority-only decline is wrong, and it is wrong on a row this document
already contains.**

Under direct-only reachability, `relay control` manufactures a false
disagreement: `A(untrusted)` is directly untrusted, and `B(relay)` reads clean
despite relaying `A` verbatim, because its own authority is DERIVED. The pair
then appears to disagree, the decline fires, and the mechanism records no parent
for a chain that AM10.3's own scope correction says must still link:

> a verbatim relay produces an UNTRUSTED entry and a DERIVED entry with IDENTICAL
> content, which is content-identical across authorities, and both are
> taint-reachable, so the chain must still link (by recency, to the proximate
> relay).

"Both are taint-reachable" is true only transitively. AM10.3's correction
silently presupposed the walk. **This is why AM7 item 4 was a prerequisite of the
decline rather than a separable companion**, and it is the reason increment 2 was
scoped as step 1 plus decline plus walk together.

**Scope-inversion history, recorded because the correction ran opposite to the
anticipated risk.** The pre-build risk analysis anticipated a VACUOUS PASS: that
if every row turned on a directly untrusted candidate, a direct-authority-only
build would score identically to a walk-based one and the acceptance number would
say nothing about item 4. A read-only discrimination pass over the committed
corpus measured the opposite. A direct-only build would have REGRESSED three rows
that increment 1 already passed:

```
row                                                direct-only   walk-based   acceptable
merge-tool multi-candidate :: S(sink)              W(web)        M(merged)    {M(merged)}
merge-tool taint-preference :: S(sink)             W(web)        M(merged)    {M(merged)}
relay control :: C(consumer)                       None          B(relay)     {B(relay)}
```

The mechanism of the first two: step 1 without the walk cannot see that the
proximate parent is transitively tainted, so the taint subset collapses to the
directly untrusted entry alone and the rule promotes an ANCESTOR over the
proximate parent that carries it. Increment 1 passed those rows by plain recency,
with no taint preference at all, so a partial build would have read as a
regression rather than as a missing capability. That projection was then measured
correct in both directions: increment 2 landed at 41 of 41 with the walk, and the
walk-less projection of 38 passed, 3 failed was pre-registered as the diagnosis
for its absence.

## AM18 ONE UNMEASURED RESIDUAL, explicitly NOT resolved here

**A candidate set holding a disagreeing content-identical PAIR alongside a
distinct THIRD candidate is not covered by AM10.3's frozen text and is not
decided by this amendment.**

AM10.3 part 1 is scoped to the general multi-candidate case where candidates
DIFFER in content. Part 2 is scoped to the mirrored cell. The mixed set falls in
neither, and part 2's closing sentence, "No parent is set from either", leaves
open whether it forbids a parent entirely or only forbids taking one from either
member of the pair, which would leave a distinct third candidate selectable.

**No committed session produces such a candidate set**, verified by direct
inspection of every Tier 1 candidate set the 17 sessions generate, so the corpus
cannot decide it and no measurement here bears on it. Increment 2 declines
outright in that case, and the code comment at the decline marks the behavior
UNMEASURED and not fossilized as spec.

Resolving it requires two things, and neither is done here: a discriminating
session added to the corpus, which is itself a change to the evidentiary base and
belongs in a dated amendment, and then a dated amendment here recording the
measured resolution. **It is not resolved by decision 1's resolution, and this
amendment does not decide it.**

## AM19 STATUS AT TIME OF WRITING

Increment 1 (tier 1 candidacy, tier 2 steps 3 and 4) and increment 2 (tier 2
step 1, the AM10.3 decline, and AM7 item 4's ingestion-time cycle-guarded walk)
are built and committed. AM7 item 5, the reachability taint predicate replacing
the flat `authority == UNTRUSTED` test at the three decision-time call sites in
`context.py`, is NOT built, and it is the component carrying the family-1 and
family-2 byte-equality floor of section 6. Nothing built so far changes any
verdict a shipped check returns.

Still carried as open, with their conditions unchanged: decision 3
(`CONTAIN_MIN`, run at 24, chosen and not calibrated, AM11.2), decision 4's
normalization LEVEL (NFKC deferred to a false-link measurement, AM10.2 and
AM12.2), and the AM18 residual above. The cycle guard required by AM7 item 4 is
present and is unreachable by construction on any graph the engine builds, since
a parent is only ever selected from strictly earlier log entries, so no
acceptance result evidences it; its termination on malformed cyclic logs was
demonstrated outside the repository.

Decision 1 is no longer PROVISIONAL.
