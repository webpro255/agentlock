# Pre-registered prediction: cross-hop build increment 2 (taint preference, decline, walk)
# Date: August 11, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing

Increment 1, the untainted containment linker, is built and committed. Nothing of
increment 2 exists: `agentlock/context.py` has no reachability walk, no taint
preference in selection, and no decline rule. Every AFTER figure in this document
is a prediction, frozen before the build, in the same register as
`PREDICTIONS_crosshop.md`, its two amendments, and
`PREDICTIONS_crosshop_increment1.md`.

The acceptance suite currently reads `39 passed / 2 failed / 0 skipped`, which is
increment 1's frozen and measured result. The two failures are the two rows this
increment must flip.

---

## 0. SCOPE, AND THE CORRECTION THAT PRODUCED IT

**Recorded first, because the discrimination check INVERTED the naive scope and a
correction carried silently into a build is the failure mode AM1.0 exists to
prevent.**

The naive scope for this increment was Tier 2 step 1 plus the AM10.3 decline,
with AM7 item 4's walk deferred on the reasoning that reachability could start as
a direct authority test and gain the walk later. The stated risk was that such a
build might score identically to a walk-based one, making the acceptance number
vacuous with respect to item 4.

**A read-only discrimination pass over the committed corpus falsified that, in the
opposite direction from the one anticipated.** A direct-authority-only step 1 does
not vacuously pass. It REGRESSES three rows that pass today under increment 1,
decided there by plain recency with no taint preference at all. Step 1 without the
walk promotes a directly untrusted ancestor over the proximate parent that carries
it, and it manufactures a decline on a relay pair whose two entries only look like
a mirror when reachability is too shallow to see through the relay.

**FROZEN SCOPE for increment 2:**

- Tier 2 step 1, the taint preference (AM5 `:922`).
- The AM10.3 mirrored-cell decline.
- **AM7 item 4, the ingestion-time reachability walk over already-set parent
  links, cycle-guarded. A PREREQUISITE, not a deferrable companion.**

**EXPLICITLY EXCLUDED, deferred to increment 3:**

- **AM7 item 5**, replacing the flat `authority == UNTRUSTED` test at the three
  decision-time call sites in `context.py` (`parameter_lineage_check`,
  `novel_lineage_check`, `lineage_summary`). That change carries the family-1 and
  family-2 byte-equality floor of `PREDICTIONS_crosshop.md` section 6, which is
  the load-bearing no-regression floor of the whole family and is not under load
  in this increment.

Items 4 and 5 are two separate CONSUMERS of the same reachability relation. Item 4
consumes it at ingestion to choose a parent. Item 5 consumes it at decision time to
decide what "untrusted context" means for three shipped checks. Only item 4 is in
increment 2. Building item 4 does not oblige item 5, and nothing in this increment
changes any verdict any shipped check returns.

---

## 1. THE REACHABILITY DEFINITION, PINNED

**A candidate is taint-reachable iff its own authority is `UNTRUSTED`, OR it
chains to an untrusted ancestor through already-set `parent_provenance_id` links.
The walk is cycle-guarded.**

Two properties of that definition are load-bearing and are pinned here rather than
left to the implementation.

**Reachability is computed over RECORDED links, never over declared ground truth.**
The walk follows the `parent_provenance_id` values the mechanism itself set earlier
in the same session. The corpus's declared parents are the SCORING criterion and
must never become an input to the mechanism; a linker that consulted them would be
grading its own exam. This is why section 3's second row is a compound prediction:
its correctness depends on a link the mechanism recorded earlier in that same
session, and if that earlier link is wrong the walk faithfully propagates the
error.

**Step 1 and the AM10.3 decline MUST use the SAME definition, and it must be the
transitive one.** They are constrained from opposite sides by two different
sessions:

- `mirrored cell` requires the decline to FIRE. `A(untrusted mirror)` is directly
  untrusted and `R(real)` has no parent and no ancestor, so the disagreement is
  genuine and visible without any walk.
- `relay control` requires the decline NOT to fire. `A(untrusted)` and `B(relay)`
  are content-identical at normalized length 128, and under a direct-only test they
  appear to disagree on taint, so the decline fires and records no parent where
  `B(relay)` is required.

One definition satisfies both, and only the transitive one does. This is not a
consistency preference; it is the corpus enforcing AM10.3's own scope correction.
AM10.3 narrowed the decline from disagreement on AUTHORITY to disagreement on
TAINT-REACHABILITY, and stated that a verbatim relay produces an untrusted entry
and a derived entry with identical content where "both are taint-reachable, so the
chain must still link". **"Both are taint-reachable" is true only transitively.**
The wording correction silently presupposes the walk.

### 1.1 CYCLE GUARD SCOPE NOTE

The guard is required by AM7 item 4's wording and will be built. **Its firing
condition is structurally unreachable in every committed session.** The linker
selects a parent only from strictly earlier log entries, so every link the
mechanism records points backward in log order, and a graph built exclusively of
backward edges cannot contain a cycle.

**Therefore a `41 / 0 / 0` acceptance result says NOTHING about whether the guard
works.** It is not evidence of termination on a cyclic graph, because no cyclic
graph is ever presented to it.

The guard's verification is a SEPARATE named item in the build report, and it is
not silently bundled into the acceptance number. One of two outcomes is to be
reported explicitly:

1. A unit test that drives the walk directly with a synthetic malformed log
   containing a cycle, and asserts termination, or
2. An explicit statement that the guard is unreachable by construction in the
   corpus and is present as defensive hardening against a log the engine did not
   build (a restored, merged, or externally supplied provenance log).

Either is acceptable. Reporting neither, and letting the acceptance triple stand in
for the guard, is not.

---

## 2. THE FALSIFIER PAIR

The prediction is a PAIR of scoreboards, not a single number, because the two
plausible builds are distinguishable by the corpus and each has a specific
diagnosis.

**CORRECT build, step 1 plus decline plus the transitive walk:**

```
tests/test_v16_crosshop_parent_identity.py    41 passed, 0 failed, 0 skipped
```

The two increment-1 failures (`merge-tool taint-preference :: M(merged)` and
`mirrored cell :: B(mirror-consumer)`) flip to PASS, and NO currently-passing row
regresses.

**PARTIAL build, step 1 plus decline with direct-authority-only reachability, walk
missing or wrong:**

```
tests/test_v16_crosshop_parent_identity.py    38 passed, 3 failed, 0 skipped
```

failing exactly `merge-tool multi-candidate :: S(sink)`, `merge-tool
taint-preference :: S(sink)`, and `relay control :: C(consumer)`.

**Landing at `38 / 3 / 0` is a DIAGNOSIS, not an acceptable partial.** It means the
walk is absent or wrong, and the three named rows are the readout that says so.
Increment 2 is not complete at that point and must not be committed there.

---

## 3. THE THREE DISCRIMINATING ROWS

These are the rows that separate a walk-based reachability from a
direct-authority-only one. All three PASS today under increment 1, decided by plain
recency, which is why a partial build reads as a regression rather than as a
missing capability.

### 3.1 `merge-tool multi-candidate :: S(sink)`

`S`'s body carries `M(merged)`'s briefing, and that briefing carries `P(policy)`'s
and `W(web)`'s outputs whole, so all three are Tier 1 candidates at `S`'s ingestion.
The corpus declares this on the entry itself as `also_carried`.

In THIS session `M`'s recorded parent under increment 1 is already `W(web)`, because
the committed log order places `W` later than `P` and recency selected it. So the
walk finds `M` transitively tainted through its own recorded link, the taint subset
is `{W(web), M(merged)}`, and recency inside that subset selects `M(merged)`, which
is correct.

Direct-only sees `M` as untainted derived content, the subset collapses to
`{W(web)}` alone, and step 1 selects `W(web)`: an ancestor cited in place of the
proximate parent. Acceptable set is `{M(merged)}`.

### 3.2 `merge-tool, taint preference against recency :: S(sink)`

Same containment shape, and **this row is a COMPOUND prediction. It is the single
most diagnostic row in the corpus.**

Under increment 1, `M`'s recorded parent in THIS session is `P(policy)`, the wrong
parent: this session is the increment-1 failure row of section 4.1. A walk run over
that graph follows `M` to `P` to `None`, finds no untrusted ancestor, and reports
`M` untainted. The subset is then `{W(web)}` alone, `S` selects `W(web)`, and the
row FAILS.

`S` passes here only if BOTH pieces land: step 1 must first flip `M`'s own row to
`W(web)`, and the walk must then operate over that CORRECTED recorded link to see
`M` as transitively tainted.

**Diagnostic decomposition, recorded so the readout is unambiguous:**

- `M` flipped to `W(web)` but `S` still wrong: **the walk is broken.**
- `M` not flipped and `S` wrong: **step 1 is broken**, and `S`'s failure is
  downstream of that, not independent evidence.

### 3.3 `relay control :: C(consumer)`

`A(untrusted)` and `B(relay)` are content-identical at normalized length 128.
Direct-only: they disagree on taint, the decline fires, and `None` is recorded where
`B(relay)` is required. Walk: `B` is tainted through its recorded parent `A`, the
two candidates agree, no decline fires, and recency selects `B(relay)`. Acceptable
set is `{B(relay)}`.

**This is the row AM10.3's own wording correction was built to protect**, and it
fails under exactly the reading AM10.3 rejected.

---

## 4. THE TWO FLIP ROWS

The increment-1 failures, both pre-registered there as failing by construction,
both of which must now pass.

### 4.1 `merge-tool, taint preference against recency :: M(merged)`

The committed log order places `W(web)` at index 1 and `P(policy)` at index 2. Both
are Tier 1 candidates and both are true parents. Recency alone selects `P(policy)`,
which is what increment 1 records and why the row fails there. Step 1 prefers
`W(web)`, which is directly untrusted by its own authority, and no walk is needed to
see it. **Now PASS.**

### 4.2 `mirrored cell :: B(mirror-consumer)`

`R(real)` and `A(untrusted mirror)` are content-identical at normalized length 125
and disagree on taint-reachability: `A` is directly untrusted, `R` has no parent and
no untrusted ancestor under either reading. The decline fires and records `None`.
**Now PASS.**

**This flip is the AM11.1 and AM10.3 evidence that finalizes provisional decision
1.** AM10.3 marked the mirrored cell PROVISIONAL, resolved by reasoning and by the
falsified premise, explicitly pending the merge-tool corpus of AM11.1. That corpus
is committed and is measured by this increment. **When this row lands correctly,
alongside the two merge-tool sessions, decision 1 moves from PROVISIONAL to
RESOLVED.** That transition is recorded in a dated amendment when it happens; it is
not asserted here in advance.

---

## 5. FULL-SUITE GATE

**Measure the pre-build full-suite baseline at build time. Do not hardcode it.**
Increment 1 left the full suite at `1403 passed / 2 failed / 0 skipped`, and the two
failures are the two flip rows of section 4. That figure is recorded as context, not
as a value to assume: it is re-measured immediately before the increment-2 build,
and the re-measured number is the baseline the delta is judged against.

**The only acceptable delta is the 2 increment-1 failures flipping to pass.** No
other test regresses, and no test anywhere newly skips. On the increment-1 figure
that would be `1405 passed / 0 failed / 0 skipped`, with the total unchanged.

**Commit only if BOTH hold:** the acceptance triple reads `41 / 0 / 0` with the two
flips and the three discriminating rows still passing, AND the full-suite delta is
exactly the two flips against the freshly measured baseline.

---

## 6. FALSIFIERS

Stated before the measurement, so that no result is reconciled after the fact.

**Any deviation from `41 / 0 / 0` with the two flips and zero regressions is an
audit trigger.**

1. **Landing at `38 / 3 / 0`**: the walk is missing or wrong. The three rows of
   section 3 are the readout.
2. **`M(merged)` flipped but `merge-tool taint-preference :: S(sink)` still
   wrong**: the walk is broken (section 3.2).
3. **`M(merged)` not flipped**: step 1 is broken, and any `S(sink)` failure in that
   session is downstream of it rather than independent evidence.
4. **`relay control :: C(consumer)` failing**: reachability is direct-only in the
   decline path, or step 1 and the decline are using two different definitions,
   which section 1 forbids.
5. **Any OTHER row failing**: the increment did something outside the frozen scope.
   In particular a failure among the family-1 or family-2 suites would mean item 5
   leaked into this increment, since nothing in the frozen scope touches a
   decision-time check.
6. **Any unrelated regression or new skip anywhere in the repo.**
7. **The cycle guard reported only through the acceptance number**, with neither of
   section 1.1's two outcomes stated. That is a reporting failure rather than a
   mechanism failure, and it is caught here because a guard whose verification is
   assumed is a guard nobody has tested.

A deviation is not reconciled by editing this document. It is recorded in a dated
amendment, as with families 1 and 2, and this file is not edited once the increment
is launched.

---

## 7. CONFIDENCE LABELING

**Every scoreboard figure in sections 2, 3, and 4 is SIMULATION-BACKED against
committed corpus data**, produced by a read-only discrimination pass that replayed
both reachability definitions over all 17 committed sessions and compared the
recorded parent per entry. None of it is measurement of built code. All of it must
be re-checked against the built increment, and a mismatch is an audit trigger of the
same kind as any other in section 6.

The simulation used the default source-to-authority map, which is what the
acceptance suite's replay exercises, since that replay registers no tool carrying a
`context_policy`. A build that resolves authority differently would invalidate these
figures for a reason unrelated to reachability.

**The cycle guard is the one piece with NO corpus-backed figure of either class.**
Its status is recorded in section 1.1 and its verification is a separate reported
item.

**Retro-note, discharging the labeling debt from increment 1.** Increment 1's
headline prediction, 10 of 10 correct parents on the 10-call session, was
SPEC-DERIVED rather than simulation-backed: it followed from the AM5 rule by
reasoning, the 10-call session was never simulated before the build, and
`PREDICTIONS_crosshop_increment1.md` section 5 carried no provenance label either
way, while section 4's multi-candidate resolution was labeled. The build confirmed
it exactly at 10 of 10. The label was missing, not wrong, and the omission is
recorded here rather than corrected in a frozen file. This freeze's figures are
simulation-backed, which is the stronger of the two classes, and every figure in it
carries its class explicitly.

---

## 8. CONDITIONS

- Frozen baseline engine: this branch's tip with increment 1 built, acceptance file
  at `39 passed / 2 failed / 0 skipped`.
- Frozen corpus: `tests/crosshop_corpora/`, 17 sessions, 49 entries demanding a
  non-`None` parent. A corpus edit invalidates every figure here. In particular the
  three discriminating rows of section 3 depend on the committed log ORDER of the
  two merge-tool sessions and on the `also_carried` shape of both `S(sink)` entries.
- Frozen spec: `PREDICTIONS_crosshop.md` AM5 (the two-tier predicate), AM7 items 4
  and 5, AM10.3 (the decline, provisional), AM10.4, and AM11.1. This document
  selects a subset; it does not amend them.
- `CONTAIN_MIN = 24` unchanged from increment 1. AM11.2's condition (a) still
  stands.
- Nothing in the frozen scope modifies any adapter, any family-1 or family-2 code,
  or any decision-time check.
- Verification method: run the acceptance suite, compare against the section 2 pair,
  check the three section 3 rows and the two section 4 flips by name, then compare
  the full-suite delta against the freshly measured baseline. Report the cycle
  guard's status separately per section 1.1.

## 9. Reproduction of status

No increment-2 mechanism code exists. No walk, no taint preference, no decline. The
scope correction in section 0 and the figures in sections 2 through 4 came from a
read-only discrimination pass over committed corpus data, run before this document
was written and with nothing written to the repository by it. This file is the
prediction of record for build increment 2.
