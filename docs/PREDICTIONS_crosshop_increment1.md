# Pre-registered prediction: cross-hop build increment 1 (the untainted linker)
# Date: August 11, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing

No mechanism code exists. `agentlock/context.py` contains no containment linker,
`notify_context_write` has no parameter for a call's input arguments, and nothing
in the engine or either adapter has been modified. Every AFTER figure in this
document is a prediction, frozen before the build, in the same register as
`PREDICTIONS_crosshop.md` and its two amendments.

This document is scoped to ONE increment. It does not restate, revise, or reopen
the frozen spec in `PREDICTIONS_crosshop.md` AM5 and AM7, or the AM10 to AM14
decisions of AMENDMENT 2. Those remain the prediction of record. This file freezes
what the FIRST slice of that spec is predicted to measure, and it exists because
the acceptance suite is already committed and already armed, so the increment's
result is knowable in advance and must be written down before it is observed.

The AM13 pre-build checklist is satisfied and nothing blocks the build. The
corpus foundation is committed (`tests/crosshop_corpora/`, 17 sessions, per-entry
declared ground-truth parents) and the acceptance criterion is executable
(`tests/test_v16_crosshop_parent_identity.py`).

---

## 1. SCOPE OF THE INCREMENT (frozen)

The increment is AM7 items 1 and 2, plus the lower half of AM7 item 3. It is
deliberately partial, and what is EXCLUDED is as much a part of the freeze as
what is included.

### 1.1 In scope

**Placement.** A module-level `_containment_parent` helper (or the name that
lands, edited once at `tests/test_v16_crosshop_parent_identity.py:55`) in
`agentlock/context.py`, called from `record_write` strictly before the append at
`context.py:674`.

The file matters and is not a preference. `linker_present()`
(`tests/test_v16_crosshop_parent_identity.py:65-72`) reads
`Path(ctx.__file__).read_text()`, so it greps `agentlock/context.py` and nothing
else. AM7 item 1 permits the match to sit in `record_write` or in
`notify_context_write`, and `notify_context_write` lives in `gate.py`. A linker
placed there satisfies AM7 and is invisible to the discriminator, so the
acceptance suite would skip forever and read green. That is the vacuous pass the
suite was written to prevent. It goes in `context.py`, which is also where AM5's
only two reuses live (`_iter_param_leaves` at `context.py:494`, and the
`ContextProvenance.content` field at `context.py:555`).

**Input arguments at ingestion.** The `parameters` kwarg threaded
`notify_context_write` (`gate.py:2450`) to `record_write` (`context.py:600`).
This is AM7 item 2, engine side only. Without it the suite does not skip and does
not quietly pass: `_record` (`:151-159`) raises an `AssertionError` naming AM7
item 2 as unimplemented, because a linker that never sees the call's inputs cannot
establish a link. AM14 confirms the needle side needs no adapter change, since
both adapters already write untruncated `content`. Adapter changes for the input
side are NOT part of this increment; the acceptance suite drives the gate directly.

**Tier 1 candidacy**, exactly as frozen in AM5:

- Leaves from `_iter_param_leaves`, lowercased.
- Symmetric normalization on BOTH sides, the AM10.2 safe core: strip, case fold,
  whitespace-run collapse. No decode primitives, no parsing. Percent-decoding and
  hex-decoding are forbidden by shipped family-2 guards that grep the whole of
  `context.py` (`tests/test_v16_family2_encoding.py:286-296`,
  `tests/test_v16_family2_base64composite.py:364-369`). NFKC and JSON
  canonicalization are out of the first cut (AM10.2).
- A prior entry `e` is a candidate iff its normalized content `c` satisfies
  `len(c) >= CONTAIN_MIN` with `CONTAIN_MIN = 24`, and `c` is a substring of at
  least one leaf.
- Reverse iteration over the log, which AM5 records as binding and not cosmetic.
- No auth short-circuit at ingestion (AM5 `:930-935`).
- Match before write, strictly before the append (AM2), so the log holds prior
  entries only.

**Tier 2, steps 3 and 4 only.** Most recent by log index, then longest normalized
content, then lexically by `provenance_id`. An empty candidate set records
`parent_provenance_id = None`.

### 1.2 Explicitly excluded from this increment

- **Tier 2 steps 1 and 2**, the taint-reachability preference.
- **The AM10.3 mirrored-cell decline**, content-identical candidates that
  disagree on taint-reachability.
- **AM7 item 4**, the transitive cycle-guarded walk.
- **AM7 item 5**, the reachability taint predicate replacing the flat
  `authority == UNTRUSTED` test at three call sites.

Excluding items 4 and 5 is what makes this increment measurable on its own.
`test_parent_identity` reads only `prov.parent_provenance_id`, so it scores the
GRAPH and not any verdict. No walk and no taint predicate are needed to return a
real number from it. Nothing in this increment touches families 1 and 2, so the
no-regression floor of `PREDICTIONS_crosshop.md` section 6 is not yet under load;
that floor comes under load at AM7 item 5, not here.

---

## 2. FROZEN SCOREBOARD TRIPLE

**Baseline before the build, measured, not predicted:**

```
tests/test_v16_crosshop_parent_identity.py    23 passed, 18 skipped, 0 failed
```

The 18 skips are the two `@needs_linker` tests: `test_parent_identity`
parametrized over all 17 sessions, plus
`test_am3_ten_call_session_is_repaired_by_the_built_linker`. The skip reason names
the five unbuilt AM7 items and classifies the state as a MISSING mechanism rather
than a failing one.

**Predicted after the increment lands, with the symbol in `context.py` and the
`parameters` kwarg threaded:**

```
tests/test_v16_crosshop_parent_identity.py    39 passed, 2 failed, 0 skipped
```

All 18 skips flip to judged. Of them, 16 pass and 2 fail. The 23 unconditional
tests are unaffected and must all still pass, including the non-vacuity floor of
49 entries that demand a non-`None` parent, and
`test_link_count_criterion_is_not_what_is_tested`, which pins that the old
link-count criterion is not what is being scored.

`39 / 2 / 0` is the frozen triple. It is a prediction of an exact number, not a
range and not a floor.

---

## 3. THE TWO PREDICTED-FAILING ROWS

Both fail BY CONSTRUCTION. Neither is a defect of the increment, and neither is a
row to fix during the build. They are the two rows that measure what the
increment deliberately omits, and their failure is the evidence that the omitted
controls are the ones doing the work.

### 3a. `merge-tool, taint preference against recency :: M(merged)`

`tests/crosshop_corpora/sessions_new.py:136` (`MERGE_TOOL_TAINT_VS_RECENCY`).
The committed log order places
`W(web)`, the untrusted entry, at index 1, and `P(policy)`, the clean derived
entry, at index 2. Both are true parents and both are Tier 1 candidates at
`M(merged)`'s ingestion. Tier 2 step 3 alone selects the more recent one, which
is `P(policy)`. The declared acceptable set is the singleton `{W(web)}`, because
the row is a SELECT and step 1 asserts which true parent is recorded.

**Predicted FAIL.**

This is the AM11.1 evidence, and it is the reason that session exists. Its own
declared reason says so: recency alone would select `P(policy)`, so a recording of
`P(policy)` here measures step 3 firing WITHOUT step 1. When Tier 2 steps 1 and 2
land in a later increment, this row must flip to PASS, and that flip is the
measurement that finalizes provisional decision 1 (AM10.3, coupled to AM11.1 by
AM12.1).

### 3b. `mirrored cell :: B(mirror-consumer)`

`tests/crosshop_corpora/sessions_new.py:249` (`MIRRORED_CELL`), marked
`provisional`. Both candidates, `R(real)` at index 1 and `A(untrusted mirror)` at
index 2, normalize to content of length 125, so they are content-identical under
the AM10.2 safe core and they disagree on taint-reachability. AM10.3 requires the
linker to DECLINE, and the declared acceptable set is `{None}`. Tier 2 step 3
alone selects the more recent candidate, which is `A(untrusted mirror)`.

**Predicted FAIL.**

This is AM10.3's decline being unimplemented in the untainted increment, by
design. It is the induced-taint cell: a link recorded here asserts a false
derivation from the untrusted mirror when the value may have come from the trusted
copy, and AM10.3 records that the falseness is not visible to an operator because
the two contents are identical by construction. The increment does not implement
the decline, so it writes the link, so the row fails. It must flip to PASS when the
mirrored decline lands.

Note that this is the only place in the corpus where the `(log index, normalized
length)` key comes close to a tie, and recency still resolves it. The lexical
`provenance_id` tie-break of Tier 2 step 3 does not fire anywhere in the corpus.

---

## 4. THE RESOLVED CONDITIONAL, recorded so the resolution is on the record

`merge-tool multi-candidate :: M(merged)` (`tests/crosshop_corpora/sessions_new.py:40`)
was previously stated as "fails unless the committed log order coincidentally
favors `W(web)`". A conditional prediction is not a prediction, and freezing one
would let either outcome read as expected after the fact. It was resolved by
read-only simulation against the committed session data before this document was
written.

**The committed order places `P(policy)` at index 1 and `W(web)` at index 2.**
At `M(merged)`'s ingestion the Tier 1 candidate set is exactly two entries:
`W(web)` at index 2, normalized length 128, and `P(policy)` at index 1,
normalized length 109. `U(auth)` clears `CONTAIN_MIN` at normalized length 46 but is not a substring of
any leaf, so it is not a candidate. Tier 2 step 3 selects the more recent, which
is `W(web)`, which is the declared correct parent for this SELECT row.

**Predicted PASS, determinately.** Recency and taint preference happen to agree
on this row, which is precisely why the 3a variant exists to separate them.

Recorded plainly: this was resolved by SIMULATION of the frozen predicate against
committed data, not by the built increment. The simulation was a throwaway script
outside the repo and nothing of it ships. When the increment lands, this row's
actual result must be checked against this resolved prediction. **A mismatch is an
audit trigger**, because it would mean either the committed corpus changed or the
built predicate is not the frozen one.

---

## 5. THE HEADLINE ROW

`test_am3_ten_call_session_is_repaired_by_the_built_linker` must flip from skipped
to passing, with **10 of 10 entries recording a correct parent** on the `10-call
session`.

That session is the reconstruction of the one AM3 measured with the token-based
linker B, and the figures AM3 measured on it are `true_derivations = 6` and **4
entries recording a wrong parent** (`PREDICTIONS_crosshop.md:810-813`). Those two
numbers are the measured ones and are the ones this document pins. AM10.1 was
written from that result: a graph whose link COUNT matches the true derivation
count exactly and whose parent identities do not, which is why the acceptance
criterion is parent identity and not link count.

The prediction is that whole-content carriage names every parent on that session
where token overlap named most of them wrongly. A build that reproduces AM3's
wrong-parent count while satisfying a link-count check has rebuilt the graph the
criterion was changed to reject, and
`test_link_count_criterion_is_not_what_is_tested` is the unconditional guard that
keeps the two graphs distinguishable.

---

## 6. FALSIFIERS

Stated plainly, and stated before the measurement, so that no result can be
reconciled after the fact.

**Any deviation from `39 passed / 2 failed / 0 skipped` is an audit trigger.**

Specifically, each of the following falsifies this pre-registration and is
investigated BEFORE the build proceeds to Tier 2 steps 1 and 2, AM7 item 4, or
AM7 item 5:

1. **A third row fails.** The increment is doing something other than Tier 1 plus
   Tier 2 steps 3 and 4, or the corpus changed under it.
2. **Either named row of section 3 passes.** `merge-tool taint-preference ::
   M(merged)` passing means a taint preference is present that this increment
   excludes. `mirrored cell :: B(mirror-consumer)` passing means a decline rule is
   present that this increment excludes. Both are scope leaks, and a scope leak
   that produces a green row is the harder kind to notice.
3. **The multi-candidate row of section 4 fails.** The section 4 resolution was
   simulated, not built, and a failure means the simulation and the implementation
   disagree about the frozen predicate. Investigate which one is wrong; do not
   adjust the prediction.
4. **The AM3 repair row is not 10 of 10.** Whole-content carriage did not deliver
   the parent identities the criterion was re-specified to demand, and the AM5
   measured results do not reproduce inside the engine.
5. **Anything skips.** A skip after the symbol lands means the discriminator is
   pointed at a symbol that is not there, which is the permanently-green failure
   mode of section 1.1.
6. **Any of the 23 unconditional tests fails.** The corpus or the criterion moved
   during the build, which is the exact drift the CORRECTION block at the top of
   `PREDICTIONS_crosshop.md` and AM1.0 both exist to prevent.

A deviation is not reconciled by editing this document. It is recorded in a dated
amendment, as with families 1 and 2, and this file is not edited once the
increment is launched.

---

## 7. CONDITIONS

- Frozen baseline engine: this branch's tip, with no mechanism code, measured at
  `23 passed / 18 skipped / 0 failed` on
  `tests/test_v16_crosshop_parent_identity.py`.
- Frozen corpus: `tests/crosshop_corpora/`, 17 sessions (8 must-not-trip, 7
  must-catch, 2 control), 49 entries demanding a non-`None` parent. A corpus edit
  invalidates every figure in this document.
- Frozen spec: `PREDICTIONS_crosshop.md` AM5 (the two-tier predicate), AM7 (the
  six build items), and AM10 to AM13 (the resolved decisions). This document
  selects a subset of that spec; it does not amend it.
- `CONTAIN_MIN = 24`, run at the value AM11.2 records as chosen and not
  calibrated. AM11.2's condition (a) still stands: a change to `CONTAIN_MIN`
  requires re-running all six AM5 corpora, and it would invalidate the figures
  here as well.
- Verification method: run the acceptance suite once the increment lands, compare
  the triple, then compare the two failing row identities against section 3 and
  the passing multi-candidate row against section 4.

## 8. Reproduction of status

No mechanism code exists. No linker was written in the pass that produced this
document. The section 4 resolution came from a throwaway simulation outside the
repo, run read-only against committed corpus data, and the baseline triple in
section 2 came from running the committed acceptance suite unchanged. This file is
the prediction of record for build increment 1.
