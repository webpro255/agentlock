# Pre-registered prediction: cross-hop build increment 3 (AM7 item 5, decision time)
# Date: August 11, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing

Increments 1 and 2 are built and committed: tier 1 candidacy and tier 2 steps 3
and 4 (`3f9ab12` frozen, `a585c80` built), then tier 2 step 1, the AM10.3
decline, and AM7 item 4's ingestion-time cycle-guarded walk (`26ef567` frozen,
`38a4bb6` built). Nothing of increment 3 exists: the four decision-time sites
still key on the flat `authority == UNTRUSTED` test, and no code in
`agentlock/` was modified by the passes that produced this document.

The evidentiary base is committed ahead of this freeze:
`tests/test_v16_crosshop_decision_time.py` (`500e6d1`), five sessions that
discriminate the two predicates at decision time, each carrying a measured
shipped outcome and a declared post-increment-3 outcome. Measured baselines at
time of writing:

```
tests/test_v16_crosshop_decision_time.py      12 passed,  0 failed,  8 skipped
tests/test_v16_crosshop_parent_identity.py    41 passed,  0 failed,  0 skipped
the 399-test decision-time regression floor  399 passed,  0 failed
full repo suite                             1417 passed,  0 failed,  8 skipped
```

---

## 0. THE SCOPE DECISION THIS FREEZE RECORDS

AM23.4 of AMENDMENT 4 left the increment-3 scope open between two measured
options and stated that whichever was chosen would get its own pre-registration.
**This document is that pre-registration, and the decision is OPTION (a).**

**FROZEN SCOPE:**

- `parameter_lineage_check`, `lineage_summary`, and `untrusted_sources` are
  broadened to the transitive reachability predicate.
- **`novel_lineage_check` REMAINS on the flat authority test.**

### 0.1 Why (a) and not (b)

The two options were not symmetric in cost, and the asymmetry was measured
rather than argued.

**Option (b)'s cost is a DETECTION LOSS under the DEFAULT configuration.** AM22.1
constructed it: a token that is a substring of authoritative content without
being an exact authoritative token is discarded by `parameter_lineage_check`'s
auth-first skip in every configuration, while `novel_lineage_check`'s exact
token-set membership calls it novel. Broadening novel too moves that token into
`untrusted_tokens`, novelty stops firing, and nothing else catches it: measured
`DENY:novel_lineage` becoming `ALLOW`. AM21 characterized the class precisely as
tokens a taint-reachable derived entry INTRODUCED rather than relayed, **which is
exactly the class `novel_lineage` exists for**. A relayed token was never novel in
the first place, because its ancestor's own extraction already accounted for it.

**Option (a)'s cost is a RECORDED INCONSISTENCY that is never acted on.** AM23.1
measured it: one token drawing two answers, `novel` from the flat check and
`untrusted` with a provenance citation from the broadened one. Gate ordering
(`gate.py:808` before `:823`) means `param_lineage` decides, so the contradiction
lands in the audit record and changes no verdict.

A silent loss of a denial and a visible contradiction in a record are not the
same class of cost. This freeze takes the visible one.

**Option (a) also closes two further gaps by construction**, since
`novel_lineage_check` is untouched: Gap B (AM22.2, `novel_lineage_check` running
at `min_len` 6 while `param_lineage_check` runs at a configured floor above it)
and Gap E (AM22.3, a compensating `param_lineage` catch configured weaker than
`deny`, which under (b) downgrades the outcome or loses it entirely). Under (a)
the `novel_lineage` denial stands in both configurations because nothing about
that check changes.

**Option (c) was measured degenerate** (AM23.3): the natural gating condition adds
0 of 24 tokens across all 17 corpus sessions plus the probe fixtures and collapses
exactly to (a). So (a) and (b) were the whole menu, and this is a choice between
two, not a preference among three.

### 0.2 The maintainability trade, recorded honestly

**Option (a) leaves TWO taint notions in the codebase.** Three sites answer "is
this entry untrusted" by reachability and one answers it by authority, on the same
provenance log, in the same request. That is a real cost and it is not disguised
here: it is the reason AM23.1 called the resulting record an inconsistency rather
than a nuance.

The principled path to unifying them is NOT to broaden `novel_lineage` later on
the same evidence. It is the read-side per-field provenance lever already on the
roadmap. A mechanism that can distinguish a token a tool INTRODUCED from one it
RELAYED is exactly what Gap A needs and exactly what this layer cannot supply,
since both adapters see only tool name, arguments, output, session id, token id,
and a static `context_source`. **When that lever exists, `novel_lineage`'s
broadening should be revisited**, and the revisit gets its own pre-registration
and its own measurement rather than inheriting this one.

---

## 1. THE MECHANISM TO BE BUILT

1. **A helper in `agentlock/context.py` named `_reachable_untrusted_entries`**,
   matching `BROADENING_SYMBOL` in
   `tests/test_v16_crosshop_decision_time.py:76`. The name is taken as given; the
   test constant is NOT edited. It returns the provenance entries that are
   taint-reachable under increment 2's definition: directly `UNTRUSTED`, or
   chaining to an untrusted ancestor through RECORDED `parent_provenance_id`
   links, cycle-guarded, never consulting declared ground truth from any corpus
   or fixture. It reuses `_taint_reachable`; the new symbol is the decision-time
   CONSUMER of that walk, not a second definition of it.

2. **`parameter_lineage_check`**: the `untrusted_entries` haystack
   (`context.py:1007-1011`) becomes the reachable set. **The auth-substring skip
   at `context.py:1086-1087` is NOT modified.** Gap A's protection under option
   (a) comes from `novel_lineage_check` staying flat, not from touching that skip,
   and a build that alters the skip has changed a family-1 and family-2 behavior
   that is outside this scope.

3. **`lineage_summary`**: `tainted` (`context.py:928`) and
   `post_authoritative_taint` (`context.py:941-942`) key on reachability.
   **Measured constraint, recorded so a non-change is not read as a failure:
   `tainted` provably cannot change value.** A reachable entry exists only if an
   untrusted ancestor is already in the log, so `tainted` is already `True`
   whenever broadening adds anything. Only `post_authoritative_taint` can move,
   and it moves in one direction.

4. **`untrusted_sources`** (`context.py:1194-1195`): reports the reachable set,
   which expands `context_provenance_ids` on denial records via `gate.py:351` and
   `gate.py:2395`.

5. **`novel_lineage_check`: UNTOUCHED.** Its authority dispatch at
   `context.py:1250-1255`, including the DERIVED drop at `:1255`, stays
   byte-identical. This is the load-bearing exclusion of the whole increment.

---

## 2. ACCEPTANCE CRITERION

Per AM20.6, literal byte-equality is unachievable on linked paths by design, so
the criterion is a verdict floor plus an enumerated set of permitted citation
changes, with the discriminating sessions as the actual evidence. Three parts,
all required.

### 2.A The decision-time file

`tests/test_v16_crosshop_decision_time.py` gates in mirrored halves: 5
unconditional tests, 7 gated on the discriminator's ABSENCE (the shipped
baselines), and 8 gated on its PRESENCE (the after-pins), 20 in total. Derived
from that structure, not guessed:

```
today       12 passed,  0 failed,  8 skipped
after build 13 passed,  0 failed,  7 skipped
```

All 8 after-gated tests flip from skipped to judged and pass. All 7 shipped
baselines go dormant. The 5 unconditional guards pass in both worlds, so no
vacuous state exists at any point: the non-vacuity floor is never itself gated.

Full suite, on the same derivation: `1417 passed / 0 failed / 8 skipped` becomes
**`1418 passed / 0 failed / 7 skipped`**.

### 2.B Verdict floor on all shipped suites

Unchanged verdicts required from: the 399-test decision-time regression floor (16
files), the crosshop acceptance file at `41 passed / 0 failed / 0 skipped`, and
both adapter suites' single-hop tests including the two
`test_two_hop_laundering_slips` tests, which per section 2 of
`PREDICTIONS_crosshop.md` are section-3 cases and are predicted UNCHANGED.

**This floor is a NECESSARY CONDITION and is NOT acceptance evidence, and that
must not be forgotten when the results come in.** AM20.1 measured why: those 399
tests produce 661 provenance writes carrying zero recorded links, so
`_taint_reachable` and the flat test return identical values on every path they
drive. The floor is vacuously safe. **A green floor must never be cited as
validation of increment 3.** The evidence is part 2.A.

### 2.C Permitted citation changes, enumerated

On linked paths, and ONLY there, the following movements are permitted:

| session | permitted movement |
|---|---|
| gap A control | reason `novel_lineage` to `param_lineage` |
| split classification | reason `novel_lineage` to `param_lineage` |
| P5 paraphrase | `ALLOW` to `DENY:param_lineage` |
| post-authoritative ordering | `ALLOW` to `DENY:untrusted_lineage`, the session-write-gate consequence, pinned in the corpus |
| any linked session | `context_provenance_ids` may GROW, measured 1 row to as many as 5 on the crosshop sessions |

**Any reason movement or citation change outside this enumeration is an audit
trigger, not a permitted change.** In particular a reason moving to
`novel_lineage` where it was previously something else, or a denial reason
disappearing, is outside the set.

The one row that must NOT move is stated separately because it is the point of
the scope: **`gap A, auth-substring token` must keep `DENY:novel_lineage`,
byte-identical.**

---

## 3. THE PINNED INCONSISTENCY

Option (a)'s cost is a predicted and TESTED property, not an incidental behavior,
and this freeze cites it as such.

On the `split classification` session, `request_metadata` must record BOTH
classifications for the one token `escalations@vendor-newdomain.example`:
`novel_lineage` reporting `classification == "novel"` per the flat check, and
`param_lineage` reporting a match with a non-empty `untrusted_provenance_id` per
the broadened one. `param_lineage` decides the verdict, per gate ordering
(`gate.py:808` before `:823`), so the request denies with reason `param_lineage`.

The corpus session declares the exact shape and
`test_after_split_classification_is_recorded_by_both_checks` asserts it. Those
two values are precisely what `gate.py:815` and `gate.py:829` write into
`request_metadata`, so pinning the checks pins the record.

A build in which only one of the two speaks has not implemented option (a): if
only `param_lineage` speaks, `novel_lineage` was broadened too (option (b)); if
only `novel_lineage` speaks, the broadening never reached
`parameter_lineage_check`.

---

## 4. FALSIFIERS

Stated before the measurement so that no result is reconciled after the fact.

1. **Any after-gated decision-time test failing once the symbol lands.**
2. **The `gap A, auth-substring token` row losing its `DENY:novel_lineage`.**
   This is the row option (a) exists to protect. Its failure means
   `novel_lineage_check` was touched or the build drifted to option (b), and it
   is the single most diagnostic row in this increment.
3. **Any verdict floor test changing verdict** (2.B), including the adapter
   suites.
4. **Any reason or citation movement outside the 2.C enumeration.**
5. **The split-classification metadata not matching its declared shape** (section
   3), in either direction of the two failure readings given there.
6. **Full-suite delta beyond the mirrored decision-time flips**, that is anything
   other than `1417 / 0 / 8` becoming `1418 / 0 / 7`.

Any of these is an audit trigger: investigate before proceeding, never reconcile
after. Deviations go in a dated amendment, as with families 1 and 2, and this
file is not edited once the increment launches.

---

## 5. CONFIDENCE LABELING

Per the standing discipline, and because AMENDMENT 4's own retro-note recorded
that an unlabeled figure once shipped into a build.

- **SIMULATION-BACKED**: the five sessions' after-values in 2.A and 2.C. Each was
  measured under an option-(a) emulation during the corpus-promotion pass
  (`500e6d1`), broadening the three sites by relabeling taint-reachable entries
  while holding `novel_lineage_check` on the flat view. That is emulation of the
  mechanism, not the mechanism.
- **MEASURED**: the shipped baselines in every triple above, the 399-test floor's
  vacuous safety (AM20.1: 661 writes, 0 kwargs, 0 links, 0 predicate
  disagreements), the citation growth of 1 row to 5, and the Gap A, B, C, D, E
  results of AM22.
- **SPEC-DERIVED**: the post-build file triple in 2.A and the full-suite triple.
  Both are read off the harness's gating structure (5 unconditional, 7
  shipped-gated, 8 after-gated) rather than observed, since the mechanism does not
  exist to observe.

**All figures here are PREDICTIONS to be re-checked against the built increment,
and any mismatch is an audit trigger** of the same kind as those in section 4.

---

## 6. CONDITIONS

- Frozen baseline engine: this branch's tip with increments 1 and 2 built and no
  decision-time change, measured at the four triples in the status section.
- Frozen corpus: `tests/test_v16_crosshop_decision_time.py` (5 sessions) and
  `tests/crosshop_corpora/` (17 sessions). An edit to either invalidates the
  figures here. The five decision-time sessions depend on their exact
  authoritative wording: the `gap A` and `gap A control` pair differ ONLY in the
  user's phrasing, and that difference is the mechanism isolation.
- Frozen spec: `PREDICTIONS_crosshop.md` AM7 item 5, AM20 through AM24. This
  document selects the option AM23.4 left open; it does not amend that record.
- Nothing in this scope modifies any adapter, any family-1 or family-2 code, the
  auth-substring skip, or `novel_lineage_check`.
- Verification: run the decision-time file and compare against 2.A, check the
  must-not-regress row by name, run the 2.B floor, then compare the full-suite
  delta. Cite part 2.A as the evidence and never part 2.B.

## 7. FOLLOW-UP, not done in this pass

This freeze CLOSES AM23.4's open decision. The cross-reference is completed by a
dated amendment to `docs/PREDICTIONS_crosshop.md` recording that AM23.4 is
resolved by this document, as a POINTER rather than a restatement, so the two
records cannot drift apart. **That amendment is deliberately NOT written in this
pass** and is the next documentation task.

## 8. Reproduction of status

No increment-3 mechanism code exists. The scope decision recorded in section 0
follows from the measurements in AMENDMENT 4 (AM20 through AM24), themselves
produced by two read-only passes, and the after-values were measured under
emulation in the corpus-promotion pass. Nothing in `agentlock/` was modified by
any of them. This file is the prediction of record for build increment 3.
