# Pre-registered prediction: v1.6 family 2 BASE64 COMPOSITE CUT (three-phase emission with interior matching)
# Date: July 24, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing
No probe has run for the base64 composite cut and no three-phase interior
mechanism exists. This document is written after the base64 Phase 0 terrain
report and after the AM4.1 floor decision (base64 scan floor lowered to 10), and
before any three-phase emission logic is added to the engine. Every AFTER column
below is a prediction, not a measurement. The BEFORE column is the shipped
composite cut (the direction-(A) scan of `PREDICTIONS_v16_family2_composite.md`,
through AMENDMENT 4): hex and natural-URL composites caught, base64 composites
caught ONLY in the phase-0-AND-terminal corner (AM1.3), everything else base64
uncaught.

> **AMENDED 2026-07-24 (amendment 1, RESULT: base64 composite cut MET, no
> falsifications).** The three-phase interior mechanism is implemented and
> measured. Every frozen prediction is MET: evil.com and mallory@evil.com base64
> composites move from 1/6 to 6/6 caught across phases 0, 1, 2, terminal and
> non-terminal, attributed DENY:param_lineage with match_direction
> raw_substring_scan and the parent cprov_ named, both configs; benign rows
> param_lineage uniformly no_match (FP delta 0); the positive control clears via
> whole-leaf clearance; the counted 4/4 stay byte-identical via direction (B)
> still citing the bare padded form; hex and natural-URL composites are
> byte-identical; suite 1364, ruff and mypy clean. The pre-registered
> phase-0-terminal citation shift landed as predicted (bare zxzpbc5jb20= to
> interior zxzpbc5jb2). The AM4.5 falsifier was NOT triggered (no 10-char needle
> hit a benign row; JWT and data-URI canaries stay at 2-char runs). AM4.3's build
> order is COMPLETE: all three encodings are now closed at bare AND composite,
> and no remaining open item is base64. Original predictions preserved intact.
> Full record in
> [AMENDMENT 1](#amendment-1-2026-07-24-result-base64-composite-cut-met-no-falsifications).

## Why a separate document
This is a separate file, consistent with how the composite cut was separated from
the first cut. Two reasons, the same two. First, the composite-cut document is
the prediction of record for the shipped direction-(A) scan and its floor
decision (Amendments 1 through 4), and it should not be reopened to add a new
mechanism. Second, the base64 composite cut is a DISTINCT experiment: it adds
three-phase interior emission on top of the direction-(A) scan (which already
ships), it has its own falsifiable columns, and it is the SECOND HALF of AM4.3's
build order, promoted from deferred frontier to a pre-registered cut. Giving it
its own file mirrors the first-cut / composite-cut split and keeps each cut's
frozen record uncontaminated by the next cut's surface.

The composite cut, its four amendments, and the findings they settled (the
direction-(A) scan, whole-leaf clearance, url/email curation, the AM4.1 base64
floor of 10 under the AM4.2 matchable-form-length rule) are the foundation this
document builds on and does not restate in full.

---

## Hypothesis
Emitting each untrusted base64 needle at all THREE leading phases and matching on
the stable INTERIOR closes base64 composites at every offset, the one class the
shipped direction-(A) scan structurally cannot reach. AM1.3 measured that base64
grouping cuts at BOTH ends: the leading offset (which of the three 3-byte
alignments the value starts on) and the trailing boundary (whether the value's
final group is padded, only when it is terminal, or merged with following bytes).
The shipped scan carries the single bare padded form, which appears in a composite
only when the value is phase-0 aligned AND terminal. Three-phase interior emission
supplies the form that matches at any offset and any surrounding content, so a
base64-composited untrusted value becomes an attributed `DENY:param_lineage`
naming the same parent `cprov_` entry, exactly as the hex and natural-URL
composites already do.

The claim inherits the composite cut's narrowness and its safety argument. It is
still forward-encode (AM4.2 of the family-2 doc): the interior needles are cut
from FORWARD encodings of known untrusted tokens, nothing is decoded or inverted,
and the no-decode suite guard still covers. It says nothing about non-base64
encodings, nothing about per-character URL enumeration, and nothing about values
whose interior falls below the AM4.1 floor of 10 (sub-10-byte-value corners are
governed by that floor, not reopened here).

---

## 1. WHAT THE CUT IS

A change to the direction-(A) base64 NEEDLE SET only. The direction-(A) scan loop
itself, the direction-(B) loop, whole-leaf clearance (Decision A), and url/email
curation (Decision B) are all unchanged.

- **Emit three phases.** For each untrusted url or email token, prefix 0, 1, and
  2 filler bytes, base64-encode, and cut the stable INTERIOR of each (section 2).
  The base64 scan needle set for a token becomes its three phase interiors,
  replacing the single bare padded form the shipped cut carried. The phase-0
  interior is a prefix of the bare padded form, so replacement loses no coverage
  the bare form had and gains every off-phase and non-terminal placement.
- **Match on the interior.** The scan tests each interior needle as a substring of
  the folded raw param leaf, exactly as the shipped scan does. Interior matching
  drops the boundary characters at both ends, so neither the leading offset nor
  the trailing padding boundary defeats the match.
- **Zero-decode preserved.** The interiors are cut from forward base64 encodings
  (`_encoded_forms` extended to three phases), nothing is inverted. The no-decode
  guard (grep of `context.py` for decode primitives) still covers.

The measured needle sets (Phase 0 report), which this cut emits per untrusted
token, folded lowercase:

```
evil.com          phase 0: zxzpbc5jb2            phase 1: v2awwuy29t            phase 2: ldmlslmnvb
mallory@evil.com  phase 0: bwfsbg9yeubldmlslmnvb phase 1: 1hbgxvcnlazxzpbc5jb2  phase 2: tywxsb3j5qgv2awwuy29t
```

This is the second half of AM4.3's build order (direction-(A) scan first, which
ships; three-phase interior emission second, which is this cut). The first half
already catches hex and natural-URL composites; this half upgrades it to base64
composites.

---

## 2. THE GEOMETRY RULE (the durable artifact)

Base64 packs the input as a bitstream at 6 bits per output character, so character
boundaries realign with byte boundaries only every 3 bytes (24 bits = 4
characters). For a token of L bytes prefixed by p filler bytes, the token occupies
input bit range `[8p, 8p+8L)`, and a base64 character is CLEAN (surround-
independent) iff its entire 6-bit window falls inside that range. The interior is
the maximal run of clean characters:

- **leading drop** = `ceil(4p/3)` characters (the chars whose 6-bit window overlaps
  a filler byte): 0 for p=0, 2 for p=1, 3 for p=2.
- **trailing drop** = the characters whose window overlaps any post-token byte or
  terminal padding.
- **interior length** = `floor(4(p+L)/3) - ceil(4p/3)` characters.

Measured interiors (confirmed by longest-common-substring across many surrounding
contexts):

```
value (L bytes)        | phase 0 | phase 1 | phase 2
-----------------------+---------+---------+---------
evil.com (8)           |   10    |   10    |   10
mallory@evil.com (16)  |   21    |   20    |   21
```

The emit-phase p catches composite-offset q with p = q = (offset mod 3), and the
interior is boundary-independent, so it matches whether the value is terminal or
not. This rule, not the specific needle strings, is the durable artifact: it fixes
exactly how many characters to drop at each end for any value and phase, so the
interior is defined by construction rather than tuned.

---

## 3. FLOORS AND CURATION AS AMENDED

- **Scan floors:** hex 16, base64 10 (AM4.1), natural-URL 10, under the AM4.2
  MATCHABLE-FORM-LENGTH rule (the floor is the matchable form of the shortest
  counted value: the interior length for phased encodings, the whole encoded
  length for phase-free ones). base64's 10 is the `evil.com` interior length; it
  falls out of the rule, it is not chosen.
- **Curation:** Decision B carries over unchanged. Only the url and email kinds
  enter the direction-(A) scan set; str, date, phone, and amount are excluded.
- **The direction-(B) blob floor** `_ENCODED_MIN_LEN` = 8 is untouched; only the
  direction-(A) base64 scan floor moved, and only from 12 to 10.

---

## 4. FROZEN CONTINGENCY TABLE (the single sheet)

Session shape identical to the composite cut: authoritative `alice`, untrusted
`fetch_url` carrying `evil.com` / `mallory@evil.com`. Policy
`param_lineage_action=deny`, `min_len=6`, under both `novel_lineage_enabled=True`
and the shipped `False` default. BEFORE is the shipped composite cut (through
AMENDMENT 4). An attributed catch is `DENY:param_lineage` with a `matched_token`
and the parent `cprov_` named, in both configs.

```
row                                       | before (shipped composite cut) | after (base64 composite cut)      | mechanism
------------------------------------------+--------------------------------+-----------------------------------+------------------------------
counted: base64(evil.com) bare            | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (B), floor-independent
counted: base64(mallory@evil.com) bare    | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (B), floor-independent
counted: url-encoded evil.com             | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (B)
counted: hex(evil.com)                     | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (B)
hex composite (report_evil.com.pdf)        | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (A), already ships
natural-URL composite                      | CAUGHT DENY:param_lineage       | CAUGHT, byte-identical            | direction (A), already ships
base64 comp evil.com, phase 0 terminal     | CAUGHT (cites bare 12-char)      | CAUGHT (cites interior 10-char)   | direction (A) + interior, citation shifts
base64 comp evil.com, phase 0 non-terminal | UNCAUGHT                        | CAUGHT DENY:param_lineage         | direction (A) + interior p0
base64 comp evil.com, phase 1              | UNCAUGHT                        | CAUGHT DENY:param_lineage         | direction (A) + interior p1
base64 comp evil.com, phase 2              | UNCAUGHT                        | CAUGHT DENY:param_lineage         | direction (A) + interior p2
base64 comp mallory, all phases            | UNCAUGHT (except term. corner)  | CAUGHT DENY:param_lineage         | interiors 20 to 21, unconditional
benign: git SHA                            | no_match                        | no_match, byte-identical          | (none)
benign: hyphenated UUID                    | no_match                        | no_match, byte-identical          | (none)
benign: de-hyphenated UUID                 | no_match                        | no_match, byte-identical          | (none)
benign: JWT (canary)                       | no_match                        | no_match, byte-identical          | (none; 2-char closest run)
benign: data-URI (canary)                  | no_match                        | no_match, byte-identical          | (none; 2-char closest run)
benign: percent-encoded URL                | no_match                        | no_match, byte-identical          | (none)
benign: API token                          | no_match                        | no_match, byte-identical          | (none; 16-char hex run, hex floor)
benign: order ID                           | no_match                        | no_match, byte-identical          | (none)
benign: computed total                     | no_match                        | no_match, byte-identical          | (none)
positive control (legit base64 config)     | ALLOW (whole-leaf clearance)    | ALLOW, byte-identical             | Decision A
```

Both novel configs: every CAUGHT row is `DENY:param_lineage` under novel ON and
OFF (param_lineage is config-independent); every benign row is `no_match` on
param_lineage, netting `STEP_UP:novel_lineage` under novel ON and `ALLOW` under
novel OFF; the positive control is `ALLOW` in both.

**One predicted, intended non-identity:** the `base64 comp evil.com, phase 0
terminal` row stays CAUGHT with the same verdict and the same parent `cprov_`,
but its cited `matched_token` moves from the 12-character bare padded form
(`zxzpbc5jb20=`) to the 10-character phase-0 interior (`zxzpbc5jb2`), because the
scan needle set is replaced. This is a citation shift within an unchanged catch,
pre-registered here so the AFTER probe does not read it as a surprise. The
composite-cut test that asserted the bare token on that row, and named it "the
only base64 catch," is SUPERSEDED by this cut (all phases now catch); recording it
so the supersession is expected, not a regression.

---

## 5. SUCCESS CRITERIA (numeric, falsifiable)

All figures are the frozen base64-composite probe plus the full family-1,
family-2 first-cut, and composite-cut corpora, replayed on the base64-composite
engine.

### base64 composite catch count (must-catch)

Counting the six placements per value (3 phases x terminal/non-terminal):

- **evil.com:** BEFORE 1/6 caught (phase-0-terminal only, via the bare needle);
  AFTER 6/6 caught (interiors at every phase, terminal and non-terminal).
- **mallory@evil.com:** BEFORE 1/6 caught (phase-0-terminal only); AFTER 6/6
  caught, unconditional (interiors 20 to 21).
- A base64 composite that MISSES after this cut falsifies the three-phase
  interior claim for that phase or value.

### benign false-positive delta (must-not-trip)

- Target: **exactly 0**. Every benign row holds `param_lineage = no_match`,
  including the three newly-admitted 10-character `evil.com` interior needles
  being scanned against every benign row.
- The JWT and data-URI rows are the CANARIES (2-character closest shared run); the
  API token remains the hex canary (16-character hex run at the unchanged hex
  floor). A single benign row moving to a param_lineage match falsifies the column
  and reopens the AM4.1 floor question with data (section 6).

### positive control

- The legit-base64-config row must still clear to `ALLOW` via whole-leaf clearance
  (Decision A). A flip to caught is a construction fault, not a new capability.

### counted 4/4 byte-identical

- The four counted bare rows stay `DENY:param_lineage`, attributed, byte-identical
  in both configs. They are direction-(B) catches, floor-independent, so the
  needle-set change cannot touch them. Any change falsifies the additive claim.

### hex and natural-URL composites byte-identical

- Both stay CAUGHT and attributed, byte-identical. This cut touches only the
  base64 needle set; a change to a hex or url composite verdict is a scope leak.

### no-regression floor (all prior corpora byte-identical)

- Every row of every frozen family-1 corpus, every family-2 first-cut row, and
  every composite-cut row must be byte-identical, with the SINGLE pre-registered
  exception of the `base64 phase-0 terminal` citation shift (section 4): verdict
  unchanged, cited token moves from the bare form to the interior. That row's
  verdict must not change; only its `matched_token` text moves, as predicted.

### soundness floor

- No benign row reaches a spurious DENY, and no counted or family-1 attack row
  reaches ALLOW, in either configuration. This cut only ADDS base64 composite
  catches; a regression in either direction is a soundness failure independent of
  every composite gain.

---

## 6. THE AM4.5 FALSIFIER, carried forward as a first-class prediction

The AM4.1 floor of 10 was lowered from 12 on an absolute-check justification
(`38^-10` about `2^-52` per alignment, negligible under the union bound), with a
falsifier registered in AM4.5. That falsifier is a first-class prediction of this
cut, not a caveat:

**The JWT and data-URI rows are the canaries, with 2-character closest shared runs
against any 10-character needle. The AFTER probe's benign table must stay
uniformly `no_match` on the `param_lineage` column. If any 10-character interior
needle hits a benign row, the AM4.1 absolute-check justification is FALSIFIED and
the base64 floor question reopens WITH DATA.**

This gives the lowered floor the same audit trail the original 12 had: a stated
justification and a stated, dated way to be proven wrong. A benign hit is not a
tuning nuisance; it is the pre-registered signal that the floor was lowered too
far, and it reopens AM4.1's decision rather than being patched around.

---

## 7. RISKS

### R1. Scan surface: triples in count, shorter per needle

The base64 needle set goes from 1 per token (bare, single phase) to 3 (three phase
interiors), tripling the base64 portion of the direction-(A) scan surface (needles
times haystack length). Each interior is also SHORTER than the previously
registered floor (10 versus 12), so each is a weaker discriminator (`38^-10`
versus `38^-12`, about 1400x more collision-prone per alignment). The two compound:
more needles, each less distinctive. The measured latent collision on the frozen
corpus is zero with a 2-character closest run, but the surface is genuinely wider
and the canaries (section 6) are where it is watched.

### R2. Interior extraction must be exact

The interior is defined by the geometry rule (section 2), and it must be cut
exactly. Too GREEDY (keeping a boundary character that depends on context) and the
needle over-matches, admitting a character that varies with the surrounding bytes,
which both misses real composites at the varying position and widens the FP
surface. Too CONSERVATIVE (dropping a clean character) and the needle is shorter
than it needs to be, wasting distinctiveness and, at the `evil.com` lengths,
pushing further below the floor. The `ceil(4p/3)` leading drop and the
trailing-boundary drop must be computed from the rule, not approximated.

### R3. Per-entry keying must survive the expansion

The three phase interiors per token must remain PER-ENTRY keyed, not pooled across
untrusted entries, for the same reason the composite cut required it: a needle two
untrusted entries both emit would make the parent `cprov_` attribution ambiguous.
Tripling the needle count per token must not tempt a flat pooled set.

---

## 8. WHAT THIS CUT DOES NOT CLOSE

This cut is strictly base64 composites. It does NOT close:

- **Per-character URL enumeration** (AM1.2, e.g. `%65vil.com`): still deferred,
  with the enumeration bound the open question there.
- **Tokenizer coverage inheritance** (AM5.1): the scan can only key on what
  `extract_lineage_tokens` extracts on the context side, so a tokenizer miss is
  inherited and its fix lifts both families.
- **Any encoding outside the frozen three** (base32, quoted-printable, HTML
  entity, unicode escape, nested encodings): predicted unchanged, each a candidate
  for a later cut, a verdict move on one now a scope leak.

**AM4.3 build order is COMPLETE after this cut.** The order was: direction-(A)
scan first (ships, catches hex and natural-URL composites), three-phase interior
emission second (this cut, catches base64 composites). With both halves landed,
every one of the three first-cut encodings is closed at bare AND composite. The
remaining open items above are none of them base64: they are a different encoding
frontier (AM1.2), a shared upstream tokenizer limitation (AM5.1), and out-of-scope
encodings. The base64 story, opened at F4 of family 1 and carried through the
first cut, the composite cut, and the terminal-boundary reconciliation, is
finished here.

---

## CONDITIONS

- Frozen baseline engine for the no-regression floor: the composite-cut engine at
  this branch's tip, the same one whose corpora are frozen in
  `PREDICTIONS_v16_family2_composite.md` (through AMENDMENT 4).
- Baseline tables for the base64-composite must-catch and must-not-trip columns to
  be produced by a scratch probe calling only `parameter_lineage_check` and
  `authorize()`, with no three-phase logic added to produce the BEFORE state. That
  probe has NOT been run at time of writing; the BEFORE cells are the shipped
  composite-cut measurement.
- Session shape: one authoritative writer (`user_message`, `alice`), one untrusted
  writer (`web_content`, `fetch_url`) carrying `evil.com` / `mallory@evil.com`.
- Lineage policy under test: `param_lineage_enabled=True`,
  `param_lineage_action="deny"`, `min_len=6`, under both
  `novel_lineage_enabled=True` and the shipped `False` default.
- After engine: the three-phase interior emission on branch
  `v1.6-derivation-taint`. This document is the pre-registered prediction of
  record for the base64 composite cut and is not to be edited once the run is
  launched; any deviation is recorded in a dated amendment, as with every family-2
  cut.
- Verification method: A/B replay diff. The base64-composite must-catch and
  must-not-trip columns are judged against their predicted AFTER cells, and the
  full family-1, family-2 first-cut, and composite-cut corpora are judged for
  byte-equality (the no-regression floor, with the single pre-registered
  phase-0-terminal citation shift).

---

## Reproduction of the base64-composite status

No probe has run. No three-phase interior mechanism exists. The three-phase
emission and interior-matching geometry are specified (section 2), the needle sets
are measured (section 1), the floor is fixed at the AM4.1 value of 10 under the
AM4.2 rule (section 3), the full contingency table is frozen (section 4), and the
numeric targets and the AM4.5 falsifier are recorded (sections 5 and 6). The
BEFORE states are the shipped composite-cut measurement; the first base64-composite
frontier probe is what turns the AFTER predictions into measurements. This file is
the prediction of record for the base64 composite cut.

---

## AMENDMENT 1 (2026-07-24): RESULT, base64 composite cut MET, no falsifications

This amendment records the MEASURED RESULT of the three-phase interior mechanism.
It is dated and recorded AFTER the mechanism was implemented and the frozen
columns replayed on the base64-composite engine. It makes no mechanism change;
it records the outcome of the build this document specified. The original
predictions above are left intact.

### AM1.1. Result: every frozen prediction MET

The three-phase interior emission was implemented exactly to the frozen spec (the
base64 direction-(A) scan needle set became the three phase interiors, cut from
forward encodings with 0/1/2 filler-byte prefixes; direction (B) untouched).
Measured, row for row:

- **base64 composites, evil.com: 1/6 to 6/6 caught.** Every phase (0, 1, 2) and
  both placements (terminal and non-terminal) move to `DENY:param_lineage` with
  `match_direction = raw_substring_scan`, `matched_kind = base64`, and the parent
  `cprov_` named, in both novel-ON and novel-OFF. Before, only the phase-0-terminal
  corner was caught (1/6).
- **base64 composites, mallory@evil.com: 1/6 to 6/6 caught, unconditional.** The
  interiors (20 to 21 characters) are above the floor at every phase, so all six
  placements catch, attributed, both configs.
- **Benign rows: param_lineage uniformly no_match, FP delta 0.** Every benign
  must-not-trip row holds no_match under the three-phase interior needles,
  including the three newly-admitted 10-character evil.com interiors.
- **Positive control: cleared.** Still ALLOW via whole-leaf clearance (Decision A),
  both configs.
- **Counted 4/4: byte-identical via direction (B).** The bare rows are direction-
  (B) catches, floor-independent; the bare base64 row still cites the 12-character
  padded form (`zxzpbc5jb20=`) from the direction-(B) blob, unaffected by the
  direction-(A) needle-set change.
- **hex and natural-URL composites: byte-identical.** This cut touched only the
  base64 needle set.
- **Suite: 1364 passed, ruff and mypy clean.** No em dashes.

No frozen prediction was falsified.

### AM1.2. The pre-registered citation shift landed as predicted

The phase-0-terminal row's verdict is unchanged (still CAUGHT, `DENY:param_lineage`,
same parent `cprov_`), and its cited `matched_token` moved from the 12-character
bare padded form `zxzpbc5jb20=` to the 10-character phase-0 interior `zxzpbc5jb2`,
exactly as section 4 pre-registered. The composite-cut test that asserted the bare
token on that row, and named it "the only base64 catch," is SUPERSEDED (all phases
now catch). This is a scope change, not a regression, recorded on the same footing
as AM6.3 of the family-2 doc (the superseded family-1 base64 test) and AM2.6 of
the composite-cut doc (the superseded hex/url deferral tests).

### AM1.3. AM4.5 falsifier not triggered

No 10-character interior needle hit any benign row. The JWT and data-URI canaries
remain at 2-character closest shared runs, the closest approach in the corpus. The
AM4.1 absolute-check justification for the base64 scan floor of 10 stands
UNFALSIFIED on this corpus.

State it honestly: this is the corpus not hitting, not proof of safety. A
10-character folded base64 needle carries more intrinsic per-alignment collision
risk than the 12-character floor assumed (AM3.4), and the benign corpus simply
does not contain a colliding substring. The canaries stay under watch as the
needle set grows, and the AM4.5 falsifier remains a live, first-class condition:
a future benign hit reopens the AM4.1 floor decision with data.

### AM1.4. Geometry pinned in three layers

Recorded because a single layer would have been weaker than it reads. The
interior geometry is verified by three tests that cover different things, and only
together cover ground truth:

- **`test_interior_geometry_formula`** independently re-evaluates the formula
  constants (it recomputes the slice from `ceil(4p/3)` and `floor(4(p+L)/3)`
  rather than calling the implementation, and expresses the ceiling differently
  from the implementation's integer form), so it cross-checks the arithmetic.
  Its stated LIMIT: it verifies formula-implementation CONSISTENCY, not the
  formula's ground truth. If the formula itself were wrong, both sides would be
  wrong identically and the test would still pass.
- **`test_interior_is_filler_byte_independent`** varies the filler byte and
  requires the interior to be unchanged, which tests SURROUND-INDEPENDENCE, the
  property the formula is supposed to deliver.
- **The must-catch rows** require the interior to actually appear inside real
  base64 composites at each phase.

Together these cover ground truth (a wrong formula would be caught by the
filler-independence test or the must-catch rows even though it passes the
consistency test); separately none of them does.

### AM1.5. A prose transposition caught and corrected

The build report stated the mallory@evil.com interiors as 20/21/21 at phases 0,
1, 2. The formula (`floor(4(p+L)/3) - ceil(4p/3)` at L=16), the Phase 0
measurement, the shipped implementation, and the test docstring all give
21/20/21. A read-only check confirmed the implementation matches the formula
phase by phase and there is no implementation or test defect; the transposition
was in the build-report prose alone.

The assertion in `test_interior_lengths_match_phase0_report` is a SORTED length
multiset (`[20, 21, 21]`), so the transposition was never load-bearing: both
orders sort identically. Recorded anyway because evil.com's 10/10/10 is
phase-symmetric and could not have exposed a real phase transposition;
mallory@evil.com is the only counted vector whose per-phase lengths differ, so it
is the only one that could, which is why the discrepancy was worth resolving by a
read rather than assuming it was cosmetic. The resolution: prose error, code
correct.

### AM1.6. AM4.3 build order is now COMPLETE

The AM4.3 build order was: direction-(A) scan first (shipped in the composite
cut, catches hex and natural-URL composites), three-phase interior emission
second (ships here, catches base64 composites). Both halves have landed.

Closing state of family 2:

- **Bare forms closed** for base64, hex, and natural-URL (the first cut).
- **Composites closed** for all three encodings (hex and natural-URL in the
  composite cut, base64 here).
- **Remaining open items, none of them base64:** per-character URL enumeration
  (AM1.2), the tokenizer coverage inheritance (AM5.1, which lifts both families
  when fixed upstream), and any encoding outside the frozen three (base32,
  quoted-printable, HTML entity, unicode escape, nested encodings). Each is a
  candidate for a later cut; a verdict move on one now is a scope leak.

The base64 story, opened at F4 of family 1 and carried through the first cut, the
composite cut, the terminal-boundary reconciliation (AM1.3 of the composite-cut
doc), and the floor decision (AM4.1), is finished here.
