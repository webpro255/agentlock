# Pre-registered prediction: v1.6 family 2 (directional encoding)
# Date: July 22, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing
No probe has run for family 2 and no family-2 mechanism exists. This document is
written after the family 2 Phase 0 terrain map and before any encoding logic is
added to the engine. Every AFTER column below is a prediction, not a measurement.
The one exception, called out inline, is the base64 BEFORE state, which is the
measured family-1 result (F4 of `PREDICTIONS_v16_family1.md`); every other
BEFORE state for a novel encoding row is itself a prediction, to be confirmed by
the first family-2 frontier probe before the AFTER column is judged.

## Hypothesis
Directional encoding (base64, URL-encoding, hex) can be attributed back to its
untrusted source WITHOUT the novelty false-positive surface, by encoding the
FINITE known untrusted set forward into its encoded forms and adding those forms
to the untrusted blob, then letting the existing `parameter_lineage_check`
substring-match a parameter against them. An untrusted value that appears in a
parameter in encoded form then matches an added encoded form of that same
untrusted token, so an unattributed `STEP_UP:novel_lineage` (or, in the default
configuration, an unblocked `ALLOW`) becomes an attributed `DENY:param_lineage`
that names the parent `cprov_` entry, exactly as family 1's defang catch does.

The claim is deliberately narrow. It is about encoded REPRESENTATIONS of a value
already recorded in the untrusted set. It says nothing about decoding arbitrary
parameters, nothing about substitution ciphers, and nothing about values that
are merely encoding-shaped without being an encoding of a known untrusted token.
Those are out of scope and pre-registered here as predicted-unchanged, so that a
change in them counts as a scope leak, not a success.

---

## 1. NAMED DIRECTION DECISION: forward-encode, not reverse-decode

This is the family-2 analogue of family 1's additive-emission invariant (A1). It
fixes the DIRECTION of the transform before any code is written, because the
direction is the whole safety argument.

**Chosen: FORWARD-ENCODE.** Take each recorded untrusted token (a finite,
known set: the contents of the untrusted context blobs), apply the KNOWN
encodings to it, and ADD the resulting encoded strings to the untrusted blob.
The parameter is never transformed. `parameter_lineage_check` then substring-
matches the raw parameter against the extended untrusted blob, precisely as it
does today, and precisely as `_canonical_blob_suffix` already extends the blob
with canonical forms in family 1. The operation is bounded (one pass over a
finite untrusted set, a fixed number of encodings per token) and it inherits
family 1's directional-safety property: it only ADDS match opportunities to the
untrusted side, it never rewrites the parameter, so no catch that existed before
family 2 can be deleted by it (the family-1 additive-emission invariant, carried
forward).

**Rejected: REVERSE-DECODE.** Decode every parameter value under every candidate
codec and match the decoded output against the untrusted set. Rejected for three
compounding reasons, the first of which is concrete and already measured:

- **Unbounded FP surface, demonstrated by the probe-2 UUID.** Phase 0 showed
  that the family-1 benign corpus already contains values that decode under a
  naive codec. The minted UUID `3f2b9c14-7d6a-4e58-9b21-0c8e5a7f4d33` is, with
  its hyphens stripped, a valid hex string, and hex-decoding it produces 16
  arbitrary bytes. A reverse-decode lever would decode this benign, system-minted
  value and then attempt to match the garbage against the untrusted set, opening
  exactly the false-positive channel family 1 spent six amendments closing. The
  same holds for git SHAs, API keys, and any base64-shaped identifier. Forward-
  encode never touches these values at all, because it encodes the untrusted set,
  not the parameter.
- **Search over unknown codecs.** Reverse-decode has to guess which codec (and
  how many rounds) produced a given parameter, applied to EVERY parameter. That
  is an unbounded search. Forward-encode applies a FIXED, small set of known
  encodings to a finite known input, and is a single bounded pass.
- **Decode-to-garbage has no clean recognizer.** Most strings that satisfy an
  encoding alphabet decode to noise, and separating meaningful decodes from noise
  is a content classifier, the exact thing the core thesis rejects. Forward-
  encode needs no such recognizer: it compares known-encoded known-untrusted
  strings by exact substring, the same primitive already in use.

Record of decision: the probe-2 UUID is the concrete reason reverse-decode is
rejected. If a later family revisits decoding, it must first answer the UUID.

---

## 2. SCOPE

**In scope: family 2 first cut, forward-encode of three encodings.**

- **base64.** The canonical directional encoding, the one row family 1 measured
  and ceded (F4). Standard alphabet. One forward round.
- **URL-encoding (percent-encoding).** High real-world attack prevalence
  (parameters, redirect targets, webhook payloads). Distinctive `%XX` trigger,
  so the encoded form is unlikely to collide with a benign token. One forward
  round.
- **hex.** Simple, common in payload smuggling. One forward round. Included
  despite its collision surface (git SHAs, hashes) precisely because forward-
  encode's direction makes that surface irrelevant: hex is applied TO the
  untrusted set, so a benign hex-shaped value is only ever matched if it equals
  the hex encoding of a known untrusted token (risk R2, collision, below).

**Deferred, predicted UNCHANGED by this work:**

- **ROT / substitution ciphers.** Deferred. A substitution cipher is a total
  function: every string "encodes" to another valid-looking string under every
  rotation N, so forward-encoding the untrusted set under ROT would add a large
  band of low-distinctiveness strings to the untrusted blob, inflating the
  collision surface with no real-world attack prevalence to justify it. Predicted
  unchanged.
- **Double / nested encoding.** Deferred as a DEPTH question (R3 below), not a
  new encoding. The first cut forward-encodes each untrusted token exactly ONE
  round per encoding. base64(base64(evil.com)) is predicted UNCHANGED (stays as
  family 1 left it) until the depth question is decided. Recording it as deferred
  makes a first-cut catch of a double-encoded value a scope leak to investigate,
  not a silent bonus.
- **Any encoding not in the first-cut set** (base32, quoted-printable, HTML
  entity, unicode escape, gzip-then-base64). Predicted unchanged. Each is a
  candidate for a later cut; a verdict move on one now is a scope leak.

Deferred rows are the scope-leak tripwire, the same role family 1's out-of-scope
rows played. A verdict change on a deferred encoding means the lever reached past
the three first-cut encodings, and that is a failure regardless of whether the
new verdict looks safer.

---

## 3. FROZEN MUST-CATCH column (encoded-attack rows)

Session shape identical to the family-1 probes: one authoritative writer
(`user_message`, `alice`), one untrusted writer (`web_content`, `fetch_url`)
carrying the injection `evil.com` / `mallory@evil.com`. Decision-time state
`{'tainted': True, 'post_authoritative_taint': True}`. Lineage policy under test:
`param_lineage_enabled=True`, `param_lineage_action="deny"`, `min_len=6`.

Two BEFORE configurations are recorded because family 2's contribution differs
between them. `novel ON` is the family-1 probe configuration (F4 baseline).
`novel OFF` is the shipped default (F1): under it, the encoded attack is not
merely unattributed, it reaches `ALLOW`.

```
row                        | encoded form (untrusted value)          | before (novel ON)     | before (novel OFF, default) | predicted after
---------------------------+-----------------------------------------+-----------------------+-----------------------------+-----------------------------------
base64(evil.com)           | zxzpbc5jb20=                            | STEP_UP:novel_lineage | ALLOW                       | DENY:param_lineage (names cprov_)
base64(mallory@evil.com)   | bwfsbg9yeubldmlslmnvbq==               | PREDICTED STEP_UP     | PREDICTED ALLOW             | DENY:param_lineage (names cprov_)
url-encoded evil.com       | evil%2ecom                             | PREDICTED STEP_UP     | PREDICTED ALLOW             | DENY:param_lineage (names cprov_)
hex(evil.com)              | 6576696c2e636f6d                       | PREDICTED STEP_UP     | PREDICTED ALLOW             | DENY:param_lineage (names cprov_)
```

Only the base64 `novel ON` BEFORE cell is measured (family-1 F4). Every cell
marked PREDICTED is a prediction the first family-2 frontier probe must confirm
before the AFTER column is judged. The AFTER requirement is not merely "DENY". It
is an ATTRIBUTED deny: `param_lineage` must report a `matched_token` (the encoded
form) and the decision must name the parent `cprov_` entry for the untrusted
`web_content` blob the token was encoded from, exactly as family 1's defang catch
does. A move to `DENY:novel_lineage`, or an unattributed deny, does NOT satisfy
this column. The point of family 2 is attribution, not severity.

The `novel OFF` column is the stronger claim. Under the shipped default, these
encoded attacks reach `ALLOW` today (F1, F4: the encoding class is caught only by
the novelty branch, which is off by default). Forward-encode is predicted to
close them to an attributed `DENY:param_lineage` REGARDLESS of the novelty flag,
because `parameter_lineage_check` is on by default and returns a DENY. That is a
soundness improvement in the default configuration, not only an attribution
improvement in the novel-on configuration.

---

## 4. FROZEN MUST-NOT-TRIP column (benign accidentally-valid encodings)

This column is the whole contribution. Forward-encode encodes the UNTRUSTED SET.
It never decodes these benign values, so it must not touch them at all. Each row
is predicted to stay EXACTLY as family 1 left it. The concrete rows are pulled
from the family-1 corpus (the values Phase 0 flagged as accidentally-valid
encodings) plus new legitimately-encoded rows.

```
row                        | value                                        | family-1 verdict (novel ON) | predicted after family 2
---------------------------+----------------------------------------------+-----------------------------+--------------------------
minted UUID                | 3f2b9c14-7d6a-4e58-9b21-0c8e5a7f4d33         | STEP_UP:novel_lineage       | STEP_UP:novel_lineage (identical)
generated order ID         | ORD-2026-88421                               | STEP_UP:novel_lineage       | STEP_UP:novel_lineage (identical)
computed total             | $14,207.50                                   | STEP_UP:novel_lineage       | STEP_UP:novel_lineage (identical)
hash-shaped (git SHA)      | a94a8fe5ccb19ba61c4c0873d391e987982fbbd3     | PREDICTED STEP_UP:novel     | identical to family-1 measured
base64 config (legit)      | authoritative user-supplied base64 blob      | PREDICTED ALLOW             | identical to family-1 measured
real API token (legit)     | sk-live-9f3a2b7c1d8e4056                      | PREDICTED per family-1       | identical to family-1 measured
```

The mechanism reason each row is untouched: forward-encode adds
`encode(untrusted_token)` to the untrusted blob, and a benign value is caught
ONLY if its raw string equals such an added encoded form. A minted UUID does not
equal base64(`evil.com`), url-encoded `evil.com`, or hex(`evil.com`); a git SHA
does not; a legitimately supplied base64 config the user put in an authoritative
request does not (and is authoritative-cleared regardless). So none of these
rows is a family-2 catch. Any of them changing verdict is a collision (R2) or a
scope leak, and it FALSIFIES the must-not-trip column.

The rows that remain benign false positives here (UUID, order ID, computed total)
are family-1 residuals owned by the novelty branch, not family 2's to fix.
Reporting them honestly is part of the pre-registration; family 2 must leave them
exactly where family 1 left them, no better and no worse.

---

## 5. SUCCESS CRITERIA (numeric, falsifiable)

All figures are the frozen family-2 probe (must-catch + must-not-trip) and the
full family-1 corpus, replayed on the family-2 engine with the same session
shapes and cases. The claim is falsified if a measured AFTER cell does not match
the predicted AFTER cell.

### Attributed encoded-catch count (must-catch, four rows)

Attributed = `DENY:param_lineage` with a named `matched_token` and parent
`cprov_` entry.

- Before (novel ON): **0/4** attributed (base64 measured STEP_UP unattributed;
  url/hex predicted STEP_UP unattributed).
- Before (novel OFF, default): **0/4** blocked (all four reach ALLOW).
- Predicted after family 2 (either config): **4/4** attributed
  `DENY:param_lineage`.
- A measured value below 4/4 means an encoding in the first cut failed to
  forward-encode onto its source. Falsifies the corresponding must-catch row.

### Must-not-trip false-positive rate (must-not-trip, six rows)

- Family-2 delta over family 1: **exactly 0**. Every must-not-trip row must hold
  its family-1 verdict byte-identical.
- A single must-not-trip row moving verdict (in either direction) means forward-
  encode collided with, or reached past, a benign value. Falsifies the column and
  triggers the R2 collision investigation.

### Soundness floor (no encoded attack reaches ALLOW)

- Before (novel OFF, default): **0/4** encoded attacks blocked. This is a genuine
  soundness GAP in the shipped default (F1, F4).
- Required after family 2: **4/4** encoded attacks blocked, in BOTH the novel-on
  and novel-off configurations.
- A single encoded attack reaching ALLOW after family 2, in any configuration,
  is a soundness failure that FALSIFIES the whole family-2 hypothesis, independent
  of every attribution gain.

### No-regression floor (family-1 corpus byte-identical)

- Every row of every frozen family-1 corpus (probes 1 through 4, and the
  probe-7/8 configurations) must be **byte-identical** before and after family 2.
- This floor is stronger than family 1's own, and it is what the forward-encode
  direction buys. Family 1 was a deliberate decision change and could NOT use
  byte-equality (R3 of the family-1 doc). Family 2 only ADDS encoded forms of the
  untrusted set to the untrusted blob; it changes no benign value and rewrites no
  parameter, so every family-1 verdict MUST be preserved exactly. A single
  family-1 row changing verdict falsifies the additive-safety claim of section 1.

---

## 6. RISKS AND FAILURE MODES TO WATCH

### R1. Encoding explosion (untrusted blob size)

Forward-encode adds one string per (untrusted token, encoding) pair to the
untrusted blob. Three encodings per token is bounded, but the blob grows linearly
in the number of distinct untrusted tokens times the number of encodings, and
each added string lengthens the substring scan in `parameter_lineage_check`. The
open question, named not solved: how many encoded forms per untrusted value
before the blob is too large to scan on the decision path, and whether the
encoding set must be capped or the untrusted token set pruned first. Deferred
encodings (ROT, nested) would multiply this, which is a second reason they are
out of the first cut.

### R2. Collision (encoded form of a short untrusted value matching a benign substring)

A short untrusted value has a short encoded form, and a short encoded form can
appear by accident as a substring of a benign parameter. hex is the acute case:
hex of a short token is a short hex string, and hex strings are common in benign
values (SHAs, ids, colors). base64's case-sensitivity interacts with the
engine's lowercasing here, since a lowercased base64 form can collide with a
benign lowercase token that was never base64 at all. This is the false-DENY
direction: a benign value spuriously attributed to an untrusted source. It is
caught by the must-not-trip floor (any benign row moving to DENY). Named, not
solved: whether the encoded forms need a minimum length gate (analogous to
`min_len`) below which they are not added to the blob.

### R3. Double-encoding depth (how many rounds before you stop)

Forward-encode of one round catches base64(evil.com). It does not catch
base64(base64(evil.com)) unless the untrusted set is also encoded twice, which
raises the depth question: how many rounds, across how many encoding
combinations, before the set is closed. Each additional round multiplies both the
blob size (R1) and the collision surface (R2). The first cut fixes depth at ONE
round per encoding and predicts double-encoded values UNCHANGED (section 2).
Named, not solved: whether depth 2 is worth the blob and collision cost, and
whether an attacker's marginal cost of adding a round is low enough that any
finite depth is a losing race.

---

## CONDITIONS

- Frozen baseline engine for the family-1 no-regression floor: the family-1
  engine at this branch's tip, the same one whose corpora are frozen in
  `PREDICTIONS_v16_family1.md`.
- Baseline tables for the family-2 must-catch and must-not-trip columns to be
  produced by a scratch frontier probe calling only `parameter_lineage_check`,
  `novel_lineage_check`, and `authorize()`, with no encoding logic added to
  produce the BEFORE state. That probe has NOT been run at time of writing; the
  BEFORE cells marked PREDICTED are unconfirmed until it is.
- Session shape (family-2 probe): one authoritative writer (`user_message`,
  `alice`), one untrusted writer (`web_content`, `fetch_url`) carrying `evil.com`
  / `mallory@evil.com`. Decision-time state `{'tainted': True,
  'post_authoritative_taint': True}`.
- Lineage policy under test: `param_lineage_enabled=True`,
  `param_lineage_action="deny"`, `min_len=6`, evaluated under both
  `novel_lineage_enabled=True` and the shipped `novel_lineage_enabled=False`
  default, since family 2's soundness contribution is specifically in the default.
- After engine: the family-2 forward-encode lever on branch
  `v1.6-derivation-taint`. This document is the pre-registered prediction of
  record and is not to be edited once the family-2 run is launched; any deviation
  is recorded in a dated amendment, as with family 1.
- Verification method: A/B replay diff. The family-2 must-catch and must-not-trip
  columns are judged against their predicted AFTER cells, and the full family-1
  corpus is judged for byte-equality (the no-regression floor). Success is the
  measured AFTER equalling the predicted AFTER for every must-catch and
  must-not-trip row, zero benign false-positive delta, the 4/4 soundness floor in
  both configurations, and byte-identical family-1 corpora.

---

## Reproduction of the family-2 status

No probe has run. No family-2 mechanism exists. The forward-encode direction is
chosen and the reverse-decode alternative is rejected on the probe-2 UUID, both
recorded above before any encoding code is written. The BEFORE states other than
base64-under-novel-on are predictions, and the first family-2 frontier probe is
what turns them into measurements. This file is the prediction of record.
