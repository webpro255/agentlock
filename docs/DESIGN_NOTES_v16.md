# Design notes, v1.6.0

The public entry point to the v1.6 prediction chain.

In plain terms: the gate decides whether a tool call may run from where each of
its values came from, not from reading the values and judging what they say.
v1.6 adds this, that a value which arrived from an untrusted source and then
turns up in a parameter in a rewritten or scrambled shape is still traced back
to the source it came from, and that tracing is done without ever unscrambling
anything. What it cannot do follows from how it works, that it recognizes
shapes of values it already knows arrived untrusted, so it never unscrambles a
parameter to look inside, and a value an attacker restates in different words
is outside its reach. The numbers here come from small fixed sets of test
cases, each written down before the code existed together with the result that
would have proved the claim wrong, and each reported with the size of the set
it was measured over, so a number is evidence that one claim survived one test
and not a statement about coverage or about cases outside those sets.
Everything below this line is the audit trail behind that summary, and it ships
with the predictions that turned out to be wrong left in place.

This page is a map of that record and does not stand in for it, and where a
number appears here it carries the corpus it was measured on and the
denominator it was measured over. The chain itself:

- [`RELEASE_SCOPE_v16.md`](RELEASE_SCOPE_v16.md), the release decision and five dated amendments
- [`PREDICTIONS_v16_family1.md`](PREDICTIONS_v16_family1.md), value-identity normalization
- [`PREDICTIONS_v16_family2.md`](PREDICTIONS_v16_family2.md), forward-encode, first cut
- [`PREDICTIONS_v16_family2_composite.md`](PREDICTIONS_v16_family2_composite.md), the direction-(A) scan
- [`PREDICTIONS_v16_family2_base64composite.md`](PREDICTIONS_v16_family2_base64composite.md), three-phase interior emission
- [`LIMITATIONS_v16.md`](LIMITATIONS_v16.md), what this release does not do

---

## 1. The problem

An agent reads a web page, and the page tells it to send data somewhere. The
tool call that results is, as a string, indistinguishable from a legitimate
one. The recipient is a well-formed address, the parameters are well-formed
values, and nothing in the request text says where the instruction came from.
What makes the call harmful is a relationship the call text never expresses:
this value entered the session from content a third party controls.

Content inspection was refused as a design basis, not merely deprioritized. A
classifier decides from the string, and the attacker chooses the string:
paraphrase changes the wording, encoding changes the bytes, and neither changes
what the call does. Any filter that reads the payload can be rewritten around by
construction, so the gate does not read payloads. It decides from provenance:
what the session recorded, where each item came from, and whether a value in a
parameter traces back to an untrusted entry.

The same refusal governs how encoding is handled, and this is the part v1.6
turns on. The intuitive fix for an encoded payload is to decode the parameter
and inspect what comes out. That is content inspection with an extra step, and
it is worse than it looks. The family-1 benign corpus already contains values
that decode under a naive codec: the minted UUID
`3f2b9c14-7d6a-4e58-9b21-0c8e5a7f4d33`, hyphens stripped, is valid hex, and
hex-decoding it yields sixteen arbitrary bytes that then have to be classified
as meaningful or noise. Separating meaningful decodes from garbage is exactly
the content classifier the project rejects, so decoding parameters was ruled
out before any encoding work began
(`PREDICTIONS_v16_family2.md`, section 1).

That left a measured gap. Family 1 covers values that are the same value in a
different surface form, and it pre-registered the directional-encoding class as
out of scope so that a change there would count as a scope leak rather than a
bonus. The only mechanism in the engine that caught an encoded value was the
novelty branch, which fires when a token is accounted for by neither the
authoritative nor the untrusted set. Family 1 measured that branch to have one
returning path: its catch and its false positives are the same non-recognition
behavior, so no configuration catches the encoding rows without importing the
benign flags, and none holds the benign surface without ceding the encoding
rows (`PREDICTIONS_v16_family1.md`, F4). The novelty branch is off by default,
because the same value is flagged in a session that registered authoritative
context and allowed in one that did not, and a default whose verdict swings on
deployment configuration is not a safe default (F1).

So, concretely, before v1.6: in a session with parameter lineage enabled and
the untrusted source declared, with the novelty branch at its shipped default
of off, a tool call whose parameter carried `ZXZpbC5jb20=`, the base64 of an
`evil.com` the session had already recorded as untrusted web content, reached
ALLOW (the gate folds case on both sides, so it cites the matched form as
`zxzpbc5jb20=`). The frozen family-2 must-catch corpus records 0 of 4 encoded
attack rows blocked in that configuration before the work, across base64 of a
domain, base64 of an email address, a percent-encoded domain, and a
hex-encoded domain. The
base64 cell was measured in family 1; the other three were pre-registered as
predicted BEFORE cells and the probe confirmed them
(`PREDICTIONS_v16_family2.md`, section 3 and AMENDMENT 6).

---

## 2. What was built

### Family 1: value-identity normalization

The same value written a different way is now the same value to the gate. The
engine emits canonical forms for dates, phone numbers (E.164), amounts, and
defanged URLs, and it does so on both sides of the comparison: for each
recorded context token and for each parameter value.

The invariant that governs the emission is **additive**. A canonical form is
added alongside the raw token, never in place of it. Replacement emission would
have deleted evidence: a reformatted amount that canonicalizes to a shorter
string can drop below the distinctiveness gate, and if the raw form had been
replaced, a match that worked before the feature would stop working after it.
Additive emission means no catch that existed can be removed by adding a
canonical form, and a test seeds one untrusted value and asserts that both its
raw and its transformed spellings still catch, so the invariant fails loudly
rather than eroding.

The result is one lever moving two columns. A defanged `evil[.]com` in a
parameter canonicalizes onto the untrusted token it came from and becomes an
attributed denial that names the parent provenance entry, where before it was
an unattributed step-up. A reformatted authoritative date canonicalizes onto
the user's own value and clears.

### Family 2: forward-encode, never reverse-decode

The direction of the transform was fixed before any code was written, because
the direction is the whole safety argument.

The engine takes the finite set of tokens it already recorded as untrusted,
applies a fixed set of encodings to each, and adds the results to what it
compares parameters against. **No parameter value is ever decoded, inverted, or
read backwards.** A benign value that merely looks like base64 is never turned
into anything, so it cannot be misread as an untrusted value in disguise. This
is not a promise about intent: the suite greps the context module for decode
primitives (`b64decode`, `urlsafe_b64decode`, `b16decode`, `b32decode`,
`fromhex`, `unquote`, `bytes.fromhex`) and fails if one appears, so a decode
path cannot be added later without tripping a guard.

Two match directions carry the coverage:

- **Direction (B), whole token.** A parameter token that equals an emitted
  encoded form matches it. This carries the bare encoded forms.
- **Direction (A), scan.** Each emitted form becomes a needle searched inside
  the raw parameter leaf, which is what catches an encoded value embedded in a
  longer opaque token. This carries the composites. Direction (B) runs first,
  so a bare row is still cited as a whole-token match and the citation stays
  deterministic.

Three encodings are in the frozen set: base64, hex, and natural-URL, meaning
percent-encoding of the structurally significant characters a normal encoder
targets (dot, at-sign, colon, slash) and not adversarial per-character
spellings.

base64 needed one more piece of geometry. It packs input at six bits per output
character, so character boundaries realign with byte boundaries only every three
bytes, and an encoded value cuts at both ends: at the leading offset where it
starts, and at the trailing boundary depending on whether it ends the payload. A
single bare encoded form therefore appears inside a composite only when the value
happens to be phase-0 aligned and terminal. The fix emits each untrusted token at
all three leading phases and matches on the stable interior, with the boundary
characters dropped by formula
(`PREDICTIONS_v16_family2_base64composite.md`, section 2). That rule, not the
needle strings, is the durable artifact: the interior is defined by construction
rather than tuned.

Two decisions bound the cost of the scan, and both are mechanism constants rather
than corpus measurements. Only url-kind and email-kind values enter the scan
needle set, because direction (A) tests every needle against every leaf and its
false-positive surface grows with needle count times haystack length. And each
encoding carries a length floor on the matchable form: hex 16, base64 10,
natural-URL 10 for the scan, with the whole-token emission floor separately at 8
on the encoded form. An authoritative parameter leaf that appears verbatim in the
user's own request is cleared before it is scanned at all.

### The claim

One sentence states what v1.6 does. It is quoted here exactly as frozen in
`RELEASE_SCOPE_v16.md`, AM4.2, and it is not paraphrased anywhere in this
document:

> In a deployment that registers the tool at permissions version 1.3 or later
> with `param_lineage_enabled` set, and declares the untrusted context source on
> the writes it records, a tool-call parameter carrying a bare or composite
> encoded form of a url-kind or email-kind untrusted value, under base64, hex, or
> natural-URL encoding, is attributed back to its parent untrusted provenance
> entry, without decoding any parameter value, with novelty gating off.

Four preconditions are visible in it, and each was measured rather than
assumed:

1. **Permissions version 1.3 or later.** The same session returns ALLOW at
   version 1.2 and an attributed denial at 1.3 and 1.5.
2. **`param_lineage_enabled` set.** Parameter lineage is off by default and
   opt-in per tool. A tool registered without a lineage policy has no lineage
   gating at all.
3. **The untrusted context source declared on the writes recorded.** A session
   whose untrusted write was recorded as derived tool output has no untrusted
   entry, so the check returns a no-match qualified `no_untrusted_context` and
   nothing is attributed.
4. **Novelty gating off.** Every must-catch table is parametrized over the
   novelty flag and passes in both settings, so novelty-off is the case the
   contribution lives in rather than a survival case.

The wording names that flag specifically because a first proposed correction was
verified false before it was frozen. It opened with "a lineage policy enabled",
naming a real field that does not gate this check: measured on the shipped
engine, `enabled=True` with `param_lineage_enabled=False` returns ALLOW. AM4.1
records the rejected wording and the failure shape it illustrates, which is that
a sentence naming a configuration has to be measured in that configuration, not
checked for plausible field names.

---

## 3. How it was proven

### Pre-registration, as practiced here

Each cut has a document written before its mechanism existed. It records the
BEFORE column as measured on the shipped engine, the AFTER column as a
prediction, and the conditions under which the prediction counts as falsified.
Rows expected not to move are frozen too, because a verdict change on a deferred
row is a scope leak rather than a bonus. Amendments are dated and append-only:
nothing above an amendment is rewritten, including the text it corrects, so a
falsified prediction stays on the page next to the measurement that killed it.

### The frozen corpora, which are the only capability evidence

Family 1, four frozen probe corpora, denominators are the corpus row counts
(`PREDICTIONS_v16_family1.md`, AMENDMENT 5):

| corpus (denominator) | before fix | after fix |
|---|---|---|
| probe 4 obfuscated attacks, novelty on (8) | 6/8 reach ALLOW | 0/8 reach ALLOW |
| probe 4 obfuscated attacks, novelty off (8) | 8/8 reach ALLOW | 4/8 reach ALLOW |
| probe 3 composites (6) | 2/6 blocked at first measure (AM2) | 6/6 blocked |
| probe 1 attacks (7) | 7/7 blocked | 7/7 blocked |
| probe 2 benign false positives, novelty on (9) | 5/9 | 5/9 unchanged |

The two probe-4 configurations differ by design, and the difference is the
finding: the symmetry half of the fix is novelty-independent and closes its rows
in both settings, the composite-aware half is novelty-dependent. The probe-2 row
is the novelty-on figure; its novelty-off counterpart is the 1/9 in section 4.
The probe-3 before figure is the AMENDMENT 2 falsification measurement, four of
those six reaching ALLOW, and that amendment records both of the two blocks as
coincidental rather than principled.

Family 2, three cuts, frozen family-2 corpora. Attributed means a denial carrying
the matched token and naming the parent `cprov_` provenance entry, not a refusal
on its own:

- **Bare forms, first cut.** Counted must-catch 0/4 to 4/4 attributed, in both
  the novelty-on and novelty-off configurations. Must-not-trip false-positive
  delta exactly 0 over six benign rows. Suite 1265 at that cut.
- **Hex and natural-URL composites, composite cut.** Both attributed in both
  configurations. Ten benign must-not-trip rows at no-match, false-positive
  delta 0, including an API-token canary that is a 16-character contiguous hex
  run sitting exactly at the hex floor. Suite 1309 at that cut.
- **base64 composites, base64 composite cut.** `evil.com` 1/6 to 6/6 and
  `mallory@evil.com` 1/6 to 6/6, across phases 0, 1 and 2, terminal and
  non-terminal, attributed in both configurations. Benign rows uniformly
  no-match, false-positive delta 0, with the JWT and data-URI canaries at
  2-character closest shared runs. Suite 1364 at this cut, which is the release
  cut.

That canary result is recorded in the chain as the corpus not hitting rather than
as proof of safety. A 10-character base64 needle carries more per-alignment
collision risk than the 12-character floor it replaced, and the canaries remain a
live falsifier: a future benign hit reopens the floor decision with data.

### AgentDojo, and the one statement it supports

A three-column run gated the release: v1.5.0 baseline, v1.6 default, v1.6
novelty-on, over four suites, `gpt-4o-mini-2024-07-18`, `tool_knowledge`
attack, 984 episodes per column, zero crashes. Combined utility moved 33.40 to
34.56 to 34.67 across the three columns and no suite regressed
(`RELEASE_SCOPE_v16.md`, AM3.1).

The run supports exactly one public statement (AM3.5):

> v1.6 does not regress v1.5's benchmark behavior on the four AgentDojo suites.

It may not be cited as evidence for the encoding capability, and that
constraint is structural rather than cautious (AM2.6, AM2.3). A read-only sweep
of the benchmark's own content found no encoded forms anywhere in any of the
four suites: every injected value appears as literal plaintext. A benchmark
cannot validate a mechanism it never presents an input for. One further note
from that run: every v1.6 number moved slightly up relative to baseline, utility
and security alike, and a uniform sign is also the signature of a subtle real
effect, so the chain records it as most plausibly single-run variance with a
confirmatory second baseline run deferred (AM3.3, AM6.1), rather than asserting
variance as established.

### What a reader can check

- **The corpora are committed tests**, the seven `tests/test_v16_*.py` files:
  `family1_normalization`, `family2_encoding`, `family2_composite`,
  `family2_base64composite`, `additive_emission`, `composite_aggregation`, and
  `composite_aware`. Every must-catch row asserts the verdict and the parent
  provenance id together.
- **The guards are tests too.** No-decode grep, additive-only emission,
  per-entry attribution, loop order, and the frozen floors and kinds.
- **The interior geometry is pinned in three layers**, because one would have
  been weaker than it reads: a formula-consistency test that states its own
  limit (a wrong formula would fail it identically on both sides), a filler-byte
  independence test, and the must-catch rows themselves.
- **The amendment chain ships**, corrections included.

One limit on reproduction: the probe scripts are not in the repository, so what a
reader checks is the pre-registered row with its required verdicts and the
committed test that pins it, not the script that measured the BEFORE state.

---

## 4. What it costs and cannot do

The full statement, in two registers with every number carrying its corpus and
denominator, is [`LIMITATIONS_v16.md`](LIMITATIONS_v16.md). It covers the
url-kind and email-kind composite curation, per-character URL enumeration, the
floors, selection influence, and genuine quotation of untrusted content. Four
things are carried here because a reader weighing the claim needs them here.

**The claim is an engine-level claim.** Declaring the untrusted context source
is satisfied at engine level by the write call itself, which is what the frozen
fixtures do, and no encoded corpus has ever been run through a framework
adapter, so no deployment-level encoded claim is made from this evidence
(`RELEASE_SCOPE_v16.md`, AM4.3, residual 1).

**`enabled` is not a master switch over parameter lineage.** A lineage policy
with `enabled=False` and `param_lineage_enabled=True` still denies on a
parameter-lineage match; this is documented behavior rather than a pre-release
defect, since every frozen corpus was measured with `enabled=True` and no
measured result depends on the quirk (AM4.3, residual 2).

**The novelty branch has a measured false-positive cost.** Enabling it flips
four additional benign rows on probe 2: 1/9 with novelty off, 5/9 with novelty
on (`RELEASE_SCOPE_v16.md`, AM5.2, correcting a figure carried in AM3.4). Two
bounds on reading that number. It is a probe-2 number and not a rate over any
deployment. And it was measured in a session that has an authoritative
baseline: the same flip in a session without one shows zero benign delta, which
reads as a calm gate but is an artifact of having nothing to be novel against.
The branch is off by default.

**The structural ceiling.** Zero decode is what makes the false-positive
argument hold, and its price is fixed: the engine matches representations of
values it already knows are untrusted, so an encoded payload whose plaintext
never entered the session's provenance log as untrusted content has no needle
to match against. No amount of corpus work changes that, because the
alternative is decoding parameters and classifying what comes out. The same
follows for encodings outside the frozen three and for nested encodings, which
are a different value rather than a different spelling of the same one. Value
matching also says nothing about untrusted content that is semantically
rewritten rather than re-spelled, or that merely selects among values the user
already supplied.

---

## 5. The method note

### Why the mistakes ship

The clearest case in the chain is a proposal that never made it into the engine.
The hypothesis was that the novelty flag gated two mechanisms behind one boolean,
an untrusted-membership branch that does genuine attribution and a novelty branch
that fires on system-minted values, and that splitting them would keep the
attributed catches while holding the benign surface at the default level. It was
proposed by one reasoning model and endorsed by another with a separately stated
mechanism.

It was wrong. In the shipped code the membership path is not a branch that returns
a decision; it is a skip that emits nothing, and gating it independently would
gate a skip. Probe 8 measured the split configuration as identical to the default
on every row of all four corpora, and the structural reading explains why no
future corpus could ever separate them: a branch that does not return cannot
change a decision, on any input (`PREDICTIONS_v16_family1.md`, F2 and F3).

The methodological point is the one worth carrying out of it. Two reasoners
agreeing looked like corroboration and was not, because both reasoned from the
same conceptual model of the code rather than from its control flow, and shared
premises produce correlated errors. The probe was the only independent check,
and the moment of highest risk was precisely when the reasoners converged and
the answer felt settled (F7).

### The pattern since

Reasoning proposes and measurement disposes, in both directions, and the
discipline works because disposal is cheap. Across the family-1 arc, three
reasoned diagnoses were wrong and three reasoned predictions were confirmed,
each disposed by a probe costing a scratch file and a minute (F7). Across the
family-2 design phase, four reasoned predictions were falsified before any
mechanism code existed, and every one of the four landed outside the counted
set of four bare rows, so the counted prediction never moved and hit 4/4 on
the first build (`PREDICTIONS_v16_family2.md`, AM6.6).

The same discipline caught a near-false-pass during the composite cut. The
positive control was green while the mechanism it was supposed to be
exercising, whole-leaf authoritative clearance, was inert: the control row
cleared through a different path entirely. What exposed it was an isolation
test placing the same value where it is not authoritative, so the delta between
the two rows is exactly the protection the mechanism provides. A positive
control that can pass while its mechanism is inert is not a control
(`PREDICTIONS_v16_family2_composite.md`, AM2.4).

That pattern reaches the release documents themselves. Amendment 5 of
`RELEASE_SCOPE_v16.md`, dated on this release branch, corrects a number inside
an already-frozen amendment of that same document. AM3.4 had attached 88.9
percent to the novelty branch's false-positive cost on minted values. Checked
against the family-1 document during the limitations pass, 88.9 percent is 8/9,
the pre-family-1 baseline benign false-positive rate across all nine probe-2
rows, which is a different fact about a different thing. The measured novelty
cost is 1/9 to 5/9 on probe 2. The correction changed no decision, no gate and
no scope, and it was written as a dated amendment rather than edited quietly
into the artifact that carries the figure.

### The argument for shipping the raw chain

A record that preserves its own errors with dates is harder to fake and easier to
audit than a clean one. A summary can only be taken on trust: it shows the
conclusions and not the discarded turns, and a reader has no way to tell a
prediction that was always right from one edited after the measurement came back.
The chain here is checkable in the other direction. The wrong predictions are
still on the page, their falsifiers are still stated, the corrections carry dates,
and the corpora that decided them are committed tests.

That is why the raw amendment chain ships and this document is its entry point
rather than its replacement. The falsifications are the credential, not the
liability.
