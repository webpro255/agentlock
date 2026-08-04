# Limitations, v1.6.0

What this release does not do, and what its numbers are and are not evidence
for.

The document is split into two registers, and the split is not presentational.
It follows the rule pre-registered at `PREDICTIONS_v16_family1.md:1344-1361`:

> The claims in this arc live in two registers, and they must not be conflated.
> **The mechanism claim is corpus-independent** ... These are statements about
> control flow, true on every input, and they are stated structurally.
> **The coverage enumeration is corpus-specific.** Which rows fall on which side
> of the frontier, which transformation class is ceded, the counts ... are exact
> on the frozen probe corpora and nowhere else.

So: register one states bounds that hold on every input, and states them without
rates. Register two states measured results, and every one of them carries the
corpus it was measured on. A number in register two is a fact about that corpus,
never a general rate.

One clarification about numbers in register one. Spec constants, the floors
below, are part of the mechanism rather than measurements of a corpus, so citing
their values does not put a coverage number into the structural register. What
would break the rule is stating a rate, and no rate appears in register one.

---

## Register one: structural

Corpus-independent. Each of these follows from what the mechanism does, so a new
corpus does not change any of them.

### S1. Composite coverage is url-kind and email-kind only

The direction-(A) scan makes each forward-encoded untrusted form a needle
searched inside the raw parameter leaf, which is what catches an encoded value
embedded in a longer opaque token. Only url-kind and email-kind values enter
that needle set (`RELEASE_SCOPE_v16.md:119-120`, Decision B; enforced by the
shipped `_SCAN_KINDS`).

Why the scope is drawn there rather than wider: direction (A) scans every needle
against every leaf, so its false-positive surface grows with the product of the
needle count and the haystack length, unlike direction (B)'s whole-token
comparison. Curating the needle set to the injection-relevant kinds is what
bounds that surface. Admitting `str` would widen it to the least distinctive
tokens the extractor emits.

The consequence, stated plainly: a value that tokenizes only as `str`, which
includes bare IPv4 and IPv6 addresses and `host:port` forms, is covered in its
bare encoded form by the all-kinds direction-(B) emission, and is **not** covered
inside a composite. `RELEASE_SCOPE_v16.md:138-144` records this as a curation
interaction rather than a tokenizer miss: the value extracts correctly, it is
the scan set that excludes it.

### S2. Per-character URL enumeration is not emitted

The natural-URL encoding covers the structurally significant characters that a
normal encoder targets, the dot, at-sign, colon and slash. Adversarial
per-character spellings such as `%65vil.com`, and the subsets of positions an
attacker could choose to encode, are combinatorial in the number of positions
and are deliberately not emitted (`RELEASE_SCOPE_v16.md:145-147`, AM1.2).

### S3. Encoded forms below the floors are not matchable

Two separate floors bound what an encoded form must be before it is admitted,
and both are spec constants of the mechanism:

- The direction-(B) blob emission floor is **8** characters on the ENCODED form,
  not on the plaintext token (`_ENCODED_MIN_LEN`, `context.py`).
- The direction-(A) scan floors are per encoding: **hex 16, base64 10,
  natural-URL 10** (`_SCAN_FLOORS`; `RELEASE_SCOPE_v16.md:121-122`).

A form shorter than its floor is not emitted, so it cannot be matched. This is
the floor working as specified, not a gap. Separately, a plaintext value below
the `min_len` distinctiveness gate is never tokenized at all, so nothing can be
encoded from it (`RELEASE_SCOPE_v16.md:148-150`).

### S4. Zero decode, and what that forgoes

Every needle is a FORWARD encoding of a value already known to be untrusted.
Nothing in a parameter is ever decoded or inverted, and a suite guard greps the
context module for decode primitives so a decode path cannot be added silently.

This is the whole false-positive argument: a benign value that merely looks like
base64 is never turned into anything, so it can never be misread as an untrusted
value in disguise.

What it structurally forgoes, as the price of that argument: an encoded value
that the gate has no untrusted plaintext for cannot be recognized. The mechanism
matches representations of KNOWN untrusted values. An encoded payload whose
plaintext never entered the session's provenance log as untrusted content has no
needle to match against, and no amount of corpus work changes that, because the
alternative is decoding parameters and classifying what comes out, which is the
approach this project rejects.

The same follows for encodings outside the frozen set and for nested encodings,
which are a different value again rather than a different spelling of the same
one.

### S5. Selection influence is not covered

Untrusted content that chooses among values the user already supplied is outside
what any value-identity mechanism can see. Every token in such a call traces to
the authoritative request; nothing is planted, so there is nothing for a
provenance match to fire on. `PREDICTIONS_v16_family1.md:214-216` states it:

> **Selection influence** (scenario B: untrusted content chooses among
> authoritative values). Every token traces to the user; there is nothing for a
> value-identity normalizer to fire on.

It is a named, pre-registered non-capability rather than an unnoticed gap: the
row is carried in the family-1 frozen prediction table
(`PREDICTIONS_v16_family1.md:293-294`) with its required verdicts, ALLOW when
the tool is not gated and `STEP_UP:untrusted_lineage` when it is, and a change
in either would have counted as a scope leak. The session write-gate is what
covers the gated case, not parameter lineage.

Reproduction reference, stated honestly: the reference is the pre-registered
row and its required verdicts in the family-1 document, not a script. The
family-1 and family-2 probe scripts are not in the repository, which
`RELEASE_SCOPE_v16.md:414-419` already records as a residual on this release's
evidence.

### S6. Genuine quotation of untrusted content is still a match

A parameter that really does carry a value from untrusted content is denied even
when the surrounding work is legitimate. The clearest case is a summarization
tool whose summary genuinely quotes an attacker-supplied address: the value is
present, so `param_lineage` matches, and matching is correct behavior rather
than an error. `PREDICTIONS_v16_family1.md:217-219`:

> **Taint relevance** (`benign: untrusted mention`, `legit summarization`). The
> token genuinely appears in untrusted content, so param_lineage matches
> correctly. Normalizing the value does not change that it is really present.

Scoped out deliberately, not deferred by oversight: family 1 pre-registered
these rows as remaining benign false positives after the work, and
`PREDICTIONS_v16_family1.md:296-298` states that reporting the residual honestly
is part of the pre-registration and that a later family owns them. Deciding that
a quotation is benign requires judging what the value is FOR, which is a content
judgement the gate does not make.

### S7. The v1.6 capability claim is an ENGINE-level claim

The frozen claim requires that the deployment "declares the untrusted context
source on the writes it records" (`RELEASE_SCOPE_v16.md:693-698`). At engine
level that is satisfied by the context-write call itself, which is what the
frozen fixtures do. The framework-adapter equivalent is a per-tool opt-in on the
wrapper.

**No encoded corpus has been run through an adapter**
(`RELEASE_SCOPE_v16.md`, AM4.3, residual 1). The encoded capability is therefore
measured at the engine and not at a deployment, and no deployment-level encoded
claim is made from this evidence.

Two adapter-level bounds follow from the adapters' own documentation and hold
independently of this release. Provenance enforcement is opt-in per tool: a
wrapper that does not declare a tool's output as untrusted records it as derived,
which leaves no untrusted entry for any lineage check to fire on. And adapter
enforcement is **single-hop**: it catches a value going from an untrusted tool's
output directly into a later tool's parameters, and a value laundered through an
intermediate tool that rewrites it is not caught, because no parent link is
recorded across hops.

### S8. `enabled` is not a master switch over parameter lineage

A lineage policy with `enabled=False` and `param_lineage_enabled=True` still
denies on a parameter-lineage match. The gate consults only
`param_lineage_enabled` for this check, so `enabled` governs the session
write-gate rather than acting as an outer switch.

This is DOCUMENTED BEHAVIOR, not a defect (`RELEASE_SCOPE_v16.md`, AM4.3,
residual 2). Every frozen corpus was measured with `enabled=True`, so no measured
result in this release depends on it. It is recorded here because it is
counter-intuitive enough that a deployment could otherwise assume one flag
disables both. Any change to the relationship belongs to a later version, under
its own pre-registration.

---

## Register two: coverage

Corpus-relative. Every number below is exact on the named corpus at the named
cut and is not a rate over anything else. A new transformation family extends
the corpus and the enumeration is re-run; the structural claims above are not
re-run, because they do not depend on which rows exist.

### C1. Family 1, per configuration, four frozen probe corpora

Measured after the symmetry and composite-aware fix, from the table at
`PREDICTIONS_v16_family1.md:1089-1095`. Denominators are the corpus row counts.

| corpus (denominator) | before fix | after fix |
|---|---|---|
| probe 4 obfuscated attacks, novel ON (8) | 6/8 reach ALLOW | 0/8 reach ALLOW |
| probe 4 obfuscated attacks, novel OFF (8) | 8/8 reach ALLOW | 4/8 reach ALLOW |
| probe 3 composites (6) | 2/6 blocked at first measure (AM2) | 6/6 blocked |
| probe 1 attacks (7) | 7/7 blocked | 7/7 blocked |
| probe 2 benign FP, novelty on (9) | 5/9 | 5/9 unchanged |

The two probe-4 configurations differ by design and the difference is the
finding: the symmetry half is novelty-independent, so those rows close in both
configurations, while the composite-aware half is novelty-dependent, so its rows
close only with novelty ON. The probe-3 before figure is the AMENDMENT 2
falsification measurement (`PREDICTIONS_v16_family1.md:687-731`), four of those
six reaching ALLOW, and that amendment records both of the two blocks as
coincidental rather than principled, so the principled before figure is 0/6.

### C2. Family 2, three cuts, frozen family-2 corpora

Each cut's result as recorded in that cut's closing amendment.

- **Bare forms, first cut.** Counted must-catch **0/4 to 4/4** attributed
  `DENY:param_lineage` naming the parent `cprov_` entry, in BOTH the novelty-ON
  and novelty-OFF configurations. Must-not-trip false-positive delta **exactly
  0**, with `param_lineage` uniformly no-match. Suite 1265 at that cut.
  (`PREDICTIONS_v16_family2.md`, AMENDMENT 6.)
- **Hex and natural-URL composites, composite cut.** Both attributed in both
  configurations. **Ten** benign must-not-trip rows at no-match, FP delta **0**,
  including an API-token canary that is a 16-character contiguous hex run
  exactly at the hex floor. The counted 4/4 bare rows byte-identical. base64
  composites still uncaught at this cut except the phase-0-and-terminal corner,
  asserted as uncaught so the boundary stayed visible. Suite 1309 at that cut.
  (`PREDICTIONS_v16_family2_composite.md`, AMENDMENT 2.)
- **base64 composites, base64 composite cut.** `evil.com` **1/6 to 6/6** and
  `mallory@evil.com` **1/6 to 6/6**, across phases 0, 1 and 2, terminal and
  non-terminal, attributed with the parent `cprov_` named, in both
  configurations. Benign rows uniformly no-match, FP delta **0**, with the JWT
  and data-URI canaries holding. Suite **1364** at this cut, which is the
  release cut. (`PREDICTIONS_v16_family2_base64composite.md`, AMENDMENT 1.)
  That suite total is measured with the `crypto` and `mcp` extras installed. A
  bare install runs **1351** and skips the 13 optional-extra tests, none of
  which belong to the corpora above.

These corpora are the ONLY capability evidence for the encoding work. See C4.

### C3. The novelty branch's false-positive cost

Enabling the novelty branch flips four additional benign rows on probe 2:
**1/9 with novelty off, 5/9 with novelty on**
(`PREDICTIONS_v16_family1.md:1267-1268`). The rows it adds are system-minted and
computed values, an order ID, a minted UUID, a computed total, and one amount
case, none of which trace to an authoritative baseline.

Two bounds on reading that number. It is a probe-2 number and not a rate over
any deployment. And it is measured in a session that HAS an authoritative
baseline: the same flip in a session with no baseline shows zero benign delta,
which reads as a calm gate but is an artifact of having nothing to be novel
against (`PREDICTIONS_v16_family1.md:1262-1268`). The novelty branch remains OFF
by default.

The AgentDojo run did not show this cost, and that is a property of the
benchmark rather than evidence the branch is cheap: its benign tasks supply
their values in the user instruction, so there is little novel-but-clean
material to flag (`RELEASE_SCOPE_v16.md`, AM3.4).

### C4. AgentDojo, and the one statement it supports

Three columns, v1.5.0 baseline, v1.6 default, v1.6 novelty-on, over the four
suites, `gpt-4o-mini-2024-07-18`, `tool_knowledge` attack, 984 episodes per
column, zero crashes (`RELEASE_SCOPE_v16.md`, AM3.1). Combined utility 33.40,
34.56, 34.67 across the three columns; no suite regressed.

The run supports exactly one public statement (`RELEASE_SCOPE_v16.md`, AM3.5):

> v1.6 does not regress v1.5's benchmark behavior on the four AgentDojo suites.

It is a **no-regression gate and not capability evidence**, and the reason is
structural rather than a matter of caution (`RELEASE_SCOPE_v16.md`, AM2.3): a
read-only sweep of the benchmark found NO encoded forms anywhere in any of the
four suites, with every injected value appearing as literal plaintext. A
benchmark cannot validate a mechanism it never presents an input for. The
encoding capability is established by C2 and by nothing else here.

---

## What is not in this release

Cross-hop derivation linking is not part of v1.6.0. Adapter enforcement is
single-hop as described in S7, and a value laundered through an intermediate
tool that rewrites it is not caught.
