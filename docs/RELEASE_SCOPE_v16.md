# Release scope: v1.6 (families 1 and 2)
# Date: July 24, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

This is a DECISION document, not a changelog. It states what v1.6 ships, at what
claim strength, with which limitations, and what gates the release. Where a
decision is genuinely open it is presented as options with a recommendation and
marked OPEN, not silently chosen. Nearly every load-bearing sentence is cited to
the pre-registered prediction chain rather than restated from memory.

Source documents (all amendments included):
- `PREDICTIONS_v16_family1.md` (family 1, value-identity normalization)
- `PREDICTIONS_v16_family2.md` (family 2 first cut, forward-encode)
- `PREDICTIONS_v16_family2_composite.md` (composite cut, direction-(A) scan)
- `PREDICTIONS_v16_family2_base64composite.md` (base64 composite cut, three-phase
  interior)

Current branch state: version `1.5.0` in `pyproject.toml` and `__init__.py` (NOT
yet bumped, see gating), 1364 tests collected, 32 commits ahead of `main`,
license AGPL-3.0-or-later.

---

## 1. Ship together or staged

**Recommendation: ship together, as v1.6.**

Reasoning, from the chain:

- Family 2 is meaningless without family 1. Its catch surface is exactly the
  image of family 1's context-side tokenization under the encoding set (AM5.1),
  and the measurement confirmed this is a strict two-layer inheritance: family 2
  can only narrow what family 1 tokenizes, never add to it (AM7.3). Shipping
  family 2 without family 1 ships an encoder with nothing to encode.
- Family 1 alone re-ships the F4 binary frontier as its headline limitation. F4
  is the family-1 measured result that the encoding class (base64 and its
  siblings) is caught only by the unattributed novelty branch, which is OFF by
  default (family-1 AMENDMENT 6: "the novelty branch is the only mechanism that
  catches the encoding class, and its catch and its false positives are one
  non-recognition behavior"). Family 2 is precisely the third point on that
  frontier, the attributed catch for the encoding class. Shipping family 1 alone
  would document a frontier as open that has since been closed on this branch.
- Splitting produces two changelogs that undercut each other: a family-1 release
  whose stated limitation is the thing the family-2 release then removes, two
  weeks apart.

**Counter-case, stated:** family 1 is the more mature line (six amendments, a
falsified-and-fixed soundness floor, an implemented and characterized FP profile,
family-1 AMENDMENT 5), while family 2's newest cut landed most recently. A
risk-averse reading could ship family 1 first to de-risk. This is outweighed:
family 1's maturity is not in question (it is measured and pinned by tests), and
the de-risking gain does not offset re-publishing a closed frontier as open. Ship
together.

---

## 2. The public claim, at the right strength

**Do NOT claim "provenance survives encoding" unqualified.** The scoped claim:

> A tool-call parameter carrying a bare or composite encoded form of a
> url-kind or email-kind untrusted value, under base64, hex, or natural-URL
> encoding, is attributed back to its parent untrusted provenance entry, without
> decoding any parameter value, and this holds in the shipped default
> configuration.

Each qualifier, and what establishes it:

- **"url-kind or email-kind"** is the load-bearing scope limit. Family 2's
  surface is the curation image of the tokenization image (AM7.3): the
  direction-(A) composite scan admits only url and email kinds (Decision B,
  composite-cut AM2.2). Values that tokenize only as `str` (bare IPs, host:port,
  data: URIs, no-TLD emails) are covered bare but not composite (AM7.2). Claiming
  more than url/email for composites would overstate.
- **"bare or composite"** spans three cuts: bare forms (first cut, family-2
  AMENDMENT 6), hex and natural-URL composites (composite cut, composite-cut
  AMENDMENT 2), and base64 composites at every phase (base64 composite cut,
  base64 AMENDMENT 1).
- **"base64, hex, or natural-URL"** is the frozen encoding set, natural-URL
  meaning the structurally-significant-character form only (AM1.2), not
  adversarial per-character enumeration.
- **"attributed back to its parent untrusted provenance entry"** means a named
  `cprov_` entry, not merely a denial (family-2 AMENDMENT 6, must-catch: attributed
  DENY:param_lineage naming the parent).
- **"without decoding any parameter value"** is zero-decode by construction: all
  needles are forward encodings, and a suite guard greps the module for decode
  primitives (AM4.2, family-2 AMENDMENT 6; base64 AMENDMENT 1). This is the whole
  false-positive argument (the reverse-decode rejection on the probe-2 UUID,
  family-2 section 1).
- **"shipped default configuration"** is the strong form. param_lineage is on by
  default and returns the attributed DENY regardless of the novelty flag; the
  soundness floor is met with novelty ON and OFF (family-2 AMENDMENT 6). This is a
  default-configuration soundness improvement, not only a novel-on attribution
  improvement.

---

## 3. Scope table

Every capability with the cut that delivered it and the amendment that records
its measurement.

```
capability                              | cut                     | measurement recorded in
----------------------------------------+-------------------------+--------------------------------
value-identity normalization            | family 1                | family-1 AMENDMENT 5
  (date/phone/amount/defang canonical,  |                         |   (implemented, FP characterized,
   defang to attributed DENY, P1/P2)    |                         |    1237 tests at that point)
forward-encode first cut                | family 2 first cut      | family-2 AMENDMENT 6
  (bare base64/hex/natural-URL,         |                         |   (0/4 to 4/4 attributed, both
   attributed, both configs)            |                         |    configs, floor 8)
direction-(A) composite scan            | composite cut           | composite-cut AMENDMENT 2
  (hex and natural-URL composites)      |                         |   (attributed, both configs)
three-phase interior emission           | base64 composite cut    | base64 AMENDMENT 1
  (base64 composites, all phases)       |                         |   (1/6 to 6/6, geometry pinned)
whole-leaf auth clearance (Decision A)  | composite cut           | composite-cut AMENDMENT 2.4
  (positive control, leaf granularity)  |                         |   (isolation test, fold finding)
needle curation (Decision B)            | composite cut           | composite-cut AMENDMENT 2.2
  (url and email kinds only)            |                         |
per-encoding floors (Decision C)        | composite cut + AM4     | composite-cut AMENDMENT 4.1/4.2
  (hex 16, base64 10, natural-URL 10)   |                         | base64 AMENDMENT 1
```

Structural guards shipped alongside (family-2 AMENDMENT 6, composite-cut
AMENDMENT 2.5, base64 AMENDMENT 1): additive-only emission, no-decode grep,
auth-first positive control, per-entry attribution, loop-order pin, geometry
formula pin. Suite total on branch: 1364.

---

## 4. Limitations

Each with its amendment citation, because the paper trail is the point. Every one
was found INTERNALLY, by a read-only measurement or a pre-build check, not by an
external report.

- **Bare-IP composites.** Bare IPv4/IPv6 and host:port values are covered bare
  (they tokenize as `str`, direction (B) encodes them) but NOT composited, because
  Decision B curation excludes `str` from the direction-(A) scan (AM7.2). This is
  a CURATION interaction, not a tokenizer miss: the value extracts fine (AM7.2
  inverted the natural premise). Preferred fix shape named: a distinct `ip` kind
  admitted to the scan set (AM7.4, option (a)). Found internally (AM5.1
  measurement, AMENDMENT 7).
- **Per-character URL enumeration.** `%65vil.com` and the 2^n subsets of encoded
  positions are combinatorial and deferred; only the natural-encoder form is
  emitted (AM1.2). Found internally (pre-build, AMENDMENT 1).
- **Sub-min_len values.** Values below the `min_len` gate are not tokenized and
  so not encodable. This is the min_len contract working as specified, declined
  with reason rather than deferred (AM7.7). Found internally (AMENDMENT 7).
- **Defect A, trailing-punctuation divergence.** `_plain_qualifies` keeps a
  trailing period that `_canon_url` strips, so `evil.com.` yields both `evil.com.`
  (str) and `evil.com` (url), which mint different base64 phase interiors. Now a
  family-2 correctness question, not only a family-1 wart, with a registered check
  for whenever it is next touched (AM7.5). Found internally (AMENDMENT 7),
  inherited from the family-1 Defect A record.
- **The true miss set.** `localhost` (not an exfil endpoint), sub-min_len values,
  and bare keywords (`secret`, outside lineage's remit) are declined with reasons
  (AM7.7). Found internally (AMENDMENT 7).
- **The containment boundary itself.** Every family-2 cut was safe because it
  added needles over a frozen token set; the next coverage increment costs a
  shared-extraction change with both-families blast radius (AM7.8). This is a
  limitation of the METHOD, measured from the inside. Found internally
  (AMENDMENT 7).

Family-1 residuals that persist under v1.6 (all family-1 measured, not
family-2's to fix): interstitial `e-v-i-l.com` deferred (hyphen-stripping unsafe,
family-1 A3); the scheme-form benign FP (family-1 AMENDMENT 5, characterized);
amount canonical below min_len (family-1 A6); and the novel-side laundering that
is MASKED by precedence rather than eliminated, making the check-precedence
ordering a load-bearing invariant (family-1 AMENDMENT 3, C4). Note these
family-1 benign FPs are novelty-branch residuals, and the novelty branch is OFF
by default (family-1 AMENDMENT 6), so in the shipped default they do not fire.

---

## 5. What the predictions docs become

**OPEN.** Three options:

- **(a) Ship as-is as documentation.** Maximum transparency; the pre-registered,
  falsifier-carrying record is unusual and arguably half the value of the work.
- **(b) Distill into a design-notes / methodology page.** Extract the method
  (pre-registration, cheap read-only falsification before build, F7) and the
  final scope, leave the blow-by-blow internal.
- **(c) Keep internal.**

**Recommendation: (b), distill the method into a short public design-notes page,
keep the raw amendment chain internal.** Reasoning: the method is genuinely
publishable value (four reasoned claims were falsified by cheap reads before they
reached a probe or build: AM2.1's composite claim, the natural-URL partition, the
length-aware floor reconstruction of composite-cut AMENDMENT 3, and the base64
terminal boundary; each recorded consistently with family-1 F7). But the raw docs
also contain every wrong turn in full detail and the complete defensive playbook,
and the project has an existing precedent for not publishing design documents that
would let a competitor copy the playbook. Distilling captures the method's value
without publishing the playbook or the dead ends. The specific split (what goes
in the design-notes page versus stays internal) is a judgment call and stays OPEN.

---

## 6. What gates the release

**Explicitly NOT gating: the IP composite cut.** It is the highest-relevance open
coverage item (AM7.4), but it is across the containment boundary (a both-families
change requiring family-1 regression measurement, AM7.8), and shipping it inside
v1.6 would delay a complete, measured release for a cross-boundary change. It
becomes the first post-release roadmap item, measured against a SHIPPED baseline
rather than a moving branch tip (item 7).

**Gating, and each is David's manual step per the project release workflow (Claude
Code does not bump versions, merge, tag, or push):**

- **Version numbering.** The branch is still `1.5.0` in both `pyproject.toml` and
  `__init__.py`; they must be bumped together to the chosen v1.6 number and must
  match before publish. The number itself is OPEN (item 8).
- **Changelog.** A v1.6 changelog entry does not exist yet and must be written
  (this document is scope, not changelog).
- **Branch merge to main, and how.** The branch is 32 commits ahead of `main`.
  Whether it merges as-is, and by what mechanism (the project's manual no-commit
  merge, squashed, or otherwise), is David's decision and gates the release.
- **Test count, recorded and verified at the tag.** 1364 on the branch now; per
  the standing rule, the version and test-count claims in any release artifact
  must be verified against the specific tag, not carried from this document.
- **Public repo changes.** At minimum the version bump, the changelog, and the
  README version-history table. Whether the predictions docs are published is the
  item-5 decision and gates only if (a) or (b) is chosen.

**David's call, noted not decided:** whether a fresh evaluation run (the current
substrate is AgentDojo, not the historical AgentShield) gates the release, and
whether its numbers are "good enough." Per the workflow, deciding benchmark
adequacy is explicitly David's, not Claude Code's.

---

## 7. Roadmap (post-release)

Order drawn from the amendment chain, annotated by containment because that is
what determines the cost of each.

1. **IP composite cut.** NOT contained. A both-families change: a new `ip` kind
   shifts the token set and can move `kind_rank` citation ordering on family-1
   rows even where `str` already matched, so it requires family-1 regression
   measurement, not a family-2 amendment (AM7.4, AM7.8). Highest attack relevance
   (bare IPs are canonical exfil and C2 endpoints), which is why it leads despite
   being the most expensive.
2. **Defect A.** NOT contained. The fix lives in `_plain_qualifies` (the shared
   extractor), so it changes what both families see; a family-2 correctness check
   is registered for it (AM7.5). An extractor-hygiene change (family-1 Defect A
   record).
3. **Per-character URL enumeration.** CONTAINED. It adds more encoded forms of
   already-tokenized url values over the frozen token set, so it is family-2-only
   like the shipped cuts; the open question is the enumeration BOUND, not
   containment (AM1.2). Lowest attack relevance of the three (adversarial,
   gratuitous encoding), which is why it trails despite being the cheapest.

Note the order is relevance-driven, not containment-driven: the one contained item
is sequenced last. If a low-risk increment is wanted first, per-char URL
enumeration is the only contained option, but it buys the least.

---

## 8. Open questions (human decision required)

Genuinely undecided; not recommendations dressed as settled.

- **The v1.6 version number.** v1.6 is assumed throughout, but the branch is
  `1.5.0` and the actual number (and whether the AGPL feature addition warrants
  anything other than a minor bump) is unset.
- **Whether the predictions docs ship, and in what form** (item 5). Recommendation
  is (b) distill, but the exact public/internal split is a judgment call.
- **Whether a fresh AgentDojo evaluation gates the release**, and whether its
  numbers are adequate. Explicitly David's call per the workflow.
- **The IP composite fix shape.** AM7.4 names option (a) (an `ip` kind) as
  preferred over (b) (`str` wholesale), but (a) is not contained and the family-1
  regression it requires has not been measured, so choosing and scoping it is a
  real open decision, not a settled recommendation.
- **Whether Defect A is fixed inside v1.6 or deferred.** It became a family-2
  correctness question (AM7.5); whether that rises to a release blocker or a
  roadmap item is undecided.
- **The exact public claim wording** (item 2) as it will appear in the README,
  the changelog, and any paper. The scoped claim is drafted here; its final form
  is not locked.

---

## Summary of decisions and open questions

**Decisions recommended:** ship families 1 and 2 together as v1.6 (1); publish the
scoped claim, not the unqualified one (2); IP composite cut does not gate and
leads the roadmap (6, 7); distill the method publicly and keep the raw chain
internal (5, recommended, split OPEN).

**Open, human required:** the version number; the predictions-docs disposition;
whether an evaluation run gates; the IP fix shape and its family-1 regression;
whether Defect A blocks v1.6; the final claim wording (8).
