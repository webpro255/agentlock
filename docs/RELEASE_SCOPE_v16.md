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

---

## AMENDMENT 1 (2026-07-24): four open questions closed, independence determination dated before the run

This amendment closes four of the item-8 open questions and records the
corpus-independence determination BEFORE any v1.6 AgentDojo run, so the framing is
fixed before the numbers exist. It makes no mechanism change. The original
document is left intact; the questions it left OPEN are resolved here, not
rewritten above.

### AM1.1. Version: 1.6.0

Closed, no ceremony. Both families are new capability over a shipped 1.5.0, so a
minor bump is the correct level. `pyproject.toml` and `__init__.py` move together
from 1.5.0 to 1.6.0 (David's manual step per the workflow; the number is now
decided, the bump is not yet done).

### AM1.2. Defect A does not gate

Defect A has been deferred since family 1 (the family-1 doc records it as a
"separate extractor-hygiene change"). Its family-2 consequence (AM7.5) is a
REGISTERED CHECK, not a measured defect: nobody has measured whether the divergent
trailing-punctuation spelling (`evil.com.` as `str` alongside `evil.com` as `url`)
mints needles outside the AM4.1 floor analysis. Blocking a release on an
unmeasured possibility that was RECORDED rather than DISCOVERED is backwards. It
stays a roadmap item, the registered check intact, and it runs when Defect A is
next touched. Defect A therefore does NOT gate v1.6, resolving the item-8 question
"whether Defect A blocks v1.6."

### AM1.3. Predictions docs: ship the raw chain, distilled doc as its entry point

Resolving the item-5 OPEN and superseding its recommendation. **Ship the raw
amendment chain, with a distilled document as its ENTRY POINT**, not as a
replacement.

- Rejected: distillation alone. It loses the falsifications, and the
  falsifications are the CREDENTIAL rather than the liability: four reasoned
  claims killed by cheap reads before a build (AM2.1's composite claim, the
  natural-URL partition, the length-aware floor reconstruction, the base64
  terminal boundary) are the evidence the method works, not embarrassments to
  hide.
- Rejected: internal-only. The method is half the value; hiding it keeps the
  weaker half.
- The distilled doc's job is to make the chain LEGIBLE (a reader's entry point
  and map), not to stand in for it.

The playbook concern (the reason earlier design docs were kept private) is thin
HERE, because every mechanism the chain describes is being shipped open source
regardless: forward-encode, the three encodings, the direction-(A) scan, the
three decisions, the floors, and the three-phase interior geometry are all in the
released code. There is no playbook to protect that the code does not already
publish. (This is a narrower judgment than the general no-publish-design-docs
precedent, and it turns on the mechanisms being open-source in this specific
release.)

### AM1.4. AgentDojo: a fresh run gates the release

Resolving the item-6 "David's call" and the item-8 "whether an evaluation run
gates" toward GATING, with the reasoning recorded.

The public claim's spine is "effective in the shipped default" (section 2). The
evidence for that spine is the frozen corpora, which only we can run. The
independently reproducible artifact, the published benchmark table, describes the
PRE-v1.6 engine. For a release whose differentiator is falsifier-carrying
measurement discipline, shipping with the reproducible number STALE and the
internal number LOAD-BEARING inverts exactly what the method advertises. So a
fresh run gates.

Outcome asymmetry, recorded so the gate is not mistaken for a risk:

- If the encoded-attack rows flip to caught and utility holds, that is the
  changelog headline.
- If something unexpected moves, the frozen corpora had a blind spot and it
  surfaced BEFORE release, which is the method working.
- No run OUTCOME makes the release worse. Only SKIPPING the run does.

**Run design: three columns if the harness allows.** `v1.5.0` baseline, `v1.6`
default, `v1.6` novel-on. The three columns show the gap (baseline), the fix
(v1.6 default), and the residual family-1 novelty surface the limitations section
already owns (novel-on). A single v1.6 column proves the engine passes; three
prove we know WHY, which is the claim the method makes.

### AM1.5. Independence determination, dated before the run

A read-only trace over all four prediction docs returns ZERO matches for
`agentdojo`, `benchmark`, `dojo`, or any variant: the chain never references the
benchmark by any name. **Verdict: FULL INDEPENDENCE.**

- **Attack rows** trace to the engine's own scratch probes in its own cprov
  session structure (one authoritative `user_message`/`alice`, one untrusted
  `web_content`/`fetch_url` carrying the injection), with encodings from the
  Phase 0 taxonomy and the threat model (F4, real-world attack prevalence).
- **Benign rows** trace to probe 2's minted-values finding (`system`/
  `authoritative` origin labels), the Phase 0 accidentally-valid-encoding surface
  (git SHA, API token, base64 config), and the terrain report's substring-carrier
  enumeration (JWT, data-URI, percent-encoded URL, de-hyphenated UUID).
- **No design decision cites benchmark behavior.** Decisions A, B, and C, the
  AM4.1 floor amendment, the AM4.2 anchor rule, AM4.3's rejection of option (b),
  and the `_SCAN_KINDS` curation each trace to the threat model, the collision
  math, encoded or interior lengths, or absolute per-alignment probability, never
  to a benchmark row cleared or a benchmark task needing a kind.

**Therefore the v1.6 AgentDojo run is EXTERNAL VALIDATION, not regression
evidence.** This framing was fixed BEFORE the numbers existed, so it is not
retrofitted to a result. That is the point of dating it here, before the run
AM1.4 gates.

### AM1.6. Two residuals on the determination

Recorded rather than smoothed:

- **SILENT on the literal choice of `evil.com` and `mallory@evil.com`.** The docs
  state the ROLE of these strings ("the injection") but never why THESE literals.
  Resolved as placeholder convention (the domain analogue of `example.com`) with
  no stated external source. Marked SILENT rather than inferred independent.
- **The probe and terrain scripts are NOT in the repo** (the family-1 doc states
  "Probes are not committed to the repo"). The determination rests on origins the
  documents STATE, not on construction code. If a probe had silently copied an
  external template at construction time, uniformly internal stated origins would
  not reveal it. Nothing in the text suggests this; the text cannot fully exclude
  it. What would settle it: inspecting the uncommitted probe and terrain scripts.
  This is the one channel the committed documents cannot close by themselves.

### AM1.7. Item-8 status after this amendment

Closed here: the version number (1.6.0, AM1.1), whether Defect A blocks (no,
AM1.2), the predictions-docs disposition (ship raw with a distilled entry point,
AM1.3), and whether an evaluation run gates (yes, AM1.4). Still OPEN, unchanged:
the IP composite fix shape and its family-1 regression, and the final public-claim
wording.

---

## AMENDMENT 2 (2026-07-24): corrects AM1.4 and AM1.5 before any run

This amendment CORRECTS the framing that Amendment 1 gave the v1.6 AgentDojo run,
on the basis of a measured read-only sweep of the benchmark's own content. It is
dated and recorded BEFORE any run. The original document and Amendment 1 are left
intact; AM1.4 and AM1.5 are superseded on the "external validation" claim only,
and this section states what replaces it.

### AM2.1. Measured finding: AgentDojo contains no encoded forms

A read-only sweep of the installed agentdojo package across all four suites
(banking, slack, travel, workspace) found NO encoded forms anywhere: no encoding
function calls, no percent-encoding, no base64 blobs, no hex escapes, no
defanging, no homoglyphs. Every injected target value (IBANs, recipients, URLs,
file IDs, passwords) appears as literal PLAINTEXT, wrapped in a social-engineering
template that embeds the goal verbatim without transformation.

Two representation quirks were found, and neither is an encoding:

- **Scheme-less bare domains.** A domain written without `http(s)://` is a form
  `_URL_RE` already reads (its scheme prefix is optional), so it is a plaintext
  token the tokenizer handles directly, not a transformed one.
- **A bit.ly shortener.** A shortened URL is a plaintext token expandable only by
  NETWORK RESOLUTION, not by string normalization or decoding. Forward-encode
  acts on string representations of known untrusted values; a shortener is a
  different value that resolves elsewhere, outside the mechanism's remit.

### AM2.2. AM1.4 and AM1.5 are corrected

Both framed the v1.6 AgentDojo run as EXTERNAL VALIDATION of the release claim.
That framing conflated two separate things. AM1.5 established that the frozen
corpora and the benchmark share no provenance, which is TRUE and REMAINS TRUE. But
provenance-independence is NECESSARY AND NOT SUFFICIENT for external validation:
the benchmark is ALSO independent of the CAPABILITY, because it never presents an
encoded payload for the encoding mechanism to act on (AM2.1). A run cannot
validate what it does not exercise. AM1.4's "the run is external validation" and
AM1.5's "therefore the run is EXTERNAL VALIDATION, not regression evidence" are
corrected on exactly this point.

### AM2.3. Corrected framing: the run is a no-regression gate

The AgentDojo run is a NO-REGRESSION GATE. It establishes that v1.6 does not break
the injection-blocking and utility behavior v1.5 had. It does NOT validate the
encoding capability, because the benchmark contains no encoded payload to catch.

The frozen corpora remain the ONLY capability evidence for the encoding work, and
there is no external validation of that capability available from this benchmark.
State this plainly, as a WEAKER position than AM1.4 assumed: "we ran the
benchmark" must not be allowed to imply more than a no-regression result. The
capability is proven internally (the four cuts, measured MET) and is not
externally corroborated by AgentDojo.

### AM2.4. The run still gates, for the corrected reason

v1.6 changes verdicts BY DESIGN and is not decision-invariant the way v1.5's work
was (family-1 R3 made this explicit for family 1, and family 2 adds encoded
catches). So a no-regression measurement against the published baseline is
required before release REGARDLESS of what the benchmark can validate: a
verdict-changing release must show it did not change the wrong verdicts. The
three-column design stands (v1.5.0 baseline, v1.6 default, v1.6 novel-on), but its
OUTPUT is a NO-REGRESSION TABLE, not a capability table. The columns show that the
baseline behavior is preserved (utility held, injection-blocking not regressed)
across the shipped default and the novel-on configuration, not that an encoded
attack was caught.

### AM2.5. Open, not decided: a custom encoded-injection variant

Whether to author a CUSTOM INJECTION VARIANT that encodes AgentDojo's own target
values (the IBANs, recipients, URLs, file IDs) and runs them through the same
harness is recorded as an OPEN option, not decided here.

- **Value:** it would exercise the mechanism on benchmark TASK SHAPES rather than
  on probe constructions, which is closer to external than the frozen corpora
  (real suite structure, real tool surfaces, real utility tasks around the
  injection).
- **Limitation:** it is AUTHORED BY US, so it is NOT independent in the AM1.5
  sense. It would be a stronger capability demonstration than the frozen corpora
  (benchmark task shapes) but still not third-party-independent evidence, because
  we chose which values to encode and how.

Recorded as a candidate for after the no-regression run, its value and its
limitation both stated. Not decided.

### AM2.6. Consequence for the public claim

The claim wording (still OPEN per AM1.7) MUST NOT cite AgentDojo as evidence for
the encoding capability. It may cite AgentDojo for NO-REGRESSION and the frozen
corpora for CAPABILITY, with the distinction VISIBLE to the reader. A sentence
that lets AgentDojo appear to corroborate the encoding catch would overstate
exactly the way AM2.2 corrects. The honest form separates the two: AgentDojo shows
v1.6 does not regress the v1.5 behavior; the frozen corpora show the encoded
attack is caught and attributed.

### AM2.7. Status after this amendment

AM1.5's independence VERDICT stands (the corpora and benchmark share no
provenance). AM1.4's GATING decision stands (the run happens before release). What
is corrected is the CHARACTER of the run: no-regression gate, not external
validation of capability. The item-8 open list is unchanged by this amendment (the
IP fix shape and the claim wording remain open), with the added AM2.6 constraint
on how the claim may cite the benchmark, and the added AM2.5 open option of a
custom encoded variant.

---

## AMENDMENT 3 (2026-07-24): the three-column AgentDojo no-regression run

This amendment records the measured result of the three-column AgentDojo run that
AM1.4 gated and AM2.3 re-characterized as a no-regression gate. The original
document and Amendments 1 and 2 are left intact. No mechanism change.

Run configuration, identical across all three columns: model
`gpt-4o-mini-2024-07-18`, `tool_knowledge` attack, agentlock defense, four suites
(workspace, slack, travel, banking), adapter defaults, 984 episodes per column,
zero crashes, `scored_as_attack_success=0`. Model calls billed to
platform.openai.com. All figures aggregated from per-episode JSONL, not stdout
(so an anomalous row can be audited per AM4.4).

### AM3.1. The table (utility / security per suite)

```
column                          | workspace     | slack         | travel        | banking       | combined
--------------------------------+---------------+---------------+---------------+---------------+---------------
baseline  (1.5.0, novel off)    | 37.68 / 0.00  | 4.76 / 17.14  | 32.14 / 0.71  | 38.89 / 0.00  | 33.40 / 2.00
v16-default (v1.6, novel off)   | 39.29 / 0.00  | 4.76 / 20.00  | 33.57 / 2.14  | 38.89 / 0.00  | 34.56 / 2.53
v16-novel-on (v1.6, novel on)   | 40.00 / 0.00  | 4.76 / 20.95  | 32.86 / 0.71  | 37.50 / 0.00  | 34.67 / 2.42
```

Utility is benign-task success; security is attack-success (lower is better).

### AM3.2. No-regression result confirmed

Baseline to v16-default: slack and banking utility identical to the decimal
(4.76 and 38.89), workspace and travel within single-run sampling spread, combined
33.40 to 34.56. NO suite regressed. Slack held at exactly 4.76 in all three
columns, the structurally pinned value (its floor comes from taint-gated outbound
and membership writes plus lineage blocks on reads, section 6 of the README's
AgentDojo notes), which confirms run stability across columns. The gate engaged
where expected: episodes with untrusted lineage gated tool calls, and a smoke test
showed a 7-call gating with reason `untrusted_lineage`. This is the release's
no-regression gate, and it PASSES.

### AM3.3. The uniform positive drift, recorded honestly

Every v16-default number moved slightly UP relative to baseline, utility AND
security, uniformly signed. Most plausibly single-run variance stacking (no seed
pinning, one `gpt-4o-mini` call per episode), and AgentDojo contains no encoded
payloads (AM2.1), so the family 2 mechanism cannot fire here to explain it. But a
uniform sign is ALSO the signature of a subtle real effect, and honesty requires
not asserting variance as if it were established. The clean separation is a
confirmatory SECOND BASELINE run, which measures baseline's own run-to-run drift
and tells variance from effect. Recorded as: no regression, small uniform positive
drift, most plausibly variance, the second baseline OPEN (carried to AM3.6).

### AM3.4. Novel-on did not drop utility, and why that is expected here

v16-novel-on combined utility 34.67 is flat against v16-default 34.56. The
predicted family-1 novelty false-positive cost DID NOT appear. This is a property
of AgentDojo's task shapes, NOT evidence that novel-on is cheap.

`novel_lineage` fires on unrecognized tokens WHEN an authoritative baseline
exists. AgentDojo's benign tasks supply their values in the user instruction, so
the tokens the agent uses are largely already authoritative, and there is little
novel-but-clean material to false-positive on. The real FP cost of novel-on was
measured at 88.9 percent on benign MINTED values (order IDs, UUIDs, computed
totals) in family 1's probe 2, none of which AgentDojo's benign tasks generate. So
the flat novel-on column is CONSISTENT with probe 2: the FP surface exists, this
benchmark does not exercise it.

This is the same limitation as the encoding-payload gap (AM2.2): the benchmark
cannot show what it does not present. The limitations section must state that
novel-on's FP cost is established by the FROZEN CORPORA, not by AgentDojo, exactly
as the encoding capability is.

### AM3.5. Consequence for the claim

The run supports exactly ONE public statement: v1.6 does not regress v1.5's
benchmark behavior on the four AgentDojo suites. It does NOT support any claim
about the encoding capability (AM2.2) or about novel-on's cost (AM3.4), both of
which the benchmark structurally cannot measure. Capability evidence remains the
frozen corpora only. Keep this distinction VISIBLE in the README and the paper: a
no-regression sentence citing AgentDojo, a capability sentence citing the frozen
corpora, and no sentence letting the benchmark appear to corroborate either the
encoding catch or the novelty cost.

### AM3.6. Open, carried forward

- The confirmatory SECOND BASELINE run (AM3.3), to separate the uniform positive
  drift from variance.
- The custom encoded-injection variant (AM2.5), which remains the one path toward
  external capability evidence, still authored-by-us and so not independent in the
  AM1.5 sense.
- The final claim wording (item 8), which this run now CONSTRAINS to no-regression
  language for AgentDojo (AM3.5) on top of the AM2.6 constraint.

The gating decision (AM1.4) is satisfied: the no-regression gate ran and passed
(AM3.2). The IP composite fix shape (item 8) is untouched by this run.
