# Pre-registered prediction: the adapter threading arc
# Date: August 12, 2026
# Author: David Grice
# Branch: v1.6-derivation-taint

## Status at time of writing

No mechanism code for this arc exists anywhere. Neither adapter threads the tool
call's input arguments to `notify_context_write`, so no parameters reach the
engine's ingestion path from any deployed flow, no links are recorded, and the
entire cross-hop mechanism (the containment linker, the taint preference, the
AM10.3 decline, and increment 3's broadened decision-time sites) is inert in
every deployed flow. That is the deployment prerequisite AM20.5 records, and
this document freezes the prediction for closing it.

**This arc changes NO engine code.** `agentlock/` is untouched by the builds
predicted here. The engine repository's only role in this arc is to hold this
record.

### World at freeze time, read rather than recalled

| repository | commit | tree |
|---|---|---|
| `agentlock` (this repo) | `192dd727f678e0d96c2f2e9d6219d1fd94308ea7` | clean |
| `crewai-agentlock` | `1b69b6d087913d972d295883dc7965b18905b463` | clean |
| `mcp-agentlock` | `f10204210920cf1f7e300e9104d756fbc2350eb3` | clean |

Measured suites at those three commits:

```
agentlock (this repo)          1418 passed,  0 failed,  7 skipped
crewai-agentlock                 58 passed,  0 failed,  0 skipped
mcp-agentlock                    66 passed,  0 failed,  0 skipped
```

### One environment fact that governs reproduction

`site-packages` carries `agentlock 1.4.0`, while both adapters declare
`agentlock>=1.5`. Every adapter figure in this document was produced with
`PYTHONPATH=/home/n1trolab/agentlock-v1.4`, verified in process as
`engine 1.6.0 /home/n1trolab/agentlock-v1.4/agentlock/__init__.py`. Without that
pin the adapter suites silently measure the 1.4 engine, in which the containment
linker does not exist, and every figure below is unreproducible. Any re-run that
does not state this pin has not reproduced anything.

---

## 0. FOUR PREMISE CORRECTIONS THIS FREEZE CARRIES

The read-only discrimination pass that produced this document was briefed from a
designer-chat description of the world that was wrong in four places. Each is
corrected here so the frozen record carries the correction rather than the
briefing.

### 0.1 No S7 adapter-verified claim exists

The briefing described `mcp-agentlock` as carrying an "S7 adapter-verified
claim": three frozen encodings producing `param_lineage` denials byte-for-byte
identical to the bare engine over in-memory transport. **No such claim exists.**
A grep for `S7` across both adapter repositories returns nothing.

The actual S7 is `docs/LIMITATIONS_v16.md:143`, and it is titled
**"The v1.6 capability claim is an ENGINE-level claim"**. It says the opposite of
the briefing:

> **No encoded corpus has been run through an adapter**
> (`RELEASE_SCOPE_v16.md`, AM4.3, residual 1).

`RELEASE_SCOPE_v16.md:763-765` records the verifying grep, and the discrimination
pass **re-ran it at both adapter HEADs named above**: the pattern
`b64encode|base64|.hex()|%2e|b16encode|urlsafe` across `crewai-agentlock/tests`
and `mcp-agentlock/tests` returns no matches. AM4.3 residual 1 holds exactly as
written. The briefing's description was a designer-chat error and is corrected
here rather than propagated. See section 8 for what was built in its place and
what promoting it would retire.

### 0.2 No mcp<2 tourniquet exists

The briefing described a `mcp>=1.26,<2` pin constraining the request object's
shape. There is no such pin. `mcp-agentlock/pyproject.toml` declares `mcp>=1.0`,
and this repository's optional extra is `mcp = ["mcp>=1.0"]`. Version `1.26.0` is
what happens to be installed, not what is pinned.

The guarantee the briefing attributed to the pin comes from SDK code instead. In
`mcp/server/lowlevel/server.py`:

```
arguments = req.params.arguments or {}                              # :524
if validate_input and tool:
    jsonschema.validate(instance=arguments, schema=tool.inputSchema)  # :530
results = await func(tool_name, arguments)                          # :535
```

So `arguments` reaches the guarded handler as a plain dict already validated
against the tool's `inputSchema`, because `lock_call_tool` registers with
`validate_input=True` by default (`registration.py:77`). That is a property of
the dispatch code, not of a version bound, and no version bound in this arc
protects it.

### 0.3 The arguments live one frame up, and crewai has TWO call sites

The briefing named `crewai-agentlock/src/crewai_agentlock/wrapper.py:78` and
`mcp-agentlock/src/mcp_agentlock/wrapper.py:273` as the threading sites. Both
line numbers are correct as the location of the `notify_context_write` call, and
**at neither line are the arguments in scope.** In both adapters that call sits
inside a module-level helper
`_maybe_record_provenance(gate, session_id, tool_name, token_id, output, source)`
which is not passed them.

The arguments exist one frame up, in the caller, as a plain dict:

| adapter | call sites | local name |
|---|---|---|
| `crewai-agentlock` | **two**: `_run` at `:242`, `_arun` at `:280` | `kwargs` |
| `mcp-agentlock` | **one**: `guarded` at `:456` | `arguments` |

In both adapters that same dict is **already** being handed to the engine on the
same call: `gate.authorize(parameters=kwargs or None)` at crewai `:177` and
`gate.authorize(parameters=arguments or None)` at mcp `:385-391`, plus
`gate.execute(parameters=...)` at crewai `:240` and
`validate_and_consume` / `begin_execution` at mcp `:407` and `:409`. Threading
routes no data to the engine that the engine was not already receiving
microseconds earlier from the same variable. That is why this arc's risk class is
as low as it is, and the claim is structural rather than optimistic.

The crewai count of two is the single most important correction of the four,
because it is the omission mode this arc has to defend against. See section 5.

### 0.4 Both two-hop laundering tests pass for a reason their docstrings misstate

`crewai-agentlock/tests/test_provenance.py:267` and
`mcp-agentlock/tests/test_provenance.py:290`, both named
`test_two_hop_laundering_slips`, assert that no provenance entry has a parent and
that the laundered value reaches the sink. Both docstrings attribute the slip to
the adapter: "the wrapper sets no `parent_provenance_id`". Both READMEs' single
hop enforcement sections say the same.

Under the threading emulation both tests still pass, and **not for the reason
stated.** The relay in each test is invoked without the untrusted value:

```
relay.run(text="ignored")                                  # crewai :295
await client.call_tool("summarize", {"text": "ignored"})   # mcp, via_summarize path
```

Shim capture confirms the parameters reaching ingestion are `{'text': 'ignored'}`.
The untrusted page text is never an argument to the relay, so no link can form no
matter what the adapter threads. Post-threading these tests pin **"an uncarried
value does not link"**, which is true and unremarkable, and NOT "the adapter
cannot link across a hop", which is the boundary the prose claims they record.

**Rewrite obligation of this arc**, recorded here so it cannot be forgotten at
build time: both docstrings, and both READMEs' single hop enforcement sections.
The tests themselves are kept and their assertions stand (section 3.1).

---

## 1. SCOPE: ONE ARC, TWO BUILD INCREMENTS PLUS CORPUS WORK

The two adapter changes are pre-registered as **one arc**. They share the shape
(add a `parameters` argument to `_maybe_record_provenance`, pass the call's input
dict from each call site), the risk class (the dict already flows to the engine
on the same call), and the measured consequence (identical inertness, identical
activation). The prediction in section 2 is one prediction verified twice, not
two predictions.

**Corpus increment, landing BEFORE either build.** Carriage sessions committed to
both adapter suites, per the shapes frozen in section 3. The corpus lands first
so that each build is measured against a corpus that already exists, and so the
must-catch row is available as the tripwire section 4 depends on.

**Increment A, `crewai-agentlock`.** Add a `parameters` argument to
`_maybe_record_provenance` and pass the call's `kwargs` dict from **both** call
sites: the sync `_run` at the `:242` region and the async `_arun` at the `:280`
region. **The async site is named here as the place an omission could hide while
the sync suite stays green**, which is why it is a falsifier in its own right
(section 5) rather than a build detail.

**Increment B, `mcp-agentlock`.** The same helper change, one call site in
`guarded` at the `:456` region, passing `arguments`. The per-tool
`record_provenance` opt-out branch is preserved unchanged: threading sits inside
that branch, so a tool configured `record_provenance=False` continues to record
nothing at all.

**Engine repository.** No engine code changes in this arc. `agentlock/` is
untouched. The engine suite figure in section 2.3 is a no-movement assertion, not
a target.

---

## 2. THE FROZEN PREDICTION

Verified twice in the discrimination pass, once per adapter, and pinned here.

### 2.1 INERTNESS ON THE SHIPPED CORPORA

**Threading changes no existing test outcome in either adapter.**

| adapter | before | after |
|---|---|---|
| `crewai-agentlock` | 58 passed, 0 failed, 0 skipped | 58 passed, 0 failed, 0 skipped |
| `mcp-agentlock` | 66 passed, 0 failed, 0 skipped | 66 passed, 0 failed, 0 skipped |

Per file, unchanged in both directions:

```
crewai   test_context 8   test_decorator 6   test_denial 5   test_provenance 9
         test_registration 10   test_session 5   test_wrapper 15
mcp      test_context 11  test_denial 7   test_provenance 12
         test_registration 8   test_session 11  test_wrapper 17
```

**Zero ingestion writes gain a parent link.** Census pinned:

| adapter | ingestion writes | with parameters | linked |
|---|---|---|---|
| `crewai-agentlock` | 13 | 13 | **0** |
| `mcp-agentlock` | 24 | 19 | **0** |

The mcp gap of 5 is faithful rather than a harness defect: those are
empty-arguments calls, where `parameters=arguments or None` correctly passes
`None`. A built increment reproducing 24 with 24 would indicate the normalisation
at `guarded:353` was disturbed.

**No provenance shape any test asserts on changes.** Source, authority, content,
content hash, writer id, tool name and token id are all written from the same
expressions as today; the threading change adds one argument and alters none.

**Mechanism, stated so the prediction is falsifiable by reasoning as well as by
running.** No session in either shipped suite carries a prior entry's whole
content in a parameter. `_containment_parent` (`agentlock/context.py:694`) links
by whole content carriage: a prior entry's normalized content must be at least
`CONTAIN_MIN = 24` characters and must appear as a substring of a parameter leaf.
Across both suites only 9 writes carry any leaf of 24 characters or more, and
every one is a short URL or an email address, never a full prior tool output.
Inertness on the shipped corpora is therefore structural, and it is the same
structural fact that makes the mechanism inert in deployment.

### 2.2 ACTIVATION UNDER REAL CARRIAGE

On a three-hop session in which the relay genuinely carries the fetched untrusted
content (`relay.run(text=page)` in crewai, `call_tool("summarize", {"text": PAGE})`
in mcp), with everything else identical to the laundering shape:

- the ingestion write for the **relay** links to the untrusted **fetch** entry,
- the sink call is **DENIED** with reason **`param_lineage`**,
- the denial cites the **RELAY** entry (`summarize:cprov_...`) as the untrusted
  origin, **not** the fetch entry,
- the sink never executes, so no third provenance entry is written.

Measured shape of the flip, both adapters:

```
before threading                        after threading
[0] web_fetch   untrusted  parent=-     [0] web_fetch   untrusted  parent=-
[1] summarize   derived    parent=-     [1] summarize   derived    parent=cprov_<fetch>
[2] send_email  derived    parent=-     (no third entry: the sink never ran)
sink: sent to <laundered>               sink: DENY param_lineage, citing summarize:cprov_...
```

Identical behavior in both adapters, with the mcp arm measured over a live
in-memory server and returning `isError=True`.

The citation naming the relay rather than the fetch entry is the load-bearing
detail. It is the observable signature that the decision-time path consumed a
link recorded at ingestion: `summarize` is `DERIVED` by its own authority and
enters `parameter_lineage_check`'s haystack only through
`_reachable_untrusted_entries` (`agentlock/context.py:665`) walking the recorded
parent edge. A denial that cites the fetch entry instead would mean the flat
authority view produced it and the link was not consulted, which is a falsifier
(section 5), not a cosmetic difference.

This is also the first end-to-end traversal of the deployed stack: ingestion
linking through increment 3's broadened decision-time sites, in an adapter flow.
**No existing adapter test traverses that path**, because with an empty link
graph the broadened sites select exactly the entries that are untrusted by their
own authority, which is byte-identical to pre-increment-3 behavior. The corpus in
section 3 is what makes the traversal exist.

### 2.3 THE ENGINE SUITE IS UNTOUCHED

`1418 passed, 0 failed, 7 skipped` before and after. This arc modifies no file
under `agentlock/`. Any movement at all is a falsifier (section 5).

---

## 3. CARRIAGE CORPUS SHAPES

This freeze pins the shapes and their expected outcomes. The corpus increment
pins the exact assertions.

### 3.1 Must-not-link session

The existing laundering shape, relay called without the value. Expected: no
links, the slip proceeds, the sink returns the laundered value.

**Kept, with an honest docstring replacing the stale one** (section 0.4). The
assertions stand as written. What changes is the prose: it must say the session
does not carry the value, rather than that the adapter cannot link.

### 3.2 Must-catch session

The real-carriage shape of section 2.2. **Both states are pinned so the corpus
measures the flip rather than only the end state:**

| | expected |
|---|---|
| before threading | 3 entries, no parents, sink allowed (the slip) |
| after threading | link formed, sink denied `param_lineage` citing the relay entry, no third entry |

The corpus mirrors on the threading change the same way the decision-time harness
mirrors on its symbol.

### 3.3 What the discriminator keys on

**The `parameters` argument appearing in `_maybe_record_provenance`'s signature,
per adapter, checked by `inspect.signature`.**

This cannot false-positive today. Both current signatures were read at the
commits named in the status section:

```
crewai  _maybe_record_provenance(gate, session_id, tool_name, token_id,
                                 output, source=ContextSource.TOOL_OUTPUT) -> None
mcp     _maybe_record_provenance(gate, session_id, tool_name, token_id,
                                 output, source) -> None
```

Neither carries a `parameters` parameter:
`'parameters' in inspect.signature(...).parameters` is `False` for both. The
discriminator is therefore a genuine mirror at freeze time, and a corpus row that
reports the after-state before either build has launched is itself an audit
trigger.

---

## 4. SEQUENCING CONSTRAINTS AGAINST THE MCP 2.0 MIGRATION

Recorded as frozen constraints, not preferences.

**Threading and its corpus land BEFORE the mcp 2.0 migration.** A per-request
`ServerSession` inversion would make `mcp_session_id()` mint a new id per
request, `get_binding(connection_id)` would miss, identity would fall back, and
`_provenance_session_id` would return the `ctx.session_id` that `guarded:381-382`
has just set to the per-request connection id. Every ingestion write would then
land in a different session log, the linker's `prior` list would be empty on
every call, and **threading would go silently inert with every suite green**. The
existing suites already pass with zero links, so they cannot detect this.

**The must-catch carriage row is the tripwire.** It is what makes that regression
visible, as a lost denial on a row that is required to catch. **A post-migration
carriage re-run is mandatory**, and this paragraph is recorded here as a standing
condition on the migration arc, to be cited by that arc's own pre-registration.

**Otherwise the two are orthogonal.** They read disjoint data paths inside
`guarded`. Threading reads `arguments`, a direct positional parameter of the
handler supplied by the SDK at `server.py:535`, which never touches
`request_context`, `ServerSession`, or the binding registry. The migration
concerns the session-id path: `current_request_context()` to `mcp_session_id()`
to `_CONNECTION_IDS[ServerSession]` to `get_binding()` at `:369-371`, consumed by
`resolve_context`, `_provenance_session_id` and `_build_metadata`. They meet only
at the `_maybe_record_provenance` call, where the migration would alter argument
2 (`session_id`) and threading adds argument 7 (`parameters`). That is textual
adjacency and a possible one-line merge conflict, not a semantic dependency.
Neither change constrains the other's design.

---

## 5. FALSIFIERS

- **Any existing adapter test changing outcome** under the built threading.
- **Any link forming on the shipped corpora**, in either adapter.
- **The must-catch carriage row not flipping** to the attributed denial, **or
  citing the fetch entry instead of the relay entry.**
- **The crewai async path recording writes without parameters while the sync path
  records them with.** This is the named omission mode of section 0.3, and it is
  listed separately because the sync suite stays green while it is happening.
- **The mcp `record_provenance` opt-out ceasing to suppress writes.**
- **The engine suite moving at all** from `1418 passed, 0 failed, 7 skipped`.

Any of these is an audit trigger: investigate before proceeding, never reconcile
after. Deviations go in a dated amendment, as with families 1 and 2 and the
cross-hop increments, and **this file is not edited once the builds launch.**

---

## 6. CONFIDENCE LABELING

Per the standing discipline.

- **SIMULATION-BACKED**: predictions 2.1 and 2.2 in full. Both were produced by
  the discrimination pass's emulation, which replaced each adapter's module-level
  `_maybe_record_provenance` with a version reading the call's arguments out of
  the caller's frame and forwarding them as `parameters=`, with the content and
  hash arguments byte-identical to the shipped helper. Runs were against
  `rsync` copies of both adapter repositories with the engine at `192dd72`. That
  is emulation of the mechanism, not the mechanism. Both crewai call sites were
  confirmed exercised, including the async one by separate frame capture, so the
  figures are not silently single-path.
- **MEASURED**: every figure in the status section (the three commits, the three
  suite triples, the per-file baselines), the census counts in 2.1, the two
  current helper signatures in 3.3, the AM4.3 residual 1 re-verification in 0.1,
  the pyproject declarations in 0.2, and the SDK dispatch lines in 0.2.
- **SPEC-DERIVED**: the corpus mirror structure in section 3, which is read off
  the discriminator rule rather than observed, and remains spec-derived until the
  corpus increment commits it. Prediction 2.3 is likewise spec-derived: it
  follows from the scope decision that `agentlock/` is untouched, and is an
  assertion about what the arc does not do.

**All figures here are PREDICTIONS to be re-checked against the built
increments, and any mismatch is an audit trigger** of the same kind as those in
section 5.

---

## 7. CONDITIONS

- **Frozen baseline**: the three commits named in the status section, with their
  three measured triples. A change to any of the three invalidates the figures
  here.
- **Frozen environment**: the engine resolved from the working tree at `192dd72`
  via `PYTHONPATH`, never the `1.4.0` in `site-packages`. Stated in the status
  section because it is a reproduction precondition, not a convenience.
- **Frozen spec**: AM20.5 for the deployment prerequisite this arc closes, and
  `PREDICTIONS_crosshop_increment3.md` for the broadened decision-time sites this
  arc's must-catch row is the first adapter-level consumer of. This document
  amends neither.
- Nothing in this scope modifies `agentlock/`, any engine test, any family-1 or
  family-2 code, or the mcp session-id path.
- **Verification order**: land the corpus, confirm the must-not-link and
  must-catch rows read their before-states, build increment A, re-run crewai and
  compare against 2.1 and 2.2, build increment B, re-run mcp and compare, then
  re-run the engine suite and confirm 2.3.

---

## 8. FOLLOW-UP, not part of the threading increments

**The encoded-corpus shape was built and measured in the discrimination pass, and
is deferred here with its evidence named.**

Because no adapter-level encoded corpus existed (section 0.1), the discrimination
pass constructed the shape the briefing had described and ran it: 7 rows (the
four counted bare encodings, the two composites, and the positive control), each
in novelty-on and novelty-off, giving 14 comparisons per arm, bare engine against
the mcp adapter over in-memory transport. The bare-engine reference was
reproduced from `tests/test_v16_family2_base64composite.py`'s `_build` and `_net`.
**All 14 comparisons identical in both arms, baseline and emulated.**

Two things follow, and only two.

**It is not evidence for this arc.** It is reported here so the work is not lost
and not re-done.

**Promoting it to a committed `mcp-agentlock` corpus would retire AM4.3
residual 1**, with a dated amendment to `RELEASE_SCOPE_v16.md` and a
corresponding correction to `docs/LIMITATIONS_v16.md:143`. That is a **named
follow-up of this arc and explicitly not part of the threading increments.** It
is deliberately not done in this pass.

One scope note to carry into that follow-up, so it is not promoted as broader
than it is. The byte-equality holds because the shape is single-hop: the only
adapter-owned ingestion write is the fetch, whose parameters do not carry a prior
entry's content, so no link forms and the citation row does not move. Extend that
corpus to a multi-hop session with real carriage and the cited provenance id
moves off the fetch entry onto the relay entry, exactly as section 2.2 measured.
The retirement amendment must scope the claim to single-hop sessions rather than
stating it unqualified.

---

## 9. Reproduction of status

No threading mechanism code exists in either adapter at the commits named in the
status section, and none is written by the pass that produced this document. The
figures in section 2 were produced by a read-only discrimination pass that copied
both adapter repositories to scratch, ran each suite baseline and under the
frame-capture emulation described in section 6, and instrumented every ingestion
write to census the links formed. Neither adapter repository was modified. The
four corrections in section 0 were each read from the current trees rather than
carried from the briefing, which is why they are corrections.

---

## AMENDMENT 1: the arc built and matched
# Date: August 12, 2026

Pointer style. This amendment records outcomes and cites the commits that carry
them; it does not restate the frozen sections above, and it edits none of them.

### AM1.1. BUILT AND MATCHED

Five commits, in landing order, each gated on exact match before the next began.

| step | repo | commit | shape |
|---|---|---|---|
| corpus | `crewai-agentlock` | `d5fa2ea` | carriage sessions, sync and async, mirrored |
| corpus | `mcp-agentlock` | `64a9fad` | carriage session over in-memory transport, mirrored |
| increment A | `crewai-agentlock` | `92c97b5` | 4 added lines: helper signature, the forward, BOTH call sites including async |
| increment B | `mcp-agentlock` | `5b87da6` | 3 added lines: helper signature, the forward, the one call site INSIDE the `record_provenance` branch |
| documentation | `crewai-agentlock` | `094f779` | docstrings and README, AST-strip-verified documentation-only |
| documentation | `mcp-agentlock` | `7b88efa` | docstrings and README, AST-strip-verified documentation-only |

**Prediction 2.1, inertness, HELD.** Census over the shipped corpora under each
BUILT adapter: crewai 13 writes, 13 carrying parameters, **0 linked**; mcp 24
writes, 19 carrying parameters, **0 linked**, the 5 without being
empty-arguments calls where `arguments or None` passes `None`. Exactly the
figures section 2.1 pinned, now measured through the mechanism rather than
through the emulation. Every pre-existing test unchanged in isolation: crewai
58, mcp 66.

**Prediction 2.2, activation, HELD, on all three paths.** Denial reason
`param_lineage`; citation naming the **RELAY** entry and never the fetch entry;
relay entry's `parent_provenance_id` equal to the fetch entry's
`provenance_id`; two provenance entries because the sink never executed; and
for mcp `isError` true over a live in-memory server. Verified on crewai sync,
crewai async, and mcp.

**Prediction 2.3, engine unmoved, HELD.** `1418 passed, 7 skipped` before every
build, after every build, and at this amendment. No file under `agentlock/` was
modified by any commit of this arc.

**Triples matched exactly, and the mirrors were derived before building** as
section 3.3 requires: crewai `65 / 0 / 3`, mcp `72 / 0 / 2`, each verified per
test for the membership flip rather than by count alone.

**One prompt-side expectation was wrong and is corrected here.** The brief for
increment B expected mcp's mirror to be ASYMMETRIC, so that its triple would
move across the build. It does not. Both mirrors are symmetric: crewai splits 4
unconditional / 3 absence-gated / 3 presence-gated, mcp splits 4 / 2 / 2, so
each triple is invariant across its own flip and only membership changes. mcp
lacks crewai's sync-and-async carriage pair, which removes one gated pair, and
gains the `record_provenance` opt-out guard, which crewai has no equivalent of.
The derivation was performed and stated before building in both cases, which is
why the discrepancy surfaced as a correction rather than as a surprise at
measurement time. **No triple in section 2 is amended: 2.1 predicted the crewai
and mcp suite behavior, not the arithmetic of the corpus mirrors, which did not
exist when the freeze was written.**

### AM1.2. AM20.5 IS CLOSED

The deployment prerequisite recorded at `PREDICTIONS_crosshop.md` AM20.5, that
neither shipped adapter passes a tool call's input arguments and therefore no
cross-hop linking occurs in production, **is closed by increments A and B.**

Cross-hop enforcement is now live end to end in both deployed adapter flows:
ingestion linking, taint reachability, and the increment-3 broadened
decision-time sites all have a live consumer. Section 2.2's note that no
existing adapter test traversed that path is retired by the carriage rows,
which traverse it in both repos.

### AM1.3. DOCUMENTATION CORRECTED

Both READMEs' single-hop sections are rewritten to the measured claim, which is
cross-hop enforcement bounded by carriage rather than by hop count, with the
three remaining bounds stated as a list: an uncarried value produces no link,
linking requires whole-content carriage clearing the engine's containment
floor, and encoded forms are measured at the engine with no adapter-level claim
made. Both helper docstrings document `parameters` in the shape the engine's
own `notify_context_write` uses. Both `tests/test_provenance.py` module
docstrings are corrected, and mcp's README test count is refreshed with an
explanation of what its two skips are.

**One residue, recorded rather than silently carried.**
`test_single_hop_is_still_enforced_after_a_relay_call` in `mcp-agentlock` keeps
its now-stale name so its test id stays stable; its docstring records that the
name predates cross-hop linking and states what the test actually measures. A
rename is its own commit if it is ever wanted, and is not owed by this arc.

Section 0.4's rewrite obligation is discharged.

### AM1.4. OPEN ITEMS OF THIS ARC, carried and not dropped

**a. The encoded-corpus follow-up of section 8 is STILL OPEN.** Promoting the
measured S7-shape corpus into `mcp-agentlock` would retire AM4.3 residual 1,
with the retirement amendment scoped to single-hop sessions per section 8's own
note. Nothing in this arc retires that residual, and no adapter-level encoded
claim may be made until it does.

**b. The migration tripwire is now ARMED.** Section 4 recorded the condition;
what was missing was the row that fires. Both repos now carry a carriage
must-catch row, so a post-mcp-2.0 carriage re-run has something that fails
visibly if a per-request `ServerSession` inversion scatters writes across
per-request session logs. The standing condition on the migration arc is
unchanged and now enforceable rather than aspirational.

**c. The docstring and README claims are now load-bearing public statements.**
They describe linker semantics in prose: whole-content carriage, and a
containment floor. Any future change to those semantics, a `CONTAIN_MIN`
recalibration or an NFKC admission among them, must sweep both adapters'
READMEs and both helper docstrings in the same arc that changes the engine.
This is a new maintenance obligation created by this arc and is recorded here
because nothing else would carry it.

### AM1.5. PUSH STATE AT AMENDMENT TIME, read rather than assumed

Nothing in this arc has been pushed anywhere.

| repo | local | remote | ahead |
|---|---|---|---|
| `agentlock` | `5ffeb9b` plus this commit | `private/v1.6-derivation-taint` at `192dd72` | 2 after this commit |
| `crewai-agentlock` | `094f779` | `origin/main` at `b124280` | 4 |
| `mcp-agentlock` | `7b88efa` | `origin/main` at `f102042` | 3 |

Two corrections to the values this amendment was briefed with, both read from
the repositories rather than carried forward:

- **`mcp-agentlock` is 3 commits ahead, not 4.** Its arc is exactly corpus,
  build, documentation. The brief said four.
- **`agentlock`'s branch tracks `private/v1.6-derivation-taint`, not `origin`.**
  `origin/main` is at `2287bae`, a different line entirely, so "remote tip
  `192dd72`" is correct only against the private remote.

`crewai-agentlock`'s four is correct as a count, with one qualification worth
recording: only three of those four belong to this arc. `1b69b6d`, the
provenance write-target resolution, predates the arc and was already unpushed
when the freeze was written.
