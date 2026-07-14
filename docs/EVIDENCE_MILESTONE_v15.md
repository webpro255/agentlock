# v1.5 evidence milestone: decision invariance

The v1.5 evidence work changes what the gate RECORDS. It does not change what
the gate DECIDES. This document records how that was verified, and states the
limits of the verification rather than rounding them off.

The milestone closes five gaps in what the engine writes down, four of them in
this branch: lineage evidence on lineage-gated denials, a session id on the
taint-introduction record, an audit record for the resolution of a deferred
action, and the population of `context_provenance_ids`, which had been declared
in the schema since v1.1 and passed by no call site. A fifth commit makes the
cited lineage token deterministic across processes. None of it touches a
decision path: the evidence is built after the decision, from values the gate
had already computed, and nothing in the gate reads an audit record back.

## Method

The claim under test is that every authorization decision is identical before
and after. Re-running the AgentDojo benchmark cannot establish that. It samples
at temperature 1.0 with no seed, so a second run produces different agent
trajectories regardless of the engine, and would compare two different sets of
tool calls.

So the decisions were replayed instead, offline and deterministically:

* Every episode of the frozen v1.4 benchmark run supplies the model's tool
  calls, their arguments, and the tool outputs, read from the saved transcripts.
  The model is not in the loop and cannot vary.
* The replay drives a real `AuthorizationGate` through the same sequence the
  benchmark adapter drives: seed the provenance log from the episode's message
  history, authorize each tool call with the same action-class flags, record
  each executed tool's output back into the provenance log, then resolve the
  deferred-commit queue at end of turn.
* That harness is run twice against identical inputs: once with a `git worktree`
  checked out at tag `v1.4.0`, once against this branch. The engine is the only
  variable. Any difference in the decision stream is attributable to the engine
  and to nothing else.

The harness lives outside the engine tree and is not part of the package. The
benchmark artifacts were read, never modified.

## Result: zero decisions changed, on the decisions that could be replayed

| Condition | Suite | Decisions replayed | Differences |
|---|---|---|---|
| R1-slack-identity | slack | 760 | 0 |
| R2-travel-baseline | travel | 1360 | 0 |
| R3-travel-selective | travel | 1493 | 0 |
| R4-slack-control | slack | 777 | 0 |
| D1-slack-defended-benign | slack | 152 | 0 |
| **Total** | | **4542** | **0** |

Every ALLOW, DENY, DEFER, STEP_UP and end-of-turn COMMIT is identical between
the two engines, including the `param_lineage` and `untrusted_lineage` denials
this milestone touches. The result held before and after the citation-sort fix.

## Harness validity, and where it stops

A replay that cannot reproduce the decisions the benchmark actually recorded
cannot certify that those decisions did not change. So the baseline replay was
checked against the frozen `decisions.jsonl` the real run wrote.

It reproduces that log exactly on the three slack conditions: R1 (760), R4
(777), and D1 (152), or 1689 decisions matching in tool, decision, reason, and
arguments.

It does not reproduce the two travel conditions in full, and the reason is not
the engine and not the harness. Those runs' decision logs contain more gate
calls than their own saved transcripts contain tool calls: 176 more in
R2-travel-baseline and 108 more in R3-travel-selective, 284 in total. Those
decisions cannot be replayed by any harness, because the inputs that produced
them were never persisted. Episode-by-episode alignment shows the rest
reproducing exactly and in order (144 of 146 in R2), with the surplus
concentrated in four episodes of a single user task.

The surplus is a property of the benchmark artifacts, not of this milestone. It
is written up separately, outside this repository, as a benchmark
artifact-integrity finding.

## Execution confirmation (E7), and the invariant that governs it

An `allowed` record is a grant of permission. It is not evidence that anything
ran. The gate now writes an attempt record before a tool is invoked and a
completion record when it returns or raises, so three facts that used to be one
indistinguishable state are now three readable ones:

| Evidence | Reading |
|---|---|
| attempt, then completion | ran, and the status says how it ended |
| attempt, no completion | attempted, never returned (hang, crash, kill) |
| neither, with a grant | authorized, never attempted |

Callers that own their own execution (an MCP server, an async tool, any
framework with its own executor) report through the public `begin_execution` and
`confirm_execution`, bound to the grant by token id, or by deferral id for an
action committed at end of turn. Those calls verify; they never authorize. They
issue no token, consume none, extend no TTL, consult no policy, and write nothing
that `authorize()` reads.

**The invariant, stated exactly.** Never break and never alter are absolute, and
they are enforced by tests: a backend that throws on every write, on the attempt
only, or on the completion only cannot break, block, or change a tool call the
gate has already authorized. The failure is swallowed at the writer boundary,
reported out of band to the `agentlock.audit` logger, and counted on
`gate.evidence_write_failures`, so a blind evidence layer says so rather than
failing quietly.

Never block is **not** a property of the gate. It is a property of the audit
backend the deployment chooses. Synchronous is the default because a record that
cannot survive a crash cannot describe one: the attempt record is durable before
control leaves the gate, which is what makes an orphaned attempt mean anything.
`AsyncAuditBackend` is available for deployments that cannot afford the write on
the hot path. It never blocks, drops loudly when its queue is full, and loses
queued records if the process dies, so under it the absence of a record is not
evidence that the thing did not happen. Every record it writes is stamped
`writer_mode` and `durable_before_execution`, so a reconstruction reads that
limitation out of the log rather than out of a config file it does not have.

One scope note, asserted in a test rather than left implicit: the non-fatal rule
covers the execution path. On the authorize path a backend failure still
propagates and no token is issued, so the call fails closed. That polarity is
deliberate. An unrecordable decision must not become an unrecorded permission.

An absent completion record supports the conclusion "attempted, never returned"
only where the log is contiguous across that action's window. In a rotated,
filtered, or partially exported log, the completion may simply sit in a segment
the reader does not hold. Absence claims must be coverage-qualified.

The invariance replay above was re-run after execution confirmation landed and
still shows zero diffs across all 4542 replayable decisions. Its scope is worth
stating precisely: the replay drives `authorize()`, not `execute()`, so it proves
the authorization path did not move and says nothing about the execution path,
which the unit tests cover instead.

## What is therefore claimed, and what is not

Claimed: across 4542 decisions replayed from the frozen v1.4 benchmark under
identical inputs, the v1.5 evidence changes moved zero decisions. Together with
the full test suite (1074 tests, 0 failures), that is the invariance evidence.

Not claimed: that all 4826 decisions in the frozen logs were verified. 284 of
them could not be replayed, and no confidence is asserted about them beyond the
fact that they lie on the same code paths as the 4542 that were. Invariance here
is bounded, not total. Saying otherwise would be the same error this milestone
exists to correct: reporting a conclusion the evidence does not support.
