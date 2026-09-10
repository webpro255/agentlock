# v1.10 Integration Hardening: Baseline of Record and Frozen Predictions

Date: 2026-09-10
Branch: `v1.10-integration-hardening`, cut from `4b0409f Merge
v1.9.1-binding-collision: binding completeness, red pass closed`, which is the
v1.9.1 merge on `main`.
Working tree at measurement time: clean except the review's test file, which
this freeze adds.

This arc closes seven issue groups found by an external review of the published
1.9.1 wheel. The review supplied a runnable 33 test oracle, saved verbatim at
`tests/test_v110_system_review.py`. That file is the contract for the arc: it is
the definition of done and it is not edited again after the two mechanical
changes recorded in section 3.

No new detection feature. No new denial reason class beyond reusing the two
lineage reasons the engine already has. No push, merge, tag, or upload.

Nothing in this document describes code that has been written on this branch.
Every reproduction below is a measurement of the engine as it stands at
`4b0409f`.

---

## 1. The seven groups

The review's own prose is not in this checkout; only its oracle is. The group
statements below are therefore reconstructed from the failing assertions in
`tests/test_v110_system_review.py` and from the decisions of record in section
2, and each one names the test that pins it. Where a statement goes beyond what
the oracle can observe, it is marked as such.

**G1. The execution contract is not one contract.** `gate.authorize` computes
parameter transformations and an output modifier and then throws the
transformed parameters away. The output modifier survives only on `AuthResult`,
where a caller has to know to thread it by hand. Every path that does not
thread it by hand returns untransformed output, and no path at all runs the
callable with transformed parameters. Five of the six execution routes leak.
Pinned by `test_output_transform_reaches_caller[call|sync|async|mcp]` and
`test_parameter_transform_reaches_callable`.

**G2. `whitelist_path` compares prefixes as strings.** The containment check is
`value.replace("\\", "/").startswith(prefix)`, so `/allowed/../private.txt` and
a symlink at `/allowed/link.txt` pointing outside both start with the allowed
prefix and both are permitted. The tool then reads the file the prefix was
meant to exclude. Pinned by `test_path_containment[dotdot|symlink]`.

**G3. MCP identity is client supplied.** `_extract_auth` reads
`_meta.agentlock_role` and `_agentlock_role` out of the tool call arguments
first and falls back to the host configured default only when the client sent
nothing. A client that sends `_agentlock_role: admin` to a host configured with
`default_role="user"` is authorized as an admin. Pinned by
`test_mcp_role_cannot_override_host[flat|meta]`.

**G4. HTTP tool selection is client supplied.** The FastAPI middleware reads
`X-AgentLock-Tool` first and consults `tool_name_from_path` only when that
header is absent. A caller reaching an admin route can name a low risk tool in
the header and be authorized against that tool's permission block while the
admin handler runs. Pinned by
`test_fastapi_route_policy_cannot_be_switched[True]`.

**G5. Deferred commit does not re-evaluate parameter lineage.** The end of turn
re-decision consults the action class disjunct and the session taint flag and
nothing else. A queued action whose parameter provably traces to content that
entered after it was queued commits anyway, even though a fresh `authorize` of
the identical call at the identical moment denies. Pinned by
`test_deferred_commit_rechecks_parameter_lineage[True]`.

**G6. Terminal deferral states are not terminal.** `resolve_commit_queue`
overwrites `resolution` on every queued record unconditionally, so a record
already resolved to `deny` by a timeout sweep is rewritten to `committed`. The
same method has no expiry rule of its own, so a record past its timeout that no
sweep happened to visit resolves as though it were fresh. Pinned by
`test_timeout_denial_is_terminal`.

**G7. A failed async call leaves its token ACTIVE.** The async decorator
consumes the token after the awaited call returns. On the exception path it
re-raises without consuming, so the grant survives the failure and remains
replayable for the rest of its TTL. The sync path already consumes first and is
correct. Pinned by `test_failed_execution_consumes_token[async]`.

---

## 2. Decisions of record

**E1. One execution contract.** `gate.authorize` computes effective parameters
(after parameter transformations) and an output modifier. `AuthResult` carries
both as `effective_parameters` and `modify_output_fn`. The execution token is
bound to the effective parameters. `gate.execute` validates the token against
the effective parameters, runs the callable with them, and applies the output
modifier. `gate.call` forwards both. The decorators rebuild the call from the
effective parameters through a new `binding.apply_effective_parameters(bound,
effective)` that writes values back into `BoundArguments` by name (positional
only and var positional included, flattened var keyword keys restored to the
mapping), then invoke `func(*bound.args, **bound.kwargs)` and apply the output
modifier. The MCP hooks, both 1.x and 2.x, apply the output modifier to every
`TextContent` in the returned result and pass effective parameters to the
handler. Same for autogen `guarded`.

**E2. Token lifecycle.** Both decorators validate and consume the token before
beginning the call, the ordering the sync path already uses. A call that raises
has a used token. No decorated call leaves a token ACTIVE.

**E3. `whitelist_path` enforces resolved containment**: backslash
normalization, `posixpath.normpath`, `os.path.realpath` on the candidate and on
each prefix, allow only if `os.path.commonpath([candidate, prefix]) == prefix`.
Any exception blocks. The action docstring states this is canonicalization at
authorization time and not a race resistant filesystem sandbox; hosts that need
that must open files safely themselves.

**E4. MCP identity precedence.** When `default_user_id` or `default_role` is
configured, the configured value is authoritative; client supplied
`_agentlock_user_id`, `_agentlock_role`, and `_meta.agentlock_*` are stripped
and ignored with an audit signal. When no default is configured the client
value is used and the docstring says this trusts the transport. Both hook
paths.

**E5. HTTP tool selection.** In fastapi and flask, when `tool_name_from_path`
is configured it is authoritative; a differing `X-AgentLock-Tool` header yields
403 with reason `tool_selection_conflict`; the header is honored only when no
path mapping is configured. When a JWT is configured, the identity headers are
ignored.

**E6. Deferred commit re-evaluates parameter lineage and novel lineage** against
the completed context, using the immutable queued parameters, before
committing. A record whose re-evaluation denies resolves as `"denied"` with the
denial reason attached. The clean context control still commits.

**E7. Terminal deferral states are immutable.** `resolve_commit_queue` skips any
record with an existing resolution and enforces expiry itself: a record past its
timeout resolves as `"deny"` even if no timeout sweep ran. Resolved records
leave the pending queue.

**E8. Version 1.10.0.** CHANGELOG Security section for the seven groups,
crediting "an external review of the 1.9.1 wheel". README versions row and
counts. CITATION.cff version and `date-released`.

**E9. Files.** `agentlock/gate.py`, `agentlock/binding.py`,
`agentlock/decorators.py`, `agentlock/modify.py`, `agentlock/defer.py`,
`agentlock/token.py`, `agentlock/types.py` only if `AuthResult` or a status
needs it, `agentlock/integrations/mcp.py`,
`agentlock/integrations/fastapi.py`, `agentlock/integrations/flask.py`,
`agentlock/integrations/autogen.py`, `agentlock/__init__.py`, `pyproject.toml`,
`CHANGELOG.md`, `README.md`, `CITATION.cff`,
`tests/test_v110_system_review.py` (0a edits only),
`tests/test_v110_hardening.py` (new, for engine level cases the oracle does not
cover: MCP 1.x output modification through the `FakeServer` fixture, flask tool
selection conflict, autogen effective parameters, deferral expiry without a
sweep), `docs/PREDICTIONS_v110_hardening.md` (append only). Nothing else.

### E9 addendum: existing tests that assert the old behavior

Predicted before editing: **zero** edits to existing test files. The survey
that produced that number:

| Path being changed | Existing assertions found | Survives? |
|---|---|---|
| `whitelist_path` (E3) | `tests/test_modify.py:134-165` (3), `tests/test_first_call_defer_and_deny_on_block.py:113-168` (4), `tests/test_receipts.py:370-403` (1), `tests/test_gate_v12.py:48-61` (registration only) | Yes. Every allowed case uses an absolute prefix with an absolute candidate directly beneath it (`/data/` with `/data/customers.csv`, `/data/report.csv`); every blocked case (`/etc/passwd`, `./config.json`) resolves outside every prefix. Resolved containment returns the same verdict on all eight. |
| MCP identity (E4) | `tests/test_v18_recipient_integrations.py:93,156`, `tests/test_v19_enforcement_gaps.py:187,310,366,427,599` all pass `_agentlock_user_id` / `_agentlock_role` in arguments | Yes. None of those constructions configure `default_user_id` or `default_role`, so the client value is still used. The single construction that does configure a default, `tests/test_v15_integration_confirmation.py:135` (`default_role="user"`), sends no client role. |
| HTTP tool selection (E5) | none. No test in the suite sends `X-AgentLock-Tool` or references `HEADER_TOOL` | Yes, vacuously |
| Deferred commit (E6) | `tests/test_v13_deferred_and_param_lineage.py:74-120`, `tests/test_v14_defer_policy.py:88-231`, `tests/test_v15_commit_resolution_audit.py:79-170`, `tests/test_v15_confirm_execution.py:244-291` | Yes. `param_lineage_enabled` and `novel_lineage_enabled` both default False (`agentlock/schema.py:377,386`), so the new re-check is inert for every one of these blocks. The v1.4 rows that expect `"committed"` carry no lineage parameter values for a match to find. |
| Deferral immutability (E7) | the same four files | Yes. Every record in them is resolved once, fresh, inside its 60 second window. |
| Token binding to effective parameters (E1) | `tests/test_gate_v12.py:157-215` (execute with and without a modifier) | Yes. The gate level `modify_policy` blocks in the suite either transform `output` only, or use `whitelist_path` / `restrict_domain`, whose only non identity outcome is `[BLOCKED: ...]`, which is already escalated to DENY at authorize time and never reaches `execute`. |

If a measurement in STEP 2 contradicts this table, the number above is the
prediction that failed and it is amended in place, dated, before any commit.

---

## 3. STEP 0 verbatim

### 3.1 (0a) Em dash scan and the two mechanical edits

Byte scan of `tests/test_v110_system_review.py` as received:

```
$ python3 -c "d=open('tests/test_v110_system_review.py','rb').read(); \
  print('emdash count:', d.count(b'\xe2\x80\x94')); \
  print('double-hyphen count:', d.count(b'--')); print('size:', len(d))"
emdash count: 0
double-hyphen count: 0
size: 11839
```

**Zero em dashes (bytes `e2 80 94`) and zero ASCII double hyphens.** No
character replacement was made, and none was needed.

The only edits to the file for the whole arc are the four
`pytest.importorskip` guards, one immediately before each in function framework
import, so the file is collectable in an environment without `mcp`, `fastapi`,
or `flask`. Nothing else was touched. The diff, verbatim:

```diff
--- oracle.orig.py
+++ tests/test_v110_system_review.py
@@ -38,6 +38,7 @@
         wrapped = agentlock(g, name='task', permissions=p)(task)
         result = asyncio.run(wrapped(_user_id='alice', _role='user'))
     else:
+        pytest.importorskip("mcp")
         from mcp.server import Server
         import mcp.types as mt
         from agentlock.integrations.mcp import AgentLockMCPServer
@@ -83,6 +84,7 @@
 
 @pytest.mark.parametrize('spoof', [None, 'flat', 'meta'])
 def test_mcp_role_cannot_override_host(spoof):
+    pytest.importorskip("mcp")
     from mcp.server import Server
     import mcp.types as mt
     from agentlock.integrations.mcp import AgentLockMCPServer
@@ -104,6 +106,7 @@
 
 @pytest.mark.parametrize('spoof', [False, True])
 def test_fastapi_route_policy_cannot_be_switched(spoof):
+    pytest.importorskip("fastapi")
     from fastapi import FastAPI
     from agentlock.integrations.fastapi import AgentLockMiddleware
     g, p, _ = setup()
@@ -199,6 +202,7 @@
 
 @pytest.mark.parametrize('role,status', [('user', 200), ('guest', 403)])
 def test_flask_role_enforcement(role, status):
+    pytest.importorskip("flask")
     from flask import Flask
     from agentlock.integrations.flask import agentlock_required
     g, _, _ = setup()
```

`from agentlock.receipts import ...` in `test_signed_receipt_rejects_changed_decision`
also has an out of tree dependency (PyNaCl, for `ed25519`), but it is an
`agentlock` import and not a framework import, so per the instruction it is left
unguarded. Every environment in this arc has PyNaCl.

### 3.2 (0b) The oracle against the 1.9.1 engine

Environment: `/tmp/al18-extras`, Python 3.14.6, pytest 9.1.1, mcp 2.2.0,
fastapi 0.141.1, Flask 3.1.3, PyNaCl 1.6.2. `pip install -e .` was rerun first;
the installed engine reports `agentlock 1.9.1` from
`/home/n1trolab/agentlock-v1.4/agentlock/__init__.py`.

Summary line, verbatim:

```
================== 13 failed, 20 passed, 4 warnings in 0.49s ===================
```

Per test outcome, verbatim:

```
tests/test_v110_system_review.py::test_output_transform_reaches_caller[explicit] PASSED [  3%]
tests/test_v110_system_review.py::test_output_transform_reaches_caller[call] FAILED [  6%]
tests/test_v110_system_review.py::test_output_transform_reaches_caller[sync] FAILED [  9%]
tests/test_v110_system_review.py::test_output_transform_reaches_caller[async] FAILED [ 12%]
tests/test_v110_system_review.py::test_output_transform_reaches_caller[mcp] FAILED [ 15%]
tests/test_v110_system_review.py::test_parameter_transform_reaches_callable FAILED [ 18%]
tests/test_v110_system_review.py::test_path_containment[allowed] PASSED  [ 21%]
tests/test_v110_system_review.py::test_path_containment[outside] PASSED  [ 24%]
tests/test_v110_system_review.py::test_path_containment[dotdot] FAILED   [ 27%]
tests/test_v110_system_review.py::test_path_containment[symlink] FAILED  [ 30%]
tests/test_v110_system_review.py::test_mcp_role_cannot_override_host[None] PASSED [ 33%]
tests/test_v110_system_review.py::test_mcp_role_cannot_override_host[flat] FAILED [ 36%]
tests/test_v110_system_review.py::test_mcp_role_cannot_override_host[meta] FAILED [ 39%]
tests/test_v110_system_review.py::test_fastapi_route_policy_cannot_be_switched[False] PASSED [ 42%]
tests/test_v110_system_review.py::test_fastapi_route_policy_cannot_be_switched[True] FAILED [ 45%]
tests/test_v110_system_review.py::test_deferred_commit_rechecks_parameter_lineage[False] PASSED [ 48%]
tests/test_v110_system_review.py::test_deferred_commit_rechecks_parameter_lineage[True] FAILED [ 51%]
tests/test_v110_system_review.py::test_timeout_denial_is_terminal FAILED [ 54%]
tests/test_v110_system_review.py::test_failed_execution_consumes_token[sync] PASSED [ 57%]
tests/test_v110_system_review.py::test_failed_execution_consumes_token[async] FAILED [ 60%]
tests/test_v110_system_review.py::test_core_execution_rejects_invalid_grants[replay] PASSED [ 63%]
tests/test_v110_system_review.py::test_core_execution_rejects_invalid_grants[revoked] PASSED [ 66%]
tests/test_v110_system_review.py::test_core_execution_rejects_invalid_grants[expired] PASSED [ 69%]
tests/test_v110_system_review.py::test_core_execution_rejects_invalid_grants[wrong_tool] PASSED [ 72%]
tests/test_v110_system_review.py::test_core_execution_rejects_invalid_grants[changed_params] PASSED [ 75%]
tests/test_v110_system_review.py::test_signed_receipt_rejects_changed_decision PASSED [ 78%]
tests/test_v110_system_review.py::test_flask_role_enforcement[user-200] PASSED [ 81%]
tests/test_v110_system_review.py::test_flask_role_enforcement[guest-403] PASSED [ 84%]
tests/test_v110_system_review.py::test_memory_policy_enforcement[valid] PASSED [ 87%]
tests/test_v110_system_review.py::test_memory_policy_enforcement[writer] PASSED [ 90%]
tests/test_v110_system_review.py::test_memory_policy_enforcement[credentials] PASSED [ 93%]
tests/test_v110_system_review.py::test_memory_policy_enforcement[persistence] PASSED [ 96%]
tests/test_v110_system_review.py::test_context_chain_detects_changed_content PASSED [100%]
```

Thirteen failures, distributed across the seven groups exactly as section 1
assigns them: G1 five, G2 two, G3 two, G4 one, G5 one, G6 one, G7 one.

**One qualification, recorded rather than glossed.** The instruction was to
match the review's Appendix B row for row. The review document itself is not in
this checkout; only its oracle file is. What was actually verified is the stated
expected summary, 13 failed and 20 passed, and the distribution of those 13
across the seven groups. Both match. If Appendix B is added to the repo later
and any row disagrees with the table above, that is a STOP condition and this
section is the thing to re-measure against.

### 3.3 (0c) Full suite baselines

`/tmp/al18-extras`, whole suite including the new file:

```
=========== 13 failed, 1540 passed, 9 skipped, 29 warnings in 3.42s ============
```

1540 + 13 = 1553 = the 1520 passing baseline before this file plus its 33 tests.
Skips unchanged at 9. All 13 failures are in
`tests/test_v110_system_review.py`; no pre-existing test changed outcome.

Checkout venv (system Python 3.14.6; fastapi and Flask present, `mcp` absent):

```
=========== 10 failed, 1534 passed, 18 skipped, 29 warnings in 3.37s ===========
```

1534 = the 1515 passing baseline plus 19; 18 = the 14 skip baseline plus 4. The
4 new skips are the `mcp` guarded tests added in 0a
(`test_output_transform_reaches_caller[mcp]` and the three
`test_mcp_role_cannot_override_host` cases); 19 + 10 + 4 = 33. The 10 failures
are the 13 minus the 3 that are `mcp` guarded.

**Commit A therefore leaves the suite red by exactly the 13 review failures
(10 where `mcp` is absent). That is the intended freeze state.** The suite is
red on purpose: the oracle is the specification, and it is committed before the
code that satisfies it so that the before state is in the history and cannot be
retold later.

### 3.4 (0d) H6 and H7 at the source

**H6: commit resolution evaluates the action class disjunct and never parameter
lineage.** `agentlock/gate.py:2377-2395`, verbatim:

```python
        def _should_deny(record: DeferralRecord) -> bool:
            # No taint at commit -> nothing to gate on; commit, as before.
            if not tainted:
                return False
            permissions = self._tools.get(record.tool_name)
            if permissions is None:
                return True  # fail closed: unregistered at commit time
            lineage_policy = active_lineage_policy(permissions)
            if lineage_policy is None:
                return True  # fail closed: no live policy to consult
            if record.action_flags is None:
                return True  # fail closed: caller recorded no classes
            return lineage_gated_action(
                lineage_policy, permissions, record.action_flags
            )

        resolved = self._deferral_manager.resolve_commit_queue(
            session_id, deny=_should_deny, taint_at_commit=taint_at_commit,
        )
```

The whole decision is `lineage_gated_action(lineage_policy, permissions,
record.action_flags)` at line 2389. That predicate reads action classes and the
`gate_*` flags. It never sees `record.parameters`. The parameter lineage check
that `authorize` runs lives at `agentlock/gate.py:815-826` and is keyed off
`self._context_tracker.parameter_lineage_check(...)`; nothing in the commit path
calls it. Novel lineage, at `agentlock/gate.py:830-839`, is likewise absent.

Consequence, exactly as the oracle demonstrates: with
`gate_consequential=False` and `is_value_carrying=True`, line 2389 returns
False, so a queued action commits under end of turn taint while a fresh
`authorize` of the identical call at the identical moment denies it on
`param_lineage`. The two enforcement points disagree, which is the precise
failure v1.4 introduced this predicate to prevent, reappearing one level down.

**H7: `resolve_commit_queue` overwrites a record whose resolution is already
set, and has no expiry rule.** `agentlock/defer.py:281-289`, verbatim:

```python
        queued = self._commit_queue.pop(session_id, [])
        now = time.time()
        decide = deny if callable(deny) else (lambda _record, _d=deny: _d)
        for record in queued:
            record.taint_at_commit = taint_at_commit
            record.resolution = "denied" if decide(record) else "committed"
            record.resolved_at = now
            record.resolved_by = "deferred_commit"
        return queued
```

Line 286 is an unconditional assignment. There is no `if record.is_resolved:
continue` above it, and no reference to `record.is_expired` or
`record.timeout_seconds` anywhere in the method. Two consequences:

1. A record that `check_timeouts` already resolved to `"deny"`
   (`agentlock/defer.py:350-354`) is rewritten to `"committed"` by the next
   `resolve_commit_queue` on its session. A terminal denial is not terminal.
2. Expiry is enforced only by whoever happens to call `check_timeouts`. A
   deployment that never calls it, or calls it on a different cadence, resolves
   long expired records as though they were fresh. The timeout is advisory
   rather than structural, which is the opposite of what a timeout that defaults
   to DENY exists to be.

For contrast, the guard that does exist is on the record, at
`agentlock/defer.py:66-69`:

```python
    @property
    def is_expired(self) -> bool:
        if self.is_resolved:
            return False
        return time.time() > (self.created_at + self.timeout_seconds)
```

`check_timeouts` respects `is_resolved` through this property.
`resolve_commit_queue` consults neither.

---

## 4. Frozen predictions

Stated before any implementation code is written. A MISMATCH on any of these is
a STOP: no commit, report, and amend the failed prediction in place, dated,
before proceeding.

**K1.** `tests/test_v110_system_review.py`: **33 passed** in `/tmp/al18-extras`,
with zero edits to that file beyond the four `importorskip` guards recorded in
3.1.

**K2.** Full suite:
* `/tmp/al18-extras`: **1553 plus any new engine tests passed, 0 failed, 9
  skipped**.
* checkout venv: **1515 plus the new non skipped tests passed, 0 failed**, with
  the review file's framework guarded tests counted as skips.
* `/tmp/al19-mcp1`: **0 failed**.
* `/tmp/al18-probe313`: **0 failed**.

**K3.** `mypy agentlock/` reports **0 errors**; `ruff check .` is clean; the
corpus grep returns **0**.

**K4.** Files touched are **exactly E9** and nothing else.

**K5.** Rebuild in `/tmp/al18-extras`: `twine check dist/*` **PASSED**, and the
metadata reports **Version 1.10.0**. A fresh venv with only the built wheel
installed, running a copy of `tests/test_v110_system_review.py` placed outside
the checkout so it resolves the engine from the wheel and not from the source
tree: **33 passed**.

---

## 5. Build order

Per the review's suggested order: E1, E4, E5 together; then E3; then E6, E7, E2
together; then E8.

---

# AMENDMENT 1

Date: 2026-09-10. Appended after STEP 1 and STEP 2, before any code commit.
Section 4 above is left exactly as it was frozen; this section records what
happened to each of its predictions and amends the two that were defective.

## A1.1 Result table

| # | Prediction | Measured | Verdict |
|---|---|---|---|
| K1 | oracle: 33 passed in `/tmp/al18-extras`, no edits beyond 0a | `33 passed, 4 warnings in 0.41s` | MET |
| K2a | `/tmp/al18-extras`: 1553 plus new engine tests passed, 0 failed, 9 skipped | `1583 passed, 9 skipped` (1553 + the 30 in `tests/test_v110_hardening.py`) | MET |
| K2b | checkout venv: 1515 plus new non skipped passed, 0 failed, framework guarded tests as skips | `1568 passed, 24 skipped` (1515 + 29 + 24; skips 14 + 4 + 6) | MET |
| K2c | `/tmp/al19-mcp1`: 0 failed | `4 failed, 1568 passed, 20 skipped` | **MISMATCH, prediction defect, amended in A1.2** |
| K2d | `/tmp/al18-probe313`: 0 failed | `1584 passed, 8 skipped` | MET |
| K3a | mypy 0 | `Success: no issues found in 34 source files` | MET |
| K3b | ruff clean | clean only after the amendment in A1.3 | **MISMATCH, prediction defect, amended in A1.3** |
| K3c | corpus grep 0 | 0 over the diff and 0 in the new test file | MET |
| K4 | files exactly E9 | 16 files, all in E9; `agentlock/types.py` not needed and not touched | MET |
| K5a | twine PASSED, Version 1.10.0 | both artifacts `PASSED`; `importlib.metadata.version("agentlock")` is `1.10.0` | MET |
| K5b | fresh wheel venv, oracle copied to `/tmp`: 33 passed | `33 passed` from `/tmp/al110-oracle`, resolving `/tmp/al110-wheel/lib/python3.14/site-packages/agentlock/__init__.py` | MET |

Neither mismatch is an engine defect. Both are defects in the prediction, and
both are amended below rather than worked around in code.

## A1.2 K2c amended: the oracle cannot run against an mcp 1.x SDK

**Measured.** In `/tmp/al19-mcp1` (CPython 3.13.14, `mcp 1.30.0`, no fastapi,
no flask) the suite is `4 failed, 1568 passed, 20 skipped`. All four failures
are in `tests/test_v110_system_review.py` and all four are the same error:

```
tests/test_v110_system_review.py:47: in test_output_transform_reaches_caller
    server = Server('local-probe', on_call_tool=handler)
E   TypeError: Server.__init__() got an unexpected keyword argument 'on_call_tool'
```

`test_output_transform_reaches_caller[mcp]` and all three
`test_mcp_role_cannot_override_host` cases. `on_call_tool` is the mcp **2.x**
`Server` constructor; 1.x has no such keyword. The review wrote its fixture
against the SDK major it had installed.

**Why this is not an engine finding.** The failure is a `TypeError` raised
inside the test file, constructing the SDK's own object, on the line before
`AgentLockMCPServer` is mentioned. No engine code has run at that point, so no
engine change can affect it. Measured directly: with this branch's code stashed
and the tree back at commit A, the same environment gives
`13 failed, 16 passed, 4 skipped`, and those four are among the thirteen.
`test_mcp_role_cannot_override_host[None]` is the tell: it PASSES in
`/tmp/al18-extras` at the freeze and FAILS in `/tmp/al19-mcp1` at the freeze,
which only an SDK difference explains.

**Why it was not caught at freeze time.** Step 0c measured `/tmp/al18-extras`
and the checkout venv. `/tmp/al19-mcp1` first appears in K2, where its figure
was predicted rather than measured. The prediction assumed the oracle was
SDK-major portable. It is not, and 0a could not have made it so: the
instruction there was to add `pytest.importorskip("mcp")` and nothing else,
which guards the absence of the package, not the presence of the wrong major.

**Amendment.** K2c now reads:

> `/tmp/al19-mcp1`: **0 failed** with the four `tests/test_v110_system_review.py`
> cases that construct the mcp 2.x `Server` deselected. Measured:
> `1568 passed, 20 skipped, 4 deselected`.

**Why the file is still not edited.** It is the contract for the arc. Rewriting
its fixture to construct a 1.x server would make the oracle a thing this branch
authored, which is the one property it has that nothing else in the suite does.

**What covers the 1.x hook instead.** `tests/test_v110_hardening.py` carries
`TestMcp1xExecutionContract`, six cases over the 1.x `call_tool` branch through
the `FakeServer` fixture that `tests/test_v15_integration_confirmation.py`
already uses: output transformation as a bare string, output transformation
across `TextContent` blocks, parameter transformation into the handler, the E4
identity precedence, the documented client-trusting fallback, and the reserved
keys not leaking into the tool's arguments. Those run wherever `mcp` is
installed, at either major, and they pass in `/tmp/al19-mcp1`.

## A1.3 K3b amended: the verbatim oracle does not satisfy this project's ruff config

**Measured.** Before any amendment, `ruff check .` reported 27 findings: 2 in
engine files and 25 in `tests/test_v110_system_review.py`.

**The 2 engine findings were real and are fixed in code**, both introduced by
this branch: `SIM401` in `agentlock/binding.py` (an `if` expression that is
`dict.get` with a default) and `SIM105` in `agentlock/integrations/mcp.py` (a
`try`/`except`/`pass` that is `contextlib.suppress`). Both rewritten. No
suppression was used for either.

**The 25 remaining are all in the oracle**, and are its house style rather than
this project's: 10 `E701` (a statement on the same line as its `if` or `try`),
7 `I001` (unsorted in-function import blocks), 6 `E501` (lines over 100
characters), 2 `SIM105`. They were present at commit A and were always going
to be: K3 predicted `ruff clean` without ever having run ruff over the file.

**Amendment.** K3b now reads:

> `ruff check .` is **clean**, with `tests/test_v110_system_review.py` carrying
> a `per-file-ignores` entry in `pyproject.toml` for `E501`, `E701`, `I001`
> and `SIM105`, the four rules its verbatim text violates.

The entry is scoped to that one path and to those four rules, and carries a
comment saying why. Every other file in the repository, this branch's own new
test file included, is held to the unchanged config. The alternative,
reformatting the review's file, would have edited the artifact that defines
done, turning an independent check into a restatement of this branch's own
opinion.

## A1.4 One defect of this branch's own, recorded

`tests/test_v110_hardening.py` was first written without a
`pytest.importorskip("mcp")` guard on its six MCP cases, which failed in the
checkout venv where `mcp` is absent (`6 failed, 24 passed`). That is this
branch's file and this branch's mistake, fixed by adding the guard, after which
the same environment reports `24 passed, 6 skipped`. Recorded because the
freeze doc claims the suite goes green everywhere, and the first measurement
that said otherwise deserves to be in the record rather than only in the fix.

## A1.5 Behavior changes beyond the seven groups, declared

Three changes in this arc go slightly past the failing assertion that prompted
them. Each is listed in the CHANGELOG and repeated here so the freeze document
records the decision and not only the outcome.

1. **`AgentLockFlask` installs its `before_request` hook unconditionally.**
   E5 requires the `X-AgentLock-Tool` header to be honored where no mapping is
   configured. Flask installed the hook only when a mapping was given, so that
   case was unreachable. A request naming no tool and matching no mapping still
   passes through untouched, which is every unmapped request before this
   change; the delta is that an app with no mapping now gates a request that
   names a tool in the header, which is the FastAPI behavior it is being made
   to match.
2. **`whitelist_path` no longer passes `/data-private/x` against a `/data`
   prefix.** A consequence of comparing resolved paths with `commonpath`
   instead of comparing strings with `startswith`. It is a tightening in the
   same direction as the two cases the oracle pins, and no test in the suite
   depended on the looser reading.
3. **A bearer JWT now beats the identity headers rather than yielding to
   them.** E5 states it for the configured-JWT case; it is implemented as
   "a bearer token whose payload names a subject", in both frameworks and in
   the FastAPI dependency, because that is the condition a request can actually
   be tested against. No test in the suite sent an `Authorization` header
   before this arc.

## A1.6 What did not change

`agentlock/types.py` was listed in E9 conditionally, "only if `AuthResult` or a
status needs it". `AuthResult` is defined in `agentlock/gate.py`, and no token
or deferral status gained a value: an expired commit resolves to the existing
`"deny"` and a policy denial to the existing `"denied"`. The file is untouched.

No new denial reason was added. The two reasons the commit path newly attaches,
`param_lineage` and `novel_lineage`, are the ones `authorize()` has used since
1.3.0 and 1.4.0 respectively, which is the point: the two enforcement points
now name the same finding the same way.

---

# RED PASS FREEZE (2026-09-10)

Appended after AMENDMENT 1 and before any code that closes the findings below.
Sections 1 through 5 and AMENDMENT 1 are left exactly as they were written.

A pre-release red pass was run against the branch wheel, `agentlock-1.10.0-py3-none-any.whl`,
sha256 `0d793500416f1422731b7795f30e0b3df54ac356b339b3408272d8f9e615fb8f`, built
from `4bd3998`. 1.10.0 is unreleased, so the findings close on this branch
rather than in a patch release.

The wheel was verified to be the tree: every file this section reproduces
against was unzipped from that artifact and compared to the checkout, and
`agentlock/gate.py`, `agentlock/modify.py`, `agentlock/decorators.py`,
`agentlock/types.py`, `agentlock/integrations/fastapi.py` and
`agentlock/integrations/flask.py` are byte identical. Every reproduction below
is therefore a measurement of the shipped artifact and not of a tree that
merely resembles it.

Nothing in this section describes code written on this branch after `4bd3998`.

## R1. The three findings, reproduced

**F1. The caller's role overrides the session's role. REPRODUCED.**

`agentlock/gate.py:765-767`, verbatim:

```python
        session = self._session_store.get_by_user(user_id) if user_id else None
        if session and not role:
            role = session.role
```

The assignment is guarded by `not role`, so the session's role is consulted
only when the caller supplied none. A caller that supplies one is believed.
Measured against the wheel:

```
F1 claim-admin: allow True None
F1 no-role: allow True
F1 no-session: allow True None
```

The first line is the finding: alice holds a session at role `user`; the tool
`admin_task` is `requires_auth=True, allowed_roles=["admin"]`;
`authorize("admin_task", user_id="alice", role="admin")` is ALLOW. The second
and third lines are the controls, and both are behavior that is meant to stay.

Through the MCP wrapper with no default configured, on the real mcp 2.x SDK
(`/tmp/al18-extras`, mcp 2.2.0), the same claim runs the handler:

```
seen = ['ADMIN_ACTION']
```

E4 settled the case where the host configures a `default_role`: the
configured value wins and the client's is stripped. It left the no-default
case reading the client's value, which is documented and deliberate for a
transport the host trusts. What was never true is that a client's claim should
survive contact with an authenticated session that says otherwise. The gate
holds both facts and believes the weaker one.

**F2. Output modification covers `str` returns only. REPRODUCED.**

`agentlock/gate.py:1811` and `agentlock/decorators.py:222-228` both guard the
modifier with `isinstance(result, str)`. E1 threaded the modifier onto every
execution path, so it now reaches the call; it is then discarded for every
return shape that is not a bare string. Measured against the wheel, with a
declared `redact_pii` transformation on `output`:

```
F2 sync str    : leaked=False 'Customer SSN [REDACTED:ssn]'
F2 sync dict   : leaked=True {'note': 'Customer SSN 123-45-6789'}
F2 sync list   : leaked=True ['Customer SSN 123-45-6789']
F2 sync nested : leaked=True {'a': [{'b': 'Customer SSN 123-45-6789'}]}
F2 sync tuple  : leaked=True ('Customer SSN 123-45-6789',)
F2 sync bytes  : leaked=True b'Customer SSN 123-45-6789'
F2 call str    : leaked=False 'Customer SSN [REDACTED:ssn]'
F2 call dict   : leaked=True {'note': 'Customer SSN 123-45-6789'}
F2 call list   : leaked=True ['Customer SSN 123-45-6789']
F2 call nested : leaked=True {'a': [{'b': 'Customer SSN 123-45-6789'}]}
F2 call tuple  : leaked=True ('Customer SSN 123-45-6789',)
F2 call bytes  : leaked=True b'Customer SSN 123-45-6789'
```

A tool that returns a mapping is the ordinary case, not the exotic one, so the
declared transformation was inert for most tools that declare it. The oracle
could not see this because its every fixture returns a bare string.

**F3. Route mapping and the header. NOT REPRODUCED.**

Reported as: with `tool_name_from_path` configured, a route the callback
declines by returning `None` falls back to consulting `X-AgentLock-Tool`, so
the client selects the tool for that route.

Measured against the wheel, in `/tmp/al18-extras` (fastapi 0.141.1, Flask
3.1.3) and again in the checkout venv (fastapi 0.135.3), a mapping that returns
`None` for the route with the header naming a registered, permitted tool:

```
fastapi mapping-None + header: 200 {'ok': True} seen= ['HANDLER_RAN']
fastapi mapping-None no header: 200 seen= ['HANDLER_RAN']
fastapi header-only: 200 seen= ['HANDLER_RAN']
flask mapping-None + header: 200 seen= ['HANDLER_RAN']
flask header-only: 200 seen= ['HANDLER_RAN']
```

The header is not consulted. `agentlock/integrations/fastapi.py:191-220` reads
the header into `header_tool` before the branch, but inside the mapping branch
`header_tool` is used only for the conflict comparison, which is guarded by
`if tool_name and ...`; `tool_name` is then `None` and the request takes the
`if not tool_name` pass-through. `agentlock/integrations/flask.py:278-303` has
the identical shape. That is exactly the behavior E12 specifies, and both
docstrings already state both halves of it: fastapi point 1 says a declined
path "passes through with the header ignored" and point 2 says the header is
honored only with no mapping, and flask says the same.

**Why the finding was still worth making.** Flask had a test pinning this
branch, `TestFlaskToolSelection.test_a_declined_endpoint_passes_through_with_the_header_ignored`.
FastAPI had none: no test in the suite exercised `tool_name_from_path`
returning `None`. An untested branch that is correct reads exactly like an
untested branch that is not, and E5's own note says it "closed the conflict
case", which invites the reading that it closed nothing else. The finding is a
coverage finding rather than a defect finding, and the coverage is added below.

**Consequence for E12 and E14.** E12 requires no code change in either
integration. `agentlock/integrations/fastapi.py` and
`agentlock/integrations/flask.py` are therefore predicted untouched, and the
E14 file list is predicted to be satisfied as a proper subset. This is stated
here, before the build, so STEP 2 cannot be read as having moved the target
after the fact.

## R2. Decisions of record

Restated as received, so this document is readable without the instruction
that produced it.

**E10. Session role is authoritative.** In `authorize()`, when a session is
resolved for `user_id` and the caller supplied a nonempty `role` that differs
from `session.role`, the decision is DENY with `DenialReason.ROLE_MISMATCH`, a
new enum member with wire value `"role_mismatch"`, and a detail naming that the
claimed role does not match the authenticated session, before any policy step
runs. When no role is supplied, `session.role` is used as today. When no
session exists, the caller's role is used as today, and the docstring states
that this trusts the host. The same rule applies wherever `gate.py` resolves a
session for a caller-supplied role, the line 723 region included.

**E11. Output modification walks the return value.** `str` is modified. `dict`,
`list` and `tuple` are walked recursively and every `str` leaf is modified,
preserving container types. `bytes` are decoded as UTF-8 with
`errors="replace"`, modified, and re-encoded. Any other type is returned
unchanged. The modifier's docstring states which types are covered. Applies
wherever `modify_output_fn` is applied: `execute`, `call`, both decorators,
both MCP hooks, autogen.

**E12. Route mapping excludes the header.** In fastapi and flask, when
`tool_name_from_path` is configured the header is never consulted for tool
selection. A route for which the callback returns `None` is treated as having
no tool name and takes the existing no-tool-name path. The header is honored
only when no callback is configured. Docstrings state both.

**E13.** Version stays 1.10.0. CHANGELOG Security section extended with F1 to
F3, credited to "a pre-release red pass against the built wheel". README
counts. No schema change.

**E14. Files.** `agentlock/gate.py`, `agentlock/types.py`,
`agentlock/modify.py`, `agentlock/integrations/fastapi.py`,
`agentlock/integrations/flask.py`, `CHANGELOG.md`, `README.md`,
`tests/test_v110_hardening.py` (new class `TestRedPass`),
`docs/PREDICTIONS_v110_hardening.md` (append only). Nothing else.

## R3. Existing tests that assert the old behavior

Predicted before editing: **zero** edits to existing test files.

The survey is a measurement rather than a reading. A pytest plugin wrapped
`AuthorizationGate.authorize` and `AuthorizationGate.execute` at `4bd3998` and
recorded, with the test id, every call that the E10 and E11 changes would
reach: for E10, every `authorize` where a session exists for `user_id` and a
nonempty differing `role` was supplied; for E11, every `execute` that returned
a non-`str` with a live `modify_output_fn`. The whole suite was run under it in
`/tmp/al18-extras` (`1583 passed, 9 skipped, 24 deselected`).

| Change | Calls reached across the whole suite | Tests involved |
|---|---|---|
| E10 | 1 | `tests/test_v110_system_review.py::test_flask_role_enforcement[guest-403]` |
| E11 | 0 | none |

The single E10 hit is in the oracle, which is the one file in the arc that must
not be edited, so it is quoted in full rather than summarized. The call
recorded was `tool='task', session_role='user', claimed_role='guest'`. The
test, `tests/test_v110_system_review.py:203-218`:

```python
@pytest.mark.parametrize('role,status', [('user', 200), ('guest', 403)])
def test_flask_role_enforcement(role, status):
    ...
    response = app.test_client().post('/task', headers={'X-AgentLock-User-Id': 'alice', 'X-AgentLock-Role': role})
    assert response.status_code == status
    assert bool(seen) == (status == 200)
```

**It survives.** The two assertions are on the HTTP status and on whether the
handler ran. Today the guest case denies with `insufficient_role` and returns
403 with the handler unrun. Under E10 it denies earlier, with `role_mismatch`,
and returns 403 with the handler unrun. Neither assertion names a reason. The
`user` case is agreement, not a mismatch, and is unaffected.

That the oracle contains a case E10 changes the reason for, and that the case
still passes, is worth stating plainly: it is a near miss, not a clean margin.
If a future change to this rule needs the oracle edited, that is a STOP and this
row is where the argument starts.

E11's zero is over `gate.execute` only, which is the path `gate.call`, the sync
decorator and autogen all reach. The two paths that apply the modifier
themselves were surveyed by reading instead: every existing use of an `output`
transformation in the suite is either a direct `ModifyEngine` unit test
(`tests/test_modify.py:205-233,279-330`) or an `authorize`-only assertion
(`tests/test_gate_v12.py:29,250`, `tests/test_first_call_defer_and_deny_on_block.py:166`).
None of them executes a tool. `build_output_modifier` keeps its
`Callable[[str], str]` signature and the walk is added beside it, so
`tests/test_modify.py::TestBuildOutputModifier` is untouched by construction.

## R4. STEP 0 measurements

### R4.1 Baselines at `4bd3998`, before `TestRedPass`

| Environment | Suite |
|---|---|
| `/tmp/al18-extras` (py3.14.6, mcp 2.2.0, fastapi 0.141.1, Flask 3.1.3) | `1583 passed, 9 skipped` |
| checkout venv (py3.14.6, no mcp, fastapi 0.135.3, Flask 3.1.3) | `1568 passed, 24 skipped` |
| `/tmp/al19-mcp1` (py3.13.14, mcp 1.30.0, no fastapi, no flask), 4 deselected per K2c | `1568 passed, 20 skipped, 4 deselected` |
| `/tmp/al18-probe313` (py3.13) | `1584 passed, 8 skipped` |

All four reconcile with AMENDMENT 1 section A1.1 exactly.

Oracle alone, `/tmp/al18-extras`: `33 passed, 4 warnings in 0.41s`.

### R4.2 With `TestRedPass` added

`TestRedPass` is 24 cases: 15 strict xfails, 9 plain guards.

| Environment | Suite |
|---|---|
| `/tmp/al18-extras` | `1592 passed, 9 skipped, 15 xfailed` |
| checkout venv | `1577 passed, 25 skipped, 14 xfailed` |
| `/tmp/al19-mcp1` (4 deselected) | `1573 passed, 24 skipped, 4 deselected, 15 xfailed` |
| `/tmp/al18-probe313` | `1593 passed, 8 skipped, 15 xfailed` |

Every arithmetic difference from R4.1 is accounted for: 9 new passes
everywhere; 15 xfails wherever `mcp` is present and 14 where it is not, the
missing one being the MCP case, which skips; the checkout venv gains that 1
skip; `/tmp/al19-mcp1` has mcp but neither framework, so its 4 F3 cases skip
and only 5 guards pass there.

**No xfail XPASSes in any environment.** That is the freeze working: F1 and F2
are red in exactly the shape the fix will turn green, and F3 is not marked
xfail at all, because it is not failing.

### R4.3 The marker inventory

The 15 strict xfails, all removed by the fix:

* E10 at the gate: 2. The claimed-role denial, and the existence of the
  `role_mismatch` enum member.
* E10 through mcp 2.x: 1.
* E11 through the sync decorator: 5, one per return shape.
* E11 through `gate.call`: 5, one per return shape.
* E11 container identity: 2. `bytes` come back `bytes`, a `tuple` comes back a
  `tuple`.

The 9 plain guards, passing now and required to keep passing:

* E10 controls: 3. No role supplied resolves from the session; an agreeing
  claimed role is allowed; a claimed role with no session is trusted as before.
* E11 controls: 2. A `str` return is still modified; an unmodifiable return is
  passed through untouched.
* F3 / E12: 4. The fastapi declined route ignores the header (the reported
  finding, pinned as behavior); the fastapi conflict is still 403; fastapi
  header-only mode still works; the flask declined route ignores the header.

### R4.4 Lint, types, style

`ruff check .`: **All checks passed.** One finding was raised against the new
test file on the first run, `SIM105` for a `try`/`except DeniedError`/`pass`,
and was rewritten as `contextlib.suppress` rather than suppressed. No new
`per-file-ignores` entry was added.

Style scan of `tests/test_v110_hardening.py`: `emdash: 0 double-hyphen: 0`.
Three comment dividers were written with a pair of ASCII hyphens on the first
draft and rewritten before the commit. Corpus grep over the new test file: **0**.

`mypy agentlock/` is **environment dependent at `4bd3998`, before this arc
touches anything**, and this contradicts AMENDMENT 1's K3a. Measured at HEAD
with the tree clean of engine edits:

```
/tmp/al18-extras   agentlock/integrations/autogen.py:48: error: Cannot find implementation or library stub for module named "autogen"  [import-not-found]
                   Found 1 error in 1 file (checked 34 source files)
/tmp/al18-probe313 agentlock/integrations/autogen.py:48: error: Skipping analyzing "autogen": module is installed, but missing library stubs or py.typed marker  [import-untyped]
                   Found 1 error in 1 file (checked 34 source files)
/tmp/al19-mcp1     agentlock/integrations/fastapi.py:44: error: Cannot find implementation or library stub for module named "fastapi"  [import-not-found]
                   Found 3 errors in 3 files (checked 34 source files)
```

Every finding is a missing third-party stub for an optional integration
dependency, and the count is a function of which optional packages the
environment has, not of the engine. None is in a file this arc edits. The
`mypy` on the checkout venv's PATH is a broken install
(`/home/n1trolab/.local/bin/mypy` runs but `import mypy` fails), which is the
likeliest reason A1.1 recorded a clean run it cannot now reproduce; that is
recorded here rather than restated, per the standing rule about not
propagating a number without re-measuring it. The prediction below is written
against the measured baseline.

## R5. Frozen predictions

Stated before any implementation code is written. A MISMATCH on any of these is
a STOP: no commit, report, and amend the failed prediction in place, dated,
before proceeding.

**P1.** Every one of the 15 `xfail(strict=True)` markers is removed, and all 24
`TestRedPass` cases pass in every environment where their framework is present.
No marker is left in place, and no case is deleted or weakened.

**P2.** Full suite, per environment, equal to the R4.1 baseline plus the new
non-skipped cases and zero failures:

* `/tmp/al18-extras`: **1607 passed, 9 skipped, 0 failed, 0 xfailed**.
* checkout venv: **1591 passed, 25 skipped, 0 failed**.
* `/tmp/al19-mcp1`, 4 deselected: **1588 passed, 24 skipped, 0 failed**.
* `/tmp/al18-probe313`: **1608 passed, 8 skipped, 0 failed**.

**P3.** `mypy agentlock/` output is unchanged from the R4.4 baseline in each
environment, with **zero findings in `agentlock/gate.py`,
`agentlock/types.py` and `agentlock/modify.py`**. `ruff check .` is clean with
no new `per-file-ignores` entry. The corpus grep over the diff returns **0**,
and the diff contains **0** em dashes and **0** ASCII double hyphens.

**P4.** Files touched are **exactly E14 or a proper subset of it**, and nothing
outside it. Specifically predicted: `agentlock/integrations/fastapi.py` and
`agentlock/integrations/flask.py` are **not** touched, for the reason given in
R1 under F3, so the set is the other seven.

**P5.** Zero edits to existing test files, including
`tests/test_v110_system_review.py`, and the oracle still reports **33 passed**
in `/tmp/al18-extras`.

**P6.** Rebuild: `twine check dist/*` **PASSED** on both artifacts, metadata
**Version 1.10.0**, no version bump. A fresh venv with only the rebuilt wheel
installed runs `/tmp/al110_redpass_repro.py`, a script outside the checkout so
it resolves the engine from the wheel, and reports F1 closed, F2 closed for all
five return shapes on both paths, and F3 unchanged at the pass-through status.

---

# AMENDMENT 2

Date: 2026-09-10. Appended after STEP 1 and STEP 2, before the code commit.
The RED PASS FREEZE section above is left exactly as it was frozen; this
section records what happened to each of its predictions and amends the four
that were defective.

## A2.1 Result table

| # | Prediction | Measured | Verdict |
|---|---|---|---|
| P1 | 15 strict xfail markers removed; all 24 `TestRedPass` cases pass wherever their framework is present | 15 markers removed; `TestRedPass` is **25** cases and all pass | **MISMATCH, prediction defect, amended in A2.2** |
| P2a | `/tmp/al18-extras`: 1607 passed, 9 skipped | `1608 passed, 9 skipped` | **MISMATCH, same defect, amended in A2.2** |
| P2b | checkout venv: 1591 passed, 25 skipped | `1591 passed, 26 skipped` | **MISMATCH, same defect, amended in A2.2** |
| P2c | `/tmp/al19-mcp1`, 4 deselected: 1588 passed, 24 skipped | `1588 passed, 25 skipped, 4 deselected` | **MISMATCH, same defect, amended in A2.2** |
| P2d | `/tmp/al18-probe313`: 1608 passed, 8 skipped | `1609 passed, 8 skipped` | **MISMATCH, same defect, amended in A2.2** |
| P3a | `mypy agentlock/` unchanged from the R4.4 baseline, 0 findings in the arc's files | unchanged in all three environments; 0 findings in every file this arc edits | MET, though R4.4's framing of the baseline was itself wrong; corrected in A2.3 |
| P3b | `ruff check .` clean, no new `per-file-ignores` entry | `All checks passed!`, no new entry | MET |
| P3c | corpus grep over the diff 0; 0 em dashes; 0 ASCII double hyphens | 0, 0, and 1 remaining, which is the flag `--ignore-missing-imports` inside backticks in a pre-existing CHANGELOG sentence | MET, with the qualification in A2.5 |
| P4 | files exactly E14 or a proper subset; fastapi and flask untouched | 8 files: 6 within E14, **2 outside it**; fastapi and flask untouched as predicted | **MISMATCH, prediction defect, amended in A2.4** |
| P5 | zero edits to existing test files; oracle 33 passed | zero edits, `tests/test_v110_system_review.py` byte identical; `33 passed, 4 warnings in 0.41s` | MET |
| P6 | rebuild `twine check` PASSED at 1.10.0; fresh wheel venv runs the external script with F1 and F2 closed and F3 unchanged | both artifacts `PASSED`; `Version 1.10.0`; the script reports CLOSED on all four checks and exits 0 | MET |

None of the five mismatches is an engine defect. Four are defects in the
predictions, and one of those is a defect this branch introduced into its own
test file. All are amended below rather than worked around in code.

## A2.2 P1 and P2 amended: this branch repeated the mistake A1.2 documented

**Measured.** In `/tmp/al19-mcp1` (CPython 3.13.14, mcp 1.30.0) the fixed suite
failed one case:

```
tests/test_v110_hardening.py:695: in test_an_mcp_client_cannot_claim_a_role_over_a_session
    server = Server("local-probe", on_call_tool=handler)
E   TypeError: Server.__init__() got an unexpected keyword argument 'on_call_tool'
```

This is the freeze's own test file and the freeze's own mistake. A1.2 recorded,
about the review's file, that `pytest.importorskip("mcp")` guards the ABSENCE
of the package and not the presence of the wrong SDK major, and A1.4 recorded
this branch shipping an MCP case without a guard at all. The E10 MCP case was
then written with the 2.x constructor behind exactly the guard A1.2 had already
shown to be insufficient. Reading the amendment was not the same as applying
it.

**Fix, in this branch's file only.** Two changes, neither of them to the
oracle:

1. `test_an_mcp_client_cannot_claim_a_role_over_a_session` now checks
   `inspect.signature(Server.__init__).parameters` for `on_call_tool` and
   skips with a stated reason where it is absent. The guard names the
   constructor it needs rather than the package it needs.
2. A new case, `test_an_mcp_1x_client_cannot_claim_a_role_over_a_session`,
   carries E10 over the 1.x `call_tool` hook through the `FakeServer` fixture
   the rest of the file already uses. The hook's 1.x branch is selected by the
   presence of `call_tool` and not by the SDK version, so it runs at either
   major. Without it, skipping the 2.x case where only 1.x is installed would
   have left the finding uncovered in exactly the environment the skip was
   added for. It asserts the denial reason as well as that the handler never
   ran.

**Amendment.** P1 now reads:

> Every one of the 15 `xfail(strict=True)` markers is removed, and all **25**
> `TestRedPass` cases pass in every environment where their framework and SDK
> major are present. Measured: 25 passed in `/tmp/al18-extras`, 25 passed in
> `/tmp/al18-probe313`, `20 passed, 5 skipped` in `/tmp/al19-mcp1` (the four F3
> cases and the 2.x MCP case), `24 passed, 1 skipped` in the checkout venv.

P2 now reads:

> * `/tmp/al18-extras`: **1608 passed, 9 skipped, 0 failed**.
> * checkout venv: **1591 passed, 26 skipped, 0 failed**.
> * `/tmp/al19-mcp1`, 4 deselected: **1588 passed, 25 skipped, 0 failed**.
> * `/tmp/al18-probe313`: **1609 passed, 8 skipped, 0 failed**.

Every difference from the frozen figures is the one added case and the one
added skip. `/tmp/al19-mcp1` holds its pass count because the 2.x case it loses
to the new skip is the case the 1.x companion replaces there.

## A2.3 R4.4 corrected: the project's mypy invocation carries a flag

The freeze recorded, under R4.4, that `mypy agentlock/` reports one to three
findings depending on the environment and that this "contradicts AMENDMENT 1's
K3a". The finding was measured correctly and the conclusion drawn from it was
wrong.

Every CHANGELOG entry from 1.9.0 onward states the invocation as
`mypy agentlock/ --ignore-missing-imports`. Measured at this commit:

```
/tmp/al18-extras   Success: no issues found in 34 source files
/tmp/al18-probe313 Success: no issues found in 34 source files
/tmp/al19-mcp1     Success: no issues found in 34 source files
```

The bare invocation's findings are all `import-not-found` or `import-untyped`
against optional integration dependencies (`autogen`, `fastapi`, `flask`,
`mcp`), so its count is a function of which optional packages a venv happens to
hold and not of the engine. A1.1 abbreviated the project's command to "mypy 0"
and was reporting the flagged run; R4.4 measured the unflagged one and read the
difference as a contradiction. It is not one, and AMENDMENT 1 stands. Recorded
here rather than silently dropped, because the freeze accused a prior
measurement of being unreproducible and that accusation should not outlive the
reason for it.

Both invocations are reported from here on. The flagged one,
**`mypy agentlock/ --ignore-missing-imports`, is clean in all three
environments**, and the bare invocation's output is byte identical before and
after this arc, with **zero findings in any file the arc edits**.

## A2.4 P4 and E14 amended: E11 names two application sites E14 does not list

**Measured.** Eight files changed. Six are in E14:

```
CHANGELOG.md, README.md, agentlock/gate.py, agentlock/modify.py,
agentlock/types.py, tests/test_v110_hardening.py
```

Two are not:

```
agentlock/decorators.py, agentlock/integrations/mcp.py
```

**Why they had to be.** E11 states where the walk applies: "execute, call, both
decorators, both MCP hooks, autogen". Four of those six reach it through
`gate.execute` and so are satisfied by the change to `agentlock/gate.py`:
`execute` itself, `call`, the sync decorator (which runs through `gate.call`),
and autogen (which calls `gate.execute` directly). The other two apply the
modifier in their own code and cannot be reached from `gate.py` at all:

* `agentlock/decorators.py:222`, the async wrapper, which applies
  `auth_result.modify_output_fn` itself in the position `gate.execute` would.
* `agentlock/integrations/mcp.py:381`, `_modify_text_content`, which is the
  MCP hooks' applier for both SDK majors.

E14 listed `agentlock/integrations/fastapi.py` and
`agentlock/integrations/flask.py`, which E12 turned out not to need, and did
not list the two files E11 does need. It was written against the finding list
rather than against the call graph. E11 is the substantive decision and E14 is
the bookkeeping around it, so the bookkeeping is what moves.

**Amendment.** E14's file list now reads:

> `agentlock/gate.py`, `agentlock/types.py`, `agentlock/modify.py`,
> `agentlock/decorators.py`, `agentlock/integrations/mcp.py`, `CHANGELOG.md`,
> `README.md`, `tests/test_v110_hardening.py`,
> `docs/PREDICTIONS_v110_hardening.md` (append only). Nothing else.
> `agentlock/integrations/fastapi.py` and `agentlock/integrations/flask.py`
> were listed for E12 and are not needed, for the reason recorded in R1 under
> F3.

and P4 now reads:

> Files touched are exactly the amended E14: 8 changed plus this document.
> Nothing outside it. `agentlock/integrations/fastapi.py` and
> `agentlock/integrations/flask.py` are not touched.

The count is unchanged at eight either way, which is a coincidence and not a
justification.

## A2.5 The one remaining ASCII double hyphen, declared

The diff contains a single `--`, in the CHANGELOG's suite sentence:

```
`mypy agentlock/ --ignore-missing-imports` reports 0 errors
```

It is a command-line flag inside a code span, in a sentence that predates this
arc and that the arc re-emits only to carry new numbers. Removing the hyphens
would misname the command. It is declared here rather than treated as a style
violation to argue about later. Every other line of the diff, prose and code,
carries none, and the diff contains zero em dashes.

## A2.6 What the fix actually changed, stated for the record

**E10 placement.** The check runs after the velocity and combo signals are
recorded and before the tool-existence guard. Telemetry still sees a caller
that repeatedly claims a role it does not hold, which is exactly the behavior
a velocity detector exists to notice. The tool-existence guard runs after,
rather than before, so a caller whose claimed identity has already failed is
not told whether the tool it named is registered.

**One session lookup where there were two.** `authorize()` resolved the
session twice for the same caller, once at the hardening block and once at the
role block. E10 says the rule applies wherever the gate resolves a session for
a caller-supplied role; the way to make that true without stating it twice is
for there to be one resolution, so the two are now one, named `session`, and
the rule sits directly under it.

**Denial shape.** `role_mismatch` carries `required_role` as the session's role
and `current_role` as the claim, so `DeniedError` renders both without any
caller having to reconstruct them. It is logged with the SESSION's role, not
the claimed one, because the audit record is a record of who the caller
actually is.

**`apply_output_modifier` is a function, not a method.** It lives in
`agentlock/modify.py` beside `ModifyEngine` and takes the `str -> str` callable
as an argument. `build_output_modifier` keeps its signature and its behavior,
so `tests/test_modify.py::TestBuildOutputModifier` is untouched by construction
rather than by luck, which is what the R3 survey predicted.

**Named tuples and subclasses.** `tuple` is rebuilt through `type(value)._make`
where that exists, so a named tuple keeps its own type rather than degrading to
a plain tuple. `dict` and `list` subclasses are rebuilt as plain `dict` and
`list`, because there is no general way to call an arbitrary subclass's
constructor, and the docstring says so rather than leaving a caller to discover
it.

**Dictionary keys are not modified.** A key is a field name. A transformation
that renamed fields would corrupt the payload it was asked to sanitize, so the
walk descends into values only.

## A2.7 Final measurements

Suite, all four environments, 0 failed in each:

```
/tmp/al18-extras    1608 passed, 9 skipped, 35 warnings in 3.46s
checkout venv       1591 passed, 26 skipped, 34 warnings in 3.37s
/tmp/al19-mcp1      1588 passed, 25 skipped, 4 deselected in 3.04s
/tmp/al18-probe313  1609 passed, 8 skipped, 1 warning in 3.42s
```

Oracle alone, `/tmp/al18-extras`, from a file byte identical to the one frozen
at commit A: `33 passed, 4 warnings in 0.41s`.

Rebuild, `/tmp/al18-extras`:

```
Successfully built agentlock-1.10.0.tar.gz and agentlock-1.10.0-py3-none-any.whl
Checking dist/agentlock-1.10.0-py3-none-any.whl: PASSED
Checking dist/agentlock-1.10.0.tar.gz: PASSED
```

`importlib.metadata.version("agentlock")` in the fresh wheel venv:
`1.10.0`. The version did not move; 1.10.0 is unreleased and these findings
close inside it.

External reproduction, `/tmp/al110_redpass_repro.py`, run from `/tmp` against a
venv holding only the rebuilt wheel and its extras:

```
engine 1.10.0 from /tmp/al110-redpass-wheel/lib/python3.14/site-packages/agentlock/__init__.py
F1 gate: CLOSED (claim denied=True, session role resolves=True, agreement allowed=True, no-session trusted=True)
F1 mcp: CLOSED (handler ran: [])
F2: CLOSED (leaks: none)
F3: CLOSED (status 200, handler ['HANDLER_RAN']; the header is not consulted while a mapping is configured)
exit=0
```

The oracle, copied outside the checkout and run against that same wheel:
`33 passed, 4 warnings in 0.49s`.

---

# RED PASS 2 FREEZE (2026-09-10)

Appended after AMENDMENT 2 and before any code that closes the findings below.
Everything above, sections 1 through 5, AMENDMENT 1, the RED PASS FREEZE and
AMENDMENT 2, is left exactly as it was written.

A second pre-release red pass was run against the branch wheel,
`agentlock-1.10.0-py3-none-any.whl`, sha256
`b72739f9b49122e6f52bcfa7bf075ab62222aa1d014e343e0fff2d2bbd0c1c2e`, built from
`33d0386`. That is the wheel AMENDMENT 2 recorded rebuilding at A2.7, and it is
a different artifact from the one the first red pass ran against
(`0d793500`, built from `4bd3998`). 1.10.0 is still unreleased, so these
findings close on this branch as the first three did, and not in a patch
release.

The wheel was verified to be the tree the same way: `agentlock/modify.py`,
`agentlock/integrations/mcp.py`, `agentlock/gate.py`,
`agentlock/decorators.py` and `agentlock/types.py` were unzipped from the
artifact and compared byte for byte against the checkout at `33d0386`. All five
are identical. Every reproduction below is therefore a measurement of the
shipped artifact.

Nothing in this section describes code written on this branch after `33d0386`.

## S1. The three findings, reproduced

All three findings are in the same place: the output modification path that E1
threaded onto every execution route and E11 taught to walk a return value. The
first red pass closed the question of whether the modifier ARRIVES. This one is
about what it does once it is there.

**F4. mcp structured content is not modified. REPRODUCED, on both SDK majors.**

An MCP `CallToolResult` carries two payloads, not one. `content` is the list of
content blocks, and `structured_content` is a mapping the client reads as the
tool's machine-readable answer. `agentlock/integrations/mcp.py:382-441`,
`_modify_text_content`, handles the first and never looks at the second: it
rewrites the `text` of every content block, and where the result is not a
content-carrying model at all it hands the whole thing to
`apply_output_modifier`. A result that IS a content-carrying model and ALSO
carries structured content takes the first branch and returns with the second
untouched.

Measured against the wheel in `/tmp/al18-extras` (mcp 2.2.0), a handler
returning both payloads carrying the same SSN under a declared `redact_pii` on
`output`:

```
F4 mcp2 content   : Customer SSN [REDACTED:ssn]
F4 mcp2 structured: leaked=True {'note': 'Customer SSN 123-45-6789'}
```

One copy redacted, the other handed over intact, in the same return value. A
client reading the structured payload, which is what a client reads it for,
sees the unredacted answer.

The field is spelled differently by the two SDK majors, and the applier is one
function serving both hooks:

```
mcp 2.2.0   structured_content   (alias structuredContent)
mcp 1.30.0  structuredContent
```

Through the 1.x `call_tool` hook, against a result object carrying a content
list and a `structured_content` mapping:

```
F4 mcp1 content   : Customer SSN [REDACTED:ssn]
F4 mcp1 structured: leaked=True {'note': 'Customer SSN 123-45-6789'}
```

Both models are settable in place at the versions installed here, measured
directly, so neither hook needs the `model_copy` fallback today. The fallback
is written anyway, because `_modify_text_content` already carries one for
`content` and an SDK that freezes one field is an SDK that can freeze the
other.

**Not reproduced, and stated because E15's second sentence covers it.** E15
also says that a result which is a plain mapping or sequence rather than a
`CallToolResult` is walked the same way. Measured against the wheel, it already
is, on both shapes the 1.x handler contract allows:

```
F4 mcp1 list      : leaked=False [Text('Customer SSN [REDACTED:ssn]')]
F4 mcp1 mapping   : leaked=False {'note': 'Customer SSN [REDACTED:ssn]'}
```

The list goes through the `isinstance(result, list)` branch and the mapping
falls to `apply_output_modifier`, both of which E11 put there. Neither is
marked as an expected failure. Both are pinned as guards, for the reason R1
gave under F3: fastapi had a correct branch with no test and it came back as a
reported defect.

**F5. The walk does not cover `set` or `frozenset`. REPRODUCED.**

`agentlock/modify.py:87-101` covers `str`, `bytes`, `dict`, `list` and `tuple`
and returns everything else unchanged, and its docstring names sets among the
things returned unchanged. Naming an uncovered type documents a leak; it does
not bound one. A set of strings is an ordinary return for a tool that answers
with distinct values. Measured against the wheel through `gate.call`:

```
F5 set       : leaked=True type=set {'Customer SSN 123-45-6789'}
F5 frozenset : leaked=True type=frozenset frozenset({'Customer SSN 123-45-6789'})
```

**F6. Dict keys and arbitrary objects are not walked. REPRODUCED, and to be
stated rather than closed.**

```
F6 dict-key  : leaked=True type=dict {'Customer SSN 123-45-6789': 'v'}
F6 object    : leaked=True type=Obj Obj('Customer SSN 123-45-6789')
```

Both are deliberate and both stay. A key is a field name, and A2.6 already
recorded why renaming fields would corrupt the payload a transformation was
asked to sanitize. An arbitrary object is a type the walk was not told how to
rebuild and will not mutate in place. The decision is to say so in the
docstring and to pin the limit with cases that assert the leak, so that a
future change to either rule fails a test and gets argued rather than drifting.

## S2. Decisions of record

Restated as received, so this document is readable without the instruction that
produced it.

**E15. Structured content is modified.** In both MCP hooks, when the result
object has a `structured_content` (or `structuredContent`) attribute that is
not `None`, the E11 walker is applied to it and the result set back. When the
result is a plain mapping or sequence rather than a `CallToolResult`, which the
1.x handler contract allows, it is walked the same way.

**E16. The walker covers sets.** `set` and `frozenset` are handled by walking
their members and rebuilding the same type. The docstring states explicitly
that dictionary keys, objects, and non-UTF-8 bytes are not modified, and that a
host returning those types must redact them itself.

**E17. Files.** `agentlock/modify.py`, `agentlock/integrations/mcp.py`,
`CHANGELOG.md` (one line each under the existing 1.10.0 Security section),
`README.md` if counts change, `tests/test_v110_hardening.py` (`TestRedPass`
gains the cases), `docs/PREDICTIONS_v110_hardening.md` (append only). Nothing
else.

### E16 amended before the build: the bytes clause is false of the engine

E16 asks the docstring to state that non-UTF-8 bytes "are not modified". That
is measured to be false, and stating it would have put a false claim about the
engine's behavior into the engine's own documentation, which is the failure
mode the standing rule about verifying a claim against the artifact exists to
prevent. Recorded here, before the build, rather than discovered afterwards.

Measured against the wheel, a latin-1 payload holding an ASCII SSN and two
undecodable bytes, under a declared `redact_pii` on `output`:

```
in : b'Customer SSN 123-45-6789 \xff\xfe'
out: b'Customer SSN [REDACTED:ssn] \xef\xbf\xbd\xef\xbf\xbd'
unchanged: False | ssn present: False
```

Non-UTF-8 bytes are modified twice over. The readable part IS redacted, which
is the behavior E11 chose `errors="replace"` for and argued for in writing:
"a transformation that cannot read the bytes must not be a reason to hand them
back unread". The unreadable part is replaced with U+FFFD and re-encoded, so
the caller gets back neither the original bytes nor a faithful sanitization of
them.

E16's first sentence is a behavior directive and its second is a docstring
directive. Nothing in the three findings covers bytes, so the second sentence
is read as documentation and not as authority to overturn E11's choice. The
behavior is therefore UNCHANGED and the docstring states what is true instead:
that a byte string which is not valid UTF-8 is decoded lossily before the
transformation sees it, that the transformation cannot match on the part it
could not read, that the value returned is a UTF-8 re-encoding rather than the
original bytes, and that a host returning non-UTF-8 bytes must redact them
itself.

**This is flagged for a decision rather than settled here.** If the intent of
E16's bytes clause was that non-UTF-8 bytes should pass through untouched, that
is a behavior change to a decision of record from the previous pass, it belongs
in its own finding with its own freeze, and it is not made on this pass. It is
named here so it cannot be lost.

## S3. Existing tests that assert the old behavior

Predicted before editing: **zero** edits to existing test files.

Measured rather than read, the same way R3 was. A pytest plugin wrapped
`agentlock.modify.apply_output_modifier` and
`AgentLockMCPServer._modify_text_content` at `33d0386` and recorded, with the
test id, every call the E15 and E16 changes would reach: for E16, every walk of
a `set` or `frozenset`; for E15, every result carrying a non-`None`
`structured_content` or `structuredContent`. The whole suite was run under it.

| Change | Calls reached | Outside `TestRedPass` |
|---|---|---|
| E16 (`/tmp/al18-extras`) | 0 | 0 |
| E15 (`/tmp/al18-extras`) | 2 | 0 |
| E16 (`/tmp/al19-mcp1`) | 0 | 0 |
| E15 (`/tmp/al19-mcp1`) | 1 | 0 |

Every E15 hit is one of the new expected-failure cases this freeze adds, which
is why the count is 2 where both SDK majors' cases can run and 1 where only the
1.x companion can. Nothing else in 1612 passing tests returns a set, and
nothing else returns a result carrying structured content.

`build_output_modifier` keeps its `Callable[[str], str]` signature and both
changes are made beside it, so `tests/test_modify.py::TestBuildOutputModifier`
is untouched by construction rather than by luck, exactly as at the last pass.

## S4. STEP 0 measurements

### S4.1 Baselines at `33d0386`, before the new cases

| Environment | Suite |
|---|---|
| `/tmp/al18-extras` (py3.14.6, mcp 2.2.0, fastapi 0.141.1, Flask 3.1.3) | `1608 passed, 9 skipped` |
| checkout venv (py3.14.6, no mcp, fastapi 0.135.3, Flask 3.1.3) | `1591 passed, 26 skipped` |
| `/tmp/al19-mcp1` (py3.13.14, mcp 1.30.0, no fastapi, no flask), 4 deselected per K2c | `1588 passed, 25 skipped, 4 deselected` |
| `/tmp/al18-probe313` (py3.13.14, mcp 2.2.0, fastapi, flask) | `1609 passed, 8 skipped` |

All four reconcile with AMENDMENT 2 section A2.7 exactly.

Oracle alone, `/tmp/al18-extras`: `33 passed, 4 warnings in 0.44s`.

### S4.2 With the new cases added

`TestRedPass` goes from 25 cases to **33**: 8 added, 4 of them strict xfails and
4 of them plain guards.

| Environment | Suite |
|---|---|
| `/tmp/al18-extras` | `1612 passed, 9 skipped, 4 xfailed` |
| checkout venv | `1593 passed, 30 skipped, 2 xfailed` |
| `/tmp/al19-mcp1` (4 deselected) | `1592 passed, 26 skipped, 4 deselected, 3 xfailed` |
| `/tmp/al18-probe313` | `1613 passed, 8 skipped, 4 xfailed` |

Every arithmetic difference from S4.1 is accounted for. `/tmp/al18-extras` and
`/tmp/al18-probe313` have both a 2.x SDK and both frameworks, so all 8 cases
run: 4 passes and 4 xfails. `/tmp/al19-mcp1` has a 1.x SDK, so the 2.x
structured content case skips on the constructor guard: 4 passes, 3 xfails, 1
new skip. The checkout venv has no `mcp` at all, so the two structured content
cases and the two 1.x guards skip: 2 passes, 2 xfails, 4 new skips.

**No xfail XPASSes in any environment.** F4 and F5 are red in exactly the shape
E15 and E16 will turn green, and F6 is not marked xfail at all, because F6 is
not being closed.

`TestRedPass` alone, `/tmp/al18-extras`: `29 passed, 4 xfailed`.

### S4.3 The marker inventory

The 4 strict xfails, all removed by the fix:

* F4 through the real mcp 2.x SDK: 1. Guarded on `importorskip("mcp")` AND on
  `on_call_tool` being in the `Server.__init__` signature, per A1.2, so it
  skips against a 1.x SDK rather than failing on the SDK's own constructor.
* F4 through the 1.x `call_tool` hook and the `FakeServer` fixture: 1. This is
  the case that covers the camelCase spelling, and it is what keeps the finding
  covered in the environment where the case above skips. Same companion
  pattern A2.2 established for E10.
* F5 through `gate.call`: 2, one for `set` and one for `frozenset`. Each
  asserts the container type as well as the absence of the SSN, because a walk
  that turned a `frozenset` into a `set` would break a caller that puts it in
  another set.

The 4 plain guards, passing now and required to keep passing:

* E15's second sentence: 2. The 1.x bare list return and the 1.x plain mapping
  return are already walked, and the structured content change must not cost
  either.
* F6, the limit pinned: 2. A dict keyed by the secret comes back with the key
  intact, and an object whose `__str__` carries the secret comes back as the
  same object. Both assert the leak on purpose.

### S4.4 Lint, types, style

`ruff check .`: **All checks passed.** No new `per-file-ignores` entry. One
`noqa: N815` sits on the deliberately camelCase attribute of the 1.x result
stub, which is the SDK's own spelling and is the point of that case.

Style scan of the added test content: `emdash: 0 double-hyphen: 0`.

`mypy` at `33d0386`, both invocations, recorded so the prediction has a
baseline. The flagged invocation is the project's, per A2.3:

```
mypy agentlock/ --ignore-missing-imports
  /tmp/al18-extras    Success: no issues found in 34 source files
  /tmp/al18-probe313  Success: no issues found in 34 source files
  /tmp/al19-mcp1      Success: no issues found in 34 source files

mypy agentlock/
  /tmp/al18-extras    Found 1 error in 1 file (checked 34 source files)
  /tmp/al18-probe313  Found 1 error in 1 file (checked 34 source files)
  /tmp/al19-mcp1      Found 3 errors in 3 files (checked 34 source files)
```

Every finding of the bare invocation is a missing third-party stub for an
optional integration dependency, and none is in a file this pass edits.

## S5. Frozen predictions

Stated before any implementation code is written. A MISMATCH on any of these is
a STOP: no commit, report, and amend the failed prediction in place, dated,
before proceeding.

**Q1.** Every one of the 4 `xfail(strict=True)` markers is removed, and all 33
`TestRedPass` cases pass in every environment where their framework and SDK
major are present. No marker is left in place, and no case is deleted or
weakened. Measured expectation: `33 passed` in `/tmp/al18-extras` and
`/tmp/al18-probe313`, `27 passed, 6 skipped` in `/tmp/al19-mcp1` (the four F3
cases, the 2.x MCP role case, and the 2.x structured content case), and
`29 passed, 4 skipped` in the checkout venv.

**Q2.** Full suite, per environment, equal to the S4.2 figure with every xfail
turned into a pass and zero failures:

* `/tmp/al18-extras`: **1616 passed, 9 skipped, 0 failed, 0 xfailed**.
* checkout venv: **1595 passed, 30 skipped, 0 failed**.
* `/tmp/al19-mcp1`, 4 deselected: **1595 passed, 26 skipped, 0 failed**.
* `/tmp/al18-probe313`: **1617 passed, 8 skipped, 0 failed**.

**Q3.** `mypy agentlock/ --ignore-missing-imports` is clean in all three
environments and the bare invocation's output is unchanged from the S4.4
baseline, with **zero findings in `agentlock/modify.py` and
`agentlock/integrations/mcp.py`**. `ruff check .` is clean with no new
`per-file-ignores` entry. The diff contains **0** em dashes and **0** ASCII
double hyphens outside the one CHANGELOG flag A2.5 already declared, and the
corpus grep over the diff returns **0**.

**Q4.** Files touched are **exactly E17 or a proper subset of it**, and nothing
outside it. Specifically predicted: `agentlock/gate.py`,
`agentlock/decorators.py`, `agentlock/types.py`,
`agentlock/integrations/fastapi.py` and `agentlock/integrations/flask.py` are
**not** touched. E15 names the MCP applier and E16 names the walker, and every
other execution path reaches the walker through `agentlock/modify.py`, so
`agentlock/gate.py` and `agentlock/decorators.py` get sets and frozensets for
free. That is the same call-graph argument A2.4 had to make after the fact, made
here before the fact instead.

**Q5.** Zero edits to existing test files, including
`tests/test_v110_system_review.py`, and the oracle still reports **33 passed**
in `/tmp/al18-extras`.

**Q6.** Rebuild: `twine check dist/*` **PASSED** on both artifacts, metadata
**Version 1.10.0**, no version bump. The wheel's sha256 changes, because the
tree changed. A fresh venv holding only the rebuilt wheel runs a reproduction
script from outside the checkout and reports F4 closed on both SDK majors, F5
closed for `set` and `frozenset` with the container type preserved, and F6
unchanged at the stated limit.

**Q7.** `README.md` counts move to the Q2 figures and the CHANGELOG's 1.10.0
suite sentence moves with them. The added-test count in the README's Versions
prose moves from 88 to 96 and `TestRedPass` from 25 to 33.

---

# AMENDMENT 3

Date: 2026-09-10. Appended after STEP 1 and STEP 2, before the code commit.
The RED PASS 2 FREEZE section above is left exactly as it was frozen; this
section records what happened to each of its predictions and amends the one
that was defective.

## A3.1 Result table

| # | Prediction | Measured | Verdict |
|---|---|---|---|
| Q1a | 4 strict xfail markers removed; `33 passed` in `/tmp/al18-extras` and `/tmp/al18-probe313` | 4 removed; `33 passed` in both | MET |
| Q1b | `/tmp/al19-mcp1`: `27 passed, 6 skipped` | `27 passed, 6 skipped` | MET |
| Q1c | checkout venv: `29 passed, 4 skipped` | `27 passed, 6 skipped` | **MISMATCH, prediction defect, amended in A3.2** |
| Q2a | `/tmp/al18-extras`: 1616 passed, 9 skipped, 0 failed | `1616 passed, 9 skipped` | MET |
| Q2b | checkout venv: 1595 passed, 30 skipped, 0 failed | `1595 passed, 30 skipped` | MET |
| Q2c | `/tmp/al19-mcp1`, 4 deselected: 1595 passed, 26 skipped, 0 failed | `1595 passed, 26 skipped, 4 deselected` | MET |
| Q2d | `/tmp/al18-probe313`: 1617 passed, 8 skipped, 0 failed | `1617 passed, 8 skipped` | MET |
| Q3a | `mypy agentlock/ --ignore-missing-imports` clean in all three; bare invocation unchanged from S4.4; 0 findings in the two edited files | clean in all three; bare invocation 1, 1 and 3 findings exactly as at S4.4; 0 findings in either edited file | MET |
| Q3b | `ruff check .` clean, no new `per-file-ignores` entry | `All checks passed!`, no new entry | MET |
| Q3c | 0 em dashes, 0 ASCII double hyphens outside the flag A2.5 declared, corpus grep 0 | 0, and the only ASCII double hyphen in the diff is that same declared flag in the CHANGELOG suite sentence, and 0 | MET |
| Q4 | files exactly E17 or a proper subset; gate, decorators, types, fastapi and flask untouched | 5 files, all within E17; the five named files untouched | MET |
| Q5 | zero edits to existing test files; oracle 33 passed | `tests/test_v110_system_review.py` byte identical; `33 passed, 4 warnings` in the checkout and again against the rebuilt wheel from outside it | MET |
| Q6 | rebuild `twine check` PASSED at 1.10.0; fresh wheel venv reports F4 closed on both majors, F5 closed with types preserved, F6 unchanged | both artifacts `PASSED`; `Version 1.10.0`; the script reports CLOSED on all six checks, F6 UNCHANGED, and exits 0 | MET |
| Q7 | README counts move to the Q2 figures; added-test count 88 to 96; `TestRedPass` 25 to 33 | done, and the CHANGELOG suite sentence moved with them | MET |

One mismatch, and it is a defect in the prediction rather than in the engine.
It is amended below rather than worked around in code.

## A3.2 Q1c amended, and a figure in AMENDMENT 2 corrected with it

**Measured.** In the checkout venv, which has no `mcp` at all, the fixed
`TestRedPass` is `27 passed, 6 skipped`, not the predicted `29 passed,
4 skipped`. The class total is 33 either way, so the mismatch is entirely in
how the 33 split.

The six skips, named:

```
tests/test_v110_hardening.py:694  test_an_mcp_client_cannot_claim_a_role_over_a_session
tests/test_v110_hardening.py:738  test_an_mcp_1x_client_cannot_claim_a_role_over_a_session
tests/test_v110_hardening.py:979  test_mcp_2x_structured_content_is_modified
tests/test_v110_hardening.py:1021 test_mcp_1x_structured_content_is_modified
tests/test_v110_hardening.py:1056 test_mcp_1x_a_list_return_is_walked
tests/test_v110_hardening.py:1084 test_mcp_1x_a_mapping_return_is_walked
```

Four of those are this pass's own cases, which S4.2 predicted and measured
correctly. The other two are the E10 pair from the previous pass, and BOTH of
them skip here: `importorskip("mcp")` guards each, and the checkout venv has no
`mcp`.

**Where the wrong number came from.** A2.2 records the fixed `TestRedPass` in
the checkout venv as `24 passed, 1 skipped`. Measured now at `33d0386`, with
the tree exactly as AMENDMENT 2 left it:

```
tests/test_v110_hardening.py::TestRedPass   23 passed, 2 skipped
```

A2.2's figure is one skip short. Its argument is unaffected: the 1.x companion
was added so that skipping the 2.x case where only a 1.x SDK is installed would
not leave the finding uncovered, and that is exactly what it does in
`/tmp/al19-mcp1`. What A2.2 did not say is that in an environment with NO SDK
both cases skip together, which is the correct and intended outcome and simply
was not counted.

**How this pass then repeated it.** Q1c took A2.2's `24 passed, 1 skipped` as
given and added this pass's four cases to it, without re-measuring the figure
it was building on. That is precisely the move the standing rule exists to
forbid: a number was propagated from a prior document instead of being
re-measured against the artifact it describes. The rule was written about
version, license and test-count claims, and a per-class test count is a
test-count claim.

Two things make this a small error rather than a large one, and neither is a
defense of it. Q2b, the full-suite figure for the same environment, was derived
from a measurement taken at `33d0386` in S4.1 rather than from a prior document,
and it is exactly right: `1595 passed, 30 skipped`. And S4.2's own prose says
the checkout venv gains four skips, which reconciles. Only the per-class
absolute figure was carried forward unmeasured.

**Amendment.** Q1 now reads:

> Every one of the 4 `xfail(strict=True)` markers is removed, and all 33
> `TestRedPass` cases pass in every environment where their framework and SDK
> major are present. Measured: `33 passed` in `/tmp/al18-extras` and
> `/tmp/al18-probe313`; `27 passed, 6 skipped` in `/tmp/al19-mcp1` (the four F3
> cases, the 2.x MCP role case and the 2.x structured content case); and
> `27 passed, 6 skipped` in the checkout venv (those same four F3 cases are
> absent from that list, because fastapi and flask ARE installed there; the six
> are both MCP role cases, both structured content cases and both 1.x guards).

and A2.2's checkout venv figure is corrected from `24 passed, 1 skipped` to
**`23 passed, 2 skipped`**, measured at `33d0386`. No other figure in
AMENDMENT 2 moves; all four of its full-suite figures reproduce exactly.

## A3.3 E16's bytes clause, resolved as the freeze said it would be

S2 recorded, before the build, that E16's instruction to state "non-UTF-8 bytes
are not modified" is false of the engine, and that the behavior would be left
alone and the docstring made true instead. That is what happened. The bytes
branch of `apply_output_modifier` is byte for byte unchanged, and the docstring
now carries a "What this does not modify" block naming three limits: dictionary
keys, objects, and bytes that are not valid UTF-8, the last of which says that
the readable part IS transformed and the unreadable part is neither transformed
nor preserved.

The open question is restated here so it does not close by being forgotten: if
the intent was that non-UTF-8 bytes should pass through untouched, that is a
behavior change to E11's stated choice of `errors="replace"`, it belongs in its
own finding with its own freeze, and this pass did not make it.

## A3.4 What the fix actually changed, stated for the record

**One setter where there were two.** `_modify_text_content` already carried a
set-in-place-then-copy fallback for content models, and the structured payload
needs the same one. Rather than write it twice, it is now a module-level
`_set_field(obj, name, value)` in `agentlock/integrations/mcp.py`, and the
content rewrite path was folded onto it. The behavior of that path is
unchanged, which the previous pass's own reproduction script confirms against
the rebuilt wheel: F1, F2 and F3 all still report CLOSED.

**An object that will take neither a set nor a copy is returned unchanged.**
`_set_field` swallows the failure rather than raising. A declared
transformation that could not be applied is not a reason to fail a call the
gate has already authorized and the tool has already run, and the caller is
better served by the untransformed value than by an exception from inside the
adapter. This is the rule the content path already had; it is now stated once,
where the fallback lives.

**Both field names, tried in order, and `None` left alone.** The 2.x SDK's
`structured_content` carries `structuredContent` as a serialization alias,
which attribute access does not see, so the alias cannot stand in for the 1.x
spelling and both names have to be tried. A payload that is `None` is skipped:
absent is not empty, and writing a walked `None` back would be a change with
nothing behind it. Measured at the installed versions, neither SDK's model is
frozen, so the copy fallback does not fire today; it is written because
`_modify_text_content` already needed one for `content` and an SDK that freezes
one field can freeze the other.

**Sets rebuild the plain type, not the subclass.** `set` comes back `set` and
`frozenset` comes back `frozenset`, which is the distinction that matters to a
caller putting the value in another set. A subclass of either degrades to the
plain type, on exactly the reasoning A2.6 gave for `dict` and `list`: there is
no general way to call an arbitrary subclass's constructor. The docstring says
so rather than leaving a caller to find out.

**F6 is pinned by cases that assert the leak.** The two F6 guards assert that a
dict keyed by the secret comes back with that key intact and that an object
whose `__str__` carries the secret comes back as the same object. Asserting a
leak reads strangely until the alternative is considered: a limit that no test
holds is a limit that moves quietly. If a future change starts modifying keys
or mutating objects, these fail and the decision gets argued instead of drifting.

## A3.5 Final measurements

Suite, all four environments, 0 failed in each:

```
/tmp/al18-extras    1616 passed, 9 skipped, 35 warnings in 3.53s
checkout venv       1595 passed, 30 skipped, 34 warnings in 3.37s
/tmp/al19-mcp1      1595 passed, 26 skipped, 4 deselected in 3.05s
/tmp/al18-probe313  1617 passed, 8 skipped, 1 warning in 3.44s
```

`TestRedPass` alone: `33 passed` in `/tmp/al18-extras` and
`/tmp/al18-probe313`, `27 passed, 6 skipped` in `/tmp/al19-mcp1` and in the
checkout venv.

Oracle alone, `/tmp/al18-extras`, from a file byte identical to the one the
external review supplied: `33 passed, 4 warnings in 0.43s`.

Types and lint:

```
mypy agentlock/ --ignore-missing-imports   Success in all three environments
mypy agentlock/                            1, 1 and 3 findings, all optional-dependency
                                           stubs, unchanged from the S4.4 baseline
ruff check .                               All checks passed!
```

Rebuild, `/tmp/al18-extras`:

```
Successfully built agentlock-1.10.0.tar.gz and agentlock-1.10.0-py3-none-any.whl
Checking dist/agentlock-1.10.0-py3-none-any.whl: PASSED
Checking dist/agentlock-1.10.0.tar.gz: PASSED
```

`importlib.metadata.version("agentlock")` in the fresh wheel venv: `1.10.0`.
The version did not move; 1.10.0 is unreleased and these findings close inside
it, as the first three did.

External reproduction, `/tmp/al110_redpass2_repro.py`, run from `/tmp` against
a venv holding only the rebuilt wheel and its extras:

```
engine 1.10.0 from /tmp/al110-redpass2-wheel/lib/python3.14/site-packages/agentlock/__init__.py
F4 mcp 2.x: CLOSED (structured {'note': 'Customer SSN [REDACTED:ssn]'})
F4 mcp 1.x: CLOSED (structured {'note': 'Customer SSN [REDACTED:ssn]'})
E15 list return: CLOSED
E15 mapping return: CLOSED
F5 set: CLOSED (set {'Customer SSN [REDACTED:ssn]'})
F5 frozenset: CLOSED (frozenset)
F6 stated limit: UNCHANGED (dict key intact=True, object identical=True)
exit=0
```

The FIRST red pass's script, `/tmp/al110_redpass_repro.py`, run unchanged
against the same new wheel, still reports F1, F2 and F3 CLOSED and exits 0. The
oracle, copied outside the checkout and run against that wheel: `33 passed`.

The rebuilt artifacts:

```
d2afa56afaedfe1a67c374bdf58280310d80e37b502deacd81808cc2a1453417  dist/agentlock-1.10.0-py3-none-any.whl
c754494d57b0573bb49bce2b3eb58068f57e74259d6c67a14dbed6f32195e1c5  dist/agentlock-1.10.0.tar.gz
```

---

# RELEASE FREEZE (2026-09-10)

Appended after AMENDMENT 3 and before any release edit. Everything above,
sections 1 through 5, AMENDMENT 1, the RED PASS FREEZE, AMENDMENT 2, the RED
PASS 2 FREEZE and AMENDMENT 3, is left exactly as it was written.

This is the release session for 1.10.0. It produces one release commit and one
amendment. There is no merge, no tag, no push and no upload: those are the
maintainer's manual steps and nothing here performs them.

Three code passes have closed on this branch: the seven groups an external
review of the 1.9.1 wheel found, the three findings of a pre-release red pass
against the wheel built at `4bd3998`, and the three findings of a second red
pass against the wheel built at `33d0386`. No further engine change is
predicted. What remains is the release surface: CHANGELOG, README, CITATION.cff.

Nothing in this section describes an edit that has been made. Every figure
below labelled "at HEAD" is a measurement of `fadd292` before STEP 1 touches
anything.

## T1. State at HEAD, measured

`git status` is clean at `fadd292`.

Versions, already at the release value from the code passes:

```
pyproject.toml:7   version = "1.10.0"
agentlock/__init__.py:37   __version__ = "1.10.0"
```

The only `1.9.x` strings anywhere in `agentlock/`, `pyproject.toml` or
`CITATION.cff` are nine historical references inside docstrings and comments
(`agentlock/gate.py:1540,2232`, `agentlock/defer.py:302`,
`agentlock/modify.py:313`, `agentlock/integrations/mcp.py:124,318,418`,
`agentlock/integrations/fastapi.py:137`,
`agentlock/integrations/flask.py:213`), each of the form "through 1.9.1 this
did X". None is a current-version string.

`CITATION.cff` at HEAD already reads `version: 1.10.0`,
`date-released: 2026-09-10`, `doi: 10.5281/zenodo.22681594` and a single
identifier carrying that same concept DOI. V3 is therefore predicted to be
satisfied by a file that needs no edit, and the prediction is stated anyway so
that STEP 2 measures it rather than assumes it.

`CHANGELOG.md:10` reads `## [1.10.0] - 2026-09-10`. The 1.10.0 entry carries
the seven groups, the three first red pass findings and the three second red
pass findings, both credit strings, and the suite figures. It carries **zero**
occurrences of `__wrapped__` and **zero** occurrences of "body", so two of the
four limits V1 requires are absent and are what STEP 1 adds. Its not-additive
paragraph names the count of behavior changes but not the two caller shapes V1
requires it to name.

`README.md` carries the 1.10.0 versions row and the counts paragraph.
`grep -n "1\.9\.1" README.md` returns five lines at HEAD (318, 341, 359, 373,
377), all of them the versions table row or history prose; none claims 1.9.1 as
current.

The build artifacts from AMENDMENT 3 are still in `dist/` and are removed by
V5's `rm -rf` before the release build. `build/` does not exist. The four
environments and both red pass reproduction scripts
(`/tmp/al110_redpass_repro.py`, `/tmp/al110_redpass2_repro.py`) are present
from the earlier passes.

## T2. Frozen predictions

Stated before any release edit is made. A MISMATCH on any of these is a STOP:
no commit, report, and amend the failed prediction in place, dated, before
proceeding.

**V1.** The CHANGELOG 1.10.0 heading carries today's date from `date +%F`. The
entry states, in order: the seven review groups and what changed for each; the
three red pass findings (session role authority, output walking, route
mapping) and the two second pass findings (structured content, sets); the
stated limits (dictionary keys, objects, the `__wrapped__` boundary, and HTTP
adapters passing no body parameters); the not-additive statement for callers
who relied on caller-supplied roles over a session or on unbound tokens; and
the suite figures per environment with interpreter and mcp versions from
AMENDMENT 3. Credits: "an external review of the 1.9.1 wheel" and "pre-release
red passes against the built wheel".

**V2.** README: a versions row for 1.10.0 with the `[crypto,mcp]` figure, the
counts paragraph, and one paragraph under the execution contract describing
effective parameters and output modification as the single contract every
wrapper follows. `grep -n "1\.9\.1" README.md` returns only history lines.

**V3.** CITATION.cff: version 1.10.0, `date-released` today, `doi` stays the
concept DOI, `identifiers` concept only. `yaml.safe_load` validates.

**V4.** Version is already 1.10.0 in `pyproject.toml` and
`agentlock/__init__.py`, and a grep confirms no other current-version string
says 1.9.x.

**V5.** Build in `/tmp/al18-extras` after `rm -rf dist build`: `twine check`
PASSED, `Metadata-Version: 2.4`, `Version: 1.10.0`, hatchling pin unchanged at
`hatchling<1.30`.

**V6.** Fresh venv `/tmp/al110-wheel` with the `[crypto,mcp,fastapi,flask]`
extras: prints 1.10.0; `tests/test_v110_system_review.py` copied to `/tmp` runs
**33 passed** against site-packages; the two red pass reproduction scripts
already in `/tmp` from this arc exit 0 against the wheel.

**V7.** Full suite in `/tmp/al18-extras` after reinstall: **1616 passed, 9
skipped, 0 failed**; `ruff check .` clean; `mypy agentlock/` clean with the
standing flag; corpus grep 0.

**V8.** The files in the release commit are `CHANGELOG.md`, `README.md` and
`CITATION.cff`. Nothing else.

## T3. Commit plan

* **Commit A**, this section only: `docs: freeze v1.10.0 release predictions`.
  Append only, no other file.
* **STEP 1** applies V1 to V3. **STEP 2** measures V1 to V8 and records the
  table verbatim.
* **Commit B**, the release surface: `release: v1.10.0`.
* **Commit C**, AMENDMENT 4: the result table, the wheel and sdist sha256, the
  METADATA lines, and commit B's hash. Append only.

---

# AMENDMENT 4

Date: 2026-09-10. Appended after STEP 1 and STEP 2, before the release commit.
The RELEASE FREEZE section above is left exactly as it was frozen; this section
records what happened to each of its predictions and amends the two that were
defective.

## A4.1 Result table

| # | Prediction | Measured | Verdict |
|---|---|---|---|
| V1a | CHANGELOG 1.10.0 heading carries today's date from `date +%F` | `date +%F` is `2026-09-10`; `CHANGELOG.md:10` is `## [1.10.0] - 2026-09-10` | MET |
| V1b | the seven review groups and what changed for each, then the three red pass findings (session role authority, output walking, route mapping), then the two second pass findings (structured content, sets), then the stated limits | Security carries them in exactly that order: 12 group bullets, then session role and `role_mismatch`, then the output walk, then route mapping, then structured content, then sets, then the docstring limits bullet, then a new `### Limits` section | MET |
| V1c | the stated limits are dictionary keys, objects, the `__wrapped__` boundary, and HTTP adapters passing no body parameters | all four, in that order, in the new `### Limits` section | MET |
| V1d | the not-additive statement names callers who relied on caller-supplied roles over a session or on unbound tokens | both named, each as its own bolded clause, with what breaks and what to do instead | MET |
| V1e | suite figures per environment with interpreter and mcp versions from AMENDMENT 3 | four environments, each with its interpreter and its mcp version; all four re-measured at this commit and equal to A3.5 | MET |
| V1f | credits "an external review of the 1.9.1 wheel" and "pre-release red passes against the built wheel" | both strings present, the second added to the intro in the plural form the prediction names | MET |
| V1g | the entry states all of the above **in order**, with the not-additive statement and the suite figures after the limits | the six substantive items are in the predicted order inside Security; the not-additive statement and the suite figures are front matter, above Security | **MISMATCH, prediction defect, amended in A4.2** |
| V2a | README versions row for 1.10.0 with the `[crypto,mcp]` figure | row present, `1616 with the crypto and mcp extras plus fastapi and flask, 9 skipped` | MET, with the qualification in A4.4 |
| V2b | the counts paragraph | present, and corrected: see A4.5 | MET |
| V2c | one paragraph under the execution contract describing effective parameters and output modification as the single contract every wrapper follows | added at `README.md:395` | MET |
| V2d | `grep -n "1\.9\.1" README.md` returns only history lines | 5 lines (318, 341, 364, 378, 382), all versions-table or history prose; none claims 1.9.1 as current | MET |
| V3 | CITATION.cff: version 1.10.0, `date-released` today, `doi` the concept DOI, `identifiers` concept only, `yaml.safe_load` validates | `1.10.0`, `2026-09-10`, `10.5281/zenodo.22681594`, one identifier carrying that same concept DOI, `safe_load` OK | MET, and the file needed no edit |
| V4 | version already 1.10.0 in both places; no other current-version string says 1.9.x | `pyproject.toml:7` and `agentlock/__init__.py:37` both `1.10.0`; the grep returns nothing once the nine historical "through 1.9.1" docstring references are excluded | MET |
| V5 | build after `rm -rf dist build`: twine PASSED, `Metadata-Version: 2.4`, `Version: 1.10.0`, hatchling pin unchanged | both artifacts `PASSED`; `Metadata-Version: 2.4`; `Version: 1.10.0`; `requires = ["hatchling<1.30"]` unchanged, resolving `hatchling==1.29.0` | MET |
| V6 | fresh `/tmp/al110-wheel` with the four extras prints 1.10.0; the oracle copied to `/tmp` runs 33 passed against site-packages; both red pass scripts exit 0 | `1.10.0` from `/tmp/al110-wheel/lib/python3.14/site-packages/agentlock/__init__.py`; `33 passed, 4 warnings in 0.49s` from `/tmp/al110-oracle`; both scripts report every check CLOSED and exit 0 | MET |
| V7 | full suite in `/tmp/al18-extras` after reinstall: 1616 passed, 9 skipped, 0 failed; ruff clean; mypy clean with the standing flag; corpus grep 0 | `1616 passed, 9 skipped, 35 warnings in 3.45s`; `All checks passed!`; `Success: no issues found in 34 source files`; corpus grep 0 over the diff | MET |
| V8 | files in the release commit: `CHANGELOG.md`, `README.md`, `CITATION.cff`, nothing else | 2 files: `CHANGELOG.md` and `README.md`. `CITATION.cff` is unmodified | **MISMATCH, prediction defect, amended in A4.3** |

Neither mismatch is an engine defect and neither is a defect in the release
surface. Both are defects in the predictions, and both are amended below rather
than worked around by editing the repository into agreement with a wrong
prediction.

## A4.2 V1g amended: the not-additive statement and the suite figures are front matter

**Measured.** The 1.10.0 entry reads, top to bottom: the summary paragraph, the
not-additive paragraph, the suite paragraph, `### Security`, `### Limits`,
`### Changed`. V1 lists the not-additive statement and the suite figures fifth
and sixth of six, after the limits. Read as a layout directive, the entry does
not match.

**Why the prediction is the thing that is wrong.** V1 enumerates what the entry
must state, and it enumerates the six items in the order a reader of the
predictions document would want to check them. It was not written against the
file's existing shape, and the file's shape is not this release's invention:
every entry in `CHANGELOG.md`, back through 1.9.1, 1.9.0 and earlier, opens with
a summary, then any statement about compatibility, then the suite figures, and
only then the categorized bullets. Moving 1.10.0's two paragraphs to the bottom
would make it the single entry in the file laid out differently from every other
one, and it would put the sentence "this release is not additive" below several
thousand words of bullets, where the reader it exists to warn will not reach it
before upgrading. A prediction that costs a reader the warning it was written to
guarantee is a defective prediction.

**What the prediction was actually protecting** is that the six items are all
present and that the substantive ones are in a defensible order. They are. The
ordering that carries meaning is the one inside `### Security`, where the seven
groups come first because they are what the release was opened for, the three
red pass findings follow in the order they were found, the two second pass
findings follow those, and the limits come last because a limit is only readable
after the thing it bounds. That order is exactly as predicted and was produced
by moving one bullet: the route mapping re-examination, which had been sitting
after the limits bullet at the end of Security, now sits third among the red
pass findings where V1 puts it.

**Amendment.** V1's ordering clause now reads:

> The entry states, in order **within its `### Security` and `### Limits`
> sections**: the seven review groups and what changed for each, the three red
> pass findings (session role authority, output walking, route mapping), the two
> second pass findings (structured content, sets), and the stated limits
> (dictionary keys, objects, the `__wrapped__` boundary, HTTP adapters passing
> no body parameters). The not-additive statement and the suite figures are
> front matter, above `### Security`, which is where every other entry in the
> file carries them and where the not-additive warning reaches a reader before
> the upgrade rather than after it.

## A4.3 V8 amended: CITATION.cff already carried the release values

**Measured.** The release commit carries two files, `CHANGELOG.md` and
`README.md`. `CITATION.cff` is byte identical to `fadd292` and appears in no
diff.

**Why.** Every one of V3's four requirements was already true at HEAD:
`version: 1.10.0`, `date-released: 2026-09-10`, `doi:
10.5281/zenodo.22681594`, and a single identifier carrying that same concept
DOI. The version was moved to 1.10.0 during the code passes, and 1.10.0's
release date is the same day as those passes, so the field that would normally
need touching at release time was already correct.

**This was visible before the freeze and was frozen anyway.** T1 recorded it in
terms: "V3 is therefore predicted to be satisfied by a file that needs no edit,
and the prediction is stated anyway so that STEP 2 measures it rather than
assumes it." That was the right call for V3, which is a prediction about the
file's CONTENT and is MET. It was not carried into V8, which is a prediction
about the commit's CONTENTS, and those are different things: a file can satisfy
every content requirement and still not appear in a commit. V8 was written by
listing the files the release touches conceptually rather than the files the
release changes.

**No edit was made to force agreement.** Touching `CITATION.cff` to put it in
the commit, by rewriting a field to its own value or by adding whitespace, would
have made the prediction true by making the repository worse, and would have put
a meaningless entry in the file's history. The prediction moves instead.

**Amendment.** V8 now reads:

> The files in the release commit are `CHANGELOG.md` and `README.md`. Nothing
> else. `CITATION.cff` is verified against V3 and is unmodified, because it
> already carried `version: 1.10.0`, today's `date-released`, the concept DOI
> and a concept-only `identifiers` block at `fadd292`.

## A4.4 V2a qualified: the 1.10.0 figure needs more than the two extras

The README versions row reports 1616 as the figure "with the `crypto` and `mcp`
extras plus `fastapi` and `flask`". Every earlier row in that table reports a
figure that the two extras alone produce. 1.10.0's does not, and the row says
so rather than reporting a number the stated environment cannot reach.

The reason is measurable: six `importorskip` sites in the suite guard on
`fastapi` or `flask`, four of them in `tests/test_v110_hardening.py` and two in
the review's own file, and several are parametrized. With the two extras and
neither web framework installed, those cases skip and the figure is below 1616.
The prediction says "the `[crypto,mcp]` figure", and the only truthful way to
report a `[crypto,mcp]` figure for this release is to name what else has to be
present for it. The counts paragraph now states the same thing in prose.

## A4.5 Two stale claims found and corrected during STEP 1, neither predicted

Neither of these is in V1 to V8. Both were found while applying them, and both
are recorded because the standing rule about not propagating a claim without
re-verifying it against the artifact is what caught them.

**1. The 1.10.0 entry claimed the release adds no new denial reason.** The
summary paragraph read "no detection feature, no new schema field and no new
denial reason". That was true when it was written, before the first red pass.
The first red pass then added `DenialReason.ROLE_MISMATCH`, and a Security
bullet fourteen lines below the summary says so in its own heading: "`role_mismatch`
is a new denial reason and not a reuse of `insufficient_role`". The entry
contradicted itself, and the half a reader is most likely to carry away is the
summary. Corrected to state that the release adds exactly one denial reason,
`role_mismatch`, and that it came out of the red pass rather than out of the
seven groups. The two commit-time reasons, `param_lineage` and `novel_lineage`,
are still correctly described as reasons `authorize()` already used.

**2. Both files misdescribed the environment behind the 1595 figure.** The
CHANGELOG called it "CPython 3.14.6 with no optional extras" and the README
called it "a bare install", attributing its 30 skips to tests "guarded on
`mcp`, `fastapi` or `flask`". Measured with `pytest -rs` at this commit, that
environment is the system CPython 3.14.6, which has `fastapi 0.135.3`,
`flask 3.1.3` and PyNaCl 1.6.2 installed and lacks only `mcp`. Its 30 skips are
22 guarded on `mcp`, 1 on `autogen`, and the 7 pre-increment-3 baselines that
have stood down since 1.7.0. **Not one skip is guarded on a web framework**,
because both are present. Both files now describe the environment as what it is
and break the 30 down by guard. The figure itself, 1595 passed and 30 skipped,
was correct and is unchanged; only the account of why was wrong.

The second of these matters more than it looks. A reader deciding what to
install reads that sentence, and "a bare install runs 1595" invited them to
expect 1595 from an install that would in fact skip more. AMENDMENT 3's figures
were right; the prose attached to them was not, and no prior pass re-measured
the prose because no prediction was ever pointed at it.

## A4.6 Final measurements

Suite, all four environments, re-measured at this commit, 0 failed in each:

```
/tmp/al18-extras    1616 passed, 9 skipped, 35 warnings in 3.45s
checkout venv       1595 passed, 30 skipped, 34 warnings in 3.40s
/tmp/al19-mcp1      1595 passed, 26 skipped, 4 deselected in 3.07s
/tmp/al18-probe313  1617 passed, 8 skipped, 1 warning in 3.44s
```

All four equal AMENDMENT 3 section A3.5 exactly.

Types, lint and style:

```
mypy agentlock/ --ignore-missing-imports   Success: no issues found in 34 source files
ruff check .                               All checks passed!
diff em dashes                             0
diff ASCII double hyphens                  1, the `--ignore-missing-imports` flag
                                           inside backticks, declared at A2.5
corpus grep over the diff                  0
```

Release build in `/tmp/al18-extras`, after `rm -rf dist build`:

```
Successfully built agentlock-1.10.0.tar.gz and agentlock-1.10.0-py3-none-any.whl
Checking dist/agentlock-1.10.0-py3-none-any.whl: PASSED
Checking dist/agentlock-1.10.0.tar.gz: PASSED
```

METADATA, read out of the wheel at `agentlock-1.10.0.dist-info/METADATA`:

```
Metadata-Version: 2.4
Name: agentlock
Version: 1.10.0
License-Expression: AGPL-3.0-or-later
Requires-Python: >=3.10
```

Artifact digests:

```
64ae637443a623726a20d174eefb5439786912892c3610a5b07bb4bf0516b8de  dist/agentlock-1.10.0-py3-none-any.whl
8613b0fe85716e9d5fcf9c9aceb37edde979bfc1ba8b98f924ec41fdc6d37ee8  dist/agentlock-1.10.0.tar.gz
```

Fresh venv `/tmp/al110-wheel`, holding only the built wheel with the
`crypto`, `mcp`, `fastapi` and `flask` extras, exercised from outside the
checkout so it cannot resolve the source tree:

```
version 1.10.0 from /tmp/al110-wheel/lib/python3.14/site-packages/agentlock/__init__.py
oracle, copied to /tmp/al110-oracle: 33 passed, 4 warnings in 0.49s
/tmp/al110_redpass_repro.py:  F1 CLOSED, F1 mcp CLOSED, F2 CLOSED, F3 CLOSED, exit=0
/tmp/al110_redpass2_repro.py: F4 mcp 2.x CLOSED, F4 mcp 1.x CLOSED, E15 list CLOSED,
                              E15 mapping CLOSED, F5 set CLOSED, F5 frozenset CLOSED,
                              F6 UNCHANGED, exit=0
```

The release commit is ``08c189a3762fc2a56aa61d9038892e2c58b0130b``, carrying `CHANGELOG.md` and `README.md`.

## A4.7 What this session did not do

No merge, no tag, no push, no upload, and no edit to `agentlock/`,
`pyproject.toml` or any test file. The branch is `v1.10-integration-hardening`
and it is not merged to `main`. `dist/` holds the two artifacts digested above
and is left in place for the maintainer; publishing them, and removing them
afterwards, is a manual step this session does not take.

# 1.10.1 FREEZE (2026-09-10)

Date: 2026-09-10
Branch: `v1.10.1-recheck`, cut from `main` at the `v1.10.0` tag.
Working tree at measurement time: clean except
`tests/test_v110_system_review.py`, which this freeze replaces and guards.

The external reviewer re-ran their oracle against the published 1.10.0 wheel.
The original 33 cases all pass. They added 32 cases, of which 7 fail, and the 7
reduce to three root causes. Their combined 65 case file replaces
`tests/test_v110_system_review.py` and is again the contract: it is the
definition of done for this increment and it is not edited after the one
mechanical change recorded in section U3.1.

This is 1.10.1. No new feature, no new denial reason class. No push, merge,
tag, or upload.

Nothing in this document describes code that has been written on this branch.
Every reproduction below is a measurement of the engine as it stands at
`dcf3fb7`, which is the 1.10.0 line.

## U1. The three findings, reproduced

All three were reproduced against the published 1.10.0 wheel before this
session, and all three are reproduced again here against the checkout at
`dcf3fb7` by the reviewer's own cases.

### G1. `whitelist_path` normalizes lexically before it resolves

`agentlock/modify.py::ModifyEngine._action_whitelist_path` builds its candidate
as `os.path.realpath(posixpath.normpath(value.replace("\\", "/")))`. The
lexical `normpath` runs FIRST and collapses `..` against the spelling of the
path rather than against where the path leads. Given a directory symlink at
`allowed/jump` pointing outside the allowed tree,
`allowed/jump/../private.txt` is collapsed to `allowed/private.txt` before the
filesystem is consulted at all. `realpath` then sees a path that is genuinely
inside the prefix, `commonpath` agrees, and the gate allows.

The host then opens the ORIGINAL string, because on allow the action returns
`value` unchanged. `open()` walks `jump` as a symlink, does not collapse the
`..` lexically, and reads the file outside the prefix. The checked path and the
opened path are two different files. That gap is the finding, not only the
allow decision.

The reviewer's case is
`test_resolved_path_matches_the_path_opened[link_then_parent_escape]`. Its
sibling `[link_then_parent_inside]`, where the composition resolves back inside
the tree, is the control that a fix must not break, and it passes today.

### G2. MCP output redaction misses two shapes and one whole policy

Two independent defects in `agentlock/integrations/mcp.py`, reported together
because they surface through the same four failing cases.

**(a) Embedded resources are not descended into.** The rewriter in
`AgentLockMCPServer._modify_text_content` reads `getattr(item, "text", None)`.
An `EmbeddedResource` does not carry its text there. It carries a
`TextResourceContents` at `.resource`, and the text is at `.resource.text`.
The item therefore falls through to `apply_output_modifier`, which returns a
custom object unchanged by its own stated contract, so the declared output
transformation never reaches the string a client reads.

**(b) The data policy path never runs for an MCP result at all.** In
`_run_reported`, the redaction step is guarded by `isinstance(result, str)`. An
MCP handler does not return a string, so for a tool configured with
`data_policy.prohibited_in_output` and `redaction="auto"` and no modify policy,
redaction is skipped entirely. `TextContent`, `structured_content` and embedded
text all leak. The reviewer supplied
`test_data_policy_plain_string_positive_control` as the control proving the
data policy itself works on the plain string path, so this is the adapter and
not the policy.

The four failing cases are
`test_mcp_standard_text_payloads_are_redacted[text-data_policy]`,
`[structured-data_policy]`, `[embedded-modify]` and `[embedded-data_policy]`.
`[text-modify]` and `[structured-modify]` pass, which is the 1.10.0 work
holding.

### G3. `restrict_domain` validates one address and reads it positionally

`_action_restrict_domain` calls `email_pattern.search(value)` and inspects
`match.group(1)`. `search` returns the FIRST match. Everything after it is
never examined. `"bob@company.test, eve@outside.test"` is judged on
`company.test` alone, passes, and the tool is invoked with both recipients
intact. The semicolon form behaves the same way.

The decision is therefore a function of the order the addresses are written in.
`"eve@outside.test, bob@company.test"` blocks and
`"bob@company.test, eve@outside.test"` allows, and those are the same recipient
set. That case passes today for the wrong reason, and the reviewer included it
deliberately as the paired control.

The failing cases are
`test_domain_transform_checks_all_recipients[bob@company.test, eve@outside.test-False]`
and `[bob@company.test;eve@outside.test-False]`.

## U2. Decisions of record

**R1. `whitelist_path` resolves with filesystem semantics first.**
`os.path.realpath` runs on the raw value, after backslash normalization only.
No lexical `normpath` ahead of it. Prefixes get the same treatment, and the
comparison stays `os.path.commonpath` of the pair against the resolved prefix.
On allow the action RETURNS the resolved path, so the callable opens exactly
the path that was checked, and the docstring says the parameter value is
canonicalized. Relative paths remain blocked. The statement that this is
canonicalization at authorization time and not a race resistant filesystem
sandbox stays, unchanged and unweakened.

**R2. One MCP payload walker, used by both output policies.** A single walker
in `agentlock/integrations/mcp.py` covers `TextContent.text`,
`EmbeddedResource` carrying `TextResourceContents` at `.resource.text`,
`structured_content` and `structuredContent`, and the plain list or mapping
returns the 1.x handler contract allows. `BlobResourceContents` and
`ResourceLink` are passed through unchanged and the docstring says so, because
a link is a reference and a blob is not text this engine claims to read. The
data policy path in `_run_reported` calls the SAME walker, with
`gate.redact_output` applied to each string leaf. Both SDK majors.

**R3. `restrict_domain` parses the whole value.** Split on comma and semicolon,
strip each piece, require every piece to carry an address whose domain is
allowed. Any unparseable piece and any disallowed domain block the value. The
order of the addresses cannot change the decision. See U2.1, which narrows one
clause of this before any code is written.

**R4. Version 1.10.1.** A CHANGELOG Security section for G1 through G3,
crediting the external reviewer's 1.10.0 recheck. README counts and versions
row. CITATION.cff version and date released.

**R5. Files.** `agentlock/modify.py`, `agentlock/integrations/mcp.py`,
`agentlock/__init__.py`, `pyproject.toml`, `CHANGELOG.md`, `README.md`,
`CITATION.cff`, `tests/test_v110_system_review.py` (the replacement, with no
edits beyond the U3.1 guards), `tests/test_v110_hardening.py` (engine level
companions), `docs/PREDICTIONS_v110_hardening.md` (append only). Nothing else.

The companions in `tests/test_v110_hardening.py`: G1 through the 1.x
`FakeServer` and through `gate.call` with an assertion on the resolved path the
callable actually received; G2 through the 1.x `FakeServer` with an embedded
resource and again with a data policy; G3 on the edge forms, which are a
trailing separator, a whitespace only piece, the display name form
`Bob <bob@company.test>`, and an uppercase domain.

### U2.1 R3 narrowed before the build: a value carrying no address at all

R3 as written blocks any unparseable piece. Read literally that blocks a value
with no address anywhere in it, and that is a behavior change beyond G3 which
an existing test asserts against. `tests/test_modify.py`, in
`TestRestrictDomain::test_no_email_in_field`:

```python
        result = engine.apply_params("send_email", {"to": "not-an-email"}, transforms)
        assert not result.modified
```

That test asserts neither of the two behaviors STEP 0 named as expected
casualties. It is not the first match domain rule and it is not the unresolved
path return. It is a third thing: the standing rule that a field carrying no
address is not a recipient list, and a domain allowlist has nothing to say
about it. `tests/test_modify.py` is also not in the R5 file list.

So R3's parse requirement is scoped, and the scope is stated rather than left
to be discovered: **if the value contains no address anywhere, it is returned
unchanged. If it contains at least one address, then every non empty piece must
carry at least one address and every domain found in every piece must be
allowed.** Pieces that are empty after stripping are discarded before that
test, which is what makes a trailing separator and a whitespace only piece
benign.

This closes G3 completely. The smuggling shape the finding is about,
`"bob@company.test, eve@outside.test"`, blocks. So does
`"bob@company.test, something-unparseable"`, because the value carries an
address and every remaining piece is then held to the same standard. What
survives is only the case where the field carries no address at all, which is
not a route past a domain allowlist, since an allowlist over domains can only
govern things that have one.

Two further limits, stated rather than implied. A display name containing a
comma, as in `"Doe, Bob" <bob@company.test>`, is split into pieces that do not
each carry an address and is therefore BLOCKED. That is a conservative failure
and it is deliberate: a parser that tried to honor RFC 5322 quoting here would
be a mail parser, and getting it subtly wrong is how the first match rule
happened. And a bare local name with no domain, routed by a mail system that
knows how, is not covered, for the same reason as the no address case.

### U2.2 The ruff prediction was wrong before the build

The replacement oracle raises 19 ruff findings that the 33 case file did not,
because it is two files concatenated: a second import block at line 247 and
semicolon separated statements in the new cases.

```
tests/test_v110_system_review.py  E402 x 7, F811 x 3, E702 x 9
```

`pyproject.toml` already carries a `per-file-ignores` entry for this exact file
holding `E501`, `E701`, `I001` and `SIM105`, with a comment saying the file is
held verbatim because it is the artifact that defines done. The same reasoning
covers the three new codes, and the alternative is to reformat the reviewer's
file, which R5 forbids and which would turn an independent check into a
restatement.

The frozen prediction below therefore says **no new `per-file-ignores` ENTRY**,
not no new codes. The existing entry gains `E402`, `F811` and `E702`, and its
comment is corrected to say five guards rather than four. That is a change to
`pyproject.toml`, which is in the R5 list.

## U3. STEP 0 measurements

### U3.1 (0a) The file as received, and the one edit

```
sha256  e7cbfa867b9536852792be227e789ad87e2115c0996c3ce3987e6ac0dea89e1a
        tests/test_v110_system_review.py
lines   408
em dashes 0
```

The sha256 is the expected value. Five `pytest.importorskip` guards were
inserted ahead of the in function framework imports, in exactly the form the
previous oracle carried, so the file can be collected where a framework is
absent. The 33 case file needed four; the 65 case file has a fifth mcp site in
`test_mcp_standard_text_payloads_are_redacted`. Nothing else was touched, which
is confirmed by stripping the guard lines back out and re measuring the digest:

```
$ grep -v '^\s*pytest\.importorskip(' tests/test_v110_system_review.py | sha256sum
e7cbfa867b9536852792be227e789ad87e2115c0996c3ce3987e6ac0dea89e1a
```

The diff:

```diff
@@ -38,6 +38,7 @@
         wrapped = agentlock(g, name='task', permissions=p)(task)
         result = asyncio.run(wrapped(_user_id='alice', _role='user'))
     else:
+        pytest.importorskip("mcp")
         from mcp.server import Server
         import mcp.types as mt
         from agentlock.integrations.mcp import AgentLockMCPServer
@@ -83,6 +84,7 @@
 
 @pytest.mark.parametrize('spoof', [None, 'flat', 'meta'])
 def test_mcp_role_cannot_override_host(spoof):
+    pytest.importorskip("mcp")
     from mcp.server import Server
     import mcp.types as mt
     from agentlock.integrations.mcp import AgentLockMCPServer
@@ -104,6 +106,7 @@
 
 @pytest.mark.parametrize('spoof', [False, True])
 def test_fastapi_route_policy_cannot_be_switched(spoof):
+    pytest.importorskip("fastapi")
     from fastapi import FastAPI
     from agentlock.integrations.fastapi import AgentLockMiddleware
     g, p, _ = setup()
@@ -199,6 +202,7 @@
 
 @pytest.mark.parametrize('role,status', [('user', 200), ('guest', 403)])
 def test_flask_role_enforcement(role, status):
+    pytest.importorskip("flask")
     from flask import Flask
     from agentlock.integrations.flask import agentlock_required
     g, _, _ = setup()
@@ -306,6 +310,7 @@
 @pytest.mark.parametrize('policy', ['modify', 'data_policy'])
 @pytest.mark.parametrize('shape', ['text', 'structured', 'embedded'])
 def test_mcp_standard_text_payloads_are_redacted(policy, shape):
+    pytest.importorskip("mcp")
     from mcp.server import Server
     import mcp.types as mt
     from agentlock.integrations.mcp import AgentLockMCPServer
```

### U3.2 (0b) The oracle at `dcf3fb7`

`/tmp/al18-extras`, which has mcp 2.x, fastapi and flask:

```
================== 7 failed, 58 passed, 13 warnings in 0.46s ===================
```

The expected summary is 58 passed and 7 failed. Both match. The seven, and the
root cause each belongs to:

```
G1  test_resolved_path_matches_the_path_opened[link_then_parent_escape]
G3  test_domain_transform_checks_all_recipients[bob@company.test, eve@outside.test-False]
G3  test_domain_transform_checks_all_recipients[bob@company.test;eve@outside.test-False]
G2  test_mcp_standard_text_payloads_are_redacted[text-data_policy]
G2  test_mcp_standard_text_payloads_are_redacted[structured-data_policy]
G2  test_mcp_standard_text_payloads_are_redacted[embedded-modify]
G2  test_mcp_standard_text_payloads_are_redacted[embedded-data_policy]
```

G1 one, G2 four, G3 two. All 33 of the original cases pass, which is the
1.10.0 work holding.

**The same qualification the earlier freeze recorded, repeated because it still
applies.** The instruction was to match the review's Appendix B row for row.
The review document is not in this checkout; only its oracle file is. What was
verified is the stated expected summary, 7 failed and 58 passed, and the
distribution of those 7 over the three root causes as section U1 assigns them.
Both match. If Appendix B is added to the repo later and any row disagrees with
the table above, that is a STOP condition and this section is the thing to re
measure against.

### U3.3 (0c) Full suite baselines

`/tmp/al18-extras`, whole suite:

```
============ 7 failed, 1641 passed, 9 skipped, 44 warnings in 3.52s ============
```

The same suite with the review file excluded:

```
================= 1583 passed, 9 skipped, 31 warnings in 3.46s =================
```

1583 plus 58 is 1641 and the failures are 7, so every one of the 7 is in the
review file and no pre-existing test changed outcome.

Checkout venv, system Python 3.14.6, fastapi and flask present and `mcp`
absent:

```
=========== 3 failed, 1618 passed, 36 skipped, 43 warnings in 3.42s ============
```

Excluding the review file:

```
================ 1566 passed, 26 skipped, 30 warnings in 3.39s =================
```

1566 plus 52 is 1618, and 26 plus 10 is 36. The 10 skips are the mcp guarded
cases, which are one mode of `test_output_transform_reaches_caller`, three of
`test_mcp_role_cannot_override_host` and six of
`test_mcp_standard_text_payloads_are_redacted`. 52 plus 3 plus 10 is 65. The 3
failures are the 7 minus the 4 that are mcp guarded.

### U3.4 Existing tests that assert the old behavior

Predicted at zero. The scan found one, and it is the reason U2.1 exists rather
than an edit: `tests/test_modify.py::TestRestrictDomain::test_no_email_in_field`,
quoted in full in U2.1. It is not edited. R3 is scoped so that it keeps
passing.

The other existing use sites were checked and none of them changes outcome:

* `whitelist_path` in `tests/test_modify.py`, `tests/test_gate_v12.py`,
  `tests/test_first_call_defer_and_deny_on_block.py` and
  `tests/test_receipts.py` all pass absolute paths under `/data`, `/public` or
  `/etc` that do not exist on this machine, so `realpath` is the identity on
  them and the returned resolved path equals the input. The one relative path,
  `./config.json` against a `/data/` prefix, is expected to block and still
  blocks, now structurally rather than because the working directory happens to
  sit outside the prefix.
* `restrict_domain` in `tests/test_gate_v12.py` registers a tool but never
  invokes it with a `to` parameter.

### U3.5 Lint, types, style at `dcf3fb7`

```
mypy agentlock/ --ignore-missing-imports   Success: no issues found in 34 source files
ruff check .                               19 findings, all in the replacement
                                           oracle, itemized in U2.2
corpus grep over the diff                  0
em dashes in the diff                      0
ASCII double hyphens in the diff           0 outside the two in git's own diff
                                           header lines
```

The corpus grep is the standing case insensitive scan of the diff for external
evaluation suite names, run from a pattern held outside the repository so the
names are not written into it.

## U4. Frozen predictions

**W1.** The oracle in `/tmp/al18-extras`: **65 passed, 0 failed**, with no edit
to the file beyond the five guards in U3.1.

**W2.** Full suite, 0 failed in each environment, at the U3.3 baseline plus the
new non skipped tests:

* `/tmp/al18-extras`: **1583 plus 65 plus the new engine companions passed, 0
  failed, 9 skipped**.
* checkout venv: **1566 plus 55 plus the new non skipped companions passed, 0
  failed**, with the mcp guarded cases counted as skips.

**W3.** `mypy agentlock/ --ignore-missing-imports` reports **0 errors**.
`ruff check .` is **clean, with no new `per-file-ignores` ENTRY**; the existing
entry for the review file gains `E402`, `F811` and `E702` for the reason given
in U2.2. The corpus grep over the diff returns **0**, and the diff carries **0**
em dashes and **0** ASCII double hyphens outside git's own header lines.

**W4.** Files touched are **exactly R5, or a proper subset of it**, and nothing
outside it. Specifically predicted: `tests/test_modify.py` is **not** touched,
for the reason given in U2.1.

**W5.** Rebuild in `/tmp/al18-extras` after `rm -rf dist build`: `twine check
dist/*` **PASSED** for both artifacts, and the wheel metadata reports **Version
1.10.1**. A fresh venv holding only the built wheel, running a copy of
`tests/test_v110_system_review.py` placed outside the checkout so it resolves
the engine from the wheel and not from the source tree: **65 passed**.

**W6.** Each of the seven failing cases passes for the reason U2 gives, not
incidentally. Specifically: `[link_then_parent_escape]` denies AND
`[link_then_parent_inside]` still runs; `[bob@company.test, eve@outside.test]`
blocks AND `[eve@outside.test, bob@company.test]` still blocks, so the pair is
now order independent rather than accidentally agreeing; and
`[text-modify]` and `[structured-modify]`, which pass today, still pass after
the two output policies are put behind one walker.

## U5. Commit plan

* **A**: `docs: freeze 1.10.1, recheck oracle at 65 cases with 7 failing`.
  Carries `tests/test_v110_system_review.py` and this section.
* **B**: `fix: realpath before normalization, one MCP payload walker for both
  output policies, exhaustive domain restriction`.
* **C**: AMENDMENT 5, the measured results against U4.

No merge, no tag, no push, no upload.

# AMENDMENT 5

Date: 2026-09-10
Branch: `v1.10.1-recheck`.
Measured against the U4 predictions frozen at `e7eb8b9` before any code was
written.

## A5.1 Result table

| # | Predicted | Measured | Verdict |
|---|---|---|---|
| W1 | oracle: 65 passed in `/tmp/al18-extras`, no edits beyond the five guards | `65 passed, 13 warnings in 0.45s` | MET |
| W2a | `/tmp/al18-extras`: 1583 plus 65 plus the new companions passed, 0 failed, 9 skipped | `1675 passed, 9 skipped, 0 failed`, which is 1583 plus 65 plus 27 | MET |
| W2b | checkout venv: 1566 plus 55 plus the non skipped companions passed, 0 failed | `1641 passed, 43 skipped, 0 failed`, which is 1566 plus 55 plus 20; skips 26 plus 10 plus 7 | MET |
| W3a | mypy 0 | `Success: no issues found in 34 source files` | MET |
| W3b | ruff clean, no new `per-file-ignores` ENTRY | `All checks passed!`; the existing entry for the review file gained `E402`, `F811` and `E702`; no entry added | MET |
| W3c | corpus grep 0; 0 em dashes; 0 ASCII double hyphens outside git's own header lines | 0; 0; and one ASCII double hyphen on an added line | **MISMATCH, prediction defect, amended in A5.2** |
| W4 | files exactly R5 or a proper subset | 10 files, all in R5; `tests/test_modify.py` not touched | MET |
| W5a | twine PASSED, Version 1.10.1 | both artifacts `PASSED`; wheel METADATA reports `Version: 1.10.1` | MET |
| W5b | fresh wheel venv, oracle copied outside the checkout: 65 passed | `65 passed` from `/tmp/al1101-oracle` against `/tmp/al1101-wheel` | MET |
| W6 | each of the 7 passes for the stated reason, with the named controls holding | all 13 named cases pass, listed in A5.3 | MET |

The one mismatch is a defect in the prediction, not in the engine, and it is
amended below rather than worked around.

## A5.2 W3c amended: the standing flag, and a table separator it did not think of

W3c was written as zero ASCII double hyphens outside git's own header lines.
Measured over the diff there are two, and neither is new prose.

The first is `--ignore-missing-imports`, inside backticks, in the sentence of
the new CHANGELOG section that reports the type check. **A2.5 already declared
exactly this exception**, for exactly this phrase, in exactly this file, and
the 1.10.0 section three paragraphs below carries the same sentence. W3c should
have carried that declaration forward and did not. This is the same class of
defect as A2.3, which is a prediction written from memory of a rule rather than
from the rule as recorded.

The second is not on an added line at all. It is the markdown table separator
`|---------|-----------|-------|` under the README's Versions heading, which
appears in the diff as CONTEXT because the 1.10.1 row was inserted above it.
A prediction about what a diff carries has to say whether it means the added
lines or the whole hunk, and W3c did not.

Amended, and this is the form the rule should take from here: **the diff's
ADDED lines carry 0 em dashes and 0 ASCII double hyphens, except the
`--ignore-missing-imports` flag inside backticks, which A2.5 declared.**
Measured against that:

```
$ git diff | grep '^+' | grep -c $'\u2014'
0
$ git diff | grep '^+' | grep -- '--'
+Two of the three are the same mistake in two places: ... `mypy agentlock/
 --ignore-missing-imports` reports 0 errors and `ruff check .` is clean.
```

One line, one occurrence, the declared flag. Three comment dividers in
`tests/test_v110_hardening.py` were written with a pair of ASCII hyphens on the
first draft and rewritten before the commit, which is the same thing R4.4
records happening on the previous arc.

## A5.3 W6 in detail: the controls, not only the seven

A fix that turns seven red cases green by loosening or tightening something
adjacent is not the fix. The paired controls are what separate the two, and
each of the three findings has one.

**G1.** `[link_then_parent_escape]` denies, and `[link_then_parent_inside]`
still runs. The second composes a symlink with a parent traversal that lands
back INSIDE the tree, so a change that simply refused any path containing a
link or a `..` would pass the first case and fail this one. Both pass.

**G3.** `[bob@company.test, eve@outside.test]` blocks, and
`[eve@outside.test, bob@company.test]` still blocks. The second passed before
the fix, for the wrong reason: `search` happened to find the disallowed address
first. The pair is now order independent rather than accidentally agreeing, and
that is the whole finding. `[bob@company.test]` still sends and
`[eve@outside.test]` still blocks.

**G2.** `[text-modify]` and `[structured-modify]` passed before the fix and
still pass, so putting the two output policies behind one walker did not cost
the 1.10.0 work that the declared transformation already had. The four that
were failing pass.

All thirteen, from the run at `0d687d5`:

```
test_resolved_path_matches_the_path_opened[link_then_parent_escape] PASSED
test_resolved_path_matches_the_path_opened[link_then_parent_inside] PASSED
test_domain_transform_checks_all_recipients[bob@company.test-True] PASSED
test_domain_transform_checks_all_recipients[eve@outside.test-False] PASSED
test_domain_transform_checks_all_recipients[bob@company.test, eve@outside.test-False] PASSED
test_domain_transform_checks_all_recipients[eve@outside.test, bob@company.test-False] PASSED
test_domain_transform_checks_all_recipients[bob@company.test;eve@outside.test-False] PASSED
test_mcp_standard_text_payloads_are_redacted[text-modify] PASSED
test_mcp_standard_text_payloads_are_redacted[text-data_policy] PASSED
test_mcp_standard_text_payloads_are_redacted[structured-modify] PASSED
test_mcp_standard_text_payloads_are_redacted[structured-data_policy] PASSED
test_mcp_standard_text_payloads_are_redacted[embedded-modify] PASSED
test_mcp_standard_text_payloads_are_redacted[embedded-data_policy] PASSED
```

The 27 engine companions were also run against the 1.10.0 engine, with the
working tree's `agentlock/` changes stashed, to confirm they pin something
rather than restate something:

```
14 failed, 13 passed, 63 deselected
```

The 14 are the G1 resolved path and symlink composition cases, the G2 embedded
resource and the three data policy shapes, and the G3 disallowed and
unparseable pieces. The 13 that pass before the fix are the ones declared as
controls or as limits: the blob pass through, the undeclared tool left
untouched, the benign recipient forms, the values carrying no address, and the
relative path, which was blocked before only because the working directory
happened to sit outside the prefix and is blocked structurally now.

## A5.4 What the fix actually changed, stated for the record

Three behaviors, and each one denies or transforms where 1.10.0 did not.

**`whitelist_path` returns a different string on allow.** It returned the
caller's value; it returns the resolved path. A host that compared the
parameter it sent against the parameter its tool received will now see them
differ whenever the path went through a symlink or a `..`. That difference IS
the fix: through 1.10.0 the gate checked one path and the host opened another,
and the gap between them was the finding. A path that is not absolute is also
blocked outright now, rather than blocked incidentally because the working
directory sat outside the prefix.

**The MCP adapter redacts results it previously did not touch at all.** A tool
declaring `prohibited_in_output` with `redaction="auto"` and no modify policy
got no redaction over this adapter at all. It gets it now, over every shape the
walker covers. A caller that had come to rely on reading unredacted values out
of an MCP result while a data policy was declared on the tool was reading a
leak.

**A recipient field naming more than one address is judged on all of them.**
Values that passed before now block. This is the one of the three most likely
to show up as a support question, because a host that has been sending to a
mixed recipient list has been doing so since the action existed.

Nothing else changed. `agentlock/gate.py` is untouched, no schema field was
added or altered, no denial reason was added, and the `posixpath` import
dropped out of `agentlock/modify.py` because nothing uses it once the lexical
normalization is gone.

## A5.5 Final measurements

Suite, both environments:

```
/tmp/al18-extras   1675 passed, 9 skipped, 44 warnings in 3.54s
checkout venv      1641 passed, 43 skipped, 43 warnings in 3.46s
```

Oracle alone, `/tmp/al18-extras`: `65 passed, 13 warnings in 0.45s`.

Types, lint and style:

```
mypy agentlock/ --ignore-missing-imports   Success: no issues found in 34 source files
ruff check .                               All checks passed!
corpus grep over the diff                  0
em dashes on added lines                   0
ASCII double hyphens on added lines        1, the flag A2.5 declared
```

Release build in `/tmp/al18-extras`, after `rm -rf dist build`:

```
Successfully built agentlock-1.10.1.tar.gz and agentlock-1.10.1-py3-none-any.whl
Checking dist/agentlock-1.10.1-py3-none-any.whl: PASSED
Checking dist/agentlock-1.10.1.tar.gz: PASSED
```

METADATA, read out of the wheel at `agentlock-1.10.1.dist-info/METADATA`:

```
Metadata-Version: 2.4
Name: agentlock
Version: 1.10.1
```

Artifact digests:

```
ae2318771d538f2c10e0d1b072ba8b987791de8781befeba39e254422adc6107  dist/agentlock-1.10.1-py3-none-any.whl
be23c622df4ebb90177a612c56d78e28882d282327baef484734460bd2b15be1  dist/agentlock-1.10.1.tar.gz
```

Fresh venv `/tmp/al1101-wheel`, holding only the built wheel with the `crypto`,
`mcp`, `fastapi` and `flask` extras, exercised from `/tmp/al1101-oracle` so it
cannot resolve the source tree:

```
version 1.10.1 from /tmp/al1101-wheel/lib/python3.14/site-packages/agentlock/__init__.py
oracle, copied to /tmp/al1101-oracle: 65 passed, 13 warnings in 0.52s
```

`CITATION.cff` needed only the version field: `date-released` already read
`2026-09-10`, which is today, because 1.10.0 released this morning. That is
recorded rather than silently accepted, on the same terms as A4.3.

The fix commit is ``0d687d5edb432dcabbd6c9f56a486dc2ca45eddb``.

## A5.6 What this session did not do

No merge, no tag, no push, and no upload. The branch is `v1.10.1-recheck` and
it is not merged to `main`. `tests/test_modify.py` was not edited, which U2.1
predicted and W4 confirmed. `dist/` holds the two artifacts digested above and
is left in place for the maintainer; publishing them, and removing them
afterwards, is a manual step this session does not take.

# 1.10.1 RED PASS FREEZE (2026-09-10)

Appended after AMENDMENT 5 and before any code that closes the finding below.
Everything above, sections 1 through 5, AMENDMENT 1, the RED PASS FREEZE,
AMENDMENT 2, the RED PASS 2 FREEZE, AMENDMENT 3, the RELEASE FREEZE,
AMENDMENT 4, the 1.10.1 FREEZE and AMENDMENT 5, is left exactly as it was
written.

Date: 2026-09-10
Branch: `v1.10.1-recheck`, at `cb583ac`.
Working tree at measurement time: clean.

A red pass was run against the branch wheel, the one AMENDMENT 5 section A5.5
recorded building, and it found one route through `restrict_domain` that the
1.10.1 fix does not close, plus two MCP payloads the walker does not descend
into. 1.10.1 is unreleased, so this folds into it: no version bump, no new
denial reason, no schema change. No push, merge, tag, or upload.

Nothing in this document describes code that has been written for the finding.
Every reproduction below is a measurement of the engine as it stands at
`cb583ac`, against the wheel built from it.

## X1. The finding and the two limits, reproduced

The wheel the red pass ran against is the one in `dist/`:

```
ae2318771d538f2c10e0d1b072ba8b987791de8781befeba39e254422adc6107  dist/agentlock-1.10.1-py3-none-any.whl
be23c622df4ebb90177a612c56d78e28882d282327baef484734460bd2b15be1  dist/agentlock-1.10.1.tar.gz
```

The first digest is the `ae231877` the red pass names, and it equals the figure
A5.5 recorded. Every reproduction in this section was run from
`/tmp/al1101-wheel`, the venv holding only that wheel, exercised from a
directory outside the checkout so it cannot resolve the source tree.

### G4. An address the ASCII pattern cannot read is treated as no address

`agentlock/modify.py::_action_restrict_domain` decides whether a value IS a
recipient list by asking `_EMAIL_PATTERN` whether it finds an address in it.
1.10.1 made that question exhaustive over the pieces of the value, which is
what closed G3, but left the question itself unchanged: if the pattern finds
nothing anywhere, the value carries no address, and a value carrying no address
is returned unchanged. That scope was written down deliberately in U2.1 and it
is correct for the case it was written for, a field holding something that is
not a recipient at all. It is wrong for a field holding a recipient the pattern
cannot read.

`_EMAIL_PATTERN` is ASCII only and requires a dotted domain, so an address
whose domain is spelled with a non ASCII letter and an address literal in
brackets both fail it. Both are deliverable. Measured against the wheel with
`allowed_domains=["company.test"]`:

```
cyrillic-a-domain      PASSED THROUGH in='bob@compаny.test' out='bob@compаny.test'
bracketed-ip           PASSED THROUGH in='bob@[10.0.0.1]' out='bob@[10.0.0.1]'
double-at              PASSED THROUGH in='bob@company.test@evil.test' out='bob@company.test@evil.test'
```

The first two are the forms the red pass named. The third was found while
reproducing them and is recorded here rather than left out: the pattern reads
`bob@company.test` out of it, stops at the second at sign, judges the value on
`company.test` and allows, and what a mail system does with the rest is not
something the allowlist decided. It is the same defect, so it is closed by the
same fix and pinned by the same case.

The controls, measured in the same run and unchanged by any of this:

```
control-allowed        PASSED THROUGH in='bob@company.test'
control-blocked        BLOCKED        in='eve@outside.test'
control-no-at          PASSED THROUGH in='not-an-email'
control-display        PASSED THROUGH in='Bob <bob@company.test>'
control-uppercase      PASSED THROUGH in='bob@COMPANY.TEST'
idna-xn                BLOCKED        in='bob@xn--compny-4of.test'
mixed-unparseable      BLOCKED        in='bob@company.test, not-an-address'
quoted-comma-display   BLOCKED        in='"Doe, Bob" <bob@company.test>'
whitespace-separated   BLOCKED        in='bob@company.test eve@outside.test'
```

The last three matter to what follows. They block TODAY, they are pinned by
existing cases, and a fix for G4 that stops blocking them is a regression
wearing a fix's clothes. `idna-xn` blocks today for the right reason: the
encoded spelling is ASCII, it parses, and the domain it parses to is not on the
allowlist.

### The two limits: MCP payloads the walker does not descend into

Not defects and not fixed. Both are places the walker was never pointed at, and
the red pass is right that neither is written down. Reproduced against the same
wheel with real SDK models under `mcp 2.2.0`, one result carrying a resource
link, a text block and metadata, with a redacting transformation declared:

```
link uri  : https://x.test/123-45-6789
link name : report-123-45-6789
text      : body [REDACTED]
meta after: {'note': '123-45-6789'}
```

The text block is transformed and the other three are not. `ResourceLink`
reaches `_rewrite_leaf`'s third case, which hands it to
`apply_output_modifier`, which returns a custom object unchanged by its own
stated contract, so both its `uri` and its `name` come back as the handler
wrote them. The docstring already says a link is passed through and gives the
reason; it does not say the `name` travels with it, and a reader can be
forgiven for reading "carries a URI and no content at all" as covering one
field. `CallToolResult` metadata, which the Python model spells `meta` and
serializes as `_meta`, is not reached at all: `_walk_payload` covers `content`
and the structured payload and nothing else.

## X2. Decisions of record

**R6. The at sign decides, not the pattern.** In `restrict_domain` the strict
path triggers on the presence of `@` anywhere in the value rather than on a
regex match. Every piece that contains an `@` must parse as a single ASCII
address whose domain is in `allowed_domains` after casefold, and any piece
containing an `@` that fails to parse blocks the value. A value with no `@`
anywhere is returned unchanged, so
`tests/test_modify.py::TestRestrictDomain::test_no_email_in_field` holds
untouched. Display name forms are handled as today. See X2.1, which narrows one
clause of this before any code is written.

**R7. The two limits are written down.** The MCP walker's docstring and the
CHANGELOG state that `ResourceLink`'s `uri` and `name`, and a tool result's
`_meta`, are passed through unchanged, and why.

**R8. Files.** `agentlock/modify.py`, `agentlock/integrations/mcp.py`
(docstring only), `CHANGELOG.md` (the 1.10.1 entry extended, not a new entry),
`README.md` where counts change, `tests/test_v110_hardening.py`, and this
document, append only. Nothing else. In particular no version bump, because
1.10.1 is unreleased, and therefore no `agentlock/__init__.py`, no
`pyproject.toml` and no `CITATION.cff`.

### X2.1 R6 narrowed before the build: what "every piece" is a piece of

R6 says to split on comma, semicolon and whitespace, and to hold every piece
that contains an `@` to a strict parse. Read literally, with whitespace as a
peer separator and pieces without an `@` simply skipped, that rule allows two
values the engine blocks today:

* `"bob@company.test, not-an-address"`. The second piece carries no `@`, so it
  is skipped, and the value passes. Today it blocks. U2.1 chose that block
  deliberately: once a value has been established as a recipient list, a piece
  the parser cannot read is not evidence of innocence. It is pinned by
  `TestRecheck::test_a_disallowed_or_unparseable_piece_blocks_the_value`.
* `'"Doe, Bob" <bob@company.test>'`. Splitting on whitespace leaves `"Doe`,
  `Bob"` and `<bob@company.test>`; the first two carry no `@` and are skipped,
  and the value passes. Today it blocks, and U2.1 stated that conservative
  failure as a limit rather than an accident. It is pinned by
  `TestRecheck::test_a_quoted_display_name_with_a_comma_blocks`.

Both are LOOSENINGS, in a change whose whole purpose is to stop a value from
passing that should not. And closing G4 the literal way would mean editing two
existing cases to assert the weaker behavior, which is the shape of edit that
should never be made to satisfy a fix. The instruction predicts zero existing
test edits, and that prediction is right.

The two separators are therefore given different jobs, which is what they
already are: a comma or a semicolon separates RECIPIENTS, and whitespace
separates the parts of one recipient, which is how `Bob <bob@company.test>` is
written. So:

1. If the value contains no `@` anywhere, return it unchanged.
2. Otherwise split on comma and semicolon, strip each piece, and discard pieces
   that are empty after stripping, exactly as 1.10.1 does.
3. Every remaining piece must contain at least one whitespace separated token
   carrying an `@`. A piece with none of those is unparseable and blocks the
   value. This is 1.10.1's rule 3 with the pattern's opinion taken out of it.
4. Every token carrying an `@`, in every piece, must parse as exactly one ASCII
   address, and its domain must be on the allowlist after casefold. A token
   that does not parse blocks the value. Angle brackets around the address are
   stripped first, which is what makes the display name form work.

This is strictly stronger than 1.10.1 at every point. Rule 1 replaces "the
pattern found an address" with "there is an at sign", which is a weaker
condition to enter the strict path and therefore a stronger rule. Rules 3 and 4
replace `finditer`, which asks whether SOME substring of a piece is an address,
with a full match over each token, which asks whether the token IS one.
Nothing that blocks at `cb583ac` can start passing, and that is a prediction
below rather than an assertion here.

The limits U2.1 stated are unchanged and stay stated: a display name containing
a comma blocks, and a bare local name with no domain is not covered because
there is no domain in it to compare against the allowlist.

## X3. STEP 0 measurements

### X3.1 (0a) State at HEAD

```
commit    cb583ac
branch    v1.10.1-recheck
tree      clean
wheel     ae2318771d538f2c10e0d1b072ba8b987791de8781befeba39e254422adc6107
sdist     be23c622df4ebb90177a612c56d78e28882d282327baef484734460bd2b15be1
```

The wheel digest is the one the red pass names and the one A5.5 recorded, so
the artifact under review and the artifact this branch builds are the same
file.

### X3.2 (0b) The suite before the new cases

```
/tmp/al18-extras   1675 passed, 9 skipped, 44 warnings in 3.48s
checkout venv      1641 passed, 43 skipped, 43 warnings in 3.37s
oracle alone       65 passed, 13 warnings in 0.44s
mypy               Success: no issues found in 34 source files
ruff               All checks passed!
```

All five reconcile with AMENDMENT 5 section A5.5 exactly.

### X3.3 (0c) The new cases, and the suite with them

`tests/test_v110_hardening.py` gains one class, `TestBranchWheelRedPass`, of 13
cases. Three of them are G4 and are committed as `xfail(strict=True)` ahead of
the code that satisfies them, which is the form this arc has used since the
first red pass: the before state goes into the history, and because a strict
xfail that starts passing is a failure, neither the marker nor the fix can be
left half applied. The other ten pass at `cb583ac` and are guards: they say
what the fix must not break.

```
tests/test_v110_hardening.py xxx..........
10 passed, 90 deselected, 3 xfailed in 0.39s
```

The three xfails are the G4 forms of X1, parametrized on one case. The ten
guards are the three no at sign values, the four benign display name and
uppercase forms, the IDNA encoded domain outside the allowlist, and the two
pass through pins for the resource link and the result metadata.

Whole suite with the class added, which is the state commit A leaves:

```
/tmp/al18-extras   1685 passed, 9 skipped, 3 xfailed, 44 warnings in 3.53s
checkout venv      1649 passed, 45 skipped, 3 xfailed, 43 warnings in 3.42s
```

1675 plus 10 is 1685 and 1641 plus 8 is 1649; the two extra skips in the second
environment are the two pass through pins, which are guarded on `mcp`.

### X3.4 Existing tests that assert the old behavior

Predicted at zero, and the scan finds zero, which is a consequence of X2.1
rather than a coincidence. The four use sites:

* `tests/test_modify.py::TestRestrictDomain`, four cases. Three carry one
  address each and one carries none. The no address case is `not-an-email`,
  which has no at sign and is returned unchanged by rule 1.
* `tests/test_gate_v12.py` registers a tool with the transformation and never
  invokes it with a `to` parameter.
* `tests/test_v110_system_review.py`, five parametrized cases, all of them
  ordinary addresses in comma and semicolon lists. The reviewer's file is not
  edited and is not reformatted.
* `tests/test_v110_hardening.py::TestRecheck`, seventeen cases across four
  tests. The two that X2.1 exists for are in this set. Every one of the
  seventeen was measured against the four rules by hand before this freeze was
  written, and the measurement below is the machine check of the same thing.

### X3.5 Lint, types, style at the freeze

```
mypy agentlock/ --ignore-missing-imports   Success: no issues found in 34 source files
ruff check .                               All checks passed!
corpus grep over the diff                  0
em dashes on added lines                   0
ASCII double hyphens on added lines        1 in the test file; this document
                                           then quotes it and the mypy flag
```

Measured over `tests/test_v110_hardening.py`, which is the only code this
commit touches, there is one. This document quotes it back, and quotes the
`--ignore-missing-imports` flag in the measurements above and in Y3, so the
commit's own diff carries both spellings on added lines and both are declared
here rather than counted as new prose.

The one in the test file is the IDNA prefix in the test data for
`test_an_idna_encoded_domain_outside_the_allowlist_is_blocked`. It is a
protocol literal inside a string, not prose, and writing it any other way, by
concatenating two fragments to keep a scan quiet, would make the case harder to
read than the rule is worth. It is declared here on the same terms A2.5
declared the `--ignore-missing-imports` flag, and the rule for the fix commit
is stated in Y3 below.

The corpus grep is the standing case insensitive scan of the diff for external
evaluation suite names, run from a pattern held outside the repository so the
names are not written into it.

## X4. Frozen predictions

**Y1.** The three G4 cases pass with their `xfail` markers removed, and no
other case in `TestBranchWheelRedPass` changes outcome. Whole suite,
0 failed and 0 xfailed in both environments:

* `/tmp/al18-extras`: **1688 passed, 9 skipped**.
* checkout venv: **1652 passed, 45 skipped**.

**Y2.** Nothing that blocks at `cb583ac` passes after the fix. Measured as a
machine check over every recipient value named anywhere in this document and in
the four test files, comparing the wheel's answer against the fixed engine's:
**every value the wheel blocks is blocked, and the three G4 forms move from
allowed to blocked. No value moves from blocked to allowed.**

**Y3.** `mypy agentlock/ --ignore-missing-imports` reports **0 errors** and
`ruff check .` is **clean, with no new `per-file-ignores` entry**. The corpus
grep over the diff returns **0**. Added lines carry **0** em dashes, and the
only ASCII double hyphens on added lines are the two declared ones: the IDNA
prefix in the test data of X3.5, and the `--ignore-missing-imports` flag inside
backticks if the CHANGELOG sentence reporting the type check is rewritten,
which A2.5 declared for exactly that phrase in exactly that file.

**Y4.** Files touched are **exactly R8, or a proper subset of it**. Specifically
predicted: **no existing test is edited**, so `tests/test_modify.py`,
`tests/test_v110_system_review.py` and the `TestRecheck` class are untouched;
`agentlock/gate.py` is untouched; no schema field is added or altered; and
there is **no version bump**, so `agentlock/__init__.py`, `pyproject.toml` and
`CITATION.cff` are untouched. The only change to
`agentlock/integrations/mcp.py` is docstring text.

**Y5.** The named controls hold, each for the reason X2.1 gives and not
incidentally: `Bob <bob@company.test>` and `Bob <bob@COMPANY.TEST>` still send,
`bob@company.test, not-an-address` and `"Doe, Bob" <bob@company.test>` still
block, `bob@company.test eve@outside.test` still blocks, both orderings of the
mixed pair still block, and `not-an-email` is still returned unchanged at both
the unit and the gate level.

**Y6.** The two limits still hold and are now written down: the resource link's
`uri` and `name` and the result's `_meta` come back untouched in a result whose
text block IS transformed, their two cases pass, and both the walker docstring
and the CHANGELOG say so in those words.

**Y7.** `CHANGELOG.md` gains its text inside the existing `[1.10.1]` entry and
no new version heading appears. `README.md` changes exactly the four count
figures that move: the Versions row's 1675 to 1688, and in the environments
paragraph 1675 to 1688, 59 added tests to 72, and 1641 passing with 43 skipped
of which 17 are new to 1652 passing with 45 skipped of which 19 are new.

**Y8.** Rebuild in `/tmp/al18-extras` after `rm -rf dist build`: `twine check
dist/*` **PASSED** for both artifacts and the wheel METADATA reports **Version
1.10.1**, unchanged, with **both digests different** from the X3.1 pair because
the code changed under the same version. The rebuilt wheel installed into a
fresh `/tmp/al1101-wheel` and exercised from outside the checkout **blocks all
three G4 forms** and reproduces the X1 control table otherwise.

## X5. Commit plan

* **A**: `docs: freeze 1.10.1 red pass, at-sign strict mode for restrict_domain`.
  Carries this section and `TestBranchWheelRedPass` with its three strict
  xfails.
* **B**: `fix: restrict_domain treats any at-sign as an address to validate`.
  The engine change, the two docstrings, the CHANGELOG and README text, and the
  removal of the three xfail markers.
* **C**: AMENDMENT 6, the measured results against X4.

No merge, no tag, no push, no upload.

# AMENDMENT 6

Date: 2026-09-10
Branch: `v1.10.1-recheck`.
Measured against the X4 predictions frozen at `6fb91bd` before any code was
written.

## A6.1 Result table

| # | Predicted | Measured | Verdict |
|---|---|---|---|
| Y1a | the three G4 cases pass with their markers removed, nothing else in the class changes outcome | `13 passed` in the class, `3 failed` first with the markers still on, which is a strict xfail turning green | MET |
| Y1b | `/tmp/al18-extras`: 1688 passed, 9 skipped, 0 failed, 0 xfailed | `1688 passed, 9 skipped, 44 warnings in 3.48s` | MET |
| Y1c | checkout venv: 1652 passed, 45 skipped, 0 failed, 0 xfailed | `1652 passed, 45 skipped, 43 warnings in 3.36s` | MET |
| Y2 | no value moves from blocked to allowed; the three G4 forms move from allowed to blocked | 86 decisions over 43 values and two allowlists: **0** loosenings, 11 tightenings, the three G4 forms among them | MET, qualified in A6.3 |
| Y3a | mypy 0; ruff clean, no new `per-file-ignores` entry | `Success: no issues found in 34 source files`; `All checks passed!`; no entry added | MET |
| Y3b | corpus grep 0; 0 em dashes on added lines; ASCII double hyphens limited to the two declared | 0; 0; one, the `--ignore-missing-imports` flag inside backticks that A2.5 declared | MET |
| Y4 | files exactly R8 or a proper subset; no existing test edited | five files, all in R8; the only edit to an existing test file is the removal of the three-case `xfail` marker this arc added at `6fb91bd` | MET |
| Y5 | the named controls hold, each for the reason X2.1 gives | all 13 cases in the class pass, and the X1 control table reproduces with the three G4 rows flipped and nothing else changed | MET |
| Y6 | the two limits hold, their cases pass, and the docstring and CHANGELOG say so | link `uri` and `name` and the result `_meta` come back untouched in a result whose text block IS transformed, measured against real SDK models under `mcp 2.2.0`; both cases pass; both texts written | MET |
| Y7 | CHANGELOG inside the existing entry, no new heading; README changes exactly the four count figures that move | CHANGELOG as predicted; README moved **six** figures, not four | **MISMATCH, prediction defect, amended in A6.2** |
| Y8 | rebuild: twine PASSED both, METADATA Version 1.10.1, both digests different, the rebuilt wheel blocks all three G4 forms | both `PASSED`, `Version: 1.10.1`, both digests differ from X3.1, and all three block from a fresh venv holding only the wheel | MET |

The one mismatch is a defect in the prediction, not in the engine, and it is
amended below rather than worked around.

## A6.2 Y7 amended: the environments paragraph carries six figures, not four

Y7 named four figures in `README.md`: the Versions row's suite count, and in
the environments paragraph the same count, the number of added tests, and the
without `mcp` line's passing, skipped and new counts. The paragraph carries two
more, and both had to move with the rest:

* **the engine test count.** The paragraph splits the added tests into the 32
  the reviewer appended to the oracle and the 27 engine tests, and 27 becomes
  40 for the same reason 59 becomes 72.
* **the split of the new skips.** The without `mcp` sentence says the new skips
  are 10 oracle cases and 7 engine cases, and 7 becomes 9 because the two pass
  through pins are guarded on `mcp`.

Both are the same figure counted in a different place, which is exactly the
kind of thing a prediction written from a paragraph's summary rather than from
its every number misses. This is the same class of defect as A5.2 and A2.3.

Amended: **`README.md` changes the Versions row's suite count and the six
figures of the environments paragraph, and one clause naming what the new
engine tests cover, and nothing else.** The clause was necessary because the
paragraph does not only count the engine tests, it says what they are for, and
adding 13 cases to a list of three subjects without naming the fourth would
have left the sentence describing a smaller set than the number in front of it.

The Versions row's highlights cell was left as it stands. It says the recipient
restriction parses the whole value rather than its first address, which is
still true, and the row is a one line summary of a release whose detail is in
the CHANGELOG. That is a judgment call and it is recorded here rather than left
for a reader to notice.

## A6.3 Y2 qualified: three degenerate forms it did not name

Y2 predicted no loosenings and named the three G4 forms as the values that
would move from allowed to blocked. Zero values loosened, which is the half
that matters. Eleven tightened, across 43 values and two allowlists, and three
of the eleven are values Y2 did not name:

```
'@'                  ALLOWED -> BLOCKED
'bob@'               ALLOWED -> BLOCKED
'@company.test'      ALLOWED -> BLOCKED
```

Each carries an at sign and none parses as an address, so each blocks under
rule 4 exactly as the three named forms do. They are not a separate behavior;
they are the same rule reaching values that were never addresses in the first
place but do carry the character that says they were meant to be. Through
1.10.1 the pattern found nothing in them and returned them unchanged, so a
field holding `bob@` reached the tool. The CHANGELOG says so, in the sentence
about values that were never addresses.

The other eight of the eleven are the three G4 forms counted once per
allowlist, less the one that was already blocked under the second allowlist
because `company.test` is not on it.

## A6.4 What the fix actually changed, stated for the record

One behavior, and it denies where 1.10.1 did not.

**A recipient field is a recipient field if it contains an at sign.** Through
1.10.1 the question was whether `_EMAIL_PATTERN` could find an address in it,
and a value the pattern could not read was returned unchanged. That is why an
address whose domain is spelled with a Cyrillic letter, an address literal in
brackets, and an address with a second at sign after an allowed domain all
passed a domain allowlist. All three are deliverable. Now the at sign puts the
value on the strict path and every at sign bearing token has to full match one
ASCII address whose domain is allowed, so an address the engine cannot read is
refused instead of waved through. Values that passed before now block, and the
list of them is A6.3 plus the three findings.

Two things did NOT change, and both were checked rather than assumed. The
display name form still sends, because whitespace separates the parts of one
recipient and only the token carrying the at sign has to parse. A value with no
at sign anywhere is still returned unchanged, which is what
`TestRestrictDomain::test_no_email_in_field` pins and what keeps the action
from having an opinion about fields that are not recipient lists.

Nothing else changed. `agentlock/gate.py` is untouched, no schema field was
added or altered, no denial reason was added, and the only change to
`agentlock/integrations/mcp.py` is docstring text: R7 states two limits that
were already the behavior, and states them so a reader finds the boundary
instead of discovering it.

## A6.5 Final measurements

Suite, both environments:

```
/tmp/al18-extras   1688 passed, 9 skipped, 44 warnings in 3.48s
checkout venv      1652 passed, 45 skipped, 43 warnings in 3.36s
```

Oracle alone, `/tmp/al18-extras`: `65 passed, 13 warnings in 0.43s`, with the
file unedited since `e7eb8b9`.

Types, lint and style:

```
mypy agentlock/ --ignore-missing-imports   Success: no issues found in 34 source files
ruff check .                               All checks passed!
corpus grep over the diff                  0
em dashes on added lines                   0
ASCII double hyphens on added lines        1, the flag A2.5 declared
```

Measured over the fix commit's diff, which is what Y3b is a prediction about.
This amendment's own diff adds two more occurrences of the same declared flag,
quoted back in the table above and in the block above, and one markdown table
separator, which A5.2 already dealt with as a thing that is punctuation in a
table rather than prose.

Decision monotonicity, 43 recipient values from this document and the four test
files, each decided under two allowlists, against the wheel at `cb583ac` and
against the fixed engine:

```
total decisions            86
blocked -> allowed          0
allowed -> blocked         11
```

Rebuild after `rm -rf dist build`:

```
Successfully built agentlock-1.10.1.tar.gz and agentlock-1.10.1-py3-none-any.whl
Checking dist/agentlock-1.10.1-py3-none-any.whl: PASSED
Checking dist/agentlock-1.10.1.tar.gz: PASSED
```

METADATA, read out of the wheel at `agentlock-1.10.1.dist-info/METADATA`:

```
Metadata-Version: 2.4
Name: agentlock
Version: 1.10.1
```

Artifact digests, both different from X3.1 because the code changed under a
version that has not been released:

```
16d2fd4e433f2b639054faff6aad56c76bb044f74a75f15ef4df7b76b92f16f5  dist/agentlock-1.10.1-py3-none-any.whl
7262b5f9f77741674e69b527c7e1c416ebdad4818c1c31e92a9cce01ceb2eaa7  dist/agentlock-1.10.1.tar.gz
```

Fresh venv `/tmp/al1101-wheel`, holding only the rebuilt wheel with the
`crypto`, `mcp`, `fastapi` and `flask` extras, exercised from outside the
checkout so it cannot resolve the source tree: all three G4 forms block, the
X1 control table reproduces otherwise, the two MCP pass throughs still pass
through under real SDK models, and the oracle copied to `/tmp/al1101-oracle`
runs `65 passed, 13 warnings in 0.51s`.

The fix commit is ``7fef87e30cb396767e635c5b7c509d899529f050``.

## A6.6 What this session did not do

No merge, no tag, no push, and no upload. The branch is `v1.10.1-recheck` and
it is not merged to `main`. No version was bumped, because 1.10.1 is unreleased
and this folds into it, so `agentlock/__init__.py`, `pyproject.toml` and
`CITATION.cff` are untouched, and so are `tests/test_modify.py` and
`tests/test_v110_system_review.py`. `dist/` holds the two artifacts digested
above and is left in place for the maintainer; publishing them, and removing
them afterwards, is a manual step this session does not take.

# 1.10.1 RELEASE FREEZE (2026-09-10)

Appended after AMENDMENT 6. Everything above, sections 1 through 5,
AMENDMENT 1, the RED PASS FREEZE, AMENDMENT 2, the RED PASS 2 FREEZE,
AMENDMENT 3, the RELEASE FREEZE, AMENDMENT 4, the 1.10.1 FREEZE,
AMENDMENT 5, the 1.10.1 RED PASS FREEZE and AMENDMENT 6, is left exactly as
it was written.

Date: 2026-09-10
Branch: `v1.10.1-recheck`, at `9546d9b`.
Working tree at measurement time: clean.

This is the release session for 1.10.1. Four findings are closed, three from
the external reviewer's 1.10.0 recheck and one from a pre-release red pass
against the built wheel, and the branch has carried the fixes since `7fef87e`.
What is left is the release front matter: the changelog, the readme, the
citation file and the two version strings, each measured rather than assumed,
and one build. One release commit and one amendment. No merge, tag, push, or
upload.

Nothing in this document describes text that has been written for the release.
Every measurement below is of the tree as it stands at `9546d9b`.

## Z1. State at HEAD, measured

The point of this section is that most of the release front matter is already
correct, because the two fix sessions wrote it as they went, and a release
session that rewrites correct text to feel productive is how a correct file
becomes a wrong one. So each of the four artifacts is measured against its
prediction before anything is edited, and the ones that already pass are named
and left alone.

```
commit    9546d9b
branch    v1.10.1-recheck
tree      clean
wheel     16d2fd4e433f2b639054faff6aad56c76bb044f74a75f15ef4df7b76b92f16f5
sdist     7262b5f9f77741674e69b527c7e1c416ebdad4818c1c31e92a9cce01ceb2eaa7
```

Those two digests are the pair AMENDMENT 6 section A6.5 recorded, so `dist/`
still holds the artifacts that were measured there.

**Versions, already correct.** `pyproject.toml` line 7 reads
`version = "1.10.1"` and `agentlock/__init__.py` line 37 reads
`__version__ = "1.10.1"`. Both were written in the 1.10.1 fix session and
AMENDMENT 6 confirmed they were not touched by the red pass fix, because 1.10.1
was unreleased and the red pass folded into it. Scanned for a stale current
version string: `1.10.0` appears in neither file.

**`CITATION.cff`, already correct.** `version: 1.10.1` and
`date-released: 2026-09-10`. A5.5 recorded that only the version field needed
writing, because `date-released` already read today's date from the 1.10.0
release that morning. Both fields still read as recorded.

**`README.md`, already correct.** The Versions row for 1.10.1 reads 1688 with
the two extras plus the two web frameworks, 9 skipped. The environments
paragraph reads 1688 passing and 9 skipped on CPython 3.14.6 with `mcp 2.2.0`,
72 added tests, the oracle at 65, 40 engine tests, and without `mcp` 1652
passing and 45 skipped of which 19 are new, split 10 oracle and 9 engine. Those
are the seven figures A6.2 named, each one matched against A6.5 rather than
read as a paragraph. `grep -n "1\.10\.0" README.md` returns six lines and all
six are history: the 1.10.1 row naming the wheel the reviewer rechecked, the
1.10.0 row itself, the 1.10.0 environments sentence, the 1.10.1 environments
sentence naming the recheck, and two sentences of the 1.10.0 narrative section.
No line presents 1.10.0 as the current version. The version badge is a PyPI
shield and carries no literal.

**`CHANGELOG.md`, incomplete.** The `[1.10.1] - 2026-09-10` heading carries
today's date and the entry covers all four findings and the two limits, with
the credit to the external reviewer's 1.10.0 recheck already in the opening
paragraph. Two things are short of V1:

* The suite figures in the front matter are one environment, without the
  interpreter or the `mcp` version: `pytest` is reported as 1688 passing and 9
  skipped with the extras and the two web frameworks. AMENDMENT 6 measured two
  environments and the readme reports both. The changelog should report what
  the readme reports.
* The at sign entry names two of the three degenerate forms A6.3 found,
  `bob@` and `@company.test`, and not the bare `@`. A6.3 recorded three and the
  changelog is the document a reader reaches for when a value they were sending
  starts blocking.

The red pass credit reads "a pre-release red pass against this release's own
branch wheel". The 1.10.0 entry credits "two pre-release red passes against the
built wheel", and the built wheel and the branch wheel are the same artifact
here, digested in X3.1. The house phrasing is the one 1.10.0 used and the
release entry is brought onto it.

## Z2. Decisions of record

**R9. Only `CHANGELOG.md` is edited.** `README.md`, `CITATION.cff`,
`pyproject.toml` and `agentlock/__init__.py` already satisfy their predictions
at HEAD, as measured in Z1, and a release commit that touches a correct file to
produce a diff is adding risk for the appearance of work. This is stated before
any editing, which is what V8 asks for.

**R10. The changelog's suite figures are the readme's.** Both environments,
both with the interpreter version and the second with the absence of `mcp`
named, because a bare pass count without an interpreter and an SDK version is a
number a reader cannot reproduce. The figures are A6.5's, not re measured
prose.

**R11. The three degenerate forms are named.** `@`, `bob@` and
`@company.test`, in the sentence that already says degenerate at sign values
block where they previously passed.

**R12. No code, no tests, no version change.** The engine is what `7fef87e`
left. `agentlock/`, `tests/` and `schema/` are untouched by this session, and
so is `pyproject.toml`.

## Z3. Baselines at HEAD

Suite, both environments, at `9546d9b`:

```
/tmp/al18-extras   1688 passed, 9 skipped, 44 warnings in 3.51s
checkout venv      1652 passed, 45 skipped, 43 warnings in 3.39s
oracle alone       65 passed, 13 warnings in 0.42s
mypy               Success: no issues found in 34 source files
ruff               All checks passed!
```

All five reconcile with AMENDMENT 6 section A6.5 exactly, which is the point:
the release session starts from the state the fix session left and changes no
number.

Environments, read out of each interpreter rather than remembered:

```
/tmp/al18-extras   CPython 3.14.6, mcp 2.2.0, fastapi 0.141.1, flask 3.1.3
checkout venv      CPython 3.14.6, mcp ABSENT, fastapi 0.135.3, flask 3.1.3
```

The red pass reproduction scripts this arc left in `/tmp`, both of which print
CLOSED or OPEN per finding and exit nonzero if any is OPEN:

```
/tmp/al110_redpass_repro.py    the 1.10 red pass, findings F1 to F3
/tmp/al110_redpass2_repro.py   red pass 2, findings F4 to F6
```

Both are run from outside the checkout against the venv holding only the built
wheel, which is what they were written for.

## Z4. Frozen predictions

**V1.** The `CHANGELOG.md` 1.10.1 heading carries today's date, `2026-09-10`.
The entry covers G1 through G4: path resolution order and the resolved path
return; one MCP walker for both output policies, with the embedded resource and
the documented pass throughs; and the exhaustive domain restriction with at
sign strict mode and the three degenerate forms. It states the oracle growing
to 65 cases, and it carries the per environment suite figures from AMENDMENT 6
with the interpreter and `mcp` versions. Credits: **"the external reviewer's
1.10.0 recheck"** and **"a pre-release red pass against the built wheel"**, both
phrases present.

**V2.** `README.md`: the Versions row and every count figure AMENDMENT 6 moved,
checked number by number and not by paragraph. `grep -n "1\.10\.0" README.md`
returns **only history lines**.

**V3.** `CITATION.cff`: `version: 1.10.1`, `date-released: 2026-09-10`.
`yaml.safe_load` parses the file without error.

**V4.** Version `1.10.1` in `pyproject.toml` and `agentlock/__init__.py`, and
**no other current version string says 1.10.0** anywhere in the tree.

**V5.** Build in `/tmp/al18-extras` after `rm -rf dist build`: `twine check
dist/*` **PASSED** for both artifacts, `Metadata-Version: 2.4`, `Version:
1.10.1`.

**V6.** A fresh venv holding only the built wheel with the `crypto`, `mcp`,
`fastapi` and `flask` extras prints **1.10.1**; the oracle copied outside the
checkout runs **65 passed** against site packages; and **both** red pass
reproduction scripts named in Z3 **exit 0**.

**V7.** Full suite in `/tmp/al18-extras` after reinstalling the tree:
**1688 passed, 9 skipped, 0 failed**. `ruff check .` clean. `mypy agentlock/
--ignore-missing-imports` clean. Corpus grep **0**.

**V8.** Files in the release commit: `CHANGELOG.md`, `README.md` and
`CITATION.cff`, minus any that already satisfy their prediction at HEAD. Z1
measures README and CITATION as already satisfying theirs, so the predicted
content of the release commit is **`CHANGELOG.md` alone**. That is stated here,
before the edit, rather than discovered after it.

Style, on the same terms the previous freezes set: added lines carry **0** em
dashes, and the only ASCII double hyphens on added lines are the declared ones,
which are the `--ignore-missing-imports` flag inside backticks that A2.5
declared for exactly this file, and this document quoting it back.

## Z5. Commit plan

* **A**: `docs: freeze v1.10.1 release predictions`. This section, append only,
  and nothing else.
* **B**: `release: v1.10.1`. The changelog edits of R10 and R11, and whatever
  else V1 through V8 measure as short.
* **C**: AMENDMENT 7, the measured results against Z4, the sha256 of both
  artifacts, the METADATA lines, and commit B's hash.

No merge, no tag, no push, no upload.
