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
