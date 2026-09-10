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
