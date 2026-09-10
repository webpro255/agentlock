# v1.9 Enforcement Completeness: Baseline of Record and Frozen Predictions

Date: 2026-09-09
Branch: `v1.9-enforcement-completeness`, cut from `d56122d docs: Zenodo software
DOI badge and identifiers`, which is v1.8.0 plus that one docs commit.
Working tree at measurement time: clean except the new test file this freeze adds.

This arc fixes three enforcement gaps found by an external review of the
published 1.8.0 wheel, plus four mypy errors. It adds no detection feature and
no new denial reason. Nothing in this document describes code that has been
written; the reproductions below are measurements of the engine as it stands at
`d56122d`.

---

## 1. The three gaps, as reported

Quoted as received, before any code was read on this branch.

> **G1. Argument binding.** `agentlock/decorators.py` (async_wrapper line 119
> region, sync_wrapper line 196 region) and `agentlock/integrations/autogen.py`
> (guarded, line 115 region) build `parameters=kwargs`. A positional argument or
> a function default never reaches the gate, so with `recipient_parameter="to"`,
> `send(to="x")` is denied while `send("x")` and `send()` with a hostile default
> both execute. Then `func(*args, **params)` runs with the unbound positionals.

> **G2. Token binding.** `agentlock/token.py:108` issues `parameters_hash=""`
> when parameters is empty or None, and `token.py:144` compares only when both
> `parameters` and `token.parameters_hash` are truthy. A token authorized with no
> parameters executes with any parameters. `gate.py:1825-1845` has the same
> truthiness guard on the evidence path.

> **G3. MCP 2.x fail-open.** `agentlock/integrations/mcp.py` `_install_hook` does
> `getattr(server, "call_tool", None)` and returns silently when absent. Under
> mcp 2.x, which `agentlock[mcp]` resolves to (`mcp>=1.0`), `Server` has no
> `call_tool`; registration is `add_request_handler(method, params_type, handler)`
> with handler signature `(ctx, params)` where `params` is
> `CallToolRequestParams` with `.name` and `.arguments`. The wrapper installs
> nothing and every handler runs ungated.

> **G4. mypy:** `policy.py:219` and `:257` missing annotations; `gate.py:882` and
> `:884` in the D20 disagreement block, a variable typed `list[str]` reassigned to
> `str` and a set comparison across mismatched types.

---

## 2. Baseline of record

All measurements taken on `v1.9-enforcement-completeness` at `d56122d`,
2026-09-09.

### B1. G1 at the source

`agentlock/decorators.py:118-130`, the async wrapper's entry, verbatim:

```python
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                user_id = kwargs.pop("_user_id", "")
                role = kwargs.pop("_role", "")
                kwargs.pop("_session_id", "")
                meta = kwargs.pop("_metadata", None)

                # Authorize through the gate
                auth_result = gate.authorize(
                    tool_name,
                    user_id=user_id,
                    role=role,
                    parameters=kwargs,
```

`agentlock/decorators.py:195-209`, the sync wrapper, verbatim:

```python
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                user_id = kwargs.pop("_user_id", "")
                role = kwargs.pop("_role", "")
                kwargs.pop("_session_id", "")
                meta = kwargs.pop("_metadata", None)

                return gate.call(
                    tool_name,
                    lambda **p: func(*args, **p),
                    user_id=user_id,
                    role=role,
                    parameters=kwargs,
                    metadata=meta,
                )
```

`agentlock/integrations/autogen.py:115-136`, `guarded`, verbatim:

```python
        def guarded(*args: Any, **kwargs: Any) -> Any:
            user_id = kwargs.pop("_agentlock_user_id", default_user)
            role = kwargs.pop("_agentlock_role", default_role)

            auth = gate.authorize(
                func_name,
                user_id=user_id,
                role=role,
                parameters=kwargs or None,
            )
            auth.raise_if_denied()
            assert auth.token is not None

            def _exec(**params: Any) -> Any:
                return func(*args, **params)

            return gate.execute(
                func_name,
                _exec,
                token=auth.token,
                parameters=kwargs or None,
            )
```

Three call sites, one shape: `args` is carried past the gate and spliced back in
at execution, and the gate is handed `kwargs` alone. Every parameter-level check
the gate performs, the declared recipient parameter included, sees only what the
caller happened to pass by keyword.

The reproduction is `tests/test_v19_enforcement_gaps.py` X1, X2, X3. Each
registers one tool at permissions version 1.5 with
`scope.recipient_parameter="to"` and `allowed_recipients=known_contacts_only`,
one session for alice holding `["bob@company.com"]`, and a function
`send_email(to="attacker@evil.com", body="")`. Three routes carry the same
hostile address: positional, function default, keyword. At `d56122d` the third
denies and the first two execute.

### B2. G2 at the source

`agentlock/token.py:102-112`, verbatim:

```python
        """Issue a new execution token."""
        token = ExecutionToken(
            tool_name=tool_name,
            user_id=user_id,
            role=role,
            scope=scope or {},
            parameters_hash=(
                ExecutionToken.hash_parameters(parameters) if parameters else ""
            ),
            _ttl_seconds=ttl or self._default_ttl,
        )
```

`agentlock/token.py:144-147`, verbatim:

```python
        if parameters and token.parameters_hash:
            expected = ExecutionToken.hash_parameters(parameters)
            if expected != token.parameters_hash:
                raise TokenInvalidError("Parameter hash mismatch -- token is operation-bound")
```

`agentlock/gate.py:1825-1832`, the deferral branch of the evidence path,
verbatim:

```python
            expected = resolved["parameters_hash"]
            if (
                expected
                and parameters is not None
                and ExecutionToken.hash_parameters(parameters) != expected
            ):
                return False, "parameter_mismatch", facts
            return True, "", facts
```

`agentlock/gate.py:1840-1848`, the token branch, verbatim:

```python
            if (
                token.parameters_hash
                and parameters is not None
                and ExecutionToken.hash_parameters(parameters)
                != token.parameters_hash
            ):
                return False, "parameter_mismatch", facts
            return True, "", facts
```

The stored hash that feeds the deferral branch is written with the same
truthiness guard, at `agentlock/gate.py:2403-2406`, verbatim:

```python
                    "parameters_hash": (
                        ExecutionToken.hash_parameters(record.parameters)
                        if record.parameters
                        else ""
                    ),
```

The reproduction is X4. At `d56122d`, `authorize(parameters={})` followed by
`execute(parameters={"to": "attacker@evil.com"})` executes.

### B3. G3 at the source

`agentlock/integrations/mcp.py:124-126`, verbatim:

```python
        original_call_tool = getattr(server, "call_tool", None)
        if original_call_tool is None:
            return
```

Measured against the two installed SDKs:

```
$ /tmp/al19-mcp1/bin/python -c "import importlib.metadata as m; from mcp.server import Server; print(m.version('mcp'), hasattr(Server,'call_tool'), hasattr(Server,'add_request_handler'))"
1.30.0 True False

$ /tmp/al18-extras/bin/python -c "import importlib.metadata as m; from mcp.server import Server; print(m.version('mcp'), hasattr(Server,'call_tool'), hasattr(Server,'add_request_handler'))"
2.2.0 False True
```

Under 2.2.0 the `getattr` misses, `_install_hook` returns, and
`AgentLockMCPServer` constructs and reports nothing. The reproductions are X5
(2.x, real SDK), X6 (1.x, real SDK) and X7 (fail closed on a server with
neither surface).

### B4. G4 at the source

```
$ /tmp/al18-extras/bin/mypy agentlock/ --ignore-missing-imports
agentlock/policy.py:219: error: Function is missing a return type annotation  [no-untyped-def]
agentlock/policy.py:257: error: Function is missing a type annotation for one or more parameters  [no-untyped-def]
agentlock/gate.py:882: error: Incompatible types in assignment (expression has type "str", variable has type "list[str]")  [assignment]
agentlock/gate.py:884: error: Non-overlapping equality check (left operand type: "set[str]", right operand type: "set[list[str]]")  [comparison-overlap]
Found 4 errors in 2 files (checked 33 source files)
```

`policy.py:219` is `def active_lineage_policy(permissions: AgentLockPermissions):`
with no return annotation. `policy.py:257` is
`def lineage_gated_action(lineage_policy, permissions, flags)` with
`lineage_policy` unannotated. Both return or accept
`LineagePolicyConfig | None`.

`gate.py:882` and `:884` are inside `authorize()`. The name `_asserted` is
already bound at `gate.py:699` by `_asserted_classes(...)`, which returns
`list[str]`, so mypy carries `list[str]` as the declared type of that local for
the whole function body and rejects the D20 rebinding to `str` at `:882` and the
set comparison at `:884`. There is no runtime defect: the two uses are in
disjoint branches. The fix is a distinct name for the D20 local.

### B5. Environments and freeze suite numbers

| Environment | Interpreter | mcp | autogen | crypto |
|---|---|---|---|---|
| checkout | `/usr/bin/python3` 3.14.6, editable install | absent | absent | absent |
| `/tmp/al18-extras` | 3.14.6 | 2.2.0 | absent (extra resolves below 3.14) | PyNaCl 1.6.2 |
| `/tmp/al19-mcp1` | 3.13.14 | 1.30.0 | absent | PyNaCl 1.6.2 |
| `/tmp/al18-probe313` | 3.13.14 | 2.2.0 | pyautogen 0.9.0 | PyNaCl 1.6.2 |

`/tmp/al19-mcp1` was created for this arc:
`python3.13 -m venv /tmp/al19-mcp1` then
`pip install -e "/home/n1trolab/agentlock-v1.4[dev,crypto]" "mcp>=1.0,<2"`,
which resolved `mcp 1.30.0`.

Full suite at `d56122d` **before** `tests/test_v19_enforcement_gaps.py` exists:

| Environment | Result |
|---|---|
| checkout | `1493 passed, 10 skipped` |
| `/tmp/al18-extras` | `1495 passed, 8 skipped` |
| `/tmp/al19-mcp1` | `1495 passed, 8 skipped` |
| `/tmp/al18-probe313` | `1496 passed, 7 skipped` |

Full suite at `d56122d` **with** the freeze file present, which is the tree this
document is committed on:

| Environment | Result |
|---|---|
| checkout | `1493 passed, 13 skipped, 5 xfailed` |
| `/tmp/al18-extras` | `1495 passed, 9 skipped, 7 xfailed` |
| `/tmp/al19-mcp1` | `1496 passed, 9 skipped, 6 xfailed` |
| `/tmp/al18-probe313` | `1496 passed, 8 skipped, 7 xfailed` |

Per test, at freeze:

| Test | checkout | extras (mcp 2.2.0) | mcp1 (mcp 1.30.0) | probe313 (mcp 2.2.0, autogen) |
|---|---|---|---|---|
| X1 sync decorator | XFAIL | XFAIL | XFAIL | XFAIL |
| X2 async decorator | XFAIL | XFAIL | XFAIL | XFAIL |
| X3 autogen guarded | XFAIL | XFAIL | XFAIL | XFAIL |
| X4 token binding | XFAIL | XFAIL | XFAIL | XFAIL |
| X5 mcp 2.x gated | skipped | **XFAIL** | skipped | **XFAIL** |
| X6 mcp 1.x gated | skipped | skipped | **PASSED** | skipped |
| X7 fail closed | skipped | XFAIL | XFAIL | XFAIL |
| X8 uninspectable | XFAIL | XFAIL | XFAIL | XFAIL |

Two results in that table are findings rather than restatements.

**X5 XFAILs against the real mcp 2.2.0 SDK.** G3 is not an inference from the
`getattr`; the handler runs ungated through the SDK's own registry.

**X6 PASSES against the real mcp 1.30.0 SDK.** The 1.x hook works end to end
through `Server.call_tool()` and `server.request_handlers[CallToolRequest]`, not
only through the `FakeServer` fixture the v1.8 tests use. X6 therefore carries no
xfail marker: it is a regression guard for the path v1.9 must not break while
adding 2.x support. The freeze run recorded the denial shape it asserts, which
differs from X5's: under 1.x the SDK's own `call_tool` decorator wraps the
guarded handler and catches every exception, so a `DeniedError` arrives as a
`CallToolResult` with `isError=True` whose text carries `recipient_not_allowed`.
Under 2.x, invoking the registered entry directly off `get_request_handler`, the
guard is the outermost layer and the exception propagates. Both deny and in
neither case does the handler run.

`ruff check .` passes and `grep -ri agentshield agentlock tests schema` returns
0 hits at `d56122d`.

---

## 3. Decisions of record

Recorded as received. Section 4 records two defects in them, found while taking
the baseline above and before any code was written.

**V1.** New module `agentlock/binding.py` with
`bind_call_parameters(func, args, kwargs) -> tuple[dict[str, Any], BoundArguments]`:
`inspect.signature(func).bind_partial(*args, **kwargs)` then `apply_defaults()`;
the returned dict is every bound parameter by name, with `VAR_KEYWORD` contents
flattened to top level and `VAR_POSITIONAL` kept as a tuple under its own name.
If `inspect.signature` raises (uninspectable callable), raise a `BindingError`
(new, in `exceptions.py`, subclass of `AgentLockError`) at wrap time, not call
time: an uninspectable function cannot be gated and the wrapper refuses to
construct. Fail closed.

**V2.** `decorators.py` sync and async wrappers, and autogen `guarded`: pop
`_agentlock_user_id` and `_agentlock_role` from kwargs first, then bind per V1,
pass the bound dict as `parameters` to every `authorize` and `execute` call in
the wrapper, and invoke the function as `func(*bound.args, **bound.kwargs)`. No
call site passes `parameters=kwargs` anymore.

**V3.** `token.py`: `parameters_hash` is always
`ExecutionToken.hash_parameters(parameters or {})`. `validate_and_consume` always
compares `hash_parameters(parameters or {})` against `token.parameters_hash`; a
mismatch raises `TokenInvalidError`. The evidence-path comparisons at
`gate.py:1825-1845` use the same unconditional rule. Caller contract stated in
the CHANGELOG under a Security heading: the parameters passed to `execute` must
be the parameters passed to `authorize`. A token issued with no parameters is
bound to the empty call.

**V4.** `mcp.py` `_install_hook`: if the server has `call_tool`, patch it as
today (1.x). Elif it has `add_request_handler`, wrap `add_request_handler` so
that a registration for method `tools/call` wraps the supplied handler: the
wrapper reads `params.name` and `dict(params.arguments or {})`, pops
`_agentlock_user_id` and `_agentlock_role` from a copy of the arguments,
authorizes exactly as the 1.x path does, raises or returns the same denial shape
the 1.x path does, and on allow calls the original handler with a `params` object
whose arguments no longer contain the `_agentlock_` keys (construct via
`params.model_copy(update={"arguments": cleaned})` if `params` is a pydantic
model, else set the attribute). Else raise `IntegrationUnsupportedError` (new, in
`exceptions.py`, subclass of `AgentLockError`) naming the server type and the
installed mcp version. Fail closed: `AgentLockMCPServer` never constructs
silently without a hook.

**V5.** pyproject: the `mcp` extra stays `mcp>=1.0` (both majors are now
supported and tested). Version becomes 1.9.0. CHANGELOG 1.9.0 section with a
Security heading listing G1, G2, G3 as fixed, crediting "an external review of
the 1.8.0 wheel", and a Fixed heading for G4.

**V6.** Additive-only is NOT claimed for this release. G2 and G3 change behavior
on paths that were failing open. The CHANGELOG says so plainly.

---

## 4. Defects in the decisions and in the freeze instructions, found before the build

Three, all found while taking Section 2's measurements. They are recorded here
rather than as amendments because they were found before this document was
committed and before any mechanism code existed.

### D1. V2 names auth kwargs that `decorators.py` does not use

V2 says to pop `_agentlock_user_id` and `_agentlock_role` in the decorator
wrappers. Those are the AutoGen wrapper's names. `decorators.py` uses `_user_id`,
`_role`, `_session_id` and `_metadata`, all four popped at
`decorators.py:120-123` and `:197-200`, and they are part of the documented
public surface of the decorator (`decorators.py:61-62`). Renaming them would be a
breaking change unrelated to G1.

**Restatement, which the build follows and the predictions are scored against:**
each wrapper pops the reserved auth kwargs it already pops, under the names it
already uses, and only then binds. `decorators.py` pops `_user_id`, `_role`,
`_session_id`, `_metadata`; `autogen.py` pops `_agentlock_user_id` and
`_agentlock_role`. Everything else in V2 stands unchanged.

### D2. V4's hook does not cover a handler passed to the mcp 2.x constructor

Under mcp 2.2.0, `Server.__init__` accepts `on_call_tool=` and writes it straight
into the handler registry without going through `add_request_handler`. Measured:

```
$ /tmp/al18-extras/bin/python -c "import inspect, mcp.server.lowlevel.server as S; print([l.strip() for l in inspect.getsource(S.Server.__init__).splitlines() if '_request_handlers' in l])"
['self._request_handlers: dict[str, HandlerEntry[LifespanResultT]] = {}', 'self._request_handlers.update({m: HandlerEntry(pt, h) for m, pt, h in _spec_requests if h is not None})']
```

`AgentLockMCPServer` wraps a server that is already constructed, so a
`tools/call` handler supplied that way is registered before the hook is
installed and V4's wrapping of `add_request_handler` never sees it. The result
would be a server that constructs without raising and still runs an ungated
handler: the exact fail-open shape G3 describes, on a different route.

**Extension, which the build implements:** at install time, after wrapping
`add_request_handler`, the hook also re-registers any handler already present for
`tools/call`, wrapped. This is additive to V4 and closes the constructor route.
It is measured by a new test, X9, added at build time and not part of the freeze
file's xfail set.

### D3. The freeze instruction's suite figures name the wrong environment

The instruction to record "1495 passed ... 8 skipped, with X5 and X6 skipped here
(no mcp locally)" is not satisfiable by one environment. `1495 passed, 8 skipped`
is `/tmp/al18-extras`, which has mcp 2.2.0 and where X5 therefore does not skip.
The checkout interpreter, which has no mcp, runs `1493 passed, 10 skipped`.
Section 2's B5 records both, with every environment named. The predictions in
Section 5 are stated per environment and are scored against those.

---

## 5. Predictions

Frozen before any mechanism code exists.

**U1.** Every X test passes with its xfail marker removed, in every environment
where it is not skipped, and no test reports a strict XPASS failure. X6 has no
marker to remove and continues to pass under mcp 1.30.0.

**U2.** Checkout interpreter (`/usr/bin/python3`, no mcp, no autogen):
`1498 passed, 13 skipped, 0 failed, 0 xfailed`. The 1498 is the 1493 of record
plus X1, X2, X3, X4 and X8. The 13 is the 10 of record plus X5, X6 and X7, all
three mcp guarded.

**U3.** The three measurement environments, each with `pip install -e` re-run
against the built tree before measuring:

| Environment | Predicted |
|---|---|
| `/tmp/al18-extras` (mcp 2.2.0) | `1502 passed, 9 skipped, 0 failed`; X5 passes, X6 skips |
| `/tmp/al19-mcp1` (mcp 1.30.0) | `1502 passed, 9 skipped, 0 failed`; X6 passes, X5 skips |
| `/tmp/al18-probe313` (mcp 2.2.0, pyautogen 0.9.0) | `1503 passed, 8 skipped, 0 failed`; X5 passes, X6 skips |

Each is the environment's freeze figure with its xfails converted to passes:
extras `1495 + 7`, mcp1 `1495 + 7` (six xfails plus X6, which already passed and
is counted in the 1496 freeze line), probe313 `1496 + 7`.

X9, the D2 constructor-route test, is not counted in any figure above. It is
guarded to mcp 2.x, so it adds one pass in extras and probe313 and one skip in
checkout and mcp1. The scored figures in Section 5 of AMENDMENT 1 will state
both the U3 number and the number with X9 included, and a MATCH requires the
difference to be exactly X9.

**U4.** `mypy agentlock/ --ignore-missing-imports`: 0 errors, run with
`/tmp/al18-extras/bin/mypy` (mypy 2.3.1), the binary that produced B4.

**U5.** No existing test is edited except ones asserting the old
empty-parameter token behavior or the old silent no-op. Predicted list, exactly
one entry:

- `tests/test_token.py:110-112`, `test_issue_without_parameters_empty_hash`, old
  assertion `assert token.parameters_hash == ""`. Reason: V3 makes the hash
  unconditional, so a token issued with no parameters carries
  `hash_parameters({})` and is bound to the empty call. The test is rewritten to
  assert that, under a name that says it.

No test constructs `AgentLockMCPServer` over an object lacking `call_tool`. Both
existing MCP tests (`tests/test_v15_integration_confirmation.py:119` and
`tests/test_v18_recipient_integrations.py:126`) use a `FakeServer` that defines
`call_tool`, so both stay on the 1.x branch and neither is edited.

**U6.** Files touched, and nothing else: `agentlock/binding.py` (new),
`agentlock/decorators.py`, `agentlock/integrations/autogen.py`,
`agentlock/integrations/mcp.py`, `agentlock/token.py`, `agentlock/gate.py`,
`agentlock/policy.py`, `agentlock/exceptions.py`, `agentlock/__init__.py`,
`pyproject.toml`, `CHANGELOG.md`, `README.md` (the version row and the token
contract line), `tests/test_v19_enforcement_gaps.py`, plus the one test edit from
U5.

**U7.** `ruff check .` passes. `grep -ri agentshield agentlock tests schema`
returns 0.

---

## 6. What this document is not

It is not a description of a fix. Section 2 is the engine at `d56122d`, measured.
Section 3 is what was decided. Section 4 is where those decisions were wrong,
recorded before the build so the record cannot be tidied afterwards. Section 5
is what the build is scored against. Everything after this line is append only.

---

## AMENDMENT 1 (2026-09-09): v1.9.0 built, every prediction matched

Measured on `v1.9-enforcement-completeness` at `71100d7 fix: bind all call
arguments, always compare token hash, fail closed on unsupported MCP servers,
support mcp 2.x`, which is the build commit. Every environment was reinstalled
with `pip install -e` against the built tree before measuring.

### Scoreboard

| Prediction | Verdict | Evidence |
|---|---|---|
| U1 | MATCH | All seven xfail markers removed. No test reports XPASS or failure in any environment. Every X test passes wherever it is not skipped: 5 of 9 in the checkout (four mcp guarded skips), 8 of 9 under mcp 2.2.0 (X6 skips), 7 of 9 under mcp 1.30.0 (X5 and X9 skip), 8 of 9 under mcp 2.2.0 with pyautogen (X6 skips). Per test output below. |
| U2 | MATCH | `1498 passed, 14 skipped, 0 failed`. Predicted 1498 passed and 13 skipped excluding X9, which Section 4's D2 declared would add one skip here. 14 is 13 plus X9. |
| U3 | MATCH | `/tmp/al18-extras`: `1503 passed, 9 skipped`, predicted `1502 passed, 9 skipped` plus one X9 pass. `/tmp/al19-mcp1`: `1502 passed, 10 skipped`, predicted `1502 passed, 9 skipped` plus one X9 skip. `/tmp/al18-probe313`: `1504 passed, 8 skipped`, predicted `1503 passed, 8 skipped` plus one X9 pass. Every difference from the predicted figure is exactly X9, in the direction D2 stated in advance. 0 failed in all three. |
| U4 | MATCH | `Success: no issues found in 34 source files`, down from `Found 4 errors in 2 files (checked 33 source files)`. The extra source file is `agentlock/binding.py`. |
| U5 | MATCH | Exactly one existing test edited, the one predicted. Diff below. |
| U6 | MATCH | `git show --stat 71100d7` lists 14 paths, the 13 predicted plus `agentlock/binding.py` as the new file the prediction named. Nothing else. |
| U7 | MATCH | `ruff check .` reports `All checks passed!`. `grep -ri agentshield agentlock tests schema` returns 0. |

### The four suite lines

```
$ python3 -m pytest -q                              # checkout, CPython 3.14.6, no mcp
1498 passed, 14 skipped, 16 warnings in 2.99s

$ /tmp/al18-extras/bin/python -m pytest -q          # CPython 3.14.6, mcp 2.2.0
1503 passed, 9 skipped, 16 warnings in 3.17s

$ /tmp/al19-mcp1/bin/python -m pytest -q            # CPython 3.13.14, mcp 1.30.0
1502 passed, 10 skipped in 2.80s

$ /tmp/al18-probe313/bin/python -m pytest -q        # CPython 3.13.14, mcp 2.2.0, pyautogen 0.9.0
1504 passed, 8 skipped in 3.11s
```

### Per test, after the build

```
$ python3 -m pytest tests/test_v19_enforcement_gaps.py -q -rs   # checkout, no mcp
SKIPPED [1] tests/test_v19_enforcement_gaps.py:270: needs the mcp 2.x SDK
SKIPPED [1] tests/test_v19_enforcement_gaps.py:329: needs the mcp 1.x SDK
SKIPPED [1] tests/test_v19_enforcement_gaps.py:386: needs the mcp 2.x SDK
SKIPPED [1] tests/test_v19_enforcement_gaps.py:447: could not import 'mcp': No module named 'mcp'
========================= 5 passed, 4 skipped in 0.01s =========================

$ /tmp/al18-extras/bin/python -m pytest tests/test_v19_enforcement_gaps.py -q -rs   # mcp 2.2.0
SKIPPED [1] tests/test_v19_enforcement_gaps.py:329: needs the mcp 1.x SDK
========================= 8 passed, 1 skipped in 0.29s =========================

$ /tmp/al19-mcp1/bin/python -m pytest tests/test_v19_enforcement_gaps.py -q -rs   # mcp 1.30.0
SKIPPED [1] tests/test_v19_enforcement_gaps.py:270: needs the mcp 2.x SDK
SKIPPED [1] tests/test_v19_enforcement_gaps.py:386: needs the mcp 2.x SDK
========================= 7 passed, 2 skipped in 0.17s =========================

$ /tmp/al18-probe313/bin/python -m pytest tests/test_v19_enforcement_gaps.py -q -rs   # mcp 2.2.0 + pyautogen 0.9.0
SKIPPED [1] tests/test_v19_enforcement_gaps.py:329: needs the mcp 1.x SDK
========================= 8 passed, 1 skipped in 0.29s =========================
```

X3, the AutoGen reproduction, passes in `/tmp/al18-probe313` with a real
`pyautogen 0.9.0` present, not only under the monkeypatched import check.

### U4 verbatim

```
$ /tmp/al18-extras/bin/mypy agentlock/ --ignore-missing-imports
Success: no issues found in 34 source files
```

### U5 verbatim

One edit, the predicted one:

```diff
--- a/tests/test_token.py
+++ b/tests/test_token.py
@@ -106,10 +106,14 @@ class TestTokenStore:
         token = store.issue("tool", "user", "role", parameters=params)
         assert token.parameters_hash == ExecutionToken.hash_parameters(params)
 
-    def test_issue_without_parameters_empty_hash(self):
+    def test_issue_without_parameters_binds_the_empty_call(self):
+        """v1.9, G2: a token issued for a call carrying no parameters is bound
+        to the empty call, not to any call at all.  Through 1.8.0 this stored
+        an empty hash, and an empty hash skipped the comparison."""
         store = TokenStore()
         token = store.issue("tool", "user", "role")
-        assert token.parameters_hash == ""
+        assert token.parameters_hash == ExecutionToken.hash_parameters({})
+        assert token.parameters_hash != ""
```

No test constructing `AgentLockMCPServer` over an object lacking `call_tool`
existed, as predicted, so neither existing MCP test was touched. Both keep using
a `FakeServer` that defines `call_tool` and both stay on the 1.x branch.

### U6 verbatim

```
$ git show --stat 71100d7 --name-only --format=
CHANGELOG.md
README.md
agentlock/__init__.py
agentlock/binding.py
agentlock/decorators.py
agentlock/exceptions.py
agentlock/gate.py
agentlock/integrations/autogen.py
agentlock/integrations/mcp.py
agentlock/policy.py
agentlock/token.py
pyproject.toml
tests/test_token.py
tests/test_v19_enforcement_gaps.py
```

### D2 closed

The mcp 2.x constructor route, recorded as a defect in V4 before the build, is
covered. `Server(on_call_tool=...)` writes the handler registry directly, so the
handler is in place before `AgentLockMCPServer` is constructed and the wrapping
of `add_request_handler` alone would never see it. The hook now also
re-registers whatever is already bound to `tools/call`, wrapped. X9 measures it
against the real SDK: the constructor-registered handler denies a hostile
recipient and never runs, and runs for a known contact with the reserved keys
stripped. X9 passes in both mcp 2.2.0 environments and skips in the other two.

### Out of scope, reported and not fixed

`CITATION.cff:10` reads `version: 1.8.0` and `:18` describes a version DOI for
1.8.0. Both are now behind `pyproject.toml`. They are not touched here: U6 froze
the file list, and a version DOI cannot be written by this branch because it is
minted at release. `CITATION.cff` was written by the `4a6a7e4 release: v1.8.0`
commit and belongs to the same manual step. Naming it here so the release step
does not miss it.

### What this release is not

Additive. G2 and G3 change behavior on paths that were failing open, which is
recorded in the CHANGELOG under its own heading rather than left for a reader to
infer. A deployment that authorized one call and executed another, or that
relied on an MCP wrapper which was in fact installing no hook, will see denials
where it previously saw execution. That is the fix, not a side effect of it.

---

## RELEASE FREEZE (2026-09-09): predictions for the v1.9.0 release commit

Frozen before any release edit exists. Repo at `ce7d5f3 docs: AMENDMENT 1,
v1.9.0 built and matched`, working tree clean. This is the release session: one
release commit and one amendment, no merge, no tag, no push, no upload. The
version was already bumped by the build commit, so the release commit carries
documentation only.

Recorded as received, verbatim.

**W1.** `CITATION.cff`: version 1.9.0, `date-released` set to today's date from
`date +%F`, `doi` field set to the concept DOI 10.5281/zenodo.22681594,
`identifiers` reduced to the concept DOI entry only (the 1.9.0 version DOI is
minted by Zenodo after the GitHub release and is added in a follow-up docs
commit, as 1.8.0 did). Validated with `yaml.safe_load`.

**W2.** CHANGELOG 1.9.0 heading carries today's date. The Security section
additionally carries one scoping sentence: the engine's decorators and in-repo
integrations bind every call argument; the standalone adapters
`crewai-agentlock` and `langchain-agentlock` authorize keyword arguments only in
their current releases and are updated separately; `mcp-agentlock` passes the
SDK's arguments mapping and is unaffected. Suite figures per environment from
AMENDMENT 1 are quoted with interpreter and mcp versions.

**W3.** README: the versions table 1.9.0 row (if the build did not already add
it) and the same scoping sentence wherever the README describes argument binding
or token binding. `grep -n "1\.8\.0" README.md` returns only history rows and the
CITATION line about 1.8.0's DOI if present.

**W4.** Build in `/tmp/al18-extras` after `rm -rf dist build`: `twine check`
PASSED on both artifacts, wheel METADATA `Metadata-Version: 2.4` and
`Version: 1.9.0`, hatchling pin unchanged.

**W5.** Fresh venv `/tmp/al19-wheel`: pip install the wheel with `[crypto,mcp]`;
prints 1.9.0; then run an external reproduction script written in `/tmp` (not the
repo) that exercises the three gaps against the installed wheel only:
(a) decorator wrapper with `recipient_parameter="to"` over
`send_email(to="attacker@evil.com", body="")`, positional call raises
`DeniedError`, default call raises `DeniedError`, counter stays 0; (b) token
authorized with `parameters={}` then execute with `{"to": "x"}` raises
`TokenInvalidError`; (c) real mcp 2.x `Server(on_call_tool=handler)` wrapped by
`AgentLockMCPServer`, denied recipient never reaches the handler, and a bare
object with neither API raises `IntegrationUnsupportedError`. All pass.

**W6.** Full suite in `/tmp/al18-extras` after reinstall: `1503 passed, 9
skipped, 0 failed`; ruff clean; mypy 0 errors; `grep -ri agentshield agentlock
tests schema` returns 0.

**W7.** Files in the release commit: `CITATION.cff`, `CHANGELOG.md`,
`README.md`. Nothing else (version was bumped in the build).

---

## Defects in the release predictions, found before this freeze was committed

Two. Both were found by reading the repository and the standalone adapter
sources while preparing to apply W1 to W3, and both were found before any
release edit was written. They are recorded here rather than as a numbered
amendment for the same reason Section 4 is where it is: nothing had been
committed yet, so there is no earlier record for an amendment to correct. The
numbered amendment slot after the release commit stays AMENDMENT 2, as the
release instruction assigns it.

W1 to W7 above are reproduced exactly as received and are not edited. The
restatements below are what the release edits follow and what Section 5 of
AMENDMENT 2 is scored against.

### R1. W2's scoping sentence names three standalone adapters. Five ship.

The sentence W2 dictates reads as an inventory: "the standalone adapters
`crewai-agentlock` and `langchain-agentlock` ... `mcp-agentlock` ...". Two more
standalone adapters exist and are published from their own repositories:
`openai-agentlock` 0.1.0 and `openclaw-agentlock` 0.1.0. A scoping sentence in a
Security section is read as the full set of what is and is not covered, so an
enumeration that silently omits two shipped adapters is the failure the sentence
exists to prevent.

Each of the five was read at its current release before this was written. The
three claims W2 makes are all true as far as they go:

| Adapter | Version | What reaches the gate | Positional route |
|---|---|---|---|
| `crewai-agentlock` | 0.2.0 | `parameters=kwargs or None` at `src/crewai_agentlock/wrapper.py:188`, `:250` | open: `inner._run(*args, **params)` at `:244` carries positionals past the gate into the call |
| `langchain-agentlock` | 0.1.0 | `parameters=kwargs or None` at `src/langchain_agentlock/toolkit.py:125`, `:140`, `:151` | none: `_run(self, *args, run_manager=None, **kwargs)` discards `args`, invoking `inner.invoke(params)` |
| `mcp-agentlock` | 0.2.1 | the SDK's `arguments` mapping at `src/mcp_agentlock/wrapper.py:400`, `:423` | none: `guarded(tool_name, arguments)` hands the handler the same mapping it handed the gate |
| `openai-agentlock` | 0.1.0 | the JSON `arguments` string parsed to a dict at `openai_agentlock/wrapper.py:50`, `:66` | none: the original invoke receives the same string |
| `openclaw-agentlock` | 0.1.0 | the caller's `parameters` mapping at `openclaw_agentlock/adapter.py:73` and `executor.py:84` | none: the tool is invoked from that same mapping |

One fact holds across all five and is absent from W2's sentence: no standalone
adapter applies the wrapped function's defaults, so a parameter the caller omits
and the function defaults is not seen by the gate in any of them. That is the
second of the two G1 routes, the one the engine now closes with
`apply_defaults()`.

**Restatement, which the release edits follow:** the scoping text names all five
adapters at their current versions, separates the two that authorize keyword
arguments only from the three that hand the gate the same mapping they hand the
tool, and states the defaults fact once for all five. It is longer than the one
sentence W2 specifies. Everything else in W2 stands: the heading date, and the
suite figures quoted per environment with interpreter and mcp versions.

### R2. W3 leaves a 1.8.0 version DOI in the README that W1 removes from CITATION.cff

`README.md:371` reads:

```
Software archive (all versions): https://doi.org/10.5281/zenodo.22681594. This release: https://doi.org/10.5281/zenodo.22681595.
```

`10.5281/zenodo.22681595` is the version DOI for 1.8.0, as `CITATION.cff:16-18`
states in the entry W1 deletes. W1's reasoning is that a version DOI is minted
after the GitHub release and cannot be written by this branch, so the file
carries the concept DOI alone until a follow-up docs commit. The README line
makes exactly the claim W1 removes, in the same repository, at the same release,
and it says "This release", which at v1.9.0 is false.

W3's grep condition is not what misses it: the line carries no literal `1.8.0`,
so `grep -n "1\.8\.0" README.md` never returned it and the condition holds
either way. W3's edit list is what misses it, by naming only the versions table
row and the scoping sentence.

**Restatement, which the release edits follow:** `README.md:371` is reduced to
the concept DOI, with the version DOI described as minted at publication and
added in the follow-up docs commit, matching W1's treatment of `CITATION.cff`.
This is a third README edit beyond the two W3 names. It does not change W3's
grep condition and it does not change W7: `README.md` was already in the release
commit's file list.

Everything after this line is append only.

---

## AMENDMENT 2 (2026-09-09): v1.9.0 released, every release prediction matched

Measured on `v1.9-enforcement-completeness`. The release commit is
`e9aeb93 release: v1.9.0`, documentation only, on top of the freeze commit
`9e8d552 docs: freeze v1.9.0 release predictions`. No merge, no tag, no push,
no upload. The two restatements recorded in the freeze, R1 and R2, are what the
release edits follow; W1 to W7 are otherwise unchanged.

### Scoreboard

| Prediction | Verdict | Evidence |
|---|---|---|
| W1 | MATCH | `yaml.safe_load` loads the file, 15 top-level keys. `version: 1.9.0`, `date-released: 2026-09-09` which is `date +%F`, `doi: 10.5281/zenodo.22681594`, and `identifiers` is one entry, the concept DOI. The 1.8.0 version DOI entry is gone. Verbatim below. |
| W2 | MATCH | `CHANGELOG.md:10` reads `## [1.9.0] - 2026-09-09`. The Security section carries the scoping text as its closing bullet, in the R1 form. The suite line at `:16` quotes all three environments with interpreter and mcp versions, unchanged from AMENDMENT 1. |
| W3 | MATCH | The versions table already carried the 1.9.0 row from the build, so it was not touched. The scoping text is in the versions section, where the README describes argument binding, extended with the token contract sentence. `grep -n "1\.8\.0" README.md` returns two lines, both history: the 1.8.0 versions table row and the 1.8.0 sentence in the per-version counts paragraph that footnotes that table. Neither is a current claim. No CITATION line about 1.8.0's DOI remains: R2 removed the one the prediction allowed to stand. Verbatim below. |
| W4 | MATCH | Built in `/tmp/al18-extras` after `rm -rf dist build`. `twine check` PASSED on both artifacts. Wheel METADATA carries `Metadata-Version: 2.4` and `Version: 1.9.0`. `pyproject.toml:2` still reads `requires = ["hatchling<1.30"]` and the build resolved `hatchling==1.29.0`. |
| W5 | MATCH | `/tmp/al19-wheel`, a fresh venv on CPython 3.14.6, installed `dist/agentlock-1.9.0-py3-none-any.whl[crypto,mcp]` and prints `1.9.0`. `/tmp/al19_wheel_repro.py`, written outside the repository, reports `17 passed, 0 failed` covering (a), (b) and (c). Output below. |
| W6 | MATCH | `/tmp/al18-extras` after `pip install -e ".[dev,crypto,mcp]"`: `1503 passed, 9 skipped, 16 warnings in 3.31s`, 0 failed. `ruff check .` reports `All checks passed!`. `mypy agentlock/ --ignore-missing-imports` reports `Success: no issues found in 34 source files`. The legacy-name grep over `agentlock tests schema` returns 0. |
| W7 | MATCH | `git show --stat --name-only e9aeb93` lists `CHANGELOG.md`, `CITATION.cff`, `README.md`. Nothing else. `dist/` and `build/` are ignored at `.gitignore:5-6`. The version was bumped by the build commit and `pyproject.toml` was not touched. |

Seven predictions, seven MATCH, 0 MISMATCH.

### One thing W3 predicted loosely, stated exactly

W3 allowed the grep to return "history rows and the CITATION line about 1.8.0's
DOI if present". What it actually returns is two lines, neither of them a
CITATION line:

```
$ grep -n "1\.8\.0" README.md
318:| 1.8.0   | recipient policy enforcement at pipeline Step 8; declared recipient parameter read from the trusted permission block; recipient sets | 1495 with the `crypto` and `mcp` extras, 8 skipped |
332:install additionally skips the same 13 optional-extra tests. For 1.8.0 it
```

`:318` is a history row. `:332` is a history sentence, not a row: it is inside
the paragraph that footnotes the versions table and gives the per-version test
counts for 1.6.0, 1.7.0, 1.8.0 and 1.9.0 in turn. It is history of the same kind
as the row, in prose, and it is not a claim about the current release. It is
recorded here rather than folded into "history rows" so the difference between
what W3 said and what the repository holds is on the record.

The CITATION line the prediction was willing to tolerate is gone, per R2. It read
`This release: https://doi.org/10.5281/zenodo.22681595`, which is 1.8.0's
version DOI, and at v1.9.0 it was false.

### W1 verbatim

```
$ python3 -c "import yaml, json; d = yaml.safe_load(open('CITATION.cff')); print(d['version'], d['date-released'], d['doi']); print(json.dumps(d['identifiers']))"
1.9.0 2026-09-09 10.5281/zenodo.22681594
[{"type": "doi", "value": "10.5281/zenodo.22681594", "description": "Concept DOI, resolves to the latest version"}]
```

### W4 verbatim

```
$ /tmp/al18-extras/bin/twine check dist/*
Checking dist/agentlock-1.9.0-py3-none-any.whl: PASSED
Checking dist/agentlock-1.9.0.tar.gz: PASSED
```

Wheel `agentlock-1.9.0.dist-info/METADATA`, first three lines:

```
Metadata-Version: 2.4
Name: agentlock
Version: 1.9.0
```

Artifacts, `sha256sum dist/*`:

```
972e9633e00c18890de6cc7e334d872880534ca388e2f6e795fc0eebe16ffc88  dist/agentlock-1.9.0-py3-none-any.whl
9a28ea6a49f6eb748f1c4f1a2b59428869aca5c01c20cfa70bb87653a6c096bd  dist/agentlock-1.9.0.tar.gz
```

Neither artifact is uploaded and neither is committed. `dist/` is ignored.

### W5 verbatim

The script guards its own premise: it exits before testing anything if the
resolved `agentlock` package does not live in the venv's `purelib`. Run from
`/tmp`, it resolves the wheel.

```
$ /tmp/al19-wheel/bin/python /tmp/al19_wheel_repro.py
agentlock 1.9.0 from /tmp/al19-wheel/lib/python3.14/site-packages/agentlock/__init__.py
mcp 2.2.0

(a) G1 argument binding through the decorator
  PASS  positional call denies
  PASS  default call denies
  PASS  keyword call denies
  PASS  body never ran, counter stays 0
  PASS  known contact positional executes
  PASS  known contact keyword executes
  PASS  counter is 2 after the two allowed calls

(b) G2 token binding
  PASS  empty authorize is allowed
  PASS  execute with other parameters raises TokenInvalidError
  PASS  the empty call still executes on an empty token

(c) G3 mcp 2.x and fail closed
  PASS  handler registered by the constructor
  PASS  hostile recipient denies
  PASS  the handler never ran
  PASS  known contact reaches the handler
  PASS  reserved keys stripped
  PASS  recipient delivered unchanged
  PASS  bare object raises IntegrationUnsupportedError
        Cannot install an AgentLock authorization hook on __main__.Bare: it exposes neither 'call_tool' (mcp 1.x) nor 'add_request_handler' (mcp 2.x).  Installed mcp version: 2.2.0.  Refusing to construct rather than wrap a server whose tool calls would not be authorized.

17 passed, 0 failed
ALL PASS
```

(c) exercises the constructor route, which is D2's route rather than W5's
literal `add_request_handler` route. `Server(on_call_tool=handler)` is what W5
names, and it is the route that writes the registry directly, so the hook's
re-registration of what is already bound to `tools/call` is what the wheel is
proving here.

### W6 verbatim

```
$ /tmp/al18-extras/bin/python -m pytest -q
1503 passed, 9 skipped, 16 warnings in 3.31s

$ /tmp/al18-extras/bin/ruff check .
All checks passed!

$ /tmp/al18-extras/bin/mypy agentlock/ --ignore-missing-imports
Success: no issues found in 34 source files
```

### W7 verbatim

```
$ git show --stat --name-only --format= e9aeb93
CHANGELOG.md
CITATION.cff
README.md
```

Release commit: `e9aeb93`.

### What is left for the manual step

Three things, none of them this branch's to do.

1. Merge, tag `v1.9.0`, and push. Nothing here merged, tagged or pushed.
2. Upload `dist/agentlock-1.9.0-py3-none-any.whl` and
   `dist/agentlock-1.9.0.tar.gz`, whose hashes are recorded above, after the
   push. Nothing here uploaded.
3. After Zenodo mints the 1.9.0 version DOI from the GitHub release, add it back
   to `CITATION.cff` as a second `identifiers` entry and to the README's
   software archive line, in a follow-up docs commit. Both places now say the
   version DOI is minted at publication rather than naming a stale one.

The standalone adapters are the fourth thing and are not part of this release.
`crewai-agentlock` 0.2.0 carries both G1 routes and `langchain-agentlock`
0.1.0 carries the defaults route; both are scoped in the CHANGELOG and the README
rather than left for a reader to discover. They are fixed in their own
repositories, on their own releases.

Everything after this line is append only.
