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

---

## 1.9.1 FREEZE (2026-09-10): the variadic keyword collision

Branch `v1.9.1-binding-collision`, cut from `main` at
`80c85a6 Merge v1.9-enforcement-completeness: argument binding, token binding,
mcp 2.x fail closed`, which is the v1.9.0 tag plus the merge. Working tree clean
except the new test class this freeze adds.

This is a patch release closing one class of gap in `agentlock/binding.py`,
found by the same external review that found G1 to G4. No other change. Nothing
below describes code that has been written: Section 2 of this freeze is the
engine at 1.9.0, measured.

### 1. The gap, as reported

Quoted as received.

> `bind_call_parameters` flattens VAR_KEYWORD entries onto the top-level
> parameters dict with `parameters.update(value)`. When a flattened key equals
> the name of another bound parameter, the flattened value overwrites the bound
> one. The gate then sees a value the function does not receive.
>
> **C1.** `def send(to, /, **extras)`; `send("attacker@evil.test",
> to="bob@company.com")`: gate sees `to=bob`, function executes with
> `to=attacker`. Sync and async wrappers, and autogen `protect_functions`, all
> affected.
>
> **C2.** `def f(*args, **kw)`; `f(1, 2, args="spoof")`: gate sees
> `args="spoof"`, function receives `args=(1, 2)`.
>
> **C3.** `def g(**kw)`; `g(kw="spoof")`: gate and function see the same dict.
> Not a hiding. Must keep working.

### 2. The gap at the source, measured at 1.9.0

`agentlock/binding.py:84-95`, verbatim:

```python
    parameters: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if name not in bound.arguments:
            continue
        value = bound.arguments[name]
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            parameters.update(value)
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            parameters[name] = tuple(value)
        else:
            parameters[name] = value
    return parameters, bound
```

`signature.parameters` iterates in declaration order, so a VAR_KEYWORD is
visited last and its `update` lands on top of every name already written. The
three call sites all reach this function and none of them inspects what it
returns, so all three carry the gap: `agentlock/decorators.py:136` and `:218`,
and `agentlock/integrations/autogen.py:130`.

The three shapes, run against the checkout at 1.9.0. C1 and C2 substitute the
test file's existing constants for the report's addresses, `attacker@evil.com`
for `attacker@evil.test`; nothing else differs.

```
$ python3 repro.py
C1  gate sees {'to': 'bob@company.com'}  function runs with to = attacker@evil.com
C2  gate sees {'args': 'spoof'}  function runs with args = (1, 2)
C3  gate sees {'kw': 'spoof', 'to': 'x'}  function runs with kw = {'kw': 'spoof', 'to': 'x'}
```

C1 and C2 are confirmed as reported. C3 is confirmed as the case that is not a
hiding: the gate is shown exactly the mapping the function receives, because
`kw` is the variadic parameter itself and there is no other parameter of that
name for a flattened key to shadow.

### 3. Decisions of record

Recorded as received. Section 4 records two defects in them, found while taking
Section 2's measurements and before any code was written.

**Y1.** In `bind_call_parameters`, before flattening a VAR_KEYWORD mapping,
compute the set of names of every other parameter in the signature (all kinds
except the VAR_KEYWORD itself). If any flattened key is in that set, raise
`BindingError` naming the colliding key and the function. This is a call-time
error, raised before `authorize` is called, so the call never executes and the
gate is never shown a value the function would not receive.

**Y2.** No wrapper catches `BindingError`. It propagates to the caller, like
`TokenInvalidError` does.

**Y3.** Version 1.9.1. CHANGELOG under Security: the collision rule, the three
shapes, credit "the same external review", and the statement that C3 remains
allowed.

**Y4.** Files: `agentlock/binding.py`, `agentlock/__init__.py`,
`pyproject.toml`, `CHANGELOG.md`, `CITATION.cff` (version 1.9.1 and
`date-released` from `date +%F`, doi stays the concept DOI), `README.md`
(versions row), `tests/test_v19_enforcement_gaps.py` gains the new cases in its
own class, `docs/PREDICTIONS_v19_enforcement.md` (append only). Nothing else.

### 4. Defects in the decisions, found before this freeze was committed

Two. Both were found by reading the repository while preparing to apply Y1 to
Y4, and both before any mechanism code was written. They are recorded here
rather than as a numbered amendment for the reason Section 4 of the original
freeze is where it is: nothing had been committed yet, so there is no earlier
record for an amendment to correct. Y1 to Y4 above are reproduced exactly as
received and are not edited. The restatements are what the build follows and
what Section 6 is scored against.

#### S1. Y4's file list excludes the one docstring Y1 makes false

`agentlock/exceptions.py:260-268`, verbatim:

```python
class BindingError(AgentLockError):
    """A callable's signature cannot be read, so its calls cannot be gated.

    Raised at wrap time, never at call time.  A wrapper that cannot bind a
    call's arguments to parameter names cannot show the gate what the call
    carries, so it refuses to be built rather than gating a subset of the
    arguments and letting the rest through.
    """
```

Y1 raises `BindingError` at call time, from inside `bind_call_parameters`, and
for a reason that has nothing to do with an unreadable signature. Both the
summary line and the sentence "Raised at wrap time, never at call time" become
false the moment Y1 lands. Y4 does not name `agentlock/exceptions.py`, so
following it literally ships an exception class whose own documentation
contradicts the code that raises it.

Two other docstrings mention `BindingError` and are left alone deliberately.
`agentlock/integrations/autogen.py:110-116` documents `_wrap_function` raising
it at wrap time, which stays true of that function: the collision is raised
from `guarded`, not from `_wrap_function`. `CHANGELOG.md:24` is the 1.9.0
entry, which is history and is not edited; the 1.9.1 entry states the new rule.
Incomplete is tolerable in a changelog of a past release. False in a class
docstring is not.

**Restatement, which the build follows:** `agentlock/exceptions.py` is added to
Y4's file list, for one edit, the `BindingError` docstring, which is rewritten
to state both reasons the exception is raised and where each is raised from.
Nothing else in that file is touched. Y4 is otherwise unchanged.

#### S2. Y4's README edit leaves the per-version count paragraph naming 1.9.0 as current

Y4 names `README.md` and scopes it to "versions row". The versions table at
`README.md:314-323` is footnoted by a paragraph at `:325-341` that gives the
test counts per environment for each release in turn, ending:

```
For 1.9.0 it is 1503 passing and 9 skipped under `mcp 2.x`, the
9 being those 8 plus the mcp 1.x test, which selects on the installed
SDK major; under `mcp 1.x` it is 1502 passing and 10 skipped, the two 2.x
tests taking the place of the 1.x one. Nothing fails in any of these
environments.
```

Adding a 1.9.1 row to the table and stopping leaves that paragraph's last
entry, which a reader takes as the current release's environment breakdown,
naming the previous release. This is R2's shape from the release freeze: a
stale current claim left standing because the edit list named a narrower target
than the change requires.

**Restatement, which the build follows:** the paragraph gains one sentence for
1.9.1, in the form the sentences before it use. This is a second edit inside
`README.md`, a file Y4 already names, and it does not change Y4's file list.

### 5. Measurements at freeze

Environments are the four of record from Section 2 of the original freeze,
unchanged. Full suite on `v1.9.1-binding-collision` at `80c85a6`, **before**
the new test class exists:

| Environment | Interpreter | mcp | Result |
|---|---|---|---|
| checkout | 3.14.6 | absent | `1498 passed, 14 skipped` |
| `/tmp/al18-extras` | 3.14.6 | 2.2.0 | `1503 passed, 9 skipped` |
| `/tmp/al19-mcp1` | 3.13.14 | 1.30.0 | `1502 passed, 10 skipped` |
| `/tmp/al18-probe313` | 3.13.14 | 2.2.0, pyautogen 0.9.0 | `1504 passed, 8 skipped` |

Those four lines are AMENDMENT 1's figures, reproduced on this branch.

Full suite **with** the freeze class present, which is the tree this document
is committed on:

| Environment | Result |
|---|---|
| checkout | `1500 passed, 14 skipped, 4 xfailed` |
| `/tmp/al18-extras` | `1505 passed, 9 skipped, 4 xfailed` |
| `/tmp/al19-mcp1` | `1504 passed, 10 skipped, 4 xfailed` |
| `/tmp/al18-probe313` | `1506 passed, 8 skipped, 4 xfailed` |

The xfail count is 4 in every environment: XC1, XC2, XC3 and XC4, all strict,
all measured failing at 1.9.0. None of the six new tests is skipped anywhere:
the class needs no optional extra, and XC3 monkeypatches the AutoGen import
check as X3 does. The two added passes in each line are XC5 and XC6, which
carry no marker.

Per test, at freeze, identical in all four environments:

| Test | Shape | At 1.9.0 |
|---|---|---|
| XC1 sync decorator, `send(to, /, **extras)` | C1 | XFAIL |
| XC2 async decorator, same signature | C1 | XFAIL |
| XC3 autogen `protect_functions`, same signature | C1 | XFAIL |
| XC4 `bind_call_parameters` on `f(*args, **kw)` | C2 | XFAIL |
| XC5 `bind_call_parameters` on `g(**kw)` | C3 | PASSED |
| XC6 the 1.9.0 binding shapes | regression guard | PASSED |

`ruff check .` passes and the legacy-name grep over `agentlock tests schema`
returns 0 at `80c85a6`.

### 6. Predictions

Frozen before any mechanism code exists.

**Z1.** All XC tests pass with their xfail markers removed, in every
environment, and no test reports a strict XPASS failure. XC5 and XC6 have no
marker to remove and pass throughout, at freeze and after the build.

**Z2.** Suite figures, stated as received and with the arithmetic resolved. The
new non-skipped test count is 6 in every environment, because none of the six
is guarded.

| Environment | As received | Resolved |
|---|---|---|
| checkout | 1498 plus new non-skipped tests passed, 0 failed, 14 skipped | `1504 passed, 14 skipped, 0 failed` |
| `/tmp/al18-extras` | 1503 plus new passed, 0 failed, 9 skipped | `1509 passed, 9 skipped, 0 failed` |
| `/tmp/al19-mcp1` | 0 failed | `1508 passed, 10 skipped, 0 failed` |

`/tmp/al18-probe313` is not named by Z2 and is not scored. It is measured
anyway, because XC3 runs there against a real `pyautogen 0.9.0` rather than
under the monkeypatched import check, and the figure is recorded in the
amendment.

**Z3.** `mypy agentlock/ --ignore-missing-imports` reports 0 errors, run with
`/tmp/al18-extras/bin/mypy`, the binary that produced B4 and U4. `ruff check .`
passes. The legacy-name grep over `agentlock tests schema` returns 0.

**Z4.** Files touched, and nothing else: `agentlock/binding.py`,
`agentlock/exceptions.py` (per S1), `agentlock/__init__.py`, `pyproject.toml`,
`CHANGELOG.md`, `CITATION.cff`, `README.md`,
`tests/test_v19_enforcement_gaps.py`, `docs/PREDICTIONS_v19_enforcement.md`.
Nine paths across the three commits of this release.

**Z5.** Build in `/tmp/al18-extras` after `rm -rf dist build`: `twine check`
PASSED on both artifacts, wheel METADATA carries `Metadata-Version: 2.4` and
`Version: 1.9.1`. A fresh venv `/tmp/al191-wheel` installs the wheel and an
external script written in `/tmp`, outside the repository, reproduces C1 and C2
as `BindingError` and C3 as allowed, against the installed wheel only. The
script guards its own premise and exits before testing anything if the resolved
`agentlock` package does not live in the venv's `purelib`.

### 7. What this release is not

A behavior-preserving patch. A call whose variadic keyword mapping carries a
key that names another parameter used to be authorized against the flattened
value and executed with the bound one. It now raises. A deployment that made
such calls deliberately, with a function whose signature genuinely has a
parameter and a variadic key of the same name, will see `BindingError` where it
previously saw execution. That is the fix. C3, where there is nothing to
shadow, is untouched and stays allowed.

Everything after this line is append only.

---

## AMENDMENT 3 (2026-09-10): v1.9.1 built, every prediction matched

Measured on `v1.9.1-binding-collision` at
`92abeae fix: reject variadic keyword names that collide with bound parameters`,
which is the build commit, on top of the freeze commit
`d3aa20a docs: freeze 1.9.1 binding collision, reproductions as strict xfails`.
`/tmp/al18-extras` was reinstalled with `pip install -e ".[dev,crypto,mcp]"`
against the built tree before measuring. No merge, no tag, no push, no upload.
The two restatements recorded in the freeze, S1 and S2, are what the build
follows; Y1 to Y4 are otherwise unchanged.

### Scoreboard

| Prediction | Verdict | Evidence |
|---|---|---|
| Z1 | MATCH | The four strict xfail markers came off XC1 to XC4 and all four pass. No test reports XPASS or failure in any of the four environments. XC5 and XC6 passed at freeze and pass after the build, unmarked throughout. The class is 6 passed, 0 skipped, in every environment. |
| Z2 | MATCH | checkout `1504 passed, 14 skipped, 0 failed`; `/tmp/al18-extras` `1509 passed, 9 skipped, 0 failed`; `/tmp/al19-mcp1` `1508 passed, 10 skipped, 0 failed`. Each is the freeze environment's pre-class figure plus exactly 6, the six new tests, none of which is guarded by an optional extra. Suite lines below. |
| Z3 | MATCH | `mypy agentlock/ --ignore-missing-imports` reports `Success: no issues found in 34 source files`. `ruff check .` reports `All checks passed!`. The legacy-name grep over `agentlock tests schema` returns 0. |
| Z4 | MATCH | Nine paths across the three commits, the eight of Y4 plus `agentlock/exceptions.py` per S1. `git show --stat` for both code commits below. Nothing else. |
| Z5 | MATCH | `twine check` PASSED on both artifacts. Wheel METADATA carries `Metadata-Version: 2.4` and `Version: 1.9.1`. `/tmp/al191-wheel`, a fresh venv, installed the wheel and prints 1.9.1. `/tmp/al191_wheel_repro.py`, written outside the repository and run from `/tmp`, reports `15 passed, 0 failed`: C1 and C2 raise `BindingError` and C3 is allowed, against the installed wheel only. |

Five predictions, five MATCH, 0 MISMATCH.

### The four suite lines

```
$ python3 -m pytest -q                              # checkout, CPython 3.14.6, no mcp
1504 passed, 14 skipped, 19 warnings in 3.15s

$ /tmp/al18-extras/bin/python -m pytest -q          # CPython 3.14.6, mcp 2.2.0
1509 passed, 9 skipped, 19 warnings in 3.29s

$ /tmp/al19-mcp1/bin/python -m pytest -q            # CPython 3.13.14, mcp 1.30.0
1508 passed, 10 skipped in 2.88s

$ /tmp/al18-probe313/bin/python -m pytest -q        # CPython 3.13.14, mcp 2.2.0, pyautogen 0.9.0
1510 passed, 8 skipped in 3.30s
```

`/tmp/al18-probe313` is not scored by Z2 and is recorded because XC3 runs there
against a real `pyautogen 0.9.0` rather than under the monkeypatched import
check. Its figure is the freeze environment's 1504 plus the same 6.

Every environment's delta from its own pre-class figure is exactly 6, and every
environment's delta from its own freeze figure is exactly the four xfails
turning into passes.

### Per test, after the build

```
$ /tmp/al18-extras/bin/python -m pytest tests/test_v19_enforcement_gaps.py -q -rs
SKIPPED [1] tests/test_v19_enforcement_gaps.py:329: needs the mcp 1.x SDK
========================= 14 passed, 1 skipped in 0.32s ========================

$ python3 -m pytest "tests/test_v19_enforcement_gaps.py::TestBindingCollision" -q
============================== 6 passed in 0.01s ===============================
```

### Z3 verbatim

```
$ /tmp/al18-extras/bin/mypy agentlock/ --ignore-missing-imports
Success: no issues found in 34 source files

$ /tmp/al18-extras/bin/ruff check .
All checks passed!
```

The source file count stays 34: the release adds no module.

### Z4 verbatim

```
$ git show --stat --name-only --format= d3aa20a
docs/PREDICTIONS_v19_enforcement.md
tests/test_v19_enforcement_gaps.py

$ git show --stat --name-only --format= 92abeae
CHANGELOG.md
CITATION.cff
README.md
agentlock/__init__.py
agentlock/binding.py
agentlock/exceptions.py
pyproject.toml
tests/test_v19_enforcement_gaps.py
```

Nine distinct paths, the eight Y4 names plus `agentlock/exceptions.py`, which
S1 added to the list before the build for one edit: the `BindingError`
docstring. `agentlock/decorators.py` and `agentlock/integrations/autogen.py`
are not touched. All three call sites reach `bind_call_parameters`, so the rule
lands on all three from the one place, which is why Y1 puts it there.

### S1 and S2 closed

S1: `agentlock/exceptions.py` now states both reasons `BindingError` is raised
and where each is raised from. The wrap-time reason, an unreadable signature,
is unchanged and still described as wrap time. The call-time reason is new and
is described as call time, raised from inside the binding and before the gate
is asked anything.

S2: the README per-version count paragraph gained one 1.9.1 sentence in the
form the sentences before it use, so its last entry is the current release
rather than the previous one. The versions table gained its row. A third edit,
not required by S1 or S2 and made for the same reason both exist, extends the
adapter scoping paragraph: the standalone adapters do not carry the collision
rule either, and a paragraph that enumerates what they do and do not cover
would otherwise be read as saying they do.

### Z5 verbatim

```
$ /tmp/al18-extras/bin/twine check dist/*
Checking dist/agentlock-1.9.1-py3-none-any.whl: PASSED
Checking dist/agentlock-1.9.1.tar.gz: PASSED
```

Wheel `agentlock-1.9.1.dist-info/METADATA`, first three lines:

```
Metadata-Version: 2.4
Name: agentlock
Version: 1.9.1
```

`pyproject.toml:2` still reads `requires = ["hatchling<1.30"]` and the build
resolved `hatchling==1.29.0`.

Artifacts, `sha256sum dist/*`:

```
026c785d827c2fd579e5a4e444ee924a5aff36bf50c9f08a64321cfc316e677c  dist/agentlock-1.9.1-py3-none-any.whl
82cbcd6c16210177ccae8cf68cd5993274f571a9e107b2024e63c5c118e984f1  dist/agentlock-1.9.1.tar.gz
```

Neither artifact is uploaded and neither is committed. `dist/` is ignored.

The wheel reproduction, run from `/tmp` against a fresh venv on CPython 3.14.6.
The script guards its own premise and exits before testing anything if the
resolved `agentlock` package is not under the venv's `purelib`.

```
$ /tmp/al191-wheel/bin/python /tmp/al191_wheel_repro.py
agentlock 1.9.1 from /tmp/al191-wheel/lib/python3.14/site-packages/agentlock/__init__.py

(a) C1 through the sync and async decorators
  PASS  sync call raises BindingError
  PASS  the error names the colliding key
  PASS  the error names the function
  PASS  async call raises BindingError
  PASS  neither body ran

(a2) C1 through the AutoGen function map
  PASS  autogen call raises BindingError
  PASS  the autogen body never ran

(b) C2, a variadic key shadowing *args
  PASS  C2 raises BindingError
  PASS  the error names 'args'

(c) C3, a key equal to the variadic's own name, still allowed
  PASS  C3 binds
  PASS  the function receives the same mapping

(d) the 1.9.0 binding shapes, unchanged
  PASS  all three hostile routes deny
  PASS  no body ran
  PASS  a known contact executes
  PASS  the counter is 1

15 passed, 0 failed
ALL PASS
```

Section (d) is not required by Z5 and is there because Z1 pairs XC6 with the
XC tests for the same reason: the collision rule sits in the same function the
1.9.0 argument binding sits in, and a rule that closed C1 by breaking G1's fix
would be a worse release than no rule. The wheel carries both.

### What is left for the manual step

1. Merge, tag `v1.9.1`, and push. Nothing here merged, tagged or pushed.
2. Upload `dist/agentlock-1.9.1-py3-none-any.whl` and
   `dist/agentlock-1.9.1.tar.gz`, whose hashes are recorded above, after the
   push. Nothing here uploaded.
3. After Zenodo mints the 1.9.1 version DOI from the GitHub release, add it to
   `CITATION.cff` as a second `identifiers` entry and to the README's software
   archive line, in a follow-up docs commit. Both places still say the version
   DOI is minted at publication rather than naming a stale one, which is the
   state AMENDMENT 2 left them in and the state this release keeps.

The standalone adapters are the fourth thing and are not part of this release.
None of the five carries the collision rule, which is stated in the CHANGELOG
and the README rather than left for a reader to discover. They are fixed in
their own repositories, on their own releases.

Everything after this line is append only.

---

## 1.9.1 RED PASS FREEZE (2026-09-10): three more binding gaps

Branch `v1.9.1-binding-collision` at `5ad7066 docs: AMENDMENT 3, v1.9.1 built
and every prediction matched`. Working tree clean except the new test class this
freeze adds.

1.9.1 is built but not released: nothing merged, tagged, pushed or uploaded. A
red pass was run against the built wheel, `sha256
026c785d827c2fd579e5a4e444ee924a5aff36bf50c9f08a64321cfc316e677c`, whose content
is identical to this checkout. It found three more binding gaps. They close on
this branch, before the merge, and the version stays 1.9.1.

Nothing below describes code that has been written. Section 2 of this freeze is
the engine as it stands, measured.

### 1. The three gaps, as reported

Quoted as received, before any code was read for them.

> **P1. functools.partial:** `partial(send1, HOSTILE)` where
> `def send1(to, /, **extras)`, called with `to=CONTACT`. `inspect.signature` of
> the partial omits the pre-bound positional; the gate binds `to=CONTACT` and the
> function runs with `to=HOSTILE`. Pre-bound keywords have the same shape.

> **P2. str subclass:** `class Liar(str)` overriding `strip` and `casefold` to
> return CONTACT and `__str__` to return HOSTILE. `_normalize_recipient` calls
> the overridden methods; the gate sees the contact, the function sends to
> `str(value)` which is the attacker.

> **P3. Unobservable declared parameter:** `def send(*args, **kw)` with
> `recipient_parameter="to"` called `send(HOSTILE)`. The gate sees
> `args=(HOSTILE,)`, `"to"` is absent, Step 8 skips, the call runs. The
> declaration can never enforce for positional calls.

### 2. The three gaps at the source, measured at 1.9.1

#### P1

`agentlock/binding.py:140-141` binds the callable it is handed:

```python
    signature = ensure_bindable(func)
    bound = signature.bind_partial(*args, **kwargs)
```

For a `functools.partial`, `inspect.signature` reports the signature of the call
still to be made, not of the function that will run. The arguments the partial
already carries are gone from it.

```
$ python3 repro.py
P1 signature of partial: (**extras)
P1 RESULT: sent function ran with to = attacker@evil.com
```

The gate was shown `{'to': 'bob@company.com'}`, which is the value that landed in
`**extras`, and the function ran with the positional the partial supplied. Both
`agentlock/decorators.py:136` and `:218` and
`agentlock/integrations/autogen.py:130` reach this function, so all three
wrappers carry it. A nested partial behaves identically.

The keyword shape splits by signature. Over `def send1(to, /, **extras)`, where
`to` is positional only, `inspect.signature` refuses the partial outright and
1.9.1 already fails closed on it:

```
partial keyword prebind, po sig
   sig=SIGERR ValueError: partial object ... has incorrect arguments
   BINDERR BindingError: Cannot read the signature of ...
```

Over `def send1(to, **extras)`, where `to` can be passed by keyword, the
signature becomes `(*, to='bob@company.com', **extras)` and the pre-bound value
arrives as a default, which `apply_defaults()` already shows the gate. That
route is bound correctly at 1.9.1 and must stay bound correctly after the fix.

#### P2

`agentlock/policy.py:175-177`, verbatim:

```python
def _normalize_recipient(value: str) -> str:
    """Normalize a recipient or allowlist entry: strip, then casefold."""
    return value.strip().casefold()
```

The annotation says `str`. The value is whatever the caller passed, and a `str`
subclass satisfies every `isinstance` check the gate makes on the way here while
answering `strip` and `casefold` with anything it likes.

```
P2 recipient=: DecisionType.ALLOW None
P2 parameters=: DecisionType.ALLOW None
```

Both routes allow, against a value whose data is the attacker's address, at
`known_contacts_only` with one contact who is not the attacker.

#### P3

`agentlock/gate.py:859`, the D18 extraction's own condition, verbatim:

```python
        if _v15 and _rp and isinstance(parameters, dict) and _rp in parameters:
```

`_rp in parameters` is the skip. `bind_call_parameters` keys a `VAR_POSITIONAL`
by its own parameter name, because its entries have no names of their own, so a
positional call to `def send(*args, **kw)` produces `{'args': (HOSTILE,)}` and no
`to` at all. The declared parameter is absent, the condition is false, pipeline
step 8 never runs, and the call is allowed.

```
P3 RESULT: sent to attacker@evil.com calls = 1
P3 wrap over *args: wrapped OK
```

The second line is the wrap-time half. `def send(*args)` cannot receive a `to`
by any route, and the block declaring one is accepted anyway.

### 3. Decisions of record

Recorded as received. Section 4 records two defects in them, found while taking
Section 2's measurements and before any code was written.

**Q1.** `bind_call_parameters` unwraps `functools.partial` (and
`partialmethod`) before binding: `func` becomes `partial.func`, `args` becomes
`partial.args + args`, `kwargs` becomes `{**partial.keywords, **kwargs}`,
recursively for nested partials. The shadow rule then applies to pre-bound values
too. `ensure_bindable` applies the same unwrapping so the wrap-time check sees
the real callable.

**Q2.** In `agentlock/policy.py`, `_normalize_recipient` first coerces with
`str.__str__(value)` and every recipient helper operates on that plain `str`. In
`gate.py` D18 extraction, the same coercion is applied to each `str`-typed value
before it is placed in `recipients`, so `RequestContext` never carries a subclass
instance. `isinstance` checks are unchanged; the coercion is what changes.

**Q3.** `ensure_bindable` gains an optional keyword `must_observe: str | None`.
When given: if the (unwrapped) signature has no parameter of that name and no
`VAR_KEYWORD`, raise `BindingError` at wrap time stating that the declared
recipient parameter cannot be observed on this callable. Every wrapper
(`decorators.py` sync and async, autogen `guarded`) passes the block's
`scope.recipient_parameter` as `must_observe`, resolving it from the
`AgentLockPermissions` the wrapper already holds; `None` when the block declares
none.

**Q4.** `bind_call_parameters` gains the same optional `must_observe`. When given
and the key is absent from the bound parameters and the `VAR_POSITIONAL` tuple is
non-empty, raise `BindingError` at call time: the call supplied positional
arguments the gate cannot name while a recipient parameter is declared. When the
key is absent and there are no positional extras, the existing D19 skip applies
unchanged.

**Q5.** Version stays 1.9.1 (unreleased). CHANGELOG 1.9.1 Security section
extended with P1 to P3, and a Threat model note: the gate binds to the callable's
signature as `inspect` reports it, following `__wrapped__`; a wrapper that
advertises one signature and alters arguments before calling the inner function
is the application's own code and outside the boundary.

**Q6.** Files: `agentlock/binding.py`, `agentlock/policy.py`, `agentlock/gate.py`,
`agentlock/decorators.py`, `agentlock/integrations/autogen.py`, `CHANGELOG.md`,
`tests/test_v19_enforcement_gaps.py`,
`docs/PREDICTIONS_v19_enforcement.md` (append only). Nothing else.

### 4. Defects in the decisions, found before this freeze was committed

Two. Both were found by reading the repository while preparing to apply Q1 to
Q6, and both before any mechanism code was written. They are recorded here for
the reason Section 4 of the original freeze and Section 4 of the 1.9.1 freeze are
where they are: nothing had been committed yet, so there is no earlier record for
an amendment to correct. Q1 to Q6 above are reproduced exactly as received and
are not edited. The restatements are what the build follows and what Section 6 is
scored against.

#### T1. Q2's stated invariant is wider than the site Q2 names

Q2 names one site in `gate.py`, the D18 extraction, and one field, `recipients`.
The reason it gives is wider than that: "so `RequestContext` never carries a
subclass instance". `RequestContext` carries two recipient fields, not one.
`agentlock/gate.py:894` passes the caller's asserted `recipient` straight
through:

```python
            recipient=recipient,
```

Coercing only `resolved_recipients` leaves `ctx.recipient` holding whatever the
caller passed. Enforcement would still be correct, because
`_normalize_recipient` coerces at the point of comparison, but the invariant Q2
states as its reason would be false, and XR5 is written against exactly that
field.

**Restatement, which the build follows:** the coercion is applied at the same
site to the asserted `recipient` as well as to each entry of
`resolved_recipients`, so the field Q2's reason names is the field the build
protects. Everything else in Q2 stands unchanged, including that `isinstance`
checks are untouched.

#### T2. Q6's file list excludes the one docstring Q3 and Q4 make false

`agentlock/exceptions.py:259-277`, verbatim:

```python
class BindingError(AgentLockError):
    """A call's arguments cannot be bound to parameter names, so it cannot be
    gated.

    Two reasons, raised at two different moments.

    The callable's signature cannot be read.  Raised at wrap time: a wrapper
    that cannot bind a call's arguments cannot show the gate what the call
    carries, so it refuses to be built rather than gating a subset of the
    arguments and letting the rest through.

    Or the call's ``**kwargs`` mapping carries a key that names another
    parameter of the same callable.  Raised at call time, from inside the
    binding and before the gate is asked anything: flattening such a key over
    the parameter it names would show the gate one value while the function
    ran with the other, so the call is refused instead.  A key equal to the
    ``**kwargs`` parameter's own name shadows nothing and is bound normally.
    """
```

That docstring was itself rewritten one release ago, under S1, because the
version before it was false. "Two reasons, raised at two different moments" is an
enumeration, and Q3 and Q4 each add one: a wrap-time reason (a declared recipient
parameter no signature can carry) and a call-time reason (positional arguments
the gate cannot name while such a parameter is declared). Following Q6 literally
ships four reasons under a docstring that says two and lists them.

This is S1's shape, one release later, and the same answer applies.

**Restatement, which the build follows:** `agentlock/exceptions.py` is added to
Q6's file list, for one edit, the `BindingError` docstring, rewritten to state
all four reasons and where each is raised from. Nothing else in that file is
touched. Prediction Z9 is scored against the restated list of nine paths, not
against Q6's eight.

### 5. Two things the build does not change, recorded so the record is complete

Neither is a defect in a decision. Both are limits the decisions leave in place,
and naming them here is cheaper than discovering later that the record implied
otherwise.

**The decorator still requires an explicit `name` over a partial.**
`agentlock/decorators.py:91` reads `tool_name = name or func.__name__`, and a
`functools.partial` has no `__name__`. Q1 unwraps inside `bind_call_parameters`
and `ensure_bindable`; it says nothing about tool naming, and the build changes
nothing there. Decorating a partial without passing `name` raises
`AttributeError` at wrap time, which fails closed. XR1 and XR2 pass `name`
explicitly.

**`unwrap_partial` is public in `agentlock/binding.py` and not re-exported.**
The wrappers need the callable that will actually run, in order to invoke
`target(*bound.args, **bound.kwargs)` rather than re-applying the partial's own
arguments. It is resolved once at wrap time, not per call. It is added to
`binding.__all__` and deliberately not added to `agentlock/__init__.py`, because
Q6 excludes that file and no decision asks for a new name on the package's public
surface.

### 6. Measurements at freeze

Environments are the four of record, unchanged. Full suite on
`v1.9.1-binding-collision` at `5ad7066`, **before** the new test class exists.
These are AMENDMENT 3's figures, reproduced:

| Environment | Interpreter | mcp | Result |
|---|---|---|---|
| checkout | 3.14.6 | absent | `1504 passed, 14 skipped` |
| `/tmp/al18-extras` | 3.14.6 | 2.2.0 | `1509 passed, 9 skipped` |
| `/tmp/al19-mcp1` | 3.13.14 | 1.30.0 | `1508 passed, 10 skipped` |
| `/tmp/al18-probe313` | 3.13.14 | 2.2.0, pyautogen 0.9.0 | `1510 passed, 8 skipped` |

Full suite **with** the freeze class present, which is the tree this document is
committed on:

| Environment | Result |
|---|---|
| checkout | `1508 passed, 14 skipped, 7 xfailed` |
| `/tmp/al18-extras` | `1513 passed, 9 skipped, 7 xfailed` |
| `/tmp/al19-mcp1` | `1512 passed, 10 skipped, 7 xfailed` |
| `/tmp/al18-probe313` | `1514 passed, 8 skipped, 7 xfailed` |

Eleven tests are added and none is skipped anywhere: the class needs no optional
extra. Seven carry a strict xfail and four do not, so every environment gains
exactly 4 passes and 7 xfails over its pre-class figure.

Per test, at freeze, identical in all four environments:

| Test | Shape | At 1.9.1 |
|---|---|---|
| XR1 sync decorator over `partial(send1, HOSTILE)` | P1 | XFAIL |
| XR2 async decorator, same partial | P1 | XFAIL |
| XR3 partial pre-binding `to` by keyword, positional only signature | P1 | PASSED |
| XR4 `bind_call_parameters` on a partial with a pre-bound keyword | P1 guard | PASSED |
| XR5 lying `str` subclass asserted as `recipient` | P2 | XFAIL |
| XR6 lying `str` subclass in the declared parameter | P2 | XFAIL |
| XR7 subclass whose data is a contact, methods lying | P2 | XFAIL |
| XR8 wrap time, `def send(*args)` with `recipient_parameter` declared | P3 | XFAIL |
| XR9 wrap time, `def send(*args, **kw)` wraps | P3 guard | PASSED |
| XR10 call time, `send(HOSTILE)` on that wrapper | P3 | XFAIL |
| XR11 no declared recipient parameter, `def send(*args)` runs | P3 guard | PASSED |

XR3 passes at freeze for a reason the build replaces. `inspect.signature` refuses
`partial(send1, to=CONTACT)` over a positional only `to`, so 1.9.1 raises
`BindingError` from the unreadable signature. After Q1 the signature is readable,
the pre-bound keyword can only reach `**extras`, and the shadow rule refuses it.
The test asserts what must hold in both worlds: `BindingError` or `TypeError`,
and the function never runs with the attacker.

XR7 fails at freeze in the direction opposite to XR5 and XR6, which is why it is
in the set. At 1.9.1 the gate reads the lying methods and denies a value whose
data is a known contact. The fix is coercion, not a ban on subclasses, and XR7 is
the half of that rule the other two do not measure.

`ruff check .` reports `All checks passed!`, `mypy agentlock/
--ignore-missing-imports` reports `Success: no issues found in 34 source files`,
and the legacy-name grep over `agentlock tests schema` returns 0, all at
`5ad7066` with the freeze class present.

### 7. Predictions

Frozen before any mechanism code exists.

**Z6.** All eleven XR tests pass with their markers removed, in every
environment, and no test in `tests/test_v19_enforcement_gaps.py` reports a strict
XPASS failure. XR3, XR4, XR9 and XR11 have no marker to remove and pass
throughout, at freeze and after the build.

**Z7.** Suite figures, stated as received and with the arithmetic resolved. The
new non-skipped test count is 11 in every environment, because none of the eleven
is guarded.

| Environment | As received | Resolved |
|---|---|---|
| checkout | 1504 plus new non-skipped passed, 0 failed, 14 skipped | `1515 passed, 14 skipped, 0 failed` |
| `/tmp/al18-extras` | 1509 plus new passed, 0 failed, 9 skipped | `1520 passed, 9 skipped, 0 failed` |
| `/tmp/al19-mcp1` | 0 failed | `1519 passed, 10 skipped, 0 failed` |

`/tmp/al18-probe313` is not named by Z7 and is not scored. It is measured anyway,
because XC3 runs there against a real `pyautogen 0.9.0` rather than under the
monkeypatched import check, and the figure is recorded in the amendment. Its
resolved figure is `1521 passed, 8 skipped`.

**Z8.** `mypy agentlock/ --ignore-missing-imports` reports 0 errors, run with
`/tmp/al18-extras/bin/mypy`, the binary that produced B4, U4 and Z3. `ruff check
.` passes. The legacy-name grep over `agentlock tests schema` returns 0.

**Z9.** Files touched, and nothing else: `agentlock/binding.py`,
`agentlock/policy.py`, `agentlock/gate.py`, `agentlock/decorators.py`,
`agentlock/integrations/autogen.py`, `agentlock/exceptions.py` (per T2),
`CHANGELOG.md`, `tests/test_v19_enforcement_gaps.py`,
`docs/PREDICTIONS_v19_enforcement.md`. Nine paths across the three commits of
this red pass.

**Z10.** Rebuild in `/tmp/al18-extras` after `rm -rf dist build`: `twine check`
PASSED on both artifacts, wheel METADATA carries `Metadata-Version: 2.4` and
`Version: 1.9.1`. A fresh venv `/tmp/al191b-wheel` installs the wheel, and an
external script written in `/tmp`, outside the repository, reproduces P1 as
`BindingError`, P2 as a denial, and P3 as `BindingError` at wrap time and at call
time, against the installed wheel only. The script guards its own premise and
exits before testing anything if the resolved `agentlock` package does not live
in the venv's `purelib`.

### 8. What this red pass is not

A behavior-preserving patch, and not a new feature either.

A deployment that gates a `functools.partial` was being authorized against the
part of the call the partial had not already made. It now binds the whole call,
and where the partial's own arguments collide with the caller's, the 1.9.1 shadow
rule refuses it rather than picking a winner.

A deployment that passes a `str` subclass as a recipient was being enforced
against whatever that subclass's `strip` and `casefold` returned. It is now
enforced against the string's data. This allows values that used to deny as well
as denying values that used to allow: XR7 is the first direction and XR5 is the
second.

A deployment that declared `recipient_parameter` over a variadic signature was
getting no enforcement at all on positional calls, silently. It now raises at
wrap time when the parameter can never be carried, and at call time when a
particular call carries positional arguments the gate cannot name. Both are new
refusals on paths that previously ran.

Everything after this line is append only.
