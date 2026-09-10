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
