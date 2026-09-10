# Changelog

All notable changes to AgentLock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.10.0] - 2026-09-10

The integration hardening release. An external review of the published 1.9.1 wheel found seven groups of issue and supplied a runnable 33-test oracle for them, which is committed verbatim as `tests/test_v110_system_review.py` and is the definition of done for this release. Six of the seven are places where the engine's own execution paths did not carry a decision the gate had already made. This release adds no detection feature, no new schema field and no new denial reason: the two reasons it newly attaches at commit time, `param_lineage` and `novel_lineage`, are the ones `authorize()` already used.

**This release is not additive.** Four of the fixes change behavior on paths that were failing open, and code that relied on those paths will be denied or transformed where it previously was not. That is the point of them. The Security section says exactly which calls change.

Suite: **1568 passed, 24 skipped on CPython 3.14.6 with no optional extras**, **1583 passed, 9 skipped on CPython 3.14.6 with `mcp 2.2.0`, `fastapi`, `flask` and PyNaCl**, and **1584 passed, 8 skipped on CPython 3.13.14 with the same extras**. 0 failed in each. Under `mcp 1.30.0` the engine suite is **1568 passed, 20 skipped, 0 failed**, with the review file's four `mcp` cases deselected: they construct `Server(name, on_call_tool=...)`, which is the 2.x constructor, so they cannot run against a 1.x SDK at all. The engine's 1.x hook is covered instead by `tests/test_v110_hardening.py`, which runs in every environment. `mypy agentlock/ --ignore-missing-imports` reports 0 errors and `ruff check .` is clean.

### Security

- **One execution contract: a declared transformation now reaches the tool and the caller on every path.** `authorize()` computed parameter transformations and an output modifier and then discarded the transformed parameters entirely; the output modifier survived only on `AuthResult`, where a caller had to know to thread it by hand into `execute()`. Of the six execution routes, exactly one did that. `gate.call()`, both decorators, both MCP hooks and the AutoGen guarded map all returned untransformed output, and no route at all invoked the callable with transformed parameters. A tool declaring `redact_pii` on its output returned the raw SSN to five of six callers, and a tool declaring it on a parameter passed the raw SSN to the function in all six. `AuthResult` now carries `effective_parameters` alongside `modify_output_fn`, `gate.call()` forwards both to `gate.execute()`, and each integration applies both. Credited to an external review of the 1.9.1 wheel.
- **The execution token is bound to the effective parameters, not to the requested ones.** A grant names the call that may run. The token's `parameters_hash` is now taken over the parameters after transformation, and the token retains them as `effective_parameters` so no execution path has to re-derive them from policy. A caller that hands `execute()` the parameters it asked with is recognized by a second hash, `requested_parameters_hash`, and is executed against the grant rather than against its own copy; a caller presenting neither is rejected exactly as it was before. The parameter-binding property is unchanged: a substituted call still fails `validate_and_consume`.
- **`whitelist_path` enforces resolved containment instead of comparing strings.** The check was `value.replace("\\", "/").startswith(prefix)`, which tests how a path is spelled and not where it leads. `/allowed/../private.txt` starts with `/allowed/`, and a symlink at `/allowed/link.txt` starts with `/allowed/` whatever it points at, so both were permitted and the tool then read the file the prefix existed to exclude. The candidate is now lexically normalized and both it and each prefix are resolved with `os.path.realpath`, which collapses `..` and follows symlinks, and the path is allowed only when `os.path.commonpath` of the pair IS the resolved prefix. Any exception blocks. A side effect of the last comparison: `/data-private/x` no longer passes a `/data` prefix, which a string prefix test allowed.
- **`whitelist_path` is canonicalization at authorization time and not a race resistant filesystem sandbox, and now says so.** It reports where a path led when the gate looked. Between that moment and the host's `open()` a component can be replaced, and nothing decided here prevents that. A host that must be safe against an actively hostile filesystem has to open the file safely itself, with `O_NOFOLLOW` or an `openat` sequence anchored to a directory descriptor it already holds.
- **MCP identity is resolved host first.** `_extract_auth` read `_agentlock_role` and `_meta.agentlock_role` out of the tool call arguments and fell back to the configured default only when the client sent nothing, so a client that sent `_agentlock_role: admin` to a server constructed with `default_role="user"` was authorized as an admin. Resolution is now per field and a configured default is authoritative: the client's value for that field is stripped and ignored, and the substitution is audited as `identity_override_ignored`. A field with no configured default still takes the client's value, which trusts the transport and is documented as doing so. Both hook generations. Separately, both reserved keys are now popped unconditionally; popping them inside an `or` chain left `_agentlock_user_id` in the arguments whenever `_meta` had already supplied a value.
- **HTTP tool selection is decided by the server's route mapping.** The FastAPI middleware read `X-AgentLock-Tool` first and consulted `tool_name_from_path` only when that header was absent, so a caller reaching an admin route could name a low-risk tool in the header and be judged against that tool's permission block while the admin handler ran. A caller that can choose which block its request is judged against has no block. When a mapping is configured it is now authoritative, a differing header is refused with 403 and reason `tool_selection_conflict`, and a route the mapping declines passes through with the header ignored. The header is honored only where no mapping is configured. Flask gains the same rule over `tool_name_from_endpoint`, and with it the `X-AgentLock-Tool` header it did not previously read.
- **A bearer JWT beats the identity headers.** In both frameworks the JWT was consulted only as a fallback when `X-AgentLock-User-Id` was absent, so a caller could present a token and then override the identity inside it with a header. When the request carries a bearer token whose payload names a subject, its claims are now authoritative and the identity headers are ignored entirely rather than merged. As before, the payload is decoded and NOT verified: signature verification belongs upstream.
- **Deferred commit re-evaluates parameter and novel lineage against the completed context.** The end-of-turn re-decision consulted the action-class disjunct and the session taint flag and nothing else, so with `gate_consequential=False` and a value-carrying declaration, a queued action whose target provably traced to content that arrived after it was queued committed anyway, while a fresh `authorize()` of the identical call at the identical moment denied it. That is the same disagreement between the two enforcement points that 1.4.0 introduced the shared predicate to prevent, one level down. The two gate-owned per-parameter checks now run first at commit time, over the queued parameters, against the context as it stands at the end of the turn. An action set to `log` stays observe-only and never denies. A record that denies resolves as `denied` and carries `denial_reason`, which is also emitted in the resolution audit record.
- **The parameters a deferral is re-decided over are snapshotted at queue time.** `queue_commit` stored the caller's dict by reference, so a caller mutating it after queuing changed what the commit-time decision was taken over.
- **A terminal deferral state is terminal.** `resolve_commit_queue` assigned `resolution` unconditionally on every queued record, so a record a timeout sweep had already resolved to `deny` was rewritten to `committed` by the next call. A denial a later call can undo is not a denial. Records carrying a resolution are now skipped entirely, not even re-annotated.
- **Deferral expiry is enforced where the queue is resolved, not only by whoever remembers to sweep.** `resolve_commit_queue` had no expiry rule of its own, so a record long past its timeout that `check_timeouts` happened not to visit resolved as though it were fresh. A timeout that defaults to DENY and depends on an external cadence to be applied is advisory, which is the opposite of what it exists to be. An expired record now resolves to `deny` with `resolved_by="timeout"` whether or not a sweep ran.
- **A failed async call no longer leaves its token ACTIVE.** The async decorator consumed the token after the awaited call returned and re-raised on the exception path without consuming, so a single-use grant survived the failure of the call it was issued for and stayed replayable for the rest of its TTL. Both decorators now validate and consume before the call begins, which is the ordering the sync path already had through `gate.execute`. A call that raises has a used token.

### Changed

- **`ExecutionToken` carries two new fields.** `effective_parameters` holds the call the grant is a grant for, and `requested_parameters_hash` holds the hash of what the caller asked with. Both are set by `TokenStore.issue`. A `TokenStore` replacement implementing the backend protocol should populate them; the gate reads `effective_parameters` on the execution path and treats `None` as "the caller's parameters are the effective ones", which is the pre-1.10 behavior.
- **`gate.execute()` takes `effective_parameters`.** Existing two-step callers need no change: with the parameters they authorized with, they now get the transformation applied for them rather than silently dropped.
- **`AgentLockFlask` installs its `before_request` hook unconditionally.** It previously installed it only when `tool_name_from_endpoint` was given, which made the header case unreachable. A request naming no tool and matching no mapping passes through untouched, as every unmapped request did before; the delta is that an app with no mapping now gates a request that names a tool in `X-AgentLock-Tool`.
- **`binding.apply_effective_parameters` is new and public.** It is the inverse of the flattening `bind_call_parameters` performs: it writes authorized values back into a `BoundArguments` by name, restoring flattened `**kwargs` keys to their mapping and keeping `*args` a tuple, so a positional-only parameter can be transformed even though it has no keyword form. The decorators and the AutoGen map rebuild each call through it.
- **`tests/test_v110_system_review.py` is excluded from four ruff style rules.** It is the external review's own file, held verbatim, and reformatting the artifact that defines done would turn an independent check into a restatement.
- **The standalone adapters carry none of this.** They ship from their own repositories and are updated separately. None of them applies a declared parameter or output transformation, and `mcp-agentlock` resolves identity client-first exactly as the in-repo hook did before this release.

## [1.9.1] - 2026-09-10

A patch release closing four binding gaps, all found by the same external review that found the three 1.9.0 gaps: one in the variadic keyword flattening, and three more found in a red pass against the 1.9.1 build before it was released. No new feature, no new denial reason and no schema change. The version did not move between the two rounds, because the first was never released.

Suite: **1515 passed, 14 skipped on CPython 3.14.6 with no optional extras**, **1520 passed, 9 skipped on CPython 3.14.6 with `mcp 2.2.0`**, **1519 passed, 10 skipped on CPython 3.13.14 with `mcp 1.30.0`**, and **1521 passed, 8 skipped on CPython 3.13.14 with `mcp 2.2.0` and `pyautogen 0.9.0`**. 0 failed in every environment. `mypy agentlock/ --ignore-missing-imports` reports 0 errors.

### Security

- **A `**kwargs` key that names another parameter is refused instead of flattened over it.** `bind_call_parameters` flattened a `VAR_KEYWORD` mapping onto the top-level parameters dict with `parameters.update(value)`. A key in that mapping equal to the name of another bound parameter overwrote the bound value, and the gate was then shown a value the function does not receive. Two shapes carried it. With `def send(to, /, **extras)`, the call `send("attacker@evil.test", to="bob@company.com")` bound `to` to the attacker positionally, put `to="bob@company.com"` in `extras` because `to` is positional only, and flattened the contact over the attacker: the gate authorized a known contact and the function ran with the attacker. With `def f(*args, **kw)`, the call `f(1, 2, args="spoof")` showed the gate `args="spoof"` while the function received `args=(1, 2)`. The sync wrapper, the async wrapper and the AutoGen `protect_functions` map all reached the same binding and all three carried it. Before flattening, the binding now computes the set of names of every other parameter in the signature and raises `BindingError` if any key of the mapping is in it, naming the colliding key and the function. Credited to the same external review.
- **This is a call-time refusal and it reaches the caller.** The error is raised from inside the binding, before `authorize()` is called, so the call is never authorized and the function never runs. No wrapper catches it: it propagates like `TokenInvalidError` does. A deployment calling a function whose signature genuinely has both a parameter and a `**kwargs` key of the same name will see `BindingError` where it previously saw execution.
- **A key equal to the `**kwargs` parameter's own name is not a collision and stays allowed.** With `def g(**kw)`, the call `g(kw="spoof")` has no parameter named `kw` for the key to shadow: `kw` is the variadic itself, and the gate and the function see the same mapping. Nothing is hidden, so nothing is refused, and this call binds exactly as it did at 1.9.0.
- **A `functools.partial` is bound through to the function underneath.** `inspect.signature` of a partial describes the call still to be made, not the function that will run, so the arguments the partial already carries are absent from it. With `def send(to, /, **extras)`, `partial(send, "attacker@evil.test")` called with `to="bob@company.com"` showed the gate the contact, which had landed in `extras`, and ran the function with the attacker the partial supplied. The binding now collapses a chain of partials into the call it stands for before binding: the callable becomes `partial.func`, the positional arguments become `partial.args` in front of the call's own, and the keywords become the partial's underneath the call's, repeatedly for nested partials. The collision rule above then applies to the partial's own arguments too, which is what refuses the shape just described. `partialmethod` is collapsed the same way. Wrappers invoke the callable underneath, because that is what the binding is taken against.
- **A recipient is read for the characters it holds, not for what its methods say.** `_normalize_recipient` called `strip` and `casefold` on the value it was given. A `str` subclass satisfies every `isinstance` check the gate makes while overriding those two to name a known contact and `__str__` to name somewhere else, so the gate authorized the contact and the application, sending to `str(value)`, delivered to the attacker. Every recipient string is now coerced with `str.__str__`, which is the slot rather than the instance's override, before it is stripped, casefolded or compared, and before it is placed in the request context. Subclasses are not rejected: a subclass whose data is a known contact is allowed even if its methods claim otherwise, which is the same rule read in the other direction.
- **A declared recipient parameter that can never be observed is refused at wrap time.** A block declaring `scope.recipient_parameter="to"` over `def send(*args)` was accepted. That signature has no `to` and no `**kwargs` for one to arrive in, so pipeline step 8 looked up a key that could never be present, found nothing, skipped, and the declared recipient policy decided nothing for every call. The wrapper now raises `BindingError` at decoration when the declared name is neither a parameter of the signature nor able to arrive through `**kwargs`, before the tool is registered. `def send(*args, **kw)` still wraps: `**kw` can carry it.
- **A call that hides its recipient in `*args` is refused at call time.** `def send(*args, **kw)` can carry a `to`, so the pair is allowed to be built, but the call `send("attacker@evil.test")` binds `args=("attacker@evil.test",)` and no `to` at all, and step 8 skips again. When a recipient parameter is declared, the bound parameters carry no argument of that name, and positional arguments did arrive in `*args`, the binding now raises `BindingError`. The gate does not guess which unnamed positional was meant to be the recipient. A call with no positional extras is not this case: the declared parameter is simply absent, and the existing skip is unchanged.
- **Threat model.** The gate binds to the callable's signature as `inspect` reports it, following `__wrapped__`. A wrapper that advertises one signature and alters the arguments before calling the inner function is the application's own code, on the trusted side of the boundary, and is outside what the gate can check. What the gate guarantees is that the call it authorizes is the call it binds, and that the wrappers invoke the function from that same binding.

### Changed

- **`BindingError`'s documentation now states all four reasons it is raised and where each is raised from.** Through 1.9.0 the class docstring read "Raised at wrap time, never at call time", which the collision rule makes false. This release adds two more reasons, one at each moment: an unobservable declared recipient parameter at wrap time, and a recipient hidden in `*args` at call time. The unreadable-signature case is still a wrap-time refusal and is unchanged.
- **`AgentLockMCPServer` is unchanged, and the standalone adapters carry none of these rules.** The MCP integration does not bind call arguments to a Python signature; it passes the SDK's `arguments` mapping, which has names already. The five standalone adapters ship from their own repositories and are updated separately: none of them binds through partials, coerces recipient strings, or checks that a declared recipient parameter is observable.

## [1.9.0] - 2026-09-09

The enforcement completeness release. An external review of the published 1.8.0 wheel found three places where the engine did not enforce what its own documentation said it enforced. All three are fixed. This release adds no detection feature, no new denial reason and no schema change.

**This release is not additive.** Two of the three fixes change behavior on paths that were failing open, and code that relied on those paths will now be denied. That is the point of them. The Security section below says exactly which calls change.

Suite: **1503 passed, 9 skipped on CPython 3.14.6 with `mcp 2.2.0`**, **1502 passed, 10 skipped on CPython 3.13.14 with `mcp 1.30.0`**, and **1504 passed, 8 skipped on CPython 3.13.14 with `mcp 2.2.0` and `pyautogen 0.9.0`**. 0 failed in every environment. `mypy agentlock/ --ignore-missing-imports` reports 0 errors, down from 4.

### Security

- **Every argument of a call now reaches the gate, not just the keyword ones.** The decorator wrappers and the AutoGen function map built the gate's `parameters` dict out of `kwargs` alone and then spliced the positional arguments back in at execution. A tool declaring `scope.recipient_parameter="to"` denied `send(to=hostile)` and executed `send(hostile)`, and executed a bare `send()` whose default recipient was hostile. Every parameter-level check the gate performs was blind to both routes. Calls are now bound to the function's signature with defaults applied before authorization, and the function is invoked from that same binding, so what was authorized and what runs cannot drift apart. Credited to an external review of the 1.8.0 wheel.
- **An execution token authorized with no parameters is bound to the empty call.** `TokenStore.issue` stored an empty `parameters_hash` when the authorized call carried no parameters, and `validate_and_consume` compared hashes only when both the supplied parameters and the stored hash were non-empty. A token obtained by authorizing nothing therefore executed anything. The hash is now always computed, the empty call included, and the comparison is unconditional. The evidence path in `gate.py` follows the same rule, and a deferral's stored parameter hash is likewise always written. Credited to an external review of the 1.8.0 wheel.
- **Caller contract:** the parameters passed to `execute()` must be the parameters passed to `authorize()`. `None` and `{}` are the same call. A mismatch raises `TokenInvalidError`. Every in-repo call site already satisfied this; a deployment that authorized one call and executed another was relying on the gap.
- **An MCP server the wrapper cannot hook no longer constructs silently.** `AgentLockMCPServer._install_hook` looked for `call_tool` on the server and returned quietly when it was absent. Under mcp 2.x, which the `mcp` extra resolves to, `Server` has no `call_tool`: the wrapper installed nothing, reported nothing, and every tool handler ran ungated. A server exposing neither `call_tool` nor `add_request_handler` now raises `IntegrationUnsupportedError` at construction, naming the server type and the installed mcp version. Credited to an external review of the 1.8.0 wheel.
- **A callable whose signature cannot be read refuses to be wrapped.** A wrapper that cannot bind a call's arguments cannot show the gate what the call carries, so it would gate a subset and let the rest through. `BindingError` is raised at wrap time rather than on the first call.
- **Scope of the argument-binding fix.** The engine's own decorators and in-repo integrations bind every call argument, and that is the whole of what this release changes. The standalone adapters ship from their own repositories and are updated separately. At their current releases, `crewai-agentlock` 0.2.0 and `langchain-agentlock` 0.1.0 authorize keyword arguments only, and of those two only `crewai-agentlock` carries positional arguments past the gate into the wrapped call; `mcp-agentlock` 0.2.1 passes the SDK's `arguments` mapping, `openai-agentlock` 0.1.0 passes the parsed JSON arguments object, and `openclaw-agentlock` 0.1.0 passes the caller's parameters mapping, so each of those three hands the gate the same mapping it hands the tool and none of them has a positional route. No standalone adapter applies the wrapped function's defaults, so a parameter the caller omits and the function defaults is not seen by the gate in any of them.

### Added

- **mcp 2.x support.** `AgentLockMCPServer` now installs on both SDK generations. Under 1.x it patches the `@server.call_tool()` decorator, as before, and it now forwards that decorator's own arguments (`validate_input=` and anything the SDK adds later) instead of discarding them. Under 2.x it wraps `add_request_handler` so that any registration for `tools/call` is guarded, reads `params.name` and `params.arguments`, strips the reserved `_agentlock_` keys from a copy, and invokes the original handler with a `params` object carrying the cleaned arguments. It also wraps a `tools/call` handler that was already registered when the wrapper is constructed, which is the route `Server(on_call_tool=...)` takes: that handler is written straight into the registry and never passes through `add_request_handler`. Both majors are tested against the real SDK.
- **`agentlock/binding.py`,** with `bind_call_parameters(func, args, kwargs)` and `ensure_bindable(func)`. `bind_call_parameters` returns the dict of everything a call carries, keyed by parameter name, with defaults applied, `**kwargs` contents flattened to the top level and `*args` kept as a tuple under its own name, alongside the `BoundArguments` that reconstruct the call. Both are exported from the package root.
- **`BindingError` and `IntegrationUnsupportedError`,** both subclasses of `AgentLockError`, both exported from the package root.
- **`tests/test_v19_enforcement_gaps.py`,** nine tests. Each of the three gaps was first committed as a strict `xfail` measured failing against the engine at `d56122d`, and the markers came off as the gaps closed. Four of the nine drive the real MCP SDK: two under 2.x, one under 1.x, one on a server with neither surface.

### Fixed

- **Four mypy errors, and the type checker is clean.** `policy.py:219` and `:257` lacked annotations; both take or return `LineagePolicyConfig`. `gate.py:882` and `:884` reused the local name `_asserted`, already bound earlier in `authorize()` to a `list[str]`, for the D20 recipient disagreement check, which mypy read as a `list[str]` rebound to `str` and then compared as a set of lists. The two uses were in disjoint branches, so there was no runtime defect; the D20 local is now named `_asserted_recipient`.

### Unchanged

- The `mcp` extra stays `mcp>=1.0`. Both majors are supported and both are tested, so there is nothing to pin away from.
- `SCHEMA_VERSION` stays `1.5`. No schema file is touched.
- No denial reason, permission field, or pipeline step is added, removed or reordered.

## [1.8.0] - 2026-09-09

The recipient release. Pipeline Step 8 was a comment block from v1.0 through v1.7.0: the `recipient` argument was threaded end to end and then discarded, and `RECIPIENT_NOT_ALLOWED` existed only as an enum member that nothing raised. It is now enforced.

**The claim, at the strength the measurements support:**

> For a tool registered at permissions version 1.5 or later, a nonempty recipient is checked against the tool's `scope.allowed_recipients` at Step 8, and a recipient the policy does not admit denies with reason `recipient_not_allowed`. Blocks at version 1.4 and below take the same path they took in v1.7.0.

Suite, both runs with `pip install -e ".[dev,all]"` and 0 failed: **1495 passed, 8 skipped on CPython 3.14.6**, and **1496 passed, 7 skipped on CPython 3.13.14**. The one test between them is the AutoGen integration test, which executes on 3.13 and skips on 3.14 because the `autogen` extra resolves only below 3.14 (see below). The 7 skips common to both interpreters are the pre-increment-3 cross-hop baselines carried from 1.7.0, which are engine-state skips no install line can clear. A bare `pip install -e ".[dev]"` runs **1479 passed, 24 skipped**, and `pip install -e ".[dev,crypto,mcp]"`, the line CI now uses, reproduces the 3.14 figure exactly.

### Added

- **Recipient policy enforcement at Step 8.** Enforcement fires only when the permission block is at version 1.5 or later and a nonempty recipient is supplied. The version floor uses `version_at_least`, the same gating idiom the lineage checks use, and the check is independent of the lineage engine.
- **`known_contacts_only`.** Allows the recipient when it appears in the session's known contacts, and denies otherwise. An empty contact set denies every recipient.
- **`allowlist`.** Allows the recipient on an exact address match against `scope.recipient_allowlist`, or when an entry beginning with `@` names exactly the recipient's domain. Exact domain only: a subdomain of an allowlisted domain does not match.
- **`same_domain`.** Allows the recipient when its domain equals the domain of the session's `user_id`. A `user_id` carrying no domain denies.
- **`any`.** Skips the check entirely, admitting any recipient.
- **`known_contacts` on `create_session`.** An optional iterable of addresses, normalized and frozen onto the session at creation. It is populated only from deployer configuration at session creation, never from tool output, context writes, or model output. It defaults to `None`, meaning an empty set, so every existing call site is unaffected.
- **`recipient_allowlist` on `ScopeConfig`.** A list of strings, empty by default. Entries are full addresses or domain entries beginning with `@`, and the field is consulted only under the `allowlist` policy.
- **`recipient_parameter` on `ScopeConfig`.** The name of one top-level key in the tool's `parameters` that carries the recipient, declared in the trusted permission block and read by the gate. `None` by default, meaning no extraction. This is what makes Step 8 reachable from an adapter: through v1.7.0 the step only fired when a caller passed `recipient=` explicitly, which no shipped adapter does. The gate reads exactly the declared key at the top level. There is no scan of the parameter dict, no descent into nested values, and no guessing from key names.
- **Recipient sets.** When the declared parameter carries a list or tuple of strings, every entry is evaluated against the policy and the first denial wins. A single string is evaluated as a set of one. An explicit `recipients` tuple on `RequestContext` carries the set to the policy engine and takes precedence over the single `recipient` field when nonempty.
- **`CITATION.cff` at the repository root.** Cites the software and both papers, with the ORCID of the author and the two Zenodo DOIs. The README gains a `Papers` section and two DOI badges alongside it.

### Changed

- **`SCHEMA_VERSION` is now `1.5`**, and `schema/agentlock-v1.5.json` is generated the same way its predecessors were. `schema/agentlock-v1.4.json` is untouched.
- **The change is additive.** The default of `allowed_recipients` stays `known_contacts_only` rather than being weakened; additivity comes from the version floor instead. A permission block at version 1.4 or below receives a decision identical to the one v1.7.0 gave it, malformed and cross-domain recipients included.
- **Malformed recipients deny under every restrictive policy.** After stripping and casefolding, a recipient containing internal whitespace, a control character, a newline, a comma, or a semicolon is denied rather than parsed. Splitting a multi-recipient string into separate authorize calls is an adapter concern and is not done here.
- **A caller assertion may not contradict the declared parameter.** When a caller passes `recipient=` and the declared parameter also carries a recipient, the two must agree: the asserted address, normalized, must be the sole member of the normalized declared set. Disagreement is a fault and denies with `recipient_not_allowed`. Neither value is trusted over the other and neither appears in the denial detail, which names only the kind of fault.
- **A malformed declared parameter denies.** When the declared key is present but carries neither a string nor a list of strings, no recipient can be resolved from it and the request is denied without inspecting the value. A declared key carrying `None`, an empty string, or an empty list is not malformed: it carries no recipient, and the step is skipped as it is when no recipient is supplied at all. Both faults deny under every recipient policy, `any` included, because a request that is malformed or self-contradictory is defective regardless of where it is addressed.
- **`RATE_LIMITED` is raised as the enum member** at `exceptions.py` rather than the raw string `"rate_limited"`, and the audit call site in `gate.py` passes `DenialReason.RATE_LIMITED.value` so the stored reason stays a plain `str`. The wire value is unchanged in both paths.
- **CI installs the `crypto` and `mcp` extras.** The workflow install step is now `pip install -e ".[dev,crypto,mcp]"`. It was `pip install -e ".[dev]"`. Those two extras are the whole of what buys executed tests: measured, `[dev,crypto,mcp]` and `[dev,all]` produce an identical suite result, and the `fastapi`, `flask` and `autogen` extras add no executed test between them on the interpreters CI runs.
- **The signed-receipt tests were not executing in CI before this release.** Under the old `[dev]` install line the suite reports 1479 passed and 24 skipped, and 14 of those skips read `PyNaCl not installed`. Two of the 14 are v1.8 tests, so the signed-receipt behaviour of the feature this release ships had no CI coverage on push. The gap was invisible in local runs because the host interpreter used for development carries PyNaCl in its global site-packages, so those tests always ran there and never appeared in a skip list. The new install line closes it.
- **The `autogen` extra is pinned to `pyautogen>=0.2,<0.10; python_version < '3.14'`**, in both the `autogen` extra and the `all` extra. `pyautogen` 0.10.0 is a proxy distribution for `autogen-agentchat`: it ships a single `pyautogen/__init__.py` and provides no top-level `autogen` module at all, so `agentlock.integrations.autogen`, which imports `autogen`, raises `ImportError` with the unpinned extra installed. The pinned range resolves to 0.9.0, which does provide the module. **AutoGen support therefore resolves only below Python 3.14**, because every `pyautogen` release in that range caps `Requires-Python` at `<3.14` or lower. The environment marker is what keeps that from becoming a packaging regression: on 3.14 the requirement drops out, so `agentlock[autogen]` and `agentlock[all]` still install, the `autogen` extra resolves to nothing, `import autogen` fails as before, and the AutoGen integration test skips. Without the marker a bare pin would make `agentlock[all]` uninstallable on 3.14 while `requires-python` stays `>=3.10` with no upper bound. The other extras are unaffected.
- **The build pins `hatchling<1.30`.** hatchling 1.30.0 and later emit core metadata 2.5. The pin holds the wheel at `Metadata-Version: 2.4`, the level 1.7.0 shipped.
- **The committed schema files reproduce from their source again.** In `schema/agentlock-v1.4.json` the `ActionClassConfig` and `LineagePolicyConfig` description values carried an em dash at eight positions, and in `schema/agentlock-v1.3.json` the `LineagePolicyConfig` value carried it at two more, all left over from docstrings that were edited after the files were generated. Every one of those values now matches the current docstring exactly. Three lines change across the two files, the descriptions parse as before, and no field, type, or structure moves.

### Limitations

- **Matching is exact.** Known contacts match by exact normalized address, and domain entries match one exact domain. There is no subdomain wildcard, no display-name parsing, and no address canonicalization beyond stripping and casefolding.
- **The contact set is whatever the deployer supplies.** The gate does not consult a contacts backend, and an empty set under `known_contacts_only` denies every recipient by design.
- **Rate-limit denials still carry no signed receipt.** A recipient denial is signed, because it exits through the same path every other policy denial exits through. The rate-limit denial returns its result before reaching that path. This predates the release and is unchanged by it.
- **`recipient_parameter` is unreachable through the FastAPI and Flask integrations.** Their four `authorize()` call sites (`fastapi.py:197`, `fastapi.py:290`, `flask.py:163`, `flask.py:271`) pass only the tool name and the caller identity taken from request headers, and never pass `parameters`, so the gate has no parameter dict to read the declared key out of. This costs those two integrations every parameter-level check, not only the recipient one: the Step 6 injection filter, parameter lineage, and novel lineage are equally unreachable there. It predates this release and is not fixed by it. The AutoGen and MCP integrations do forward the caller's parameters, and recipient enforcement through both is covered end to end in `tests/test_v18_recipient_integrations.py`.

## [1.7.0] - 2026-08-12

The cross-hop release. A value that reaches a sink through an intermediate tool is now attributed to the untrusted entry it came from, and the link is recorded at ingestion rather than reconstructed at decision time.

**The claim, at the strength the measurements support:**

> In a deployment that registers the tool at permissions version 1.3 or later with `param_lineage_enabled` set, and declares the untrusted context source on the writes it records, a tool-call parameter carrying a value that a derived entry relayed from an untrusted entry, where the relaying entry's ingestion supplied the parameters carrying that untrusted entry's whole content, is attributed back through the relay to the untrusted parent, and the call denies with reason `param_lineage` citing the relay entry.

Every qualifier is load-bearing. The link is established by whole-content carriage at ingestion: when a prior entry's recorded content appears inside one of the ingesting call's argument values, that entry becomes the new write's parent. Nothing is decoded to do it, and a caller that supplies no parameters establishes no link, which leaves behaviour exactly as it was before the linker existed. Attribution means a named `cprov_` parent entry in the denial and in the audit record.

Suite: **1418 tests, 0 failures, 7 skipped, with the `crypto` and `mcp` extras installed** (`pip install -e ".[crypto,mcp]"`). The 7 skips are pre-increment-3 baselines that stand down once `_reachable_untrusted_entries` is present in `context.py`; they describe the engine before the broadening and are retired by it, not disabled.

### Added

- **Cross-hop provenance linking.** `notify_context_write` takes an optional `parameters` argument carrying the input arguments of the call that produced the content. A derived entry whose ingestion carries a prior entry's whole content records that entry as its parent. The parent lands in the existing `parent_provenance_id` field, so `SCHEMA_VERSION` stays at 1.4 and no record shape changes.
- **Taint preference, the decline, and the walk.** The linker prefers a tainted ancestor when one is reachable, and declines to attribute when the evidence does not support a single parent rather than guessing. The walk is cycle-guarded, and the guard is unreachable by construction on any graph the engine builds, since a parent is only ever selected from strictly earlier log entries.
- **Decision-time broadening over the walked chain.** `parameter_lineage_check`, `lineage_summary`, and `untrusted_sources` move from the flat `authority == UNTRUSTED` test to a transitive taint-reachability predicate, so a check consults every untrusted entry the recorded chain reaches rather than only the entries written in the current hop. A value relayed through a derived entry and then consumed denies `param_lineage` citing the relay entry.
- **`novel_lineage` deliberately stays on the flat authority test.** This is the resolution of the increment-3 scope decision as option (a) (AM25). Broadening it too was measured to cost a detection loss under the default configuration: a token that a taint-reachable derived entry introduced rather than relayed, which is exactly the class novelty exists for, moves into `untrusted_tokens`, novelty stops firing, and nothing else catches it. Option (a)'s own cost is recorded under Limitations.

### Evidence, and what each source is allowed to establish

- **Capability is established by the frozen corpora and the pre-registered predictions only.** Each increment was frozen before any mechanism code existed and then measured exact-match against its freeze: `docs/PREDICTIONS_crosshop.md` with amendments 1 through 6, and `docs/PREDICTIONS_crosshop_increment1.md`, `_increment2.md`, `_increment3.md`. The evidentiary corpora are `tests/test_v16_crosshop_parent_identity.py` and `tests/test_v16_crosshop_decision_time.py`, the latter committed with measured shipped baselines before the broadening landed, so the mirror flip was predicted rather than observed and then explained.
- **The suite count establishes no regression, and nothing else.** 1418 passing says every prior check still returns what it returned and the new corpora record their frozen outcomes. It is not capability evidence on its own: the capability rests on the corpus rows with declared ground-truth parentage, each asserted with both the verdict and the parent provenance id it cites.
- **No benchmark number is claimed for this release.** No AgentDojo run was made for cross-hop, so nothing here corroborates or contests v1.6's no-regression result, and no deployment-level cross-hop claim is made from a benchmark.

### Limitations

Each was found internally, by a read-only measurement or a pre-build check, not by an external report.

- **Linking requires whole-content carriage meeting the containment floor.** The parent link is established only when a prior entry's recorded content appears whole inside an argument value, at or above `CONTAIN_MIN`. A value that is rewritten, paraphrased, truncated below the floor, or never carried into the ingesting call's parameters does not link, and the chain stops there. The floor is run at 24, chosen and not calibrated (`PREDICTIONS_crosshop.md`, decision 3, AM11.2).
- **Encoded-corpus behavior through an adapter remains unmeasured.** No encoded corpus has been run through a framework adapter (`RELEASE_SCOPE_v16.md`, AM4.3, residual 1). That residual is untouched by this release and keeps its own future arc. Cross-hop linking being present does not retire it.
- **The AM18 mixed-set residual is not resolved.** A candidate set holding a disagreeing content-identical pair alongside a distinct third candidate is not covered by AM10.3's frozen text. No committed session produces such a set, verified by direct inspection of every Tier 1 candidate set the 17 sessions generate, so the corpus cannot decide it and no measurement here bears on it. The engine declines outright in that case, and the decline is marked UNMEASURED in the code rather than fossilized as spec.
- **Option (a) records an inconsistency it never acts on.** On a split-classification session one token draws two answers: `novel_lineage` reporting `classification == "novel"` per the flat check, and `param_lineage` reporting a match with a non-empty `untrusted_provenance_id` per the broadened one. Both land in `request_metadata`. `param_lineage` decides the verdict per gate ordering, so no verdict depends on the disagreement, but a reader of the audit record will see both and should not read the two as independent corroboration. This is a predicted and tested property, pinned by `test_after_split_classification_is_recorded_by_both_checks`, not an incidental behavior.
- **Normalization level is still deferred.** Decision 4's NFKC question remains deferred to a false-link measurement (AM10.2, AM12.2), unchanged by this release.

## [1.6.0] - 2026-08-04

The encoding release. A parameter that carries an encoded form of untrusted content is now attributed to the entry it came from, and nothing is ever decoded to do it.

**The claim, at the strength the measurements support:**

> In a deployment that registers the tool at permissions version 1.3 or later with `param_lineage_enabled` set, and declares the untrusted context source on the writes it records, a tool-call parameter carrying a bare or composite encoded form of a url-kind or email-kind untrusted value, under base64, hex, or natural-URL encoding, is attributed back to its parent untrusted provenance entry, without decoding any parameter value, with novelty gating off.

Every qualifier in that sentence is load-bearing and each one is measured. Parameter lineage is **off by default** and is opt-in per tool; a session whose untrusted writes were recorded without an untrusted context source has no untrusted entry, so there is nothing for the check to trace to and it returns a no-match with the reason `no_untrusted_context`. Attribution means a named `cprov_` parent entry in the denial and in the audit record, not merely a refusal. "With novelty gating off" is the shipped novelty default, so this is a soundness improvement in the default rather than one that needs the novelty branch turned on.

Suite: **1364 tests, 0 failures, with the `crypto` and `mcp` extras installed** (`pip install -e ".[crypto,mcp]"`). A bare install runs **1351 passed, 13 skipped**, the 13 being the optional-extra tests: 12 need PyNaCl, from the `crypto` extra, for signed receipts and hash-chained context, and 1 needs `mcp`. No test fails in either environment.

### Added

- **Value-identity normalization (family 1).** The same value written a different way is now the same value to the gate. Canonical forms are emitted for dates, phone numbers (E.164), amounts, and defanged URLs, alongside the raw token rather than instead of it, so no match that worked before stops working. A hop that writes `evil[.]com` for `evil.com` is attributed for the same reason the raw form is.
- **Directional encoding, bare forms (family 2, first cut).** The base64, hex, and natural-URL encodings of a session's untrusted tokens are emitted into the untrusted comparison blob, so a parameter carrying an encoded form of a known untrusted value matches it. Four counted encoded attacks move from ALLOW to an attributed `DENY:param_lineage` naming the parent entry, in both the novelty-on and the shipped novelty-off configuration.
- **Composite encoded forms (family 2, composite cut).** A direction-(A) scan makes each emitted untrusted form a needle against the raw parameter leaf, so an encoded value embedded inside a longer opaque token is caught, not only a bare one. Covers hex and natural-URL composites.
- **base64 composites at every alignment (family 2, base64 composite cut).** base64 groups three input bytes into four output characters, so an encoded value cuts at both ends depending on where it starts and whether it ends the payload. The scan needle is the three phase interiors, which match at any offset and with any surrounding content, so base64 composites are caught terminal and non-terminal at all three phases rather than only in the phase-0-and-terminal corner.
- **Zero decode, by construction and by guard.** Every needle is a forward encoding of a known untrusted value. Nothing in the parameter is ever decoded or inverted, which is the whole false-positive argument: a benign value that merely looks like base64 is never turned into anything. A test greps the context module for decode primitives (`b64decode`, `urlsafe_b64decode`, `b16decode`, `b32decode`, `fromhex`, `unquote`, `bytes.fromhex`) and fails if one appears, so a decode path cannot be added silently.
- **Curation and floors, so the wider scan does not cost precision.** The direction-(A) composite scan admits only url-kind and email-kind values, and carries per-encoding length floors (hex 16, base64 10, natural-URL 10). The direction-(B) blob emission keeps its wider all-kinds coverage, and its own floor stays at 8.

### Evidence, and what each source is allowed to establish

- **Capability is established by the frozen corpora only.** The encoded catches above are measured on versioned, frozen corpora with pre-registered must-catch and must-not-trip columns, and every must-catch row is asserted with both the verdict and the parent provenance id it cites.
- **AgentDojo establishes no regression, and nothing else.** A three-column run (v1.5.0 baseline, v1.6 default, v1.6 novelty-on) over the four suites, `gpt-4o-mini-2024-07-18`, `tool_knowledge` attack, 984 episodes per column, zero crashes. Combined utility moved 33.40 to 34.56 to 34.67 and no suite regressed. The run supports exactly one public statement: **v1.6 does not regress v1.5's benchmark behavior on the four AgentDojo suites.** It does **not** corroborate the encoding capability, because the benchmark contains no encoded payload anywhere in any suite: every injected value appears as literal plaintext. A benchmark cannot validate what it never presents.
- **The novelty branch's false-positive cost is likewise a frozen-corpus number, not a benchmark number.** Novelty-on did not drop utility in the run above, but that is a property of the benchmark's task shapes, which supply their values in the user instruction and so generate almost no novel-but-clean material. The measured cost lives in the frozen corpora.

### Limitations

Each was found internally, by a read-only measurement or a pre-build check, not by an external report.

- **Composites are url-kind and email-kind only.** Values that tokenize only as `str`, including bare IPv4/IPv6 addresses and `host:port` forms, are covered in their bare encoded form but not inside a composite. This is the curation decision above doing exactly what it was set to do, not a tokenizer miss.
- **Per-character URL enumeration is not emitted.** Only the natural-encoder form is, meaning the structurally significant characters. Adversarial spellings such as `%65vil.com` and the subsets of encoded positions are combinatorial and are not covered.
- **Values below the distinctiveness floor are not traceable.** A value shorter than `min_len` is not tokenized, so it cannot be encoded or matched. This is the floor working as specified.
- **The claim is an engine-level claim.** "Declares the untrusted context source" is satisfied at engine level by the write call. The framework-adapter equivalent is an opt-in on the wrapper, and no encoded corpus has been run through an adapter, so no deployment-level encoded claim is made here.
- **`enabled` is not a master switch over parameter lineage.** A lineage policy with `enabled=False` and `param_lineage_enabled=True` still denies on a parameter-lineage match. This is documented behavior, not a defect: the frozen corpora were measured with `enabled=True` and no measured result depends on it. Any change to that relationship belongs to a later version, on its own record.

## [1.5.0] - 2026-07-16

The evidence release. v1.5 records strictly more and decides identically.

**The guarantee, and its bound.** Across **4542 decisions replayed from the frozen v1.4 benchmark under identical inputs, zero changed.** Every ALLOW, DENY, DEFER, STEP_UP and end-of-turn COMMIT is byte-identical between the v1.4.0 engine and this one. The replay is offline and deterministic, driving a real `AuthorizationGate` from saved transcripts with the model out of the loop, so the engine is the only variable. It is not claimed that all 4826 decisions in the frozen logs were verified: **284 travel-suite decisions could not be replayed at all**, because those runs' decision logs contain more gate calls than their own saved transcripts contain tool calls, so the inputs that produced them were never persisted and no harness can reproduce them. Invariance here is bounded, not total. The surplus is a property of the benchmark artifacts rather than of this release. Method, per-condition results, and limits: [`docs/EVIDENCE_MILESTONE_v15.md`](docs/EVIDENCE_MILESTONE_v15.md).

None of the evidence work touches a decision path. It is built after the decision, from values the gate had already computed, and nothing in the gate reads an audit record back.

Suite: **1141 tests, 0 failures.**

### Added

- **The basis of a grant (E10).** A denial cited what it refused on; a grant said nothing about what it permitted on. A reader of an `allowed` record could observe only that no denial fired, which is evidence that nothing matched, not evidence that anything was checked. An `allowed` record now carries a `grant_basis`: which lineage checks evaluated, what they concluded, and which never ran and why. The vocabulary deliberately separates "ran the comparison and nothing matched" (`no_match`) from "had nothing to compare" (`no_match:<qualifier>`) from "declined to classify" (`not_classifiable:<qualifier>`) from "never executed" (`not_run:<reason>`), because a record that reported these alike would assert a cleanliness no check established. There is no aggregate verdict and no "clean" flag: the engine never computes an overall judgement of a grant, so the record does not invent one.
  - **The finding.** Across the 3261 grants in the replayed corpus, only **4.0% (129)** support the claim that the arguments were checked against untrusted content and came back clean. The other 96% are vacuous no-matches, and before this block every one was indistinguishable in the log from the 129 that were real.
  - **Cost, stated rather than waved at.** The block lands on ~70% of decisions. Mean `allowed` record 555.9 B to 763.5 B (+37.3%); whole decision log +20.9%. Literal user values are not in the block except where `include_parameters` already allows them, dropped by the same rule at the same boundary.
- **Execution confirmation (E7).** An `allowed` record is a grant of permission, not evidence that anything ran. The gate now writes an attempt record before a tool is invoked and a completion record when it returns or raises, so three facts that used to be one indistinguishable state are readable: ran (attempt then completion), attempted but never returned (attempt, no completion), and authorized but never attempted (neither). Callers that own their own execution report through the public `begin_execution` and `confirm_execution`, bound to the grant by token id or deferral id. Those calls verify and never authorize: they issue no token, consume none, extend no TTL, consult no policy, and write nothing `authorize()` reads.
  - **The invariant.** Never break and never alter are absolute and enforced by tests: an audit backend that throws cannot break, block, or change a call the gate has already authorized. Failures are swallowed at the writer boundary, reported out of band, and counted on `gate.evidence_write_failures`. Never *block* is a property of the chosen backend, not of the gate; `AsyncAuditBackend` never blocks but loses queued records on process death, so records are stamped `writer_mode` and `durable_before_execution` and a reader learns that limitation from the log rather than from a config file it does not have.
  - **Scope note.** The non-fatal rule covers the execution path only. On the authorize path a backend failure still propagates and no token is issued, so the call fails closed. An unrecordable decision must not become an unrecorded permission.
- **Provenance on denials (E5/E4).** A lineage-gated denial now cites the lineage it gated on, and the cited token is deterministic across processes. `context_provenance_ids`, declared in the schema since v1.1 and passed by no call site, is now populated, giving denials and context entries a join key. The taint-introduction record carries a session id (E1/E4).
- **Deferred-resolution logging (E6).** How a deferred action resolved is now an audit record of its own, rather than something a reader had to infer from the absence of one.

### Removed

- **BREAKING: the LangChain integration has left core.** `agentlock.integrations.langchain` and the `agentlock[langchain]` extra are removed in v1.5. The integration is published separately as [`langchain-agentlock`](https://github.com/webpro255/langchain-agentlock). Core now has no LangChain code and no LangChain dependency, optional or otherwise.
  - **Migration.** Replace `pip install "agentlock[langchain]"` with `pip install langchain-agentlock`, and import `wrap_tool` and `AgentLockToolkit` from `langchain_agentlock` instead of `agentlock.integrations.langchain`.
  - **Not a drop-in rename.** The standalone package is a distinct implementation, not the relocated module. `wrap_tool` and `AgentLockToolkit` carry over by name but not necessarily by signature; `AgentLockToolWrapper` has no public counterpart, its equivalent being internal to `langchain_agentlock.toolkit`. Callers who constructed `AgentLockToolWrapper` directly must move to `wrap_tool` or the toolkit. Read the standalone README before upgrading rather than assuming the import path is the only change.
  - The core gate API is untouched. The removed module only ever consumed the public `AuthorizationGate` and `AgentLockPermissions`, both of which stay exactly where they are, so nothing about writing or enforcing a permission block changes.

- **BREAKING: the CrewAI integration has left core.** `agentlock.integrations.crewai` and the `agentlock[crewai]` extra are removed in v1.5. It is published separately as [`crewai-agentlock`](https://github.com/webpro255/crewai-agentlock). Core now has no CrewAI code and no CrewAI dependency, optional or otherwise.
  - **Migration.** Replace `pip install "agentlock[crewai]"` with `pip install crewai-agentlock`. As with LangChain this is a reimplementation rather than the relocated module, and the names differ: `wrap_tool` replaces `AgentLockCrewTool`, and `lock_crew` / `lock_tools` replace `protect_crew_tools`. The standalone also adds `lock_agent`, `agentlock_session`, and denial formatters, which core never had. Read its README rather than assuming the import path is the only change.
  - Unlike the LangChain copy, core's CrewAI copy was working when removed. This is a decoupling, not a repair.

### Agent-framework adapters now live outside core

Adapters are versioned and released separately from the standard, so a framework's breaking change is no longer a core release:

| Framework | Package | Install |
|---|---|---|
| LangChain | `langchain-agentlock` | `pip install langchain-agentlock` |
| CrewAI | `crewai-agentlock` | `pip install crewai-agentlock` |
| OpenAI Agents | `openai-agentlock` | `pip install openai-agentlock` |
| OpenClaw | `openclaw-agentlock` | `pip install openclaw-agentlock` |

Only LangChain and CrewAI were ever part of core; the OpenAI and OpenClaw adapters have always been standalone and nothing moved for them. All four are Apache-2.0 adapters that depend on AGPL-3.0-or-later AgentLock, so combined use is subject to the AGPL. See each package's README.

**Core is not yet free of framework integrations.** `agentlock.integrations.autogen`, `.mcp`, `.fastapi`, and `.flask` **remain in core for this release** and are unchanged, with their `agentlock[autogen]`, `[mcp]`, `[fastapi]`, and `[flask]` extras intact. They will move to standalone packages in a future version. No standalone package exists for them yet, and removing them before there is somewhere to migrate to would strand their users, so it is deliberately deferred rather than quietly left out. Nothing you import from them today breaks in v1.5.

## [1.4.0] - 2026-07-10

### Added

- **Selective action-class gating (`ActionClassConfig`)** -- The session taint gate no longer treats every consequential write alike. `is_consequential` was never a class; it was the residual bucket "consequential, but unclassified". A tool may now declare its action class in the trusted permission block: `is_deletion`, `is_membership_change` (both value-free), or `is_value_carrying`. Value-free actions admit no attacker-chosen parameter value for per-value lineage to trace, so session taint is the only signal that catches them, and they are gated by the new `gate_deletion` / `gate_membership_change` flags independently of `gate_consequential`. A value-carrying action's effect is fully determined by an attacker-choosable parameter, which parameter and novel lineage already cover, so it need not be taint-gated. The gating disjunct becomes `C ∧ (G ∨ ¬V)`: an unclassified consequential action **fails closed**, and un-gating requires two affirmative acts, the deployment setting `gate_consequential=False` **and** the tool declaring `is_value_carrying=True`. Setting only one leaves the action gated.
  - **The polarity rule.** Gating-adding signals (`is_deletion`, `is_membership_change`) may originate in the trusted block **or** the caller's `authorize()` kwarg and combine by monotone OR, so a declaration can only ever add gating and an omitted kwarg can never escape a class the tool itself declares. Gating-removing signals (`is_value_carrying`) may originate **only** in the trusted block, never as a caller kwarg, and may weaken only the residual `is_consequential` disjunct, never a named class. There is deliberately no `is_value_carrying` kwarg on `authorize()`. A block declaring `is_value_carrying` together with `is_deletion` or `is_membership_change` raises at construction rather than failing open at runtime.
  - New `authorize()` kwargs `is_deletion` and `is_membership_change`. New `LineagePolicyConfig` fields `gate_deletion` and `gate_membership_change`, both defaulting to `True`, so an existing config that only sets `gate_consequential` is unchanged.
- **Novel lineage (`novel_lineage_enabled`, `novel_lineage_action`)** -- Sibling of parameter lineage, and independent of the `param_lineage_*` flags. Classifies a target token by exact token-set membership as trusted, untrusted, or **novel**: a target the session can account for in neither the authoritative request nor the untrusted context. Checked per target, above the coarse taint gate. Off by default; `novel_lineage_action` is one of `deny`, `step_up`, `log`.
- **Schema version 1.4 (`schema/agentlock-v1.4.json`)** -- `SCHEMA_VERSION` is now `"1.4"`. `AgentLockPermissions` and `LineagePolicyConfig` are `additionalProperties: false`, so a block carrying `action_class`, `gate_deletion`, `gate_membership_change`, or `novel_lineage_*` does not validate against the published v1.3 schema. The v1.4 document adds them. A v1.3 block still validates against v1.4. `schema/agentlock-v1.3.json` is unchanged.
- **Decision provenance in the audit record** -- every `authorize()` exit path now records the class flags the caller asserted under `AuditRecord.metadata["asserted_classes"]`. Descriptive only: written strictly after the decision, never read back by the gate, and never placed in `PolicyContext.metadata`. The key is omitted entirely when nothing was asserted. It survives `log_level=MINIMAL`, as `trust_ceiling` already does.
- **`AuthorizationGate.audit_action_classes()`** -- on-demand report over every tool with `lineage_policy.enabled`, partitioned `UNDECLARED` / `DECLARED` / `NOT_COVERED`, independent of `gate_consequential` and of risk level. Suggestions come in two tiers: lexical (name + risk) and observed (what callers actually asserted, read back from the audit log). Observed beats lexical. Gating-adding suggestions (`is_deletion`, `is_membership_change`) are paste-ready; a suggestion of `is_value_carrying` is gating-removing and always requires human confirmation -- enforced in `ActionClassFinding.__post_init__`, not merely in the formatter. `format_action_class_audit()` renders it. `query()` is called exactly once per report and never from a hot path.

### Changed

- **A step-up no longer degrades to an indistinguishable hard deny.** `AuthResult` gains `needs_approval: bool` and `approval_channel: str`. When a policy blocks a call pending out-of-band human approval rather than refusing it outright, `denial["status"]` is now `"approval_required"` instead of `"denied"`. `allowed` is still `False` and `decision` is still `DecisionType.DENY`, so no existing control flow changes; `denial["reason"]` is unchanged. Callers that distinguished the two cases could not before and can now.
- **`resolve_deferred_commits()` honours action-class declarations.** The end-of-turn re-decision previously denied every queued action whenever the session was tainted at commit, consulting only the session taint boolean and never `permissions.action_class`. With deferred commit enabled this made `gate_consequential=False` **inert**: a value-carrying write that `authorize()` un-gated at call time was silently re-gated at end of turn. The commit path now re-decides each queued record against its own permission block through the same predicate `authorize()` uses.
  - **Behaviour change.** A queued write on a tool declared `is_value_carrying` under `gate_consequential=False` now **commits** where it previously **denied**. Value-free classes are unaffected: a declared `is_deletion` or `is_membership_change` write is still denied on taint, regardless of `gate_consequential`. With no declarations anywhere the path reduces to `deny == tainted`, byte-identical to before.
  - Fail-closed at every unknown. A queued record is denied on taint when its tool is no longer in the registry at commit time, when the tool has no active lineage policy, or when the record carries no recorded action flags.
  - **API surface.** The gating disjunct is extracted to `policy.lineage_gated_action()`, with `policy.ActionFlags`, `policy.resolve_action_classes()`, and `policy.active_lineage_policy()`, and is now called from both enforcement points so they cannot drift. `DeferralRecord` gains an `action_flags` field. `AuthorizationGate.defer_consequential()` gains `record_action_flags: bool` plus the seven `is_*` class kwargs; omitting them is fail-closed. `DeferralManager.resolve_commit_queue()` accepts `deny: bool | Callable[[DeferralRecord], bool]`, the bool form preserving the previous behaviour. `ActionFlags` has no `is_value_carrying` field, by the polarity rule.

### Removed

- **The `register_tool()` undeclared-tool `UserWarning` is gone.** Registering a high/critical-risk tool with `gate_consequential=False` and no `action_class` no longer emits a `UserWarning`. A registration-time warning cannot see how a tool is actually called, so it guessed from name and risk level, fired in every importing application, and could not be acted on with evidence. **Behaviour change for strict callers:** applications running under `-W error::UserWarning` previously saw such a registration *raise*; it now returns normally. This is intended. Applications that relied on the raise as a fail-fast configuration check should call `gate.audit_action_classes()` at startup and assert on the result instead. **No gating decision changed** -- the warning was pure side effect, and the disjunct `C ∧ (G ∨ ¬V)` never consulted risk level.

### Fixed

- **Schema versions are now compared numerically, not lexicographically.** `permissions.version >= "1.3"` was a string comparison, and `"1.10" >= "1.3"` is `False` -- so a permission block declaring schema version `1.10` or later within the `1.x` line would have silently skipped the session write-gate, parameter lineage, **and** novel lineage, all three failing **open**. New `schema.parse_version()` / `schema.version_at_least()` parse into integer tuples and are applied at all six comparison sites (`policy.py` ×4, `gate.py` ×2). An unparseable version now **fails closed** -- it enforces the lineage block rather than skipping it. Latent since v1.3; found by the action-class audit during its own development, when the report had to reproduce the gate's coverage rule exactly and the rule turned out to be wrong; never exploitable, because `permissions` is trusted config and no `>=1.10` schema ever existed.

## [1.3.0] - 2026-07-06

### Changed

- **License** -- AgentLock is now licensed under the **GNU AGPL-3.0** (previously Apache 2.0), with commercial licenses available for closed-source use -- see `COMMERCIAL.md`. Versions 1.2.x and earlier remain under Apache 2.0.

### Added

- **Provenance-lineage gating (`LineagePolicyConfig`)** -- New per-tool policy block that gates tool calls based on the provenance lineage of their parameters. Two independent enforcement layers, both inert unless a `lineage_policy` is present and enabled: (1) a **session write-gate** that gates consequential calls -- `gate_financial`, `gate_external`, `gate_bulk`, `gate_account_modification`, `gate_consequential` -- whose session context carries untrusted lineage, and (2) **parameter lineage** (`param_lineage_enabled`) that matches individual parameter values back to untrusted-provenance tokens. Both are gate-owned reads: callers cannot supply the lineage verdict. Configurable `decision` (`step_up` | `defer` | `deny`) and `param_lineage_action` (`deny` | `step_up` | `log`). New helpers in `agentlock/context.py`: `extract_lineage_tokens()`, `ContextTracker.lineage_summary()`, `ContextTracker.parameter_lineage_check()`.
- **Deferred-commit queue** -- `DeferralManager` gains `queue_commit()`, `resolve_commit_queue()`, `get_commit_queue()`, and `clear_commit_queue()` to hold deferred tool calls pending out-of-band resolution.
- **Two new denial reasons** -- `DenialReason.UNTRUSTED_LINEAGE` and `DenialReason.PARAM_LINEAGE`.
- **Schema** -- `SCHEMA_VERSION` bumped to `1.3`; `AgentLockPermissions` gains an optional `lineage_policy` field. `LineagePolicyConfig` is exported from the package root.
- **Tests** -- 21 new tests (`test_v13_session_write_gate.py`, `test_v13_deferred_and_param_lineage.py`); suite total is now 868.

## [1.2.1] - 2026-04-06

### Added

- **Ed25519 signed receipts (AARM R5)** -- Every authorization decision can produce a cryptographically signed receipt verifiable offline. `ReceiptSigner` supports Ed25519 (via PyNaCl) with HMAC-SHA256 fallback for environments without asymmetric key infrastructure. `ReceiptVerifier` detects tampered receipts. Receipts include decision, tool name, user identity, parameters hash, and policy version hash. Optional dependency: `pip install agentlock[crypto]`.
- **Hash-chained tamper-evident context (AARM R2)** -- `ContextChain` creates an append-only hash chain of context entries. Each entry links to the previous entry's hash, forming a tamper-evident log. `verify_chain()` detects modification of any historical entry. `ContextProvenance` gains a `previous_hash` field. `ContextTracker.verify_context_chain()` validates chain integrity per session.
- **`first_call_any_risk` DEFER trigger** -- Defers the first tool call in a session regardless of risk level. Configured via `DeferPolicyConfig(first_call_any_risk=True)`. Unlike `first_call_high_risk`, this catches MEDIUM and LOW risk tools used as attack footholds.
- **`deny_on_block` whitelist escalation** -- When a `whitelist_path` transformation blocks a parameter (replacing it with `[BLOCKED: ...]`), the gate escalates from MODIFY to DENY. The tool does not execute. `ModifyResult` gains a `blocked_fields` list.
- **Sibling deferral** -- When one tool call is DEFERRED in a turn, subsequent tool calls in the same turn (within a 5-second window) are automatically deferred. Prevents attackers from falling through to lower-friction tools after a DEFER fires.
- **Prompt scan carry-forward** -- When a `prompt_scan` signal fires in a session, ALL subsequent tool calls are deferred regardless of whether the tool has its own `defer_policy`. Previously, tools without `defer_policy` (like `lookup_order`) bypassed scan-triggered deferral.
- **`enforce_all_at_critical` hardening** -- When `HardeningConfig(enforce_all_at_critical=True)`, the gate blocks ALL tool calls at critical hardening severity (risk score >= 10), regardless of tool risk level. Previously, `enforce_at_critical` only blocked HIGH/CRITICAL risk tools.
- **3 new `lookup_order` combo pairs** -- `(lookup_order, query_database)` weight 4, `(lookup_order, check_balance)` weight 3, `(lookup_order, search_contacts)` weight 3. Detects reconnaissance-to-data-access patterns.
- New modules: `agentlock/receipts.py`, `agentlock/chain.py`
- New exports: `SignedReceipt`, `ReceiptSigner`, `ReceiptVerifier`, `ChainedContextEntry`, `ContextChain`, `GENESIS_HASH`
- Optional dependency group: `agentlock[crypto]` for PyNaCl >= 1.5.0
- 102 new tests (847 total, 0 failures)

### Changed

- `AuthResult` gains `receipt: SignedReceipt | None` field
- `AuthorizationGate.__init__()` accepts optional `receipt_signer` parameter
- `DeferPolicyConfig` gains `first_call_any_risk: bool` field (default False)
- `DeferralManager` gains `check_first_call_any_risk()`, `check_sibling_deferral()`, `record_deferral()` methods
- `ModifyResult` gains `blocked_fields: list[str]` field
- `ContextProvenance` gains `previous_hash: str` field
- `ContextState` gains `context_chain: ContextChain` field
- `ContextTracker` gains `verify_context_chain()` method
- Package version updated to 1.2.1

### Backward Compatibility

- All 778 v1.2.0 tests pass without modification
- `receipt` field defaults to None when no signer is configured
- `first_call_any_risk` defaults to False
- `enforce_all_at_critical` defaults to False
- `blocked_fields` defaults to empty list
- `previous_hash` defaults to empty string
- Hash chain is populated transparently; existing `record_write()` callers require no changes

## [1.2.0] - 2026-03-30

### Added

- **Adaptive prompt hardening** -- When the gate detects suspicious activity (injection attempts, trust degradation, rate limiting), it generates defensive system prompt instructions for the agent framework to inject before the LLM processes the next turn. Session risk scores are monotonic and session-scoped. Three severity levels: warning, elevated, critical.
- **MODIFY decision type** -- Authorized tool calls can have their outputs transformed before the LLM sees them. Built-in actions: `redact_pii` (strips SSN, email, phone, credit card, API keys from output), `restrict_domain` (blocks external email recipients), `whitelist_path` (restricts file access to allowed directories), `cap_records` (limits output record count). Configured per-tool via `modify_policy`.
- **DEFER decision type** -- Suspends authorization when context is ambiguous. Triggers: first tool call in session is HIGH/CRITICAL risk with no history, prompt scanner fired and tool call attempted in the same turn, trust degraded below threshold. Defaults to DENY on timeout (60s).
- **STEP_UP decision type** -- Dynamically requires human approval based on session state. Triggers: hardening severity at elevated or above with HIGH/CRITICAL risk tool, multiple PII-returning tools already called in session, tool denied earlier and user retrying with a different high-risk tool. Pluggable notification via `StepUpNotifier` protocol.
- **DecisionType enum** -- Five authorization outcomes: `ALLOW`, `DENY`, `DEFER`, `STEP_UP`, `MODIFY`. `AuthResult.decision` field added alongside backward-compatible `AuthResult.allowed`.
- **Gate enforcement at critical severity** -- When session risk score exceeds the critical threshold (10+) and `enforce_at_critical` is enabled, the gate blocks HIGH/CRITICAL risk tools regardless of role authorization. MEDIUM/LOW tools remain allowed.
- **Prompt scanner** (`PromptScanner`) -- Pre-LLM analysis of user messages. Detects injection phrases, authority claims, instruction planting, encoding indicators, agent/system impersonation, format forcing, retrieval exploitation, and cross-turn repetition. Runs before the LLM processes the message, enabling hardening directives on the same turn.
- **Behavioral velocity detector** (`VelocityDetector`) -- Tracks tool call frequency and topic shifts per session. Fires on rapid calls (3+ in 60s), topic escalation (risk jump from low/medium to high/critical), and burst patterns (same tool 3+ in 30s).
- **Tool combination detector** (`ComboDetector`) -- Detects suspicious tool call sequences within a session. Configurable suspicion map with 13 default suspicious pairs and 5 default suspicious sequences covering data exfiltration, account takeover, and tool chain attack patterns.
- **Response echo detector** (`EchoDetector`) -- Framework-side signal that checks LLM responses for attack prompt echoing, tool name disclosure, system prompt leakage, credential-format strings, and compliance language in suspicious contexts.
- **Compound scoring** -- When multiple signal types co-occur, compound rules add bonus weight. `rapid_exfil` (velocity + combo, +2), `probing_attack` (echo + injection, +3).
- **Signal-aware targeted instructions** -- Hardening directives contain instructions specific to the detected signal types instead of generic severity-level text. Format forcing attacks get format-specific instructions, not irrelevant tool-blocking language.
- New schema models: `ModifyPolicyConfig`, `TransformationConfig`, `DeferPolicyConfig`, `StepUpPolicyConfig`
- New exceptions: `DeferredError`, `StepUpRequiredError`, `ModifyAppliedError`
- 276 new tests (745 total, 0 failures)

### Changed

- Schema version updated from `"1.1"` to `"1.2"`
- Package version updated to `1.2.0`
- Phone number redaction pattern expanded to cover 7-digit, US 10-digit, international (+44, +91, +1), and UK local (0-prefixed) formats
- `AuthorizationGate.__init__()` accepts optional `hardening_config`, `velocity_config`, `combo_config`
- `AuthorizationGate.execute()` accepts optional `modify_output_fn` for MODIFY output transformation
- `AuthorizationGate.authorize()` pipeline extended: velocity/combo signals recorded before policy evaluation, DEFER checked before STEP_UP, STEP_UP checked before MODIFY, MODIFY checked before token issuance

### Backward Compatibility

- All v1.0 and v1.1.x `agentlock` permission blocks remain valid
- `AuthResult.allowed` continues to work unchanged for existing callers
- New fields (`decision`, `modify_output_fn`, `deferral_id`, `stepup_request_id`) default to neutral values
- `execute()` works identically without the `modify_output_fn` parameter
- Hardening, velocity, combo, DEFER, STEP_UP, and MODIFY are all disabled by default when their respective config/policy objects are not provided
- All 469 original v1.1.2 tests pass without modification

## [1.1.2] - 2026-03-24

### Added

- **Independent filter pipeline** -- Decoupled InjectionFilter and PiiFilter into separate classes on PolicyEngine. Each runs independently with no shared logic or state.
- **InjectionFilter** -- Scans tool call parameters for reconnaissance/enumeration, prompt extraction, social engineering, and command injection patterns. Recursively inspects nested dicts and lists.
- **PiiFilter** -- Checks caller's max_output_classification against tool's output_classification using 7-level classification hierarchy. Independent from injection filtering.
- 44 new tests (test_filter_pipeline.py)

### Changed

- PolicyEngine.evaluate() refactored into three independent stages: base auth, injection filter, PII filter
- Trust degradation now runs independently of both filters
- Package version updated to 1.1.2

### Fixed

- Injection pass rate recovered from 88.6% (v1.1.1) to 93.4% by restoring behavioral filters without PII interference

## [1.1.1] - 2026-03-24

### Added

- **Gate-level PII classification check** -- max_output_classification parameter on authorize() blocks tool execution before data is retrieved when caller clearance is below tool's output classification
- 7-level classification hierarchy: PUBLIC, INTERNAL, CONFIDENTIAL, MAY_CONTAIN_PII, CONTAINS_PII, CONTAINS_PHI, CONTAINS_FINANCIAL
- 16 new tests (test_pii_defense.py)

### Fixed

- PII regression from v1.1: restored input-layer query blocking (100/A) while maintaining output-layer redaction as backup

### Backward Compatibility

- max_output_classification defaults to None. When not provided, check is skipped entirely. No existing callers affected.

## [1.1.0] - 2026-03-20

### Added

- **Context authority model** -- `context_policy` block on `AgentLockPermissions` with `source_authorities` mapping context sources (user messages, tool outputs, web content, peer agents, etc.) to authority levels (`authoritative`, `derived`, `untrusted`)
- **Trust degradation** -- `TrustDegradationConfig` with per-session trust that monotonically degrades when untrusted content enters context. Effects: `require_approval`, `elevate_logging`, `restrict_scope`, `deny_writes`. Trust never escalates within a session.
- **`allow_cascade_to_untrusted`** flag for security-critical deployments that need maximum restriction after contamination
- **Memory access control** -- `memory_policy` block with `allowed_writers`, `allowed_readers`, `prohibited_content`, `retention` limits, and `require_write_confirmation`
- **Provenance tracking** -- `ContextProvenance` dataclass with source, authority, writer identity, timestamp, content hash, and token binding for every context write
- **`ContextTracker`** -- per-session provenance log and trust state management on the authorization gate
- **`MemoryGate`** -- validates memory read/write operations against `MemoryPolicyConfig` with lazy retention enforcement
- **`notify_context_write()`** on `AuthorizationGate` -- framework integrations report context entries to the gate
- **`authorize_memory_write()` / `authorize_memory_read()`** on `AuthorizationGate`
- **New enums**: `ContextSource`, `ContextAuthority`, `DegradationEffect`, `MemoryPersistence`, `MemoryWriter`
- **New denial reasons**: `TRUST_DEGRADED`, `UNATTRIBUTED_CONTEXT`, `CONTEXT_AUTHORITY_VIOLATION`, `MEMORY_WRITE_DENIED`, `MEMORY_READ_DENIED`, `MEMORY_RETENTION_EXCEEDED`, `MEMORY_PROHIBITED_CONTENT`, `MEMORY_CONFIRMATION_REQUIRED`
- **New audit actions**: `trust_degraded`, `memory_write`, `memory_write_denied`, `memory_read`, `memory_read_denied`, `memory_expired`, `context_rejected`
- **New audit fields**: `trust_ceiling`, `is_trust_degraded`, `degradation_effects`, `context_provenance_ids`, `memory_operation`, `memory_entry_id`
- **New exception classes**: `TrustDegradedError`, `UnattributedContextError`, `MemoryWriteDeniedError`, `MemoryReadDeniedError`, `MemoryRetentionExceededError`, `MemoryProhibitedContentError`, `MemoryConfirmationRequiredError`
- CLI `validate` and `inspect` commands now display v1.1 context and memory policy fields
- `agentlock init` now generates v1.1 templates
- 142 new tests (409 total)

### Changed

- Schema version default updated from `"1.0"` to `"1.1"`
- Package version updated to `1.1.0`

### Backward Compatibility

- All v1.0 `agentlock` blocks remain valid -- new fields are optional with secure defaults
- When `version` is `"1.0"`, the gate skips all v1.1 checks entirely
- All 267 original tests continue to pass without modification

## [1.0.0] - 2026-03-18

### Added

- Core AgentLock permissions schema (v1.0)
- `AuthorizationGate`  central enforcement point with deny-by-default semantics
- `AgentLockPermissions`  Pydantic model for the `agentlock` permissions block
- `@agentlock` decorator for one-line tool protection
- Single-use, time-limited, operation-bound execution tokens
- Session management with expiry and scope tracking
- Sliding-window per-user, per-tool rate limiting
- Automatic data redaction engine with built-in PII patterns
- Policy evaluation engine with 7-step authorization checks
- Pluggable audit logging with file and in-memory backends
- CLI tool: `agentlock validate`, `agentlock schema`, `agentlock init`, `agentlock inspect`, `agentlock audit`
- Framework integrations: LangChain, CrewAI, AutoGen, MCP, FastAPI, Flask
- JSON Schema for tool definition validation
- Comprehensive test suite
- Working examples for all major use cases
- Full documentation
- GitHub Actions CI/CD pipeline
- Apache 2.0 license
