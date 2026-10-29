# v1.11 Review Gaps: Baseline of Record

Date: 2026-10-29
Branch: `probe/review-gaps`, cut from `6f73879 release: v1.10.3` (tag `v1.10.3`,
identical to `origin/main`).
Working tree at measurement time: clean except `tests/probes/` and this file.

This document records the independent reproduction of four enforcement gaps
reported against the published 1.10.3 wheel by an external review (reviewer
"Astra", received 2026-10-13). Nothing in it describes code that has been
written. Section 2 is the engine at `6f73879`, measured. Section 3 lists the
decisions that have to be made before any fix branch exists; it is empty on
purpose until they are made. Everything after Section 6 is append only.

---

## 1. The four gaps, as reported

As recorded in the project notes at the time the review was received. The
reviewer's own suite was not used for this baseline; the probes in Section 2
were written cold from the gap names and the source, with predictions frozen
before the first run.

> **G1. Deferred commit versus fresh authorization.** A queued consequential
> action is re-decided at end of turn against something other than what a fresh
> `authorize()` would decide at that moment.

> **G2. Same-user session isolation.** Two live sessions for one `user_id` are
> not kept apart by the gate.

> **G3. FastAPI and Flask parameter binding.** The HTTP adapters authorize a
> call whose parameters are not the parameters the handler runs with.

> **G4. Structured-output redaction.** `prohibited_in_output` redaction does not
> reach tool results that are not plain strings.

---

## 2. Baseline of record

All measurements taken on `probe/review-gaps` at `6f73879`, 2026-10-29, in two
environments:

| Environment | Python | mcp | PyNaCl | Where |
|---|---|---|---|---|
| Independent (first run) | 3.13.18 | 2.3.0 | 1.6.2 | cloud container, clone of the tag |
| shadowbox (`/tmp/al-probe-venv`) | as installed | as resolved by `.[crypto,mcp]` | as resolved | `~/agentlock` at `6f73879` |

Both environments produced byte-identical probe output. The shadowbox run is
the run of record; it is reproduced verbatim in B5.

Probe scripts: `tests/probes/probe_review_gaps.py` (G2, G3, G4, plus a first
G1 attempt that did not exercise the commit path) and
`tests/probes/probe_deferred_commit.py` (G1 through the documented
`defer_consequential` flow). Neither is collected by pytest; both run with no
arguments against an installed engine.

### B1. G1 at the source

`agentlock/gate.py`, inside `resolve_deferred_commits`, the `_should_deny`
predicate, verbatim:

```python
            # No taint at commit -> nothing left to gate on; commit, as before.
            if not tainted:
                return False
            if permissions is None:
                # fail closed: unregistered at commit time
                record.denial_reason = "unregistered_at_commit"
                return True
```

The untainted branch returns before the permissions check, the role check, and
any session-liveness check. The commit-time re-decision is a taint re-decision
only. A record whose session taint has been cleared by a post-authoritative user
message commits regardless of what a fresh `authorize()` would say.

Measured (`probe_deferred_commit.py`). Setup for every row: tool registered with
`decision="defer"`, `require_post_authoritative=True`; session tainted by
`WEB_CONTENT`; `authorize()` denies `untrusted_lineage`; caller queues the call
with `defer_consequential(..., is_external=True, record_action_flags=True)`;
a `USER_MESSAGE` then arrives. Between that message and
`resolve_deferred_commits`, the row's action is applied, and a fresh
`authorize()` for the same call is taken for comparison.

| Action between queue and commit | Fresh `authorize()` | Commit resolution |
|---|---|---|
| none (baseline) | allow | committed |
| `register_tool` with `allowed_roles=["admin"]` (user's role revoked) | deny, `insufficient_role` | committed |
| tool removed from `_tools` (unregistered) | deny, `no_permissions` | committed |
| `session_store.destroy(session_id)` | allow (no session: host trusted) | committed |

### B2. G2 at the source

`agentlock/session.py:104`, in `SessionStore.create`, verbatim:

```python
        self._sessions[session.session_id] = session
        self._user_sessions[user_id] = session.session_id
        return session
```

`agentlock/gate.py:734`, in `authorize`, verbatim:

```python
        session = self._session_store.get_by_user(user_id) if user_id else None
```

`authorize()` has no `session_id` parameter. The session is resolved by
`user_id`, and `create()` overwrites the per-user pointer, so the gate always
reads the newest session for a user. Taint recorded in an earlier live session
is unreachable by any `authorize()` call; taint in the newest session governs
every call for that user.

Measured (`probe_review_gaps.py`, G2 rows), tool with `decision="deny"`:

| Sequence | Result |
|---|---|
| Session A tainted by `WEB_CONTENT`; `authorize()` | deny, `untrusted_lineage` |
| then `create_session` B for the same user (clean); same `authorize()` | allow |
| Session A clean; session B tainted; `authorize()` intended for A | deny, `untrusted_lineage` (B's taint applied) |

`get_session("alice")` returns B after B is created. There is no API by which a
caller can direct an `authorize()` at A.

### B3. G3 at the source

Four call sites, none passing `parameters`:

- `agentlock/integrations/fastapi.py`, `AgentLockMiddleware.__call__`,
  `auth = self.gate.authorize(tool_name, user_id=user_id, role=role)`
- `agentlock/integrations/fastapi.py`, `require_agentlock` dependency,
  `auth = gate.authorize(tool_name, user_id=user_id, role=role)`
- `agentlock/integrations/flask.py:374`, same shape
- `agentlock/integrations/flask.py:554`, same shape

Per V3 of the v1.9 arc, a token issued with no parameters is bound to the empty
call. The HTTP adapters therefore authorize the empty call on every request;
parameter lineage, recipient policy, `max_records`, and the MODIFY path never see
the request body or query. The README and agentlock.dev already state that the
HTTP adapters do not call `execute()`; this baseline records that they also do
not pass parameters to `authorize()`.

Measured (`probe_review_gaps.py`, G3 row), tool with `param_lineage_enabled=True`,
session tainted by a page carrying `https://evil-collector.example.net/upload`:

| Call shape | Result |
|---|---|
| `authorize(..., parameters={"to": "<attacker URL>"})` (what a correct adapter would do) | deny, `param_lineage` |
| `authorize(...)` with no parameters (what both adapters do) | allow |

### B4. G4 at the source

`agentlock/gate.py:1890`, in `execute`, verbatim:

```python
        engine = self._redaction_engines.get(tool_name)
        if engine and isinstance(result, str):
```

Redaction runs only on `str` results. The input side already has a leaf walker
(`context.py`, `_iter_param_leaves`); the output side has none.

Measured (`probe_review_gaps.py`, G4 rows), tool with
`prohibited_in_output=["ssn", "email"]`, `redaction="auto"`:

| Tool result type | Output |
|---|---|
| `str` | `SSN [REDACTED:ssn] mail [REDACTED:email]` |
| `dict` | `{'ssn': '123-45-6789', 'contact': 'bob@corp.com'}` |
| `list` | `['123-45-6789', 'bob@corp.com']` |
| JSON `str` | `{"ssn": "[REDACTED:ssn]"}` |

### B5. Run of record, verbatim

shadowbox, `~/agentlock` at `6f73879`, `/tmp/al-probe-venv`, 2026-10-29:

```
gap  probe                                                      verdict                observed
G1   role revoked between queue and commit                      N/A                    initial=allow queued=0 fresh=deny resolved=[]
G1   tool unregistered between queue and commit, no taint       N/A                    initial=allow resolved=[]
G2   tainted session A, then clean session B for same user      GAP                    before=deny after=allow get_session->True
G2   clean A, tainted B, same user: call for A                  GAP(cross-contamination) decision=deny reason=untrusted_lineage
G3   HTTP adapter shape: authorize with no parameters, attacker URL in body GAP                    with_params=deny/param_lineage no_params=allow
G4   str output                                                 OK                     SSN [REDACTED:ssn] mail [REDACTED:email]
G4   dict output                                                GAP                    {'ssn': '123-45-6789', 'contact': 'bob@corp.com'}
G4   list output                                                GAP                    ['123-45-6789', 'bob@corp.com']
G4   JSON string output                                         OK                     {"ssn": "[REDACTED:ssn]"}

baseline                           call=deny/untrusted_lineage fresh=allow/None commit=[('committed', None)]
role revoked before commit         call=deny/untrusted_lineage fresh=deny/insufficient_role commit=[('committed', None)]
tool unregistered before commit    call=deny/untrusted_lineage fresh=deny/no_permissions commit=[('committed', None)]
session destroyed before commit    call=deny/untrusted_lineage fresh=allow/None commit=[('committed', None)]
```

The two G1 rows marked N/A in the first script are the first attempt, in which
`authorize()` with `decision="defer"` denied at call time and queued nothing;
the commit path is exercised only through `defer_consequential`, which the
second script uses. The N/A rows are kept as a record of the mistaken first
shape.

### B6. Pre-registered predictions and their outcome

Written into the scripts before the first run. Every prediction matched.

| Gap | Prediction | Outcome |
|---|---|---|
| G1 | untainted branch returns before the permissions check, so a queued record commits after role revocation or unregistration | MATCH, and also after session destruction |
| G2 | `create_session` for the same user replaces the first for gate purposes: A's taint invisible, B's taint applied to A | MATCH, both directions |
| G3 | `authorize()` with no parameters allows a call that the same `authorize()` with parameters denies on `param_lineage` | MATCH |
| G4 | redaction on `str` only; dict and list pass through; JSON string is redacted because it is a `str` | MATCH, all four rows |

---

## 3. Decisions of record

None yet. The following have to be decided, one each, before a fix branch is
cut. Options are listed so the decision is recorded against them; the record
will carry the chosen option and the reason.

**D-G1.** What does commit-time re-decision re-run? (a) only taint and lineage,
as today, documented as the contract; (b) taint and lineage plus the checks that
can change between queue and commit: tool registration, `allowed_roles` for the
record's role, session liveness, policy version; (c) a full fresh `authorize()`
over the snapshotted parameters, with the deferral record carrying the result.
The v1.11 `StepUpGrant` note already binds a grant to policy version and expiry;
(b) is the deferral-side counterpart.

**D-G2.** How is a session addressed? (a) add `session_id` to `authorize()`
and `execute()`, resolved first when given, with `get_by_user` kept as the
fallback and documented as ambiguous under concurrency; (b) refuse
`create_session` for a user with a live session unless the caller passes an
explicit `replace=True`; (c) both. The v1.11 shared-storage protocol has to
carry the same addressing, so this decision is made once for both.

**D-G3.** What do the HTTP adapters pass as parameters? (a) JSON body when
`Content-Type` is JSON, else query string, else form fields, merged in a
documented precedence; (b) only JSON body, with any other content type
refused (fail closed); (c) adapter-declared extractor callable per route. Note
that the adapters do not call `execute()`, so after this fix they authorize the
right call but still do not consume the token on the gate-observed path.

**D-G4.** How are non-string results redacted? (a) walk `str` leaves of
`dict`, `list`, and `tuple` results recursively, redacting in place and
counting redactions per leaf; (b) serialize to JSON, redact the string,
deserialize (changes types; rejected unless (a) is impossible); (c) refuse to
return any non-string result from a tool with `prohibited_in_output` set (fail
closed). `bytes` results are a separate question under any option.

---

## 4. Defects in this baseline, found before any decision

**D1.** The G3 baseline reads the Flask adapter at two call sites but the probe
exercises the engine shape only, not the Flask or FastAPI adapters themselves.
An adapter-level reproduction (a test client posting a body with an
attacker-planted recipient) belongs in the acceptance tests for D-G3, not here;
this baseline establishes the engine-side fact that the empty-call grant allows
what the parameterized grant denies.

**D2.** The G1 "session destroyed" row shows fresh `authorize()` returning
allow with no session. That is the documented "no session: host trusted"
behavior, not a new finding, but it means the commit-time re-decision under
option (c) of D-G1 would also allow. Option (b) needs an explicit
session-liveness rule to deny that row; the fresh-authorize comparison alone
would not.

---

## 5. Predictions

Not frozen. Predictions are written after Section 3 is filled, before any
mechanism code exists, and appended here as AMENDMENT 1.

---

## 6. What this document is not

It is not a description of a fix and it is not a design. Section 2 is the
engine at `6f73879`, measured twice. Section 3 is the list of decisions that
the fix depends on, with none taken. Section 4 is what is already known to be
incomplete about this baseline. Everything after this line is append only.

---

## AMENDMENT 1 (2026-10-29): fix/review-gaps built by measurement, decisions of record, release predictions

Branch `fix/review-gaps`, cut from `probe/review-gaps` at `eb238f5`. Built as
candidates behind acceptance tests, each defaulting to the old behavior until
chosen; David picked from the measurements. History kept as built, including
the candidate later removed.

### Decisions of record, from measurement

**D-G1: (b), the "changed" re-check.** Candidate B ("full" re-authorization at
commit) was built (`e68bd74`) and measured against A (`1983850`). B commits in
two cases where A denies: a destroyed session (no session means host trusted,
the D2 prediction) and a permission block widened between queue and commit
(not predicted). B also resolves the session by `user_id`, so the G2 ambiguity
returns through the commit path. B removed (`e366ee0`). "Policy version" is a
SHA-256 of the whole permission block snapshotted at queue time, because
`permissions.version` is a schema version and does not move when roles change.
New denial reasons: `role_revoked_at_commit`, `session_gone_at_commit`,
`policy_changed_at_commit`; `unregistered_at_commit` already existed.

**D-G2: (c), both, with B off by default.** A (`35c9b3d`): `session_id` on
`authorize()` and `execute()`, resolved first when given; missing, expired, or
another user's session denies `session_not_found`; user lookup kept as the
fallback with audit metadata `session_resolution: "by_user"`. B (`268b3a4`):
`single_session_per_user` on `AuthorizationGate` and `SessionStore`, raising
`SessionConflictError` on a second live session unless `replace=True`. Measured
cost of B on: one existing test
(`test_session.py::test_create_replaces_previous_for_same_user`). Unmeasured
cost: any deployment creating a session per request. B stays off in 1.11.0,
is recommended in the CHANGELOG, and becomes the default in 2.0. Probe row G2-1
(user-addressed caller, no `session_id`, B off) stays open and is listed under
Known limits.

**D-G3: (b), JSON body only, fail closed.** All four adapter paths (`fastapi.py`
middleware and dependency, `flask.py` decorator and extension) parse an
`application/json` body and pass it as `parameters`; any other content type
with a body is refused 403 `unsupported_content_type`; unparseable JSON is
refused `invalid_json_body`. GET with no body passes `parameters={}`. The query
string is not authorized (Known limits). The adapters still do not call
`execute()`.

**D-G4: (a), walk the leaves.** `gate.execute()` and the decorator paths redact
every `str` leaf of `dict`, `list`, `tuple`, named tuple, `set`, and
`frozenset` results, rebuilt as the same type; the async decorator path uses a
new public `gate.redact_result()`. A set can shrink when redacted members
collide (documented). `bytes` results are untouched (Known limits).

**G5, found during the build, fixed (`65836fc`).** `SessionStore.destroy(A)`
cleared the user's session pointer even when it already pointed at a newer
live session B, orphaning B; the next `authorize()` found no session and ran
as a trusted host. Measured at v1.10.3: tainted B went from deny to allow after
`destroy(A)`. Now the pointer is cleared only when it points at the destroyed
session.

**Also in this release.** The `@agentlock` decorator popped `_session_id` and
discarded it; it now passes it to `authorize()` and `execute()` (`fc1b1d0`),
and `gate.call()` passes it to `execute()` as well. One pre-existing mypy error
(`defer.py` lambda) resolved (`15ae55a`). One existing test edited:
`test_v13_deferred_and_param_lineage.py::test_deferred_commit_no_taint`
registered its tool, because the old assertion encoded the fail-open row.

### Scoreboard, acceptance tests against the baseline

| Gap | Rows | At `eb238f5` | At `3cb09fb` |
|---|---|---|---|
| G1 | 3 | xfail (committed) | pass (denied, per-check reason) |
| G2 | 2 + addressing | row 1 xfail, row 2 xfail | row 1 xfail (by design, B off), rest pass |
| G3 | 4 adapter paths | xfail (200) | pass (403 `param_lineage`) |
| G4 | 4 + decorator + sets | dict/list xfail | pass |
| G5 | 1 | fail-open (measured) | pass |
| Benign twins | one per gap | pass | pass |

### Suite lines, full extras (`crypto`, `mcp`, `fastapi`, `flask`, `python-jose`)

| Commit | Line |
|---|---|
| `eb238f5` baseline | 1818 passed, 25 skipped (without python-jose) |
| `3cb09fb` | 1912 passed, 9 skipped, 1 xfailed |

mypy `agentlock/ --ignore-missing-imports`: 0 errors. ruff: clean on every
touched file.

### Release predictions, frozen before the release commands run

**R1.** The release commit is the CHANGELOG reword after `3cb09fb`
("docs: scope the session_id known limit to integrations/"), and the tag
`v1.11.0` points at it. `pyproject.toml`, `agentlock/__init__.py` and
`CITATION.cff` already read 1.11.0 at that commit, so no version bump happens
after the tag (the 1.10.3 slip cannot recur).

**R2.** `python -m build` from the tag produces `agentlock-1.11.0.tar.gz` and
`agentlock-1.11.0-py3-none-any.whl`; `twine check` PASSED on both;
`Metadata-Version: 2.4`, `Version: 1.11.0`.

**R3.** A fresh venv with only the wheel and the four extras prints
`1.11.0` from `agentlock.__version__`, and the two probe scripts under
`tests/probes/` run against it print the step 13 report's G1 block (three
denied rows with per-check reasons) and the G4 block (dict and list redacted).
G2 and G3 probe rows still print GAP, because those scripts call the engine
without `session_id` and without parameters; that is the documented default.

**R4.** The full suite against the installed wheel, in `/tmp/al-probe-venv`:
1912 passed, 9 skipped, 1 xfailed.

**R5.** `grep -rn "Co-Authored-By" .git/logs` over the branch's commits returns
0; `grep -rnP "\x{2014}" agentlock tests docs CHANGELOG.md README.md` returns 0.

### What this amendment is not

It is not the release. Everything above R1 is measured; R1 to R5 are what the
release is scored against, and AMENDMENT 2 records the score.
