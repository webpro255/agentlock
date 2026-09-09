# v1.8 Recipient Enforcement: Baseline of Record and Frozen Predictions

Date: 2026-09-09
Branch: `v1.8-recipient-enforcement`, cut from `6d5fa24 release: v1.7.0`
Working tree at measurement time: clean.

This document is written before any mechanism code exists. It records what the
engine does today, the decisions that govern the v1.8.0 build, and predictions
that increment 1 either meets or fails. Nothing here is a description of code
that has been written.

---

## 1. Baseline of record

All measurements taken on `v1.8-recipient-enforcement` at `6d5fa24`, 2026-09-09.

### A1. Grep for `RECIPIENT_NOT_ALLOWED`

```
agentlock/types.py:190:    RECIPIENT_NOT_ALLOWED = "recipient_not_allowed"
```

Exactly one hit: the enum definition. Nothing raises it, nothing returns it,
nothing asserts on it.

### A2. Step 8 region of `policy.py`

`agentlock/policy.py:558-572`, verbatim, with the lines immediately before and
after:

```python
        # 7. PII filter -- data classification clearance
        pii_decision = self._pii_filter.evaluate(
            context.max_output_classification,
            permissions.data_policy.output_classification,
        )
        if pii_decision is not None:
            return pii_decision

        # ── End filter chains ─────────────────────────────────────────

        # 8. Recipient policy (only if recipient is provided)
        # Detailed validation delegated to the tool or deployer;
        # here we enforce "known_contacts_only" as a marker.
        # Real-world enforcement uses a contacts backend.

        # 9. Human approval
        if permissions.human_approval.required:
```

Step 8 is a comment block. No code path reads the recipient argument. Every
`recipient` reference in the package is either a declaration or a write:

| Location | Kind |
|---|---|
| `agentlock/policy.py:50` | docstring line for the field |
| `agentlock/policy.py:72` | `recipient: str = ""` field on `RequestContext` |
| `agentlock/gate.py:641` | `recipient: str = ""` parameter of `authorize()` |
| `agentlock/gate.py:664` | docstring line for that parameter |
| `agentlock/gate.py:848` | `recipient=recipient` into the `RequestContext` |
| `agentlock/schema.py:103` | `allowed_recipients` field on `ScopeConfig` |

The value is threaded end to end and then discarded.

### A3. `RecipientPolicy` members

`agentlock/types.py:85-91`, verbatim:

```python
class RecipientPolicy(str, Enum):
    """Allowed recipient scope for outbound communication tools."""

    KNOWN_CONTACTS_ONLY = "known_contacts_only"
    SAME_DOMAIN = "same_domain"
    ALLOWLIST = "allowlist"
    ANY = "any"
```

There are no per-member docstrings. The class docstring shown above is the only
prose attached to the type.

Role mapping:

| Member | Wire value | Role |
|---|---|---|
| `KNOWN_CONTACTS_ONLY` | `known_contacts_only` | known-contacts |
| `SAME_DOMAIN` | `same_domain` | NONE (unassigned by D1 through D13) |
| `ALLOWLIST` | `allowlist` | explicit-allowlist |
| `ANY` | `any` | unrestricted |

All three roles named in the decisions have a member. One member, `SAME_DOMAIN`,
mapped to NONE at the time of the first report. D14, added 2026-09-09, assigns it.

### A4. Session construction

`agentlock/gate.py:598-626`, verbatim:

```python
    def create_session(
        self,
        user_id: str,
        role: str,
        data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """Create an authenticated session after out-of-band auth completes.

        This should only be called by the authentication infrastructure,
        never by the agent.
        ...
        """
        return self._session_store.create(
            user_id=user_id,
            role=role,
            data_boundary=data_boundary,
            max_duration=self._session_duration,
            metadata=metadata,
        )
```

`agentlock/session.py:22-42`, verbatim. Note `@dataclass` with no `frozen=` and
no `slots=`:

```python
@dataclass
class Session:
    """An authenticated session.
    ...
    """

    user_id: str
    role: str
    data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    session_id: SessionId = field(default_factory=_generate_session_id)
    metadata: dict[str, Any] = field(default_factory=dict)

    _max_duration: int = 900
```

`SessionStore.create` (`agentlock/session.py:73-91`) accepts `user_id`, `role`,
`data_boundary`, `max_duration`, `metadata`.

Complete field list on the session object: `user_id`, `role`, `data_boundary`,
`created_at`, `expires_at`, `session_id`, `metadata`, `_max_duration`. Plus the
properties `is_expired` and `remaining_seconds` and the method `validate`.

No contacts field. No allowlist field. No recipient-related field of any kind.
Matches the stated expectation.

### A5. How a policy step returns DENY, and whether Step 8 would be signed

Return type is `PolicyDecision`, `agentlock/policy.py:89-99`:

```python
@dataclass(slots=True)
class PolicyDecision:
    """Result of policy evaluation."""

    allowed: bool
    reason: DenialReason | None = None
    detail: str = ""
    required_role: str = ""
    suggestion: str = ""
    needs_auth: bool = False
    needs_approval: bool = False
    approval_channel: str = ""
```

`DenialReason` is attached as an enum member on the `reason` field. Representative
denial, Step 5, `agentlock/policy.py:530-543`:

```python
        # 5. Max records
        if scope.max_records and context.record_count > scope.max_records:
            return PolicyDecision(
                allowed=False,
                reason=DenialReason.MAX_RECORDS_EXCEEDED,
                detail=(
                    f"Requested {context.record_count} records; "
                    f"limit is {scope.max_records}."
                ),
                suggestion=(
                    f"Reduce your request to {scope.max_records} records "
                    f"or fewer."
                ),
            )
```

Path from that return to receipt signing:

1. `agentlock/gate.py:863`: `decision = self._policy.evaluate(permissions, ctx)`
2. `agentlock/gate.py:1528`: the `else` branch taken when `decision.allowed` is falsey
3. `agentlock/gate.py:1529-1531`: `denial_reason = decision.reason.value if decision.reason else "unknown"`
4. `agentlock/gate.py:1543-1556`: audit record written with `action="denied"`, `reason=denial_reason`
5. `agentlock/gate.py:1558-1578`: `AuthResult` built with `decision=DecisionType.DENY` and the `denial` dict
6. `agentlock/gate.py:1581`: `return self._sign_result(auth_result, tool_name, user_id, role, parameters)`

`_sign_result` is defined at `agentlock/gate.py:2539`. Its first statement,
`agentlock/gate.py:2548-2549`:

```python
        if self._receipt_signer is None:
            return result
```

**Verdict: a Step 8 return at the existing pipeline position would be
CONDITIONAL.** Signed whenever a `ReceiptSigner` was supplied to the gate
constructor (`agentlock/gate.py:207`, stored at `agentlock/gate.py:230`),
unsigned when no signer is configured. This is exactly the behavior of every
other policy-step denial, because all of them exit through
`agentlock/gate.py:1581`. Step 8 inherits signing for free by returning a
`PolicyDecision` like its neighbors.

`_sign_result` has exactly three call sites: `agentlock/gate.py:1470` (parameter
blocked), `agentlock/gate.py:1527` (allow and modify), `agentlock/gate.py:1581`
(policy denial).

Nothing was fixed. See the out-of-scope finding in section 3 regarding
`agentlock/gate.py:944`.

### A6. Grep for `rate_limited` and `DenialReason.RATE_LIMITED`

```
agentlock/types.py:182:    RATE_LIMITED = "rate_limited"
agentlock/exceptions.py:99:        super().__init__(reason="rate_limited", **kwargs)
agentlock/gate.py:940:                    reason="rate_limited",
tests/test_gate.py:118:        assert result.denial["reason"] == DenialReason.RATE_LIMITED.value
```

Four hits. One enum definition, two raw-literal uses, one test that already
reads the enum's value rather than the literal. D5 targets exactly the two
raw-literal sites.

### A7. Existing policy-step tests

File: `tests/test_policy.py`. Module fixture, `tests/test_policy.py:21-23`:

```python
@pytest.fixture
def engine():
    return PolicyEngine()
```

Representative test, `tests/test_policy.py:163-174`, verbatim:

```python
class TestMaxRecords:
    def test_max_records_exceeded(self, engine):
        perms = AgentLockPermissions(
            risk_level=RiskLevel.MEDIUM,
            allowed_roles=["user"],
            scope=ScopeConfig(max_records=10),
        )
        ctx = RequestContext(user_id="alice", role="user", record_count=50)
        decision = engine.evaluate(perms, ctx)
        assert decision.allowed is False
        assert decision.reason == DenialReason.MAX_RECORDS_EXCEEDED
```

The pattern to mirror: construct `AgentLockPermissions` directly, construct
`RequestContext` directly, call `engine.evaluate`, assert on `decision.allowed`
and `decision.reason` as an enum member.

### A8. Full suite

Command, taken from `pyproject.toml:84-86`:

```
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"
```

CI (`.github/workflows/ci.yml`) runs `pytest --cov=agentlock --cov-report=xml -v`,
adding only coverage flags. Command run: `pytest`.

Summary line, verbatim:

```
================= 1417 passed, 8 skipped, 14 warnings in 3.11s =================
```

The first pass of this measurement halted on the stated stop condition, which
expected 1418 passed and 7 skipped. The discrepancy was resolved as an
environment fact, not a regression: the eighth skip is an optional extra that is
not installed in this virtualenv.

```
$ python -c "import mcp"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
    import mcp
ModuleNotFoundError: No module named 'mcp'
```

Full skip list from `pytest -rs`, verbatim:

```
=========================== short test summary info ============================
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
================= 1417 passed, 8 skipped, 14 warnings in 3.11s =================
```

**Baseline of record: 1417 passed, 0 failed, 8 skipped, with the skip list above.**
Total collected is 1425.

### A9. Behavioral baseline

Script written to the session scratchpad, outside the repository, at
`/tmp/claude-1000/-home-n1trolab-agentlock-v1-4/b0956e14-022c-4ff0-962c-f922b6f537ce/scratchpad/a9_baseline.py`.

Arguments passed to reach Step 8, the minimum: a tool registered under
`risk_level=MEDIUM`, `requires_auth=True`, `allowed_roles=["user"]`,
`scope=ScopeConfig(allowed_recipients=RecipientPolicy.KNOWN_CONTACTS_ONLY)`; a
session created with `create_session(user_id="alice", role="user")`; then
`gate.authorize("send_email", user_id="alice", role="user", recipient=r)`. No
other arguments were needed. The same tool was registered once at
`version="1.5"` and once at `version="1.4"`.

Output, verbatim:

```
=== version 1.5 ===
recipient='attacker@evil.com'  decision=allow  allowed=True  reason=None
recipient='user@company.com'   decision=allow  allowed=True  reason=None
recipient=''                   decision=allow  allowed=True  reason=None
recipient='not an address'     decision=allow  allowed=True  reason=None
recipient='a@b.com, c@d.com'   decision=allow  allowed=True  reason=None
=== version 1.4 ===
recipient='attacker@evil.com'  decision=allow  allowed=True  reason=None
recipient='user@company.com'   decision=allow  allowed=True  reason=None
recipient=''                   decision=allow  allowed=True  reason=None
recipient='not an address'     decision=allow  allowed=True  reason=None
recipient='a@b.com, c@d.com'   decision=allow  allowed=True  reason=None
=== recipient_allowlist registration attempt ===
ValidationError: 1 validation error for ScopeConfig
recipient_allowlist
  Extra inputs are not permitted [type=extra_forbidden, input_value=['@company.com'], input_type=list]
    For further information visit https://errors.pydantic.dev/2.13/v/extra_forbidden
```

No run returns `RECIPIENT_NOT_ALLOWED`. Ten of ten calls ALLOW, at both schema
versions, including the two malformed forms and the cross-domain address. This
is the behavior v1.8.0 changes at version 1.5 and preserves at version 1.4.

The schema rejects unknown fields. `ScopeConfig` carries
`model_config = {"extra": "forbid"}` at `agentlock/schema.py:105`, so
`recipient_allowlist` must be declared before it can be set. The exact error is
`extra_forbidden`, as quoted above.

### A10. `create_session` call sites

Definition: `agentlock/gate.py:598`. Signature reproduced in A4.

Call sites excluding the definition: **134**.

Distribution:

| Location | Count |
|---|---|
| `tests/` | 129 |
| `docs/history.md` | 3 (lines 188, 239, 270) |
| `README.md` | 1 (line 147) |
| `examples/multi_role.py` | 1 (line 72) |

Every call passes only `user_id` and `role`, positionally or by keyword, with
two exceptions: `tests/test_gate.py:155` also passes
`data_boundary=DataBoundary.TEAM`, and `tests/test_gate_v11.py:249` spans
multiple lines. No call site passes anything that a new trailing keyword with a
default would collide with.

This bounds D8 and D15: a `known_contacts: Iterable[str] | None = None`
keyword is additive against all 134.

---

## 2. Decisions of record, with Part B verdicts

D1 through D13 were set before measurement, 2026-09-09. D7 was replaced and D14
through D16 were added later the same day, after the baseline was reported. All
amendments are marked and dated. Amendments are append-only; the superseded text
of D7 is retained below rather than deleted.

### D1. Contact origin
> Known contacts live on the session, populated only at create_session from
> deployer supplied config. Never from tool output, context writes, or model
> output.

**CONSISTENT.** `Session` is a plain mutable `@dataclass` (`session.py:22`) with
no `frozen=` and no `slots=`, so a field is addable; `create_session`
(`gate.py:598`) is the sole construction path reached by all 134 call sites in
A10, and no other writer of session state exists.

### D2. Trigger condition
> Enforcement fires only when the tool's allowed_recipients is a restrictive
> member AND a nonempty recipient is supplied. Otherwise the step is skipped.
> Additive-only: every call that does not meet both conditions gets a decision
> identical to v1.7.0.

**CONSISTENT.** `RequestContext.recipient` defaults to `""` (`policy.py:72`) and
A2 shows nothing reads it, so a guard on both conditions cannot alter any
decision measured in A9.

### D3. No lineage coupling
> Recipient check is independent of the lineage engine. No coupling.

**CONSISTENT.** Step 8 sits above every lineage gate (`policy.py:623`,
`policy.py:671`) and the recipient value reaches the engine on the
`RequestContext` field, never through `context.metadata`, which is the dict the
`InjectionFilter` scans as attacker-controlled text.

### D4. Fail-safe
> Fail-safe: anything that fails membership denies.

**CONSISTENT.** The step returns `PolicyDecision(allowed=False, ...)` in the
shape of `policy.py:530`, and the version guard it sits behind already fails
closed by contract (`schema.py:80-92`: an unparseable version returns `True`,
meaning enforce).

### D5. RATE_LIMITED enum
> RATE_LIMITED: the raw string "rate_limited" (gate.py near line 940,
> exceptions.py near line 99) becomes DenialReason.RATE_LIMITED. Wire value
> unchanged.

**CONSISTENT, with one implementation note.** Both sites confirmed at
`exceptions.py:99` and `gate.py:940` by A6. `DeniedError.__init__` already
normalizes at `exceptions.py:37`:

```python
        self.reason = str(reason.value if hasattr(reason, "value") else reason)
```

Measured directly: `RateLimitedError().to_dict()["reason"]` is `'rate_limited'`
today, and `DeniedError(reason=DenialReason.RATE_LIMITED).to_dict()["reason"]`
is also `'rate_limited'`. The wire value is unchanged and no string comparison
breaks. Every `reason ==` comparison in the repo either compares against a
`DenialReason` member or against a plain audit string; none is affected.

Note for the build: `gate.py:940` is an argument to `AuditLogger.log`, whose
`reason` parameter is typed `str` (`audit.py:387`) and whose `AuditRecord.reason`
field is typed `str` (`audit.py:49`), with no normalization on the way in.
Because `DenialReason` subclasses `str`, passing the member would still compare
and serialize as `"rate_limited"`, but the stored object would be an enum
member rather than a plain `str`. Use `DenialReason.RATE_LIMITED.value` at that
call site to keep the stored type exactly what it is today. `exceptions.py:99`
takes the bare member, since line 37 normalizes it.

### D6. Signed receipts
> Recipient denials emit a signed receipt like every other decision.

**CONSISTENT.** A5 establishes that every `PolicyDecision` denial exits through
`_sign_result` at `gate.py:1581`; a Step 8 denial inherits this with no new
code, conditional only on a signer being configured (`gate.py:2548`).

### D7. Schema default (SUPERSEDED 2026-09-09)
> ~~The schema default of allowed_recipients changes from KNOWN_CONTACTS_ONLY to
> the unrestricted member. Rationale: the current default is unenforced, so
> enforcing it would change every tool's decisions; an unrestricted default
> changes none. Explicitly configured restrictive values become enforced.~~

Superseded by D7 (replaced) below. Retained for the record.

### D7 (replaced, 2026-09-09). Version gating instead of default weakening
> The schema default of allowed_recipients stays KNOWN_CONTACTS_ONLY. Step 8
> enforcement is gated on version_at_least(permissions.version, (1, 5)),
> mirroring how lineage_policy gates on (1, 3). Blocks at version 1.4 and below
> get identical decisions to v1.7.0. Blocks at 1.5 get allowed_recipients
> enforced as written, default included.

**CONSISTENT.** `version_at_least` is already the established gating idiom at six
sites (`policy.py:168`, `policy.py:623`, `policy.py:671`, `policy.py:846`,
`gate.py:760`, `gate.py:784`) plus `action_class_audit.py:258`, and
`AgentLockPermissions.version` defaults to `SCHEMA_VERSION`
(`schema.py:482`). This amendment is strictly better than the superseded text:
it preserves the secure default recorded at `tests/test_schema.py:229` instead
of weakening it, and it buys the same additivity from the version floor. A9 was
re-run under this amendment at both 1.5 and 1.4 and shows no behavioral
difference on v1.7.0, which is the correct pre-build reading.

### D8. create_session gains known_contacts
> create_session gains known_contacts (iterable of str, default None). Stored on
> the session as a frozenset after normalization. None means empty set. Empty
> set under KNOWN_CONTACTS_ONLY denies every recipient.

**CONSISTENT.** A10 counts 134 call sites, none of which pass a keyword that
would collide, and all of which keep working under a trailing default of `None`.

### D9. recipient_allowlist scope field
> New scope field recipient_allowlist: list of str, default empty. Entries are
> full addresses or domain entries beginning with "@". Consulted only when the
> policy is the explicit allowlist member.

**CONSISTENT.** `ScopeConfig` is `extra="forbid"` (`schema.py:105`) and A9
measured the exact `extra_forbidden` rejection, so the field must be declared.
Declaring it with `default_factory=list` is additive: no existing block changes
meaning, and the field is consulted only under `ALLOWLIST`.

### D10. Normalization and matching
> Normalization on both sides: strip outer whitespace, casefold. Known contacts:
> exact match only. Allowlist: exact match, or a domain entry matches when the
> recipient substring after its last "@" equals the entry with the leading "@"
> removed. Exact domain only, no subdomain wildcard.

**CONSISTENT.** No recipient normalization, parsing, or matching exists anywhere
in the package today (A2), so there is no prior behavior to contradict.

### D11. Malformed recipients
> Malformed: after stripping, a recipient containing internal whitespace, any
> control character, a newline, a comma, or a semicolon is DENY
> RECIPIENT_NOT_ALLOWED under any restrictive policy. Multi-recipient strings are
> split by adapters into separate authorize calls in a later increment.

**CONSISTENT.** A9 confirms both `"not an address"` and `"a@b.com, c@d.com"`
currently ALLOW, so this is new behavior on an unenforced path, reachable only
above the 1.5 version floor.

### D12. Empty recipient
> Empty recipient string equals not supplied: step skipped.

**CONSISTENT.** `RequestContext.recipient` defaults to `""` (`policy.py:72`) and
A9 measured `""` as ALLOW, which the skip preserves exactly.

### D13. Pipeline position
> Step 8 stays at pipeline position 8. First denial in pipeline order wins.

**CONSISTENT.** The Step 8 comment block occupies position 8 verbatim between the
PII filter return (`policy.py:558-564`) and human approval (`policy.py:571`), and
every step above it returns early, so ordering is already first-denial-wins.

### D14 (added 2026-09-09). SAME_DOMAIN semantics
> SAME_DOMAIN: the recipient's domain (substring after its last "@", normalized
> per D10) must equal the domain of the session user_id (substring after its last
> "@", normalized). If user_id contains no "@", DENY RECIPIENT_NOT_ALLOWED. Exact
> match only.

**CONSISTENT.** `SAME_DOMAIN` exists at `types.py:89` and `RequestContext.user_id`
(`policy.py:70`) is populated at `gate.py:843` and available at Step 8. This
amendment closes the one gap flagged in the first baseline report, where
`SAME_DOMAIN` mapped to no role in D1 through D13 and would have been a
restrictive member with undefined semantics under D2.

### D15 (added 2026-09-09). Threading
> RequestContext gains known_contacts: frozenset[str] = frozenset().
> gate.authorize() populates it from the resolved session, adjacent to the
> context_state resolution. Session gains known_contacts: frozenset[str] =
> field(default_factory=frozenset). SessionStore.create and
> AuthorizationGate.create_session gain known_contacts: Iterable[str] | None =
> None, normalized per D10 and frozen at creation.

**CONSISTENT.** `RequestContext` is `@dataclass(slots=True)` (`policy.py:40`), so
a new field with a default is legal and cheap; the adjacency point named is
`gate.py:757-767`, where `resolved_session_id` and `context_state` are derived
from `session`; `Session` and `SessionStore.create` are both mutable and take
only keyword-defaulted additions (A4).

### D16 (added 2026-09-09). Schema
> SCHEMA_VERSION becomes "1.5". A new schema/agentlock-v1.5.json is generated
> from AgentLockPermissions.model_json_schema() the same way v1.4 was;
> schema/agentlock-v1.4.json is untouched. ScopeConfig gains recipient_allowlist:
> list[str] = Field(default_factory=list). Exactly two existing test assertions
> change, "1.4" to "1.5", at tests/test_backward_compat.py:68 and
> tests/test_gate_v12.py:284. No other existing test is edited.
> tests/test_schema.py:229 (the KNOWN_CONTACTS_ONLY default) remains true and
> unedited.

**CONSISTENT, verified line by line.** A grep for the hardcoded literal `"1.4"`
across `tests/` and `agentlock/`, excluding the `SCHEMA_VERSION` definition
itself, returns exactly two assertions:

```
tests/test_backward_compat.py:68:        assert SCHEMA_VERSION == "1.4"
tests/test_gate_v12.py:284:        assert SCHEMA_VERSION == "1.4"
```

Every other version test compares against the `SCHEMA_VERSION` symbol rather
than a literal (`tests/test_backward_compat.py:70`, `:78`, `:265`,
`tests/test_gate_v12.py:293`) and therefore needs no edit.
`tests/test_schema.py:229` reads `assert sc.allowed_recipients ==
RecipientPolicy.KNOWN_CONTACTS_ONLY`, which amended D7 preserves. The `schema/`
directory holds `agentlock-v1.0.json`, `agentlock-v1.2.json`,
`agentlock-v1.3.json`, `agentlock-v1.4.json`, confirming the add-new-and-leave-old
convention this decision follows.

---

## 3. Out-of-scope finding, reported and not fixed

**The rate-limit denial is the one decision path that never gets a signed
receipt.** `agentlock/gate.py:915-950` returns its `AuthResult` directly:

```python
                return AuthResult(
                    allowed=False,
                    decision=DecisionType.DENY,
                    denial=e.to_dict(),
                    audit_id=record.audit_id,
                    hardening=directive,
                )
```

`_sign_result` has exactly three call sites (`gate.py:1470`, `gate.py:1527`,
`gate.py:1581`) and this return is none of them. So with a `ReceiptSigner`
configured, an ALLOW, a MODIFY, a parameter-blocked DENY, and every policy DENY
carry a receipt, while a rate-limit DENY carries `receipt=None`. D6 asserts that
recipient denials are signed "like every other decision", and that premise holds
for the path Step 8 sits on but is not universally true of the gate today.

This is a finding for the human. It is out of scope for v1.8.0 as specified, it
is not a recipient-enforcement bug, and nothing here changes it.

---

## 4. Predictions for increment 1 (engine build)

Each is falsifiable by a command. If any fails, the increment did not match its
prediction, and that is the finding.

### P1. The denial reason is actually reachable
Grep for `RECIPIENT_NOT_ALLOWED` returns at least three hits: the enum
definition at `agentlock/types.py:190`, at least one return site in
`agentlock/policy.py` Step 8, and at least one test assertion.

### P2. New tests, all passing
All new tests live in a single new file, `tests/test_v18_recipient.py`,
mirroring the `tests/test_policy.py` style shown in A7: construct
`AgentLockPermissions` and `RequestContext` directly and call
`engine.evaluate` for policy-level cases; use `AuthorizationGate` for the
session-threading and receipt cases.

At schema version 1.5:

| Case | Expected |
|---|---|
| contacts-only, recipient in `known_contacts` | ALLOW |
| contacts-only, recipient not in `known_contacts` | DENY `RECIPIENT_NOT_ALLOWED` |
| contacts-only, `known_contacts` empty | DENY `RECIPIENT_NOT_ALLOWED` |
| allowlist, exact address match | ALLOW |
| allowlist, domain entry, recipient in domain | ALLOW |
| allowlist, domain entry, recipient out of domain | DENY `RECIPIENT_NOT_ALLOWED` |
| allowlist, domain entry, recipient in a subdomain of it | DENY `RECIPIENT_NOT_ALLOWED` |
| same_domain, recipient domain equals `user_id` domain | ALLOW |
| same_domain, recipient domain differs | DENY `RECIPIENT_NOT_ALLOWED` |
| same_domain, `user_id` contains no "@" | DENY `RECIPIENT_NOT_ALLOWED` |
| `ANY`, arbitrary recipient | ALLOW |
| restrictive policy, empty recipient | step skipped, baseline decision |
| each malformed form in D11: internal whitespace, control character, newline, comma, semicolon | DENY `RECIPIENT_NOT_ALLOWED` |
| recipient denial through the gate with a `ReceiptSigner` configured | `AuthResult.receipt` is not None and verifies |

At schema version 1.4:

| Case | Expected |
|---|---|
| the same restrictive tool, recipient `"attacker@evil.com"` | identical decision to v1.7.0, that is ALLOW |

Plus: `RATE_LIMITED` is raised as `DenialReason.RATE_LIMITED` with wire value
`"rate_limited"`, and the existing assertion at `tests/test_gate.py:118` is
untouched and still passes.

### P3. Suite arithmetic
The full suite reports 1417 plus the number of new tests passed, 0 failed, 8
skipped, with the identical skip list recorded in A8. Exactly two pre-existing
assertions are edited, the two `"1.4"` to `"1.5"` lines at
`tests/test_backward_compat.py:68` and `tests/test_gate_v12.py:284`. No other
existing test is edited.

### P4. The A9 script, rerun on the built branch
The version 1.5 run returns DENY `RECIPIENT_NOT_ALLOWED` for
`"attacker@evil.com"`, for `"user@company.com"` (because `known_contacts` is
empty in that script), for `"not an address"`, and for `"a@b.com, c@d.com"`; and
returns the baseline decision, ALLOW, for `""`.

The version 1.4 run returns the baseline decisions for all five, that is ALLOW
across the board, byte-identical to the A9 output above.

A third run at version 1.5 with `known_contacts=["user@company.com"]` returns
ALLOW for that address only, and DENY `RECIPIENT_NOT_ALLOWED` for the other
three nonempty recipients.

### P5. Raw literal cleanup
Grep for the raw literal `"rate_limited"` returns hits only at the enum value
definition (`agentlock/types.py:182`) and at `tests/test_gate.py:118`. The two
current raw-literal uses at `agentlock/exceptions.py:99` and
`agentlock/gate.py:940` are gone.

### P6. Files touched
The build touches only: `agentlock/policy.py`, `agentlock/gate.py`,
`agentlock/exceptions.py`, `agentlock/schema.py`, `agentlock/session.py`,
`agentlock/types.py` only if a docstring needs it, `schema/agentlock-v1.5.json`
(new), `tests/test_v18_recipient.py` (new), the two assertion lines named in P3,
and `CHANGELOG.md`. Nothing else. `git diff --stat` names no other path.

### P7. Call-site compatibility
All 134 existing `create_session` call sites from A10 work unmodified under the
new `known_contacts` keyword defaulting to `None`.

### P8. Schema compatibility
Every existing schema-version test continues to pass with only the two edits from
P3, and a v1.4 permission block still validates against
`schema/agentlock-v1.5.json`. This mirrors the claim made for v1.4 at
`CHANGELOG.md:137` ("A v1.3 block still validates against v1.4"), and unlike that
claim it is to be measured, not asserted.

---

## 5. What this document is not

It is not a design. The decisions above were made before measurement and are not
reopened here. It is not a description of code: at the time of writing, Step 8 is
four lines of comment and `RECIPIENT_NOT_ALLOWED` has one occurrence in the
entire repository. Its only purpose is to make increment 1 checkable against
something written down before it existed.

---

## AMENDMENT 1 (2026-09-09): P5 wording defect found at measurement time, before the build was committed

Found by the build session while measuring increment 1, and recorded here before
any build change was committed. The defect is in the prediction, not in the
build.

### The defect

P5 states that a grep for the raw literal `"rate_limited"` returns hits "only at
the enum value definition (`agentlock/types.py:182`) and at
`tests/test_gate.py:118`."

That residue list was carried over from A6, whose grep was a case-insensitive
bare-word search for `rate_limited` and therefore matched
`DenialReason.RATE_LIMITED.value`. `tests/test_gate.py:118` reads:

```python
        assert result.denial["reason"] == DenialReason.RATE_LIMITED.value
```

It contains no quoted literal and never did. A case-sensitive grep for the
quoted literal cannot return it. P5's residue list is therefore unsatisfiable as
written, by any build.

### What is unchanged

The operative claim of P5 is unchanged and was met: the two raw-literal uses at
`agentlock/exceptions.py:99` and `agentlock/gate.py:940` are removed.

### P5, restated

> Grep for the raw literal `"rate_limited"` across `agentlock` and `tests`
> returns exactly two hits: the enum value definition at
> `agentlock/types.py:182`, and one intentional pin in
> `tests/test_v18_recipient.py` asserting that the wire value is unchanged. The
> two raw-literal uses at `agentlock/exceptions.py:99` and `agentlock/gate.py:940`
> are gone.

### Why the build was not altered to fit the original wording

The build was not changed to satisfy the frozen text. The pin test was kept
because it is the measured basis for the CHANGELOG's claim that the RATE_LIMITED
wire value is unchanged, and any honest assertion of that claim must contain the
literal. Removing it to make a grep come out clean would have deleted the only
evidence behind a claim the release makes.


---

## AMENDMENT 2 (2026-09-09): increment 1 built and matched

Build commit: `c1a9e01 feat: enforce recipient policy at Step 8, schema 1.5, RATE_LIMITED as enum`.

Measured on `v1.8-recipient-enforcement`. P5 is scored against its restated
wording in AMENDMENT 1, which was committed at `98d538c` before any build change
was committed.

### P1 to P8

| P | Verdict | Evidence |
|---|---|---|
| P1 | MATCH | `grep -rn RECIPIENT_NOT_ALLOWED agentlock tests` returns 16 hits: the enum definition at `agentlock/types.py:190`, the return site at `agentlock/policy.py:1039`, and 14 assertions in `tests/test_v18_recipient.py`. |
| P2 | MATCH | `44 passed in 0.03s`. Every row of the P2 table at version 1.5, the version 1.4 row, the session-threading case, the receipt case, and the RATE_LIMITED case. |
| P3 | MATCH | `1461 passed, 8 skipped, 14 warnings in 3.05s`, which is 1417 plus 44 new, 0 failed. Skip list identical to A8. `git diff --stat tests/` names 2 files, 2 insertions, 2 deletions, the two `"1.4"` to `"1.5"` lines, plus the one new file. |
| P4 | MATCH | All fifteen lines as predicted. Output below. |
| P5 | MATCH against the restated wording | `grep -rn '"rate_limited"' agentlock tests` returns exactly two hits: `agentlock/types.py:182` and `tests/test_v18_recipient.py:383`. `agentlock/exceptions.py:99` and `agentlock/gate.py:940` are gone. MISMATCH against the original wording, for the reason recorded in AMENDMENT 1. |
| P6 | MATCH | `git diff --stat` and `git status --short` name only P6 paths. `agentlock/types.py` needed no docstring change and is untouched. |
| P7 | MATCH | `grep -rn "create_session(" tests examples README.md docs \| wc -l` returns 143: A10's 134 call sites unmodified, plus 2 non-call mentions inside this document, plus 7 new calls in `tests/test_v18_recipient.py`. That the 134 run is covered by P3. |
| P8 | MATCH | Both schema-version tests pass. No repo test uses a JSON-schema validator, so `jsonschema` 4.26.0 was used: a populated v1.4 block is VALID against both `schema/agentlock-v1.4.json` and `schema/agentlock-v1.5.json`. |

### Exact suite summary line

```
================= 1461 passed, 8 skipped, 14 warnings in 3.05s =================
```

Skip list, verbatim, identical to A8:

```
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
```

### P1, verbatim

```
agentlock/types.py:190:    RECIPIENT_NOT_ALLOWED = "recipient_not_allowed"
agentlock/policy.py:1036:        """A RECIPIENT_NOT_ALLOWED denial in the shape of every other step."""
agentlock/policy.py:1039:            reason=DenialReason.RECIPIENT_NOT_ALLOWED,
tests/test_v18_recipient.py:82:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:89:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:118:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:124:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:130:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:155:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:162:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:169:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:211:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:230:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:247:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:268:        assert decision.reason == DenialReason.RECIPIENT_NOT_ALLOWED
tests/test_v18_recipient.py:312:        assert result.denial["reason"] == DenialReason.RECIPIENT_NOT_ALLOWED.value
tests/test_v18_recipient.py:324:        assert result.denial["reason"] == DenialReason.RECIPIENT_NOT_ALLOWED.value
```

### P4, verbatim, all fifteen lines

The A9 script was recreated in the session scratchpad from its description in
section A9, unchanged in its arguments, with a third run added per P4.

```
=== version 1.5 ===
recipient='attacker@evil.com'      decision=deny   allowed=False  reason=recipient_not_allowed
recipient='user@company.com'       decision=deny   allowed=False  reason=recipient_not_allowed
recipient=''                       decision=allow  allowed=True  reason=None
recipient='not an address'         decision=deny   allowed=False  reason=recipient_not_allowed
recipient='a@b.com, c@d.com'       decision=deny   allowed=False  reason=recipient_not_allowed
=== version 1.4 ===
recipient='attacker@evil.com'      decision=allow  allowed=True  reason=None
recipient='user@company.com'       decision=allow  allowed=True  reason=None
recipient=''                       decision=allow  allowed=True  reason=None
recipient='not an address'         decision=allow  allowed=True  reason=None
recipient='a@b.com, c@d.com'       decision=allow  allowed=True  reason=None
=== version 1.5, known_contacts=["user@company.com"] ===
recipient='attacker@evil.com'      decision=deny   allowed=False  reason=recipient_not_allowed
recipient='user@company.com'       decision=allow  allowed=True  reason=None
recipient=''                       decision=allow  allowed=True  reason=None
recipient='not an address'         decision=deny   allowed=False  reason=recipient_not_allowed
recipient='a@b.com, c@d.com'       decision=deny   allowed=False  reason=recipient_not_allowed
```

The version 1.4 run is byte-identical to the A9 output recorded before the build.

### P5, verbatim

```
agentlock/types.py:182:    RATE_LIMITED = "rate_limited"
tests/test_v18_recipient.py:383:        assert RateLimitedError().to_dict()["reason"] == "rate_limited"
```

### P8, verbatim

```
schema/agentlock-v1.4.json: VALID
schema/agentlock-v1.5.json: VALID
schema/agentlock-v1.4.json (block with recipient_allowlist): INVALID -- Additional properties are not allowed ('recipient_allowlist' was unexpected)
schema/agentlock-v1.5.json (block with recipient_allowlist): VALID
```

The last two lines are a control, not a prediction: the new field is accepted at
1.5 and rejected at 1.4, which is what makes the first two lines meaningful.

### Lint

`ruff check agentlock/ tests/`, the exact command CI runs
(`.github/workflows/ci.yml:32-33`), returns `All checks passed!` with exit 0.

### STEP 0b: the schema file is an envelope, not raw pydantic output

`schema/agentlock-v1.4.json` is NOT byte-identical to
`AgentLockPermissions.model_json_schema()` piped through
`json.dumps(indent=2)`. The committed file is a hand-built envelope:
`$schema`, `$id`, `title`, `description`, `type`, a `properties` block declaring
`name`, `description`, `parameters`, and `agentlock` as a `$ref`, a `required`
list of `name` and `agentlock`, and a `$defs` map. The `$defs` map is pydantic's
own `$defs` with the model's remaining top-level body promoted in under the key
`AgentLockPermissions`, then key-sorted. `json.dumps` runs at its default
`ensure_ascii=True`.

That transform was reconstructed and diffed against the committed v1.4 file.
The reconstruction is exact except for two lines, and
`schema/agentlock-v1.5.json` was generated by the same transform.

### Observation for release cleanup: two em dash description drifts in the v1.4 schema file

The two lines by which the reconstruction differs are both pre-existing source
drift, not envelope shape. In `schema/agentlock-v1.4.json`, the `description`
values of `ActionClassConfig` and `LineagePolicyConfig` contain `—`, the em
dash, at three positions each. The corresponding docstrings in
`agentlock/schema.py` now carry a double hyphen instead. The docstrings were
edited after `agentlock-v1.4.json` was generated and the file was never
regenerated, so the committed v1.4 schema no longer reproduces from its own
source.

Nothing here changes it. `agentlock-v1.4.json` was left untouched, as D16
requires. `agentlock-v1.5.json`, being generated from current source, carries the
double hyphen form. This is recorded as an item for release cleanup, not a
finding against increment 1.

### STEP 0c note

The pre-build grep for `agentshield` was expected to return zero and returned
two, both pre-existing committed prose in Markdown, neither in code, tests, or
any corpus:

```
SECURITY.md:119:v1.2.1 results (222 vectors, scored by AgentShield):
docs/RELEASE_SCOPE_v16.md:230:substrate is AgentDojo, not the historical AgentShield) gates the release, and
```

Both predate this branch and are already public on `origin`. Scoped to the code
the build touches, `grep -ri agentshield agentlock tests schema` returns zero
hits, before and after. No test and no source file added by increment 1 contains
the string.
