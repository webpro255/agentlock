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

---

## INCREMENT 2 FREEZE (2026-09-09): declared recipient parameter

Measured on `v1.8-recipient-enforcement` at `e6631f4 docs: AMENDMENT 2, increment 1
built and matched`. Working tree clean at measurement time. This section is written
before any increment 2 mechanism code exists. It appends to this document and edits
nothing above.

### Why increment 2 exists

Increment 1 made Step 8 enforce. It did not make Step 8 reachable. Neither shipped
adapter passes `recipient` to `authorize()`: `mcp-agentlock` `wrapper.py:396` and
`crewai-agentlock` `wrapper.py:184` both pass `tool_name`, `user_id`, `role`,
`parameters`, `metadata`. The in-repo integrations do the same, measured below at
M2. So `recipient` is always `""`, D12 skips the step, and every adapter call takes
the pre-v1.8 path. Increment 2 lets the trusted permission block declare which
parameter carries the recipient, and has the gate read it itself.

---

## PART M: measurements

### M1. The insertion point for D18, `agentlock/gate.py:781-867`, verbatim

```python
        # Build request metadata -- include parameters for injection filter
        request_metadata = dict(metadata or {})
        if parameters:
            request_metadata["parameters"] = parameters

        # v1.3 lineage: the gate owns this read; callers cannot supply it.
        # A worst-case taint summary of the session's provenance log is
        # attached so the policy engine can gate purely on provenance.
        _lp = permissions.lineage_policy
        _v13 = version_at_least(permissions.version, (1, 3))

        # E10 -- what each parameter-level lineage check concluded, or why it
        # never ran.  LOCALS, deliberately: these must NOT be written into
        # ``request_metadata``.  ``InjectionFilter`` scans that dict's values as
        # attacker-controlled text, so evidence placed there is evidence that
        # can change a decision.  These are read on the far side of the
        # decision, by the audit path, and by nothing else.
        _param_outcome: dict[str, Any] = {}
        _novel_outcome: dict[str, Any] = {}

        if _v13 and resolved_session_id:
            request_metadata["lineage"] = self._context_tracker.lineage_summary(
                resolved_session_id
            )
            if _lp is None:
                _no_policy = {"ran": False, "reason": "no_lineage_policy"}
                _param_outcome.update(_no_policy)
                _novel_outcome.update(_no_policy)

            # v1.3 Feature 2 -- parameter lineage. Gate-owned read: does any
            # parameter value trace to untrusted context but not the user's
            # authoritative request?  Attached for the policy engine.
            if _lp is not None and _lp.param_lineage_enabled:
                _match = self._context_tracker.parameter_lineage_check(
                    resolved_session_id,
                    parameters,
                    min_len=_lp.param_lineage_min_len,
                    outcome=_param_outcome,
                )
                if _match is not None:
                    request_metadata["param_lineage"] = _match
            elif _lp is not None:
                _param_outcome.update({"ran": False, "reason": "check_disabled"})

            # v1.4 -- novel lineage. Gate-owned read: does any parameter token
            # trace to NEITHER the authoritative nor the untrusted context?
            # Independent of param_lineage_enabled; exact-token membership.
            if _lp is not None and _lp.novel_lineage_enabled:
                _novel = self._context_tracker.novel_lineage_check(
                    resolved_session_id,
                    parameters,
                    outcome=_novel_outcome,
                )
                if _novel is not None:
                    request_metadata["novel_lineage"] = _novel
            elif _lp is not None:
                _novel_outcome.update({"ran": False, "reason": "check_disabled"})
        else:
            # Neither check ran, and the two reasons are not the same fact.  A
            # grant issued with no session was never examined for parameter
            # lineage at all, and its record has to say so rather than present
            # an unexamined call as a clean one.
            _reason = "no_session" if _v13 else "tool_below_v1_3"
            _param_outcome.update({"ran": False, "reason": _reason})
            _novel_outcome.update({"ran": False, "reason": _reason})

        # Build request context
        ctx = RequestContext(
            user_id=user_id,
            role=role,
            session_id=resolved_session_id,
            data_boundary=data_boundary or DataBoundary.AUTHENTICATED_USER_ONLY,
            record_count=record_count,
            recipient=recipient,
            known_contacts=resolved_known_contacts,
            is_bulk=is_bulk,
            is_external=is_external,
            is_financial=is_financial,
            is_account_modification=is_account_modification,
            is_consequential=is_consequential,
            is_deletion=is_deletion,
            is_membership_change=is_membership_change,
            amount=amount,
            max_output_classification=resolved_classification,
            metadata=request_metadata,
            context_state=context_state,
        )
```

**Where D18 extraction goes: immediately after `agentlock/gate.py:845`, the closing
line of the `else` branch of the v1.3 lineage block, and before the
`# Build request context` comment at `agentlock/gate.py:847`.** That is the last
line of the block preceding the `RequestContext` construction and the only position
that satisfies D18's two constraints at once: after `parameters` is available and
after `permissions` is resolved, and before `ctx` exists.

**`scope` is not a local in `authorize()`.** A grep for `scope` across
`agentlock/gate.py:630-870` returns exactly two hits, `agentlock/gate.py:670`
(a docstring line reading "data_boundary: Requested data scope.") and
`agentlock/gate.py:768` (the comment "# Apply restrict_scope effect"). Neither is a
binding. `permissions.scope` is nonetheless resolved and reachable at line 845:
`permissions` is bound at `agentlock/gate.py:692`
(`permissions = self._tools.get(tool_name)`) and is already dereferenced for other
fields at `agentlock/gate.py:766` (`permissions.version`), `:789`
(`permissions.lineage_policy`) and `:790` (`permissions.version`). D18 reads
`permissions.scope.recipient_parameter` directly, in the idiom of line 789.

`ScopeConfig` itself, `agentlock/schema.py:98-108`, verbatim, showing where D17's
field lands:

```python
class ScopeConfig(BaseModel):
    """Constrains what data a tool invocation can access."""

    data_boundary: DataBoundary = DataBoundary.AUTHENTICATED_USER_ONLY
    max_records: int | None = Field(default=None, ge=1)
    allowed_recipients: RecipientPolicy = RecipientPolicy.KNOWN_CONTACTS_ONLY
    # Entries are full addresses or domain entries beginning with "@",
    # consulted only under RecipientPolicy.ALLOWLIST.
    recipient_allowlist: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}
```

### M2. Every read of `context.metadata` in `policy.py`

`grep -n "context\.metadata" agentlock/policy.py`, verbatim:

```
113:    # Carried on the RETURN VALUE and never through ``context.metadata``.  That
577:            context.metadata.get("parameters"),
578:            context.metadata,
622:                and context.metadata.get("first_invocation", False)
652:            pmatch = context.metadata.get("param_lineage")
700:            nmatch = context.metadata.get("novel_lineage")
772:            summary = context.metadata.get("lineage")
831:                        context.metadata["session_gate_shadow"] = "DENY"
832:                        context.metadata["session_gate_shadow_detail"] = detail
```

Line 113 is a comment. Lines 577, 578, 622, 652, 700 and 772 are the six reads.
Lines 831 and 832 are writes, not reads.

**None of the six reads reads `context.recipient` or `context.recipients`.** The
only two references to the recipient field anywhere in `policy.py` are
`agentlock/policy.py:594` (the Step 8 guard) and `agentlock/policy.py:955` (the
normalization inside `_evaluate_recipient`), and neither goes through
`context.metadata`. `context.recipients` does not exist yet. Expectation met.

The `InjectionFilter` input, `agentlock/policy.py:571-597`, verbatim:

```python
        # ── Independent filter chains ─────────────────────────────────
        # These two filters are fully decoupled.  A request blocked by
        # the injection filter never reaches the PII filter.

        # 6. Injection filter -- parameter content analysis
        injection_decision = self._injection_filter.evaluate(
            context.metadata.get("parameters"),
            context.metadata,
        )
        if injection_decision is not None:
            return injection_decision

        # 7. PII filter -- data classification clearance
        pii_decision = self._pii_filter.evaluate(
            context.max_output_classification,
            permissions.data_policy.output_classification,
        )
        if pii_decision is not None:
            return pii_decision

        # ── End filter chains ─────────────────────────────────────────

        # 8. Recipient policy (only if recipient is provided)
        if context.recipient and version_at_least(permissions.version, (1, 5)):
            recipient_decision = self._evaluate_recipient(scope, context)
            if recipient_decision is not None:
                return recipient_decision
```

The filter is handed exactly two things: `context.metadata.get("parameters")` and
`context.metadata`. Both are read off the dict the gate builds at
`agentlock/gate.py:782-784`.

Adapter reach, measured in this repo: `grep -rn "recipient" agentlock/integrations/`
returns zero hits, across all four in-repo integrations (`mcp.py`, `autogen.py`,
`flask.py`, `fastapi.py`) and six `authorize()` call sites
(`mcp.py:167`, `autogen.py:119`, `flask.py:163`, `flask.py:271`,
`fastapi.py:197`, `fastapi.py:290`). The representative call,
`agentlock/integrations/mcp.py:167-172`, verbatim:

```python
                    auth = gate.authorize(
                        name,
                        user_id=user_id,
                        role=role,
                        parameters=arguments or None,
                    )
```

Same shape as the two out-of-repo adapters named above. Step 8 is unreachable from
every one of them.

### M3. Step 8 as built in increment 1

The call site, `agentlock/policy.py:593-597`, verbatim:

```python
        # 8. Recipient policy (only if recipient is provided)
        if context.recipient and version_at_least(permissions.version, (1, 5)):
            recipient_decision = self._evaluate_recipient(scope, context)
            if recipient_decision is not None:
                return recipient_decision
```

`_evaluate_recipient`, signature and docstring, `agentlock/policy.py:941-950`,
verbatim:

```python
    def _evaluate_recipient(
        self, scope: ScopeConfig, context: RequestContext
    ) -> PolicyDecision | None:
        """Enforce ``scope.allowed_recipients`` against the target recipient.

        Returns ``None`` when the recipient is permitted, so the caller falls
        through to the next pipeline step.  Every other outcome is a DENY.

        Fails safe: an unrecognized policy value denies.
        """
```

The body runs from `agentlock/policy.py:951` to `agentlock/policy.py:1032`, and the
denial constructor is the static method `_recipient_denial` at
`agentlock/policy.py:1034-1042`. The three helpers it uses,
`agentlock/policy.py:162-181`, verbatim:

```python
def _normalize_recipient(value: str) -> str:
    """Normalize a recipient or allowlist entry: strip, then casefold."""
    return value.strip().casefold()


def _recipient_domain(value: str) -> str:
    """The substring after the last "@", or "" when there is no "@"."""
    _, sep, domain = value.rpartition("@")
    return domain if sep else ""


def _recipient_is_malformed(value: str) -> bool:
    """Is this normalized recipient unusable as a single address?

    Control characters, any whitespace, commas, and semicolons all mark a
    value that is either not one address or not an address at all.
    """
    if "," in value or ";" in value:
        return True
    return any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in value)
```

Signature as built: `_evaluate_recipient(self, scope: ScopeConfig, context: RequestContext) -> PolicyDecision | None`.
It takes the scope and the context, and returns `None` on permit.

### M4. The audit log call in the policy-denial path

`agentlock/gate.py:1537-1565`, verbatim:

```python
        else:
            denial_reason = (
                decision.reason.value if decision.reason else "unknown"
            )
            # E5: a lineage denial cites the data that gated it.  Built from
            # what the gate already computed, after the decision, and never
            # read back -- ``evidence`` cannot alter ``decision``.
            denial_meta = _class_meta()
            provenance_ids = None
            evidence = self._lineage_evidence(denial_reason, ctx, permissions)
            if evidence is not None:
                denial_meta = {**(denial_meta or {}), "lineage_evidence": evidence}
                provenance_ids = self._evidence_provenance_ids(evidence)

            record = self._audit.log(
                tool_name=tool_name,
                user_id=user_id,
                role=role,
                action="denied",
                reason=denial_reason,
                risk_level=permissions.risk_level.value,
                log_level=permissions.audit.log_level,
                include_parameters=permissions.audit.include_parameters,
                parameters=parameters,
                session_id=ctx.session_id,
                duration_ms=duration_ms,
                metadata=denial_meta,
                context_provenance_ids=provenance_ids,
            )
```

**Is the recipient written to the audit record? No.** `grep -rn "recipient"
agentlock/audit.py` returns zero hits. `AuditLogger.log`
(`agentlock/audit.py:380-404`) has no recipient parameter and `AuditRecord` has no
recipient field. The only route by which a recipient value could reach an audit
record is inside `parameters`, at `agentlock/gate.py:1560`.

**Are parameter values written? Conditionally, under two gates.** In
`AuditLogger.log`, `agentlock/audit.py:459-474`:

```python
            record.response_summary = ""
            record.user_id = ""
            record.role = ""
            record.metadata = _drop_payload(record.metadata)
        elif log_level == AuditLogLevel.STANDARD:
            # + identity + scope
            record.parameters = None
            record.response_summary = ""
            record.metadata = _drop_payload(record.metadata)
        else:
            # FULL -- include everything
            if include_parameters:
                record.parameters = parameters
            else:
                record.metadata = _drop_payload(record.metadata)
            record.response_summary = response_summary
```

Parameter values are stored only when `log_level` is `AuditLogLevel.FULL` **and**
`include_parameters` is true. Both come from the trusted permission block:
`permissions.audit.log_level` at `agentlock/gate.py:1558` and
`permissions.audit.include_parameters` at `agentlock/gate.py:1559`. At MINIMAL and
STANDARD, `record.parameters` is cleared unconditionally. So the flag is
`audit.include_parameters`, effective only at `audit.log_level == FULL`.

Consequence for increment 2: a recipient read out of `parameters` under D18 changes
nothing about what the audit record holds, because the record already holds the whole
`parameters` dict or none of it, under those two flags, and the extraction adds no
new field to the record.

### M5. Behavioral baseline: the unreachable seam, measured

Script in the session scratchpad, outside the repository. Tool registered at
`version="1.5"`, `risk_level=MEDIUM`, `requires_auth=True`, `allowed_roles=["user"]`,
`scope=ScopeConfig(allowed_recipients=RecipientPolicy.KNOWN_CONTACTS_ONLY)`; session
`create_session(user_id="alice", role="user")` with no contacts. Output, verbatim:

```
call 1: no recipient argument, parameters={'to': 'attacker@evil.com'}
  decision=allow  allowed=True  denial=None
call 2: recipient='attacker@evil.com' passed explicitly
  decision=deny  allowed=False  denial={'status': 'denied', 'reason': 'recipient_not_allowed', 'detail': "Recipient is not in the session's known contacts; rejected under recipient policy 'known_contacts_only'.", 'required_role': '', 'current_role': 'user', 'suggestion': 'Send only to an address configured as a known contact for this session.'}
```

Both as expected. Call 1 is the seam: an identical hostile address, carried in the
parameter an adapter actually sends, is ALLOWED at version 1.5 with a restrictive
policy in force, because nothing reads it. Call 2 is the same tool, same session,
same address, denied, reachable only by a caller that already knows to pass
`recipient=`. Increment 2 makes call 1 behave like call 2.

The stop condition on M5 did not fire: the first call allows.

### M6. `ScopeConfig(recipient_parameter="to")` today

Verbatim:

```
ValidationError: 1 validation error for ScopeConfig
recipient_parameter
  Extra inputs are not permitted [type=extra_forbidden, input_value='to', input_type=str]
    For further information visit https://errors.pydantic.dev/2.13/v/extra_forbidden
```

`extra_forbidden`, as expected, from `model_config = {"extra": "forbid"}` at
`agentlock/schema.py:108`. The field must be declared before it can be set, the same
result A9 measured for `recipient_allowlist` before increment 1.

### M7. Full suite

`pytest -rs`, summary line verbatim:

```
================= 1461 passed, 8 skipped, 14 warnings in 3.11s =================
```

1461 passed, 0 failed, 8 skipped. Skip list, verbatim:

```
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
```

Identical to A8's skip list, line for line. The stop condition on M7 did not fire.

### M8. The AMENDMENT 2 envelope generator reproduces the committed v1.5 schema

The transform described in AMENDMENT 2's STEP 0b was re-applied on this tree:
`AgentLockPermissions.model_json_schema()`, its `$defs` popped, the model's remaining
top-level body promoted into that map under the key `AgentLockPermissions`, the map
key-sorted, wrapped in the hand-built envelope (`$schema`, `$id`, `title`,
`description`, `type`, `properties`, `required`, `$defs`), serialized with
`json.dumps(..., indent=2)` at the default `ensure_ascii=True`, plus a trailing
newline.

```
$ diff regen-v1.5.json schema/agentlock-v1.5.json && echo IDENTICAL
IDENTICAL
$ sha256sum schema/agentlock-v1.5.json regen-v1.5.json
59d13c463539d4c93965bf909bb6da45bd466a9a316b3649e97752acd75235d8  schema/agentlock-v1.5.json
59d13c463539d4c93965bf909bb6da45bd466a9a316b3649e97752acd75235d8  regen-v1.5.json
$ cmp schema/agentlock-v1.5.json regen-v1.5.json && echo "byte-for-byte identical"
byte-for-byte identical
```

Byte identical, by three independent checks. The stop condition on M8 did not fire.
This is the fact Q1 depends on: regenerating `agentlock-v1.5.json` after adding
`recipient_parameter` is a mechanical re-run, not a hand edit, and the diff it
produces will be confined to the new field.

Note, carried forward from AMENDMENT 2 and unchanged: `schema/agentlock-v1.4.json`
still does NOT reproduce from current source, because two docstrings drifted from em
dash to double hyphen after it was generated. That file stays untouched under D22.
The v1.5 file reproduces exactly, as just measured.

No stop condition fired. All eight measurements are as expected.

---

## PART N: conflict check, D17 to D23

| D | Verdict | Evidence |
|---|---|---|
| D17 | CONSISTENT | `ScopeConfig` (`agentlock/schema.py:98-108`) is a plain `BaseModel` whose two nearest neighbours are `allowed_recipients` (`:103`) and `recipient_allowlist` (`:106`); M6 shows the field is currently rejected as `extra_forbidden`, so declaring `recipient_parameter: str \| None = None` is the additive act that admits it, and a `None` default changes no existing block. |
| D18 | CONSISTENT | The named insertion point (`agentlock/gate.py:845`, before the `# Build request context` comment at `:847`) has `permissions` bound since `:692` and `parameters` in scope since the signature, and `version_at_least` is the established gate-side idiom at `:766`, `:790`, `:760`, `:784`. Nothing at that point writes to `request_metadata` after `:835`. |
| D19 | CONSISTENT | `RECIPIENT_NOT_ALLOWED` is already reachable through `PolicyEngine._recipient_denial` (`agentlock/policy.py:1034-1042`), so no new denial machinery is needed for a malformed declared value; `_recipient_is_malformed` (`agentlock/policy.py:173-181`) already denies whitespace, control characters, commas and semicolons, and the empty-value skip D19 specifies is exactly D12's existing skip, measured ALLOW at A9 and preserved. |
| D20 | CONSISTENT | `PolicyDecision.detail` is a free `str` field (`agentlock/policy.py:89-99`) and every existing denial detail is built from policy names and counts, never from caller-supplied content: the closest precedent, `agentlock/policy.py:974-976`, says "Recipient is not in the session's known contacts" without quoting the address. A detail naming the disagreement without the values is the house style, not an exception to it. |
| D21 | CONSISTENT | `RequestContext` is `@dataclass(slots=True)` (`agentlock/policy.py:41`) and a tuple default is legal there because tuples are immutable and need no `default_factory`; verified directly, a `@dataclass(slots=True)` with `recipients: tuple[str, ...] = ()` builds, reports `__slots__ == ('a', 'recipients')`, defaults to `()`, and accepts `('a@b.com', 'c@d.com')`. `recipient: str = ""` (`:75`) is untouched, and Step 8's guard at `agentlock/policy.py:594` is the single place the "recipients else (recipient,) else skip" precedence lands. |
| D22 | CONSISTENT | M8 proves the envelope generator reproduces `schema/agentlock-v1.5.json` byte for byte on this tree, so regeneration is mechanical. Schema 1.5 is unreleased: `git cat-file -e main:schema/agentlock-v1.5.json` reports the path absent on `main`, `git ls-tree v1.7.0 schema/` lists only v1.0, v1.2, v1.3 and v1.4, and the file's entire history is one commit, `c1a9e01`, on this branch. A 1.4 block carrying `recipient_parameter` validates in pydantic because the field lives on `ScopeConfig` with no version predicate, and is inert at runtime because D18's extraction sits behind `version_at_least(permissions.version, (1, 5))`. |
| D23 | CONSISTENT | The two adapters named are separate repositories and are not in this tree; the four in-repo integrations contain zero occurrences of `recipient` (M2) and none is in the Q5 file list. |

### D18, specifically: a local read of `parameters[key]` cannot change what `InjectionFilter` sees

The filter's two inputs are fixed at `agentlock/policy.py:576-579`:
`context.metadata.get("parameters")` and `context.metadata`. Both resolve to objects
the gate built at `agentlock/gate.py:782-784`, where `request_metadata["parameters"]`
is bound to the caller's `parameters` object itself, not a copy. D18 performs one
`dict` lookup on that object and binds the result to a local. A `dict` lookup is
non-mutating: it adds no key, removes none, and rebinds nothing. D18 further forbids
any write into `request_metadata`, so the dict the filter receives has the identical
key set and the identical values whether the extraction ran or not. The extraction is
therefore invisible to Step 6 by construction.

This is the same discipline the gate already documents for the lineage outcome
dictionaries at `agentlock/gate.py:792-798`: "LOCALS, deliberately: these must NOT be
written into `request_metadata`. `InjectionFilter` scans that dict's values as
attacker-controlled text, so evidence placed there is evidence that can change a
decision." D18 is that rule applied to the recipient read. Q6 is the check that the
build kept it.

One direction is worth naming because it is not symmetric. The extraction is invisible
to the injection filter, but the injection filter is not invisible to the extraction:
Step 6 runs at pipeline position 6 and Step 8 at position 8, so a parameter value that
trips the injection filter is denied before Step 8 ever evaluates it. Reading a
recipient out of `parameters` cannot weaken injection filtering, and cannot bypass it.

### D21, specifically: `slots=True` and a tuple default

`agentlock/policy.py:41` is `@dataclass(slots=True)`. `agentlock/policy.py:76`
already carries `known_contacts: frozenset[str] = field(default_factory=frozenset)`,
which uses `default_factory` because `frozenset()` is constructed. A tuple literal
`()` is a singleton immutable and needs no factory, so `recipients: tuple[str, ...] = ()`
is a legal bare default under `slots=True`. Verified directly, output verbatim:

```
slots= ('a', 'recipients')
default recipients= ()
with value= ('a@b.com', 'c@d.com')
```

---

## PART Q: predictions for increment 2

Each is falsifiable by a command. If any fails, the increment did not match its
prediction, and that is the finding.

### Q1. Schema
`agentlock/schema.py`: `ScopeConfig` gains `recipient_parameter`, declared beside
`allowed_recipients` and `recipient_allowlist`. `schema/agentlock-v1.5.json` is
regenerated by the AMENDMENT 2 envelope method recorded at M8, and is byte identical
to that generator's output on the built tree. `schema/agentlock-v1.4.json` is
untouched, unchanged by `git diff`.

### Q2. New tests, all passing
All new tests live in one new file, `tests/test_v18_recipient_parameter.py`. Cases
are gate level, through `AuthorizationGate` at permission version 1.5, unless the row
says otherwise.

| Case | Expected |
|---|---|
| declared key present, hostile `str` value, no caller `recipient` | DENY `RECIPIENT_NOT_ALLOWED` |
| declared key present, `str` value that is in `known_contacts` | ALLOW |
| declared key absent, no caller `recipient` | ALLOW, the baseline decision |
| declared key present with value `None` | ALLOW, step skipped |
| declared key present with value `""` | ALLOW, step skipped |
| declared key present with value `[]` | ALLOW, step skipped |
| declared key present with an `int` value | DENY `RECIPIENT_NOT_ALLOWED` |
| declared key present, list of two addresses both in `known_contacts` | ALLOW |
| declared key present, list of two, one not in `known_contacts` | DENY `RECIPIENT_NOT_ALLOWED` |
| declared key present, list containing a non-`str` | DENY `RECIPIENT_NOT_ALLOWED` |
| caller `recipient` equals the declared value | ALLOW |
| caller `recipient` differs from the declared value | DENY `RECIPIENT_NOT_ALLOWED` |
| caller `recipient` supplied, declared key absent, value in contacts | ALLOW, caller value used |
| caller `recipient` supplied, declared key absent, value not in contacts | DENY `RECIPIENT_NOT_ALLOWED`, caller value used |
| the same block registered at version 1.4, hostile parameter value | ALLOW, inert |
| policy level: `RequestContext(recipients=(...))` with one bad entry | DENY `RECIPIENT_NOT_ALLOWED` |
| policy level: `RequestContext(recipients=(...))` with all entries good | ALLOW |
| a recipient denial through the gate with a `ReceiptSigner` configured | `AuthResult.receipt` is not `None` and verifies |
| the `detail` string of a D20 disagreement denial | contains neither recipient value |

### Q3. Suite arithmetic
The full suite reports 1461 plus the number of new tests passed, 0 failed, 8 skipped,
with the identical skip list recorded at M7. No existing test is edited.
`tests/test_v18_recipient.py` is unchanged, byte for byte, by `git diff`.

### Q4. M5 rerun on the built branch
Call 1, no `recipient` argument, `parameters={"to": "attacker@evil.com"}`: DENY
`recipient_not_allowed`. Call 2, `recipient="attacker@evil.com"` passed explicitly:
DENY `recipient_not_allowed`. The seam is closed and the pre-existing path is
unchanged.

### Q5. Files touched
`agentlock/gate.py`, `agentlock/policy.py`, `agentlock/schema.py`,
`schema/agentlock-v1.5.json`, `tests/test_v18_recipient_parameter.py` (new), and
`CHANGELOG.md`, whose existing unreleased 1.8.0 section gains lines for
`recipient_parameter` and for recipient sets. Nothing else. `git diff --stat` and
`git status --short` name no other path.

### Q6. No new metadata write
`grep -rn "request_metadata\[" agentlock/gate.py` returns the same four lines it
returns at `e6631f4`, and no fifth:

```
agentlock/gate.py:784:            request_metadata["parameters"] = parameters
agentlock/gate.py:802:            request_metadata["lineage"] = self._context_tracker.lineage_summary(
agentlock/gate.py:821:                    request_metadata["param_lineage"] = _match
agentlock/gate.py:835:                    request_metadata["novel_lineage"] = _novel
```

Line numbers may shift. The set of writes may not grow.

### Q7. Lint and hygiene
`ruff check agentlock/ tests/`, the exact command CI runs
(`.github/workflows/ci.yml:32-33`), returns `All checks passed!` with exit 0.
`grep -ri agentshield agentlock tests schema` returns 0 hits, as it does at
`e6631f4`.

---

## AMENDMENT 3 (2026-09-09): D21 extended before increment 2 build

Found at build time, before any increment 2 mechanism code was written, and fixed
by amendment before code. Recorded here so the extension is on the record ahead of
the build it governs, not read back out of the build afterwards.

### The defect in D21 as frozen

D19 defines the malformed-parameter outcome and D20 defines the
assertion-disagreement outcome. Both are faults discovered by the gate during D18
extraction, at `agentlock/gate.py:845`, well before the `RequestContext` exists.
D21 as frozen gives the gate two channels to Step 8 and only two:
`recipient: str` and the new `recipients: tuple[str, ...]`. Neither can carry a
fault. A malformed parameter value produces no recipient string to place in either
field, and an assertion disagreement is a relation between two values rather than a
value, so it survives in neither.

That leaves the gate with no way to reach Step 8 with a fault, and the only
alternative would be for the gate to return a denial directly at the extraction
point. A gate-side direct return is refused on two counts. It would bypass pipeline
order, which D13 fixes at first-denial-in-pipeline-order-wins, by denying at a
position above Step 6 and Step 7 for a fault that belongs at position 8. And it
would bypass the signed policy-denial path, which A5 establishes reaches
`_sign_result` only through `agentlock/gate.py:1581`, so the receipt guarantee D6
makes for recipient denials would not hold for exactly the two outcomes D19 and D20
introduce.

### D21, extended

> `RequestContext` additionally gains `recipient_fault: str = ""`, with exactly
> three permitted values: `""`, `"malformed_parameter"`, and
> `"assertion_disagrees"`. The gate sets it during D18 extraction and never
> elsewhere. Step 8, when live (a nonempty `recipient`, or a nonempty `recipients`,
> or a nonempty `recipient_fault`, at permission version 1.5 or later), checks
> `recipient_fault` first and returns DENY `RECIPIENT_NOT_ALLOWED` with a detail
> naming the fault kind and carrying no recipient values, before any membership
> check runs.

### Consequences that follow from the extension

The Step 8 liveness guard widens by one disjunct. Under D21 as frozen the guard
reads "a nonempty `recipients`, else a nonempty `recipient`, else skip"; a fault
carries neither, so without the third disjunct a malformed parameter would be
indistinguishable from no recipient at all and would ALLOW. That is the failure the
extension removes.

A fault denies under every member of `RecipientPolicy`, `ANY` included. This is the
one place a fault departs from the frozen shape of Step 8, which returns `None`
under `ANY` before any evaluation. The reason it departs: a malformed declared
parameter and a disagreeing caller assertion are defects in the request itself, not
verdicts about where the request is addressed, and an unrestricted recipient policy
is a statement about destinations rather than a waiver on well-formedness. A tool
that accepts any recipient still does not accept an integer where an address was
declared, nor a caller asserting one address while the parameter carries another.

The detail string obeys D20 for both fault kinds: it names which fault occurred and
includes no recipient value, neither the declared one nor the asserted one.

### What this does not change

Q5's file list is unchanged. The new field lands on `RequestContext` in
`agentlock/policy.py`, which Q5 already names, and it is set in
`agentlock/gate.py`, which Q5 already names. No path is added.

Q6 is unaffected. `recipient_fault` is a local in the gate and then a
`RequestContext` field. It is never written into `request_metadata`, so the set of
`request_metadata` writes does not grow.

D13 is preserved rather than weakened. The fault denies at pipeline position 8, the
position D13 assigns it, and reaches the signer through
`agentlock/gate.py:1581` like every other policy denial, which is what D6 requires.

---

## AMENDMENT 4 (2026-09-09): increment 2 built and matched

Build commit: `4560e53 feat: read the declared recipient parameter in the gate, recipient sets and faults`.

Measured on `v1.8-recipient-enforcement`. AMENDMENT 3, which extended D21 with the
`recipient_fault` channel, was committed at `93a4ff0` before any increment 2 build
change was committed.

### Q1 to Q7

| Q | Verdict | Evidence |
|---|---|---|
| Q1 | MATCH | `agentlock/schema.py:109` declares `recipient_parameter: str \| None = None`, beside `allowed_recipients` (`:101`) and `recipient_allowlist` (`:105`). The AMENDMENT 2 envelope generator was re-run on the built tree: `cmp` reports byte-for-byte identity and both files hash to `9fa8d8cf937fdc8722a99951c3809838d6f2882843b1b4a50c90056baef222d4`. `git diff --stat -- schema/agentlock-v1.4.json` is empty. |
| Q2 | MATCH | `32 passed in 0.02s` in the single new file `tests/test_v18_recipient_parameter.py`. Every row of the Q2 table, plus both fault kinds denying under `RecipientPolicy.ANY`, plus the no-write assertions. |
| Q3 | MATCH | `1493 passed, 8 skipped, 14 warnings in 3.10s`, which is 1461 plus 32 new, 0 failed. Skip list identical to M7. `git diff --stat -- tests/` is empty: no existing test was edited, and `tests/test_v18_recipient.py` is unchanged. |
| Q4 | MATCH | The M5 script rerun: call 1 denies with `recipient_not_allowed`, call 2 denies with `recipient_not_allowed`. Output below. |
| Q5 | MATCH | `git diff --stat` and `git status --short` name only Q5 paths. Output below. |
| Q6 | MATCH | `grep -rn "request_metadata\[" agentlock/gate.py` returns the same four writes and no fifth. Line numbers shifted by one, which Q6 permits; the set did not grow. Output below. |
| Q7 | MATCH | `ruff check agentlock/ tests/` returns `All checks passed!` with exit 0. `grep -ri agentshield agentlock tests schema` returns 0 hits. |

### Exact suite summary line

```
================= 1493 passed, 8 skipped, 14 warnings in 3.10s =================
```

Skip list, verbatim, identical to M7 and to A8:

```
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
```

### Q1, verbatim

```
$ PYTHONPATH=. python gen_schema.py > q1-regen.json
$ cmp schema/agentlock-v1.5.json q1-regen.json && echo "byte-for-byte identical"
byte-for-byte identical
$ sha256sum schema/agentlock-v1.5.json q1-regen.json
9fa8d8cf937fdc8722a99951c3809838d6f2882843b1b4a50c90056baef222d4  schema/agentlock-v1.5.json
9fa8d8cf937fdc8722a99951c3809838d6f2882843b1b4a50c90056baef222d4  q1-regen.json
```

The generator's output on the built tree also differs from the committed v1.5 file
at `d27b5fb` by exactly the twelve lines of the new field and nothing else, which is
what makes the regeneration mechanical rather than a hand edit:

```
$ diff head-v1.5.json regen-v1.5.json
734a735,746
>         },
>         "recipient_parameter": {
>           "anyOf": [
>             {
>               "type": "string"
>             },
>             {
>               "type": "null"
>             }
>           ],
>           "default": null,
>           "title": "Recipient Parameter"
```

### Q4, verbatim

```
call 1: no recipient argument, parameters={'to': 'attacker@evil.com'}
  decision=deny  allowed=False  denial={'status': 'denied', 'reason': 'recipient_not_allowed', 'detail': "Recipient is not in the session's known contacts; rejected under recipient policy 'known_contacts_only'.", 'required_role': '', 'current_role': 'user', 'suggestion': 'Send only to an address configured as a known contact for this session.'}
call 2: recipient='attacker@evil.com' passed explicitly
  decision=deny  allowed=False  denial={'status': 'denied', 'reason': 'recipient_not_allowed', 'detail': "Recipient is not in the session's known contacts; rejected under recipient policy 'known_contacts_only'.", 'required_role': '', 'current_role': 'user', 'suggestion': 'Send only to an address configured as a known contact for this session.'}
```

Call 1 is the seam M5 measured as ALLOW at `e6631f4`. It now denies, on the same
tool, the same session and the same address as call 2, with the caller passing only
the parameter an adapter actually sends. The pre-existing explicit path is unchanged.

### Q5, verbatim

```
$ git diff --stat
 CHANGELOG.md               |  4 +++
 agentlock/gate.py          | 42 ++++++++++++++++++++++
 agentlock/policy.py        | 89 +++++++++++++++++++++++++++++++++++++++++-----
 agentlock/schema.py        |  3 ++
 schema/agentlock-v1.5.json | 12 +++++++
 5 files changed, 141 insertions(+), 9 deletions(-)
$ git status --short
 M CHANGELOG.md
 M agentlock/gate.py
 M agentlock/policy.py
 M agentlock/schema.py
 M schema/agentlock-v1.5.json
?? tests/test_v18_recipient_parameter.py
```

AMENDMENT 3 added no path to this list. `recipient_fault` is a field on
`RequestContext` in `agentlock/policy.py` and a local set in `agentlock/gate.py`,
and Q5 already named both files.

### Q6, verbatim

```
agentlock/gate.py:785:            request_metadata["parameters"] = parameters
agentlock/gate.py:803:            request_metadata["lineage"] = self._context_tracker.lineage_summary(
agentlock/gate.py:822:                    request_metadata["param_lineage"] = _match
agentlock/gate.py:836:                    request_metadata["novel_lineage"] = _novel
```

Four writes, the same four, no fifth. Each line number is one higher than at
`e6631f4` because the gate's import of `_normalize_recipient` added one line above
them. Q6 anticipates the shift and constrains the set, not the positions.

### Q7, verbatim

```
$ ruff check agentlock/ tests/
All checks passed!
$ echo $?
0
$ grep -ri agentshield agentlock tests schema | wc -l
0
```

### One deviation from the build instruction, recorded

The `recipient_parameter` comment in `ScopeConfig` was specified as a one-line
comment. Its text is 118 characters and `pyproject.toml:96` sets ruff's line length
to 100, so a single physical line would have failed the Q7 stop condition. The
comment is therefore wrapped across two physical lines, in the style of the
`recipient_allowlist` comment two lines above it. The text is unchanged.

### What increment 2 does and does not yet cover

The four in-repo integrations under `agentlock/integrations/` (`mcp.py`,
`autogen.py`, `flask.py`, `fastapi.py`) contain six `authorize()` call sites
(`mcp.py:167`, `autogen.py:119`, `flask.py:163`, `flask.py:271`, `fastapi.py:197`,
`fastapi.py:290`) and zero occurrences of `recipient`, as M2 measured and as this
increment leaves them: not one of those files is in the Q5 list and not one was
touched. They are nonetheless now covered by this mechanism, without any adapter
change, for every tool whose permission block declares `recipient_parameter`,
because each of the six already forwards the caller's parameter dict to
`authorize()` and the gate reads the declared key out of that dict itself. That is
the point of putting the extraction in the gate rather than in the adapters: the
trusted permission block, not the adapter, decides which parameter carries the
recipient, and an adapter that never heard of recipients cannot get it wrong. What
increment 2 does not do is measure that end to end. Nothing here exercises an
adapter, and the claim that a declared block reaches Step 8 through `mcp.py:167` or
`fastapi.py:197` is at present an inference from the shape of those call sites
rather than a measurement of them. Increment 3 measures it.

---

## INCREMENT 3a FREEZE (2026-09-09): integration end-to-end

Measured on `v1.8-recipient-enforcement` at `a9c38ca docs: AMENDMENT 4, increment 2
built and matched`. Working tree clean at measurement time. This section is written
before any increment 3a test code exists. It appends to this document and edits
nothing above.

Increment 3a adds no engine code. Nothing under `agentlock/` and nothing under
`schema/` is touched. AMENDMENT 4 closed with the statement that the claim that a
declared block reaches Step 8 through the in-repo integrations "is at present an
inference from the shape of those call sites rather than a measurement of them."
This increment measures it where it can be measured, and records a limitation where
it cannot.

---

### STEP 0a. Full suite

`pytest -rs`. Summary line, verbatim:

```
================= 1493 passed, 8 skipped, 14 warnings in 3.13s =================
```

1493 passed, 0 failed, 8 skipped. Skip list, verbatim, identical to A8, M7 and
AMENDMENT 4:

```
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
```

The stop condition on 0a did not fire.

### STEP 0b. The six `authorize()` call sites in `agentlock/integrations/`

`grep -n "authorize(" agentlock/integrations/*.py` returns six call sites, plus four
docstring mentions. Each call, verbatim.

`agentlock/integrations/autogen.py:119-124`:

```python
            auth = gate.authorize(
                func_name,
                user_id=user_id,
                role=role,
                parameters=kwargs or None,
            )
```

`agentlock/integrations/mcp.py:167-172`:

```python
                    auth = gate.authorize(
                        name,
                        user_id=user_id,
                        role=role,
                        parameters=arguments or None,
                    )
```

`agentlock/integrations/fastapi.py:197-201`:

```python
        auth = self.gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )
```

`agentlock/integrations/fastapi.py:290-294`:

```python
        auth = gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )
```

`agentlock/integrations/flask.py:163-167`:

```python
            auth = gate.authorize(
                tool_name,
                user_id=user_id,
                role=role,
            )
```

`agentlock/integrations/flask.py:271-275`:

```python
        auth = self.gate.authorize(
            tool_name,
            user_id=user_id,
            role=role,
        )
```

| Call site | Passes `parameters`? |
|---|---|
| `autogen.py:119` | YES, `parameters=kwargs or None` |
| `mcp.py:167` | YES, `parameters=arguments or None` |
| `fastapi.py:197` | NO |
| `fastapi.py:290` | NO |
| `flask.py:163` | NO |
| `flask.py:271` | NO |

As expected: two of six pass `parameters`, four pass only `user_id` and `role`.

This corrects one sentence in AMENDMENT 4, which said of the six that "each of the
six already forwards the caller's parameter dict to `authorize()`". Two do. Four do
not. The correction is recorded here rather than by editing that amendment, which is
append-only. It does not change any increment 2 verdict: no Q prediction concerned
the adapters, and Q5's file list excluded all four integration files, which were and
remain untouched. It changes only the reach claim, and R3 below states the corrected
reach.

### STEP 0c. `tests/test_v15_integration_confirmation.py` `TestMcpServerWrapper`, in full

`tests/test_v15_integration_confirmation.py:109-148`, verbatim:

```python
class TestMcpServerWrapper:
    def test_the_mcp_handler_reports_its_execution(self):
        """The MCP server owns execution: the gate learns the outcome only
        because the wrapper tells it."""
        pytest.importorskip("mcp")
        from agentlock.integrations.mcp import AgentLockMCPServer

        backend = InMemoryAuditBackend()
        gate = AuthorizationGate(audit_backend=backend)

        class FakeServer:
            """Stands in for an MCP Server: it only has to hand us the
            call_tool decorator the wrapper patches."""

            def __init__(self):
                self.handler = None

            def call_tool(self):
                def decorator(fn):
                    self.handler = fn
                    return fn

                return decorator

        server = FakeServer()
        AgentLockMCPServer(
            server, gate, {"read_file": _perms()}, default_role="user"
        )

        @server.call_tool()
        async def handler(name: str, arguments: dict) -> str:
            return f"read {arguments['path']}"

        result = asyncio.run(server.handler("read_file", {"path": "/etc/hosts"}))
        assert result == "read /etc/hosts"

        attempt, completed = _executions(backend)
        assert attempt.action == "execution_attempted"
        assert completed.metadata["status"] == "succeeded"
        assert completed.metadata["reported_by"] == "caller"
```

This is the fixture pattern R2 reuses: `pytest.importorskip("mcp")` first, then a
local `FakeServer` whose only job is to hand back the `call_tool` decorator that
`AgentLockMCPServer._install_hook` patches, then `asyncio.run` on the captured
handler.

### STEP 0d. `import mcp`

Verbatim:

```
$ python -c "import mcp"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
    import mcp
ModuleNotFoundError: No module named 'mcp'
```

`ModuleNotFoundError`, as expected. This is the environment fact behind the first
line of the A8 skip list.

### STEP 0e. `agentshield` grep

```
$ grep -ri agentshield agentlock tests schema | wc -l
0
```

Zero, as expected, unchanged from `e6631f4` and `a9c38ca`.

### STEP 0f (added at measurement time). `import autogen`, and what CI installs

Not in the frozen 0-series. Measured because R1 as first drafted assumed
`protect_functions` had no hard dependency on the `autogen` package, and it does.

```
$ python -c "import autogen"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
    import autogen
ModuleNotFoundError: No module named 'autogen'
```

`agentlock/integrations/autogen.py:39-47`, verbatim, is why this matters:

```python
def _check_autogen_available() -> None:
    """Verify that AutoGen is importable."""
    try:
        import autogen  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "AutoGen is required for this integration. "
            "Install it with: pip install pyautogen"
        ) from exc
```

It is called unconditionally at `AgentLockFunctionMap.__init__`
(`agentlock/integrations/autogen.py:79`), which `protect_functions` constructs at
`agentlock/integrations/autogen.py:200`. Without `pyautogen` installed,
`protect_functions` raises `ImportError` before any gate call happens. R1 as first
written could not pass in this environment, and R4 as first written, which counted
the new autogen tests as passed and predicted nine skips, was unsatisfiable with it.

`grep -rn "autogen" tests/` returns zero hits: **there is no autogen integration
test in `tests/` at all before this increment.** The path has never been exercised
by the suite.

R1 and R4 are restated below before the build, on the same footing as AMENDMENT 1
and AMENDMENT 3. R1 is guarded by `pytest.importorskip("autogen")`, the same idiom
as the `mcp` guard measured at 0c. R4's arithmetic follows from that guard.

**What CI installs.** `.github/workflows/ci.yml:27-30`, verbatim:

```yaml
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
```

The test step, `.github/workflows/ci.yml:39-40`, verbatim:

```yaml
      - name: Run tests
        run: pytest --cov=agentlock --cov-report=xml -v
```

`dev` is defined at `pyproject.toml:63-69`, verbatim:

```toml
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-asyncio>=0.23",
    "mypy>=1.10",
    "ruff>=0.4",
]
```

It contains neither `pyautogen` nor `mcp`. Those live in separate extras
(`pyproject.toml:50-51`: `autogen = ["pyautogen>=0.2"]`, `mcp = ["mcp>=1.0"]`) and in
the `all` extra (`pyproject.toml:55-62`), and CI installs none of them.

**Therefore: CI does NOT install the autogen or all extras before pytest.** The R1
and R2 tests do not execute for real in CI on push, and they do not execute locally
in this venv. They are not exercised anywhere in the automated path. **This is an
open item for the release, recorded here as such.** The nearest existing precedent
is the v1.7.0 release note at `CHANGELOG.md:56`, which reports its suite figure "with
the `crypto` and `mcp` extras installed (`pip install -e ".[crypto,mcp]"`)", a manual
step outside CI that covers `mcp` but not `autogen`. Closing this open item means
either adding the extras to the CI install line or running the suite once under
`pip install -e ".[all]"` before the release and recording that figure. Neither is
done in increment 3a, which touches no CI file.

---

### Predictions for increment 3a

R1 and R4 are the restated forms. R1 as first drafted, and R4 as first drafted, are
retained in the two blockquotes below rather than deleted, in keeping with the
append-only discipline used for D7.

#### R1 (as first drafted, SUPERSEDED at 0f, 2026-09-09)

> ~~autogen. `protect_functions` over a `send_email` callable that increments a
> counter and returns "sent". Tool registered at version "1.5",
> `allowed_recipients=KNOWN_CONTACTS_ONLY`, `recipient_parameter="to"`. Session for
> alice with `known_contacts=["bob@company.com"]`. `guarded(to="bob@company.com",
> body="hi", _agentlock_user_id="alice", _agentlock_role="user")` returns "sent" and
> the counter is 1. `guarded(to="attacker@evil.com", ...)` raises `DeniedError` whose
> reason is `"recipient_not_allowed"` and the counter is still 1.
> `guarded(to=["bob@company.com", "attacker@evil.com"], ...)` raises the same and the
> counter is still 1. A second tool registered with `allowed_recipients=ANY` and the
> same `recipient_parameter` executes for the attacker address (counter increments),
> proving the gate and not the wrapper decided.~~

Superseded only as to the guard. Every case above is unchanged.

#### R1 (restated, 2026-09-09). autogen, guarded by `importorskip`

The autogen tests are guarded by `pytest.importorskip("autogen")` at the head of
their test class, the same idiom as the `mcp` guard at
`tests/test_v15_integration_confirmation.py:113`, because
`agentlock/integrations/autogen.py:79` raises `ImportError` without `pyautogen`
installed. No stub module is installed for `autogen`, and `sys.modules` is not
written to: a stub would make the tests report as passed while measuring a wrapper
whose own import guard had been defeated, and this document does not manufacture a
green line for a path the environment cannot run.

The cases, unchanged from the first draft:

`protect_functions` over a `send_email` callable that increments a counter and
returns `"sent"`. Tool registered at version `"1.5"`,
`allowed_recipients=KNOWN_CONTACTS_ONLY`, `recipient_parameter="to"`. Session for
alice with `known_contacts=["bob@company.com"]`.

| Case | Expected |
|---|---|
| `guarded(to="bob@company.com", body="hi", _agentlock_user_id="alice", _agentlock_role="user")` | returns `"sent"`, counter is 1 |
| `guarded(to="attacker@evil.com", ...)` | raises `DeniedError`, `.reason == "recipient_not_allowed"`, counter still 1 |
| `guarded(to=["bob@company.com", "attacker@evil.com"], ...)` | raises `DeniedError`, `.reason == "recipient_not_allowed"`, counter still 1 |
| a second tool at `allowed_recipients=ANY`, same `recipient_parameter`, called with the attacker address | executes, its counter increments |

The last row is the control. It proves the gate and not the wrapper decided: the same
wrapper, the same declared key, the same hostile address, differing only in the
permission block, and the outcome differs.

In this environment every R1 test SKIPS. The prediction is written so that it is
checkable wherever `pyautogen` is installed, and so that the local result is a
recorded skip rather than a fabricated pass.

#### R2. mcp

Guarded by `pytest.importorskip("mcp")` exactly as the v15 test at 0c. Same
`FakeServer` fixture. `AgentLockMCPServer` with a `perm_map` registering `send_email`
at version `"1.5"`, `allowed_recipients=KNOWN_CONTACTS_ONLY`,
`recipient_parameter="to"`. Session for alice with
`known_contacts=["bob@company.com"]`.

| Case | Expected |
|---|---|
| handler call with `{"to": "attacker@evil.com", "body": "x", "_agentlock_user_id": "alice", "_agentlock_role": "user"}` | raises `DeniedError`, `.reason == "recipient_not_allowed"`, the underlying tool never runs |
| the same call with `"to": "bob@company.com"` | runs the tool |
| the `arguments` dict the tool receives | does NOT contain `_agentlock_user_id` or `_agentlock_role`, and DOES contain `"to"` |

The third row is the point of the test, not a detail of it: it establishes that the
`parameters` the gate read at `mcp.py:171` were the tool's own arguments, the same
object the tool goes on to receive, and not some separate auth-carrying envelope.

In this environment every R2 test SKIPS, for the reason measured at 0d.

#### R3. fastapi and flask: no test, a stated limitation

No test is written for either. The four call sites measured at 0b
(`fastapi.py:197`, `fastapi.py:290`, `flask.py:163`, `flask.py:271`) pass only
`tool_name`, `user_id` and `role` to `authorize()`. They pass no `parameters` at all.
Therefore `recipient_parameter`, and with it every parameter-level check in the gate,
is unreachable through those two integrations: the gate's D18 extraction reads a key
out of a `parameters` dict that is `None` on every one of those four paths.

This is pre-existing. It is not introduced by v1.8.0 and it is not fixed here. It is
recorded as a limitation of the release.

The scope of the limitation is wider than recipients, and the CHANGELOG line says so:
the same four call sites also carry no parameters for the injection filter at Step 6,
for parameter lineage, or for novel lineage. Those two integrations authorize on the
tool name and the caller identity taken from request headers, and on nothing else.

#### R4 (as first drafted, SUPERSEDED at 0f, 2026-09-09)

> ~~Suite: 1493 plus the number of new autogen tests passed, 0 failed, 9 skipped. The
> ninth skip is the new file's `importorskip("mcp")` line, and the other eight are
> the A8 list unchanged. No existing test edited.~~

#### R4 (restated, 2026-09-09). Suite arithmetic

The full suite reports **1493 passed, 0 failed, 10 skipped**. The ninth and tenth
skips are the new file's two `importorskip` lines, one for `autogen` and one for
`mcp`. The eight in the A8 list are unchanged, line for line. No existing test is
edited: `git diff --stat -- tests/` is empty and the only new path under `tests/` is
the one new file.

The passed count does not move, because every test in the new file skips in this
environment. That is the honest arithmetic and it is stated as a prediction, not
discovered afterwards.

#### R5. Files touched

`tests/test_v18_recipient_integrations.py` (new) and `CHANGELOG.md`, which gains a
"Limitations" line under the 1.8.0 section stating R3 in one or two sentences, naming
both `fastapi` and `flask` and saying that they authorize on tool name and identity
from request headers only. Nothing under `agentlock/`. Nothing under `schema/`.
`git diff --stat` and `git status --short` name no other path.

#### R6. Lint and hygiene

`ruff check agentlock/ tests/`, the exact command CI runs
(`.github/workflows/ci.yml:32-33`), returns `All checks passed!` with exit 0.
`grep -ri agentshield agentlock tests schema` returns 0 hits.

---

## AMENDMENT 5 (2026-09-09): increment 3a built and matched

Build commit: `1755d02 test: end-to-end recipient enforcement through the autogen and mcp integrations`.

Measured on `v1.8-recipient-enforcement`. R1 and R4 are scored against their
restated wording, recorded at STEP 0f in the freeze at
`68e45c0 docs: freeze increment 3a, integration end-to-end predictions`, before any
increment 3a test code was written. No engine code was added, and nothing under
`agentlock/` or `schema/` was touched.

### R1 to R6

| R | Verdict | Evidence |
|---|---|---|
| R1 | MATCH | `TestAutogenFunctionMap` is guarded by `pytest.importorskip("autogen")` at `tests/test_v18_recipient_integrations.py:70`, and reports `SKIPPED [1] ... could not import 'autogen'`, which is what restated R1 predicts for this environment. All four cases are present, including the `RecipientPolicy.ANY` control. No stub module is installed and `sys.modules` is not written to by the test. |
| R2 | MATCH | `TestMcpServerWrapper` is guarded by `pytest.importorskip("mcp")` at `tests/test_v18_recipient_integrations.py:121`, uses the 0c `FakeServer` fixture unchanged, and reports `SKIPPED [1] ... could not import 'mcp'`. All three rows are present, including the assertion that the arguments dict the tool receives carries `"to"` and neither `_agentlock_` key. |
| R3 | MATCH | No test exists for either integration. `grep -n "fastapi\|flask" tests/test_v18_recipient_integrations.py` returns only the module docstring lines naming the four unreachable call sites. The limitation is recorded in `CHANGELOG.md` under the 1.8.0 `### Limitations` heading. |
| R4 | MATCH | `1493 passed, 10 skipped, 14 warnings in 3.13s`, 0 failed. The passed count is unchanged from `a9c38ca`, as restated R4 predicts. The ninth and tenth skips are the new file's two `importorskip` lines; the A8 eight are unchanged line for line. `git diff --stat -- tests/` is empty: no existing test was edited. |
| R5 | MATCH | `git status --short` names exactly `M CHANGELOG.md` and `?? tests/test_v18_recipient_integrations.py`. `git diff --stat` is one file, one insertion. Zero paths under `agentlock/` and zero under `schema/`. |
| R6 | MATCH | `ruff check agentlock/ tests/` returns `All checks passed!` with exit 0. `grep -ri agentshield agentlock tests schema` returns 0 hits. |

### Exact suite summary line

```
================ 1493 passed, 10 skipped, 14 warnings in 3.13s =================
```

Full skip list, verbatim. The first four lines are the A8 eight, unchanged:

```
SKIPPED [1] tests/test_v15_integration_confirmation.py:113: could not import 'mcp': No module named 'mcp'
SKIPPED [5] tests/test_v16_crosshop_decision_time.py:479: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:491: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v16_crosshop_decision_time.py:502: '_reachable_untrusted_entries' is present in context.py, so these pre-increment-3 baselines no longer describe the engine. The after-behavior tests in this file are the live ones.
SKIPPED [1] tests/test_v18_recipient_integrations.py:70: could not import 'autogen': No module named 'autogen'
SKIPPED [1] tests/test_v18_recipient_integrations.py:121: could not import 'mcp': No module named 'mcp'
```

### The new file, run alone, verbatim

```
$ python -m pytest tests/test_v18_recipient_integrations.py -rs
collected 2 items

tests/test_v18_recipient_integrations.py::TestAutogenFunctionMap::test_recipient_enforcement_through_the_function_map SKIPPED [ 50%]
tests/test_v18_recipient_integrations.py::TestMcpServerWrapper::test_recipient_enforcement_through_the_call_tool_handler SKIPPED [100%]

=========================== short test summary info ============================
SKIPPED [1] tests/test_v18_recipient_integrations.py:70: could not import 'autogen': No module named 'autogen'
SKIPPED [1] tests/test_v18_recipient_integrations.py:121: could not import 'mcp': No module named 'mcp'
============================== 2 skipped in 0.01s ==============================
```

### R5, verbatim

```
$ git diff --stat
 CHANGELOG.md | 1 +
 1 file changed, 1 insertion(+)
$ git status --short
 M CHANGELOG.md
?? tests/test_v18_recipient_integrations.py
```

### R6, verbatim

```
$ ruff check agentlock/ tests/
All checks passed!
$ echo $?
0
$ grep -ri agentshield agentlock tests schema | wc -l
0
```

### What the suite proves here, and what it does not

Every R is a MATCH, and the reader should not take more from that than it holds.
What the suite measured is the guards and the arithmetic. Both test bodies skipped,
so the suite did not execute a single assertion in the R1 or R2 tables. A green
suite line is compatible with those two tests being syntactically valid and
semantically wrong, and that is the honest reading of the ten-skip result.

They are not wrong, and the check that establishes it is recorded here as a
diagnostic rather than as R1 or R2 evidence, because it was run outside the suite
and outside the repository. Both test bodies were copied to the session scratchpad
and run once against a `conftest.py` that placed empty `autogen`, `mcp`,
`mcp.server` and `mcp.types` modules into `sys.modules`. Result, verbatim:

```
diag_test_integrations.py::TestAutogenFunctionMap::test_recipient_enforcement_through_the_function_map PASSED [ 50%]
diag_test_integrations.py::TestMcpServerWrapper::test_recipient_enforcement_through_the_call_tool_handler PASSED [100%]

============================== 2 passed in 0.10s ===============================
```

The stub defeats exactly one thing in each integration: the import guard at
`agentlock/integrations/autogen.py:42` and the one at
`agentlock/integrations/mcp.py:42`. Neither integration uses the imported package
for anything else on the authorization path, and `_import_mcp_types`
(`agentlock/integrations/mcp.py:51`) has zero call sites in the file. Everything
after the guard is real AgentLock code, so the two `recipient_not_allowed` denials
observed in that run came from pipeline Step 8 through the real gate, reached
through the real `autogen.py:119` and `mcp.py:167` call sites, with the recipient
read out of the parameters those call sites forward.

That is the substantive result of increment 3a: the reach claim AMENDMENT 4 left as
an inference is now an observation for both integrations that can carry it. It is
recorded at the strength of the evidence, which is a diagnostic run under stubbed
imports, not a suite pass. Neither this nor the suite proves anything about
compatibility with the real `pyautogen` or `mcp` packages.

The stub lives only in the scratchpad. Nothing in the committed test file writes to
`sys.modules`, and `git status --short` at R5 shows no scratchpad path in the tree.

### The 0b correction, restated for the record

STEP 0b measured that two of the six in-repo `authorize()` call sites forward the
caller's parameter dict and four do not. AMENDMENT 4 had written that "each of the
six already forwards the caller's parameter dict to `authorize()`". Four do not:
`fastapi.py:197`, `fastapi.py:290`, `flask.py:163` and `flask.py:271` pass only the
tool name, `user_id` and `role`. AMENDMENT 4 is append-only and is not edited; the
correction stands here and in the freeze at STEP 0b, and R3 is the corrected reach
claim. No increment 2 verdict depends on it: no Q prediction concerned the
adapters, and all four files were and remain untouched.

### Open item carried forward from STEP 0f

Neither the R1 nor the R2 test is exercised anywhere in the automated path.
`.github/workflows/ci.yml:30` installs `pip install -e ".[dev]"`, and `dev`
(`pyproject.toml:63-69`) contains neither `pyautogen` nor `mcp`, so these two tests
skip in CI on every push exactly as they skip locally. Closing the item means
either adding the extras to the CI install line or running the suite once under
`pip install -e ".[all]"` before the release and recording that figure alongside the
default one. Increment 3a touches no CI file and does not close it.
