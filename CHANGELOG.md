# Changelog

All notable changes to AgentLock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
