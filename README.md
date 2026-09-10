<p align="center">
  <h1 align="center">AgentLock</h1>
  <p align="center">
    <strong>An adversarially benchmarked reference implementation for pre-action agent authorization</strong>
  </p>
  <p align="center">
    Your AI agent needs a login screen. AgentLock is that login screen.
  </p>
  <p align="center">
    <a href="https://github.com/webpro255/agentlock/actions"><img src="https://github.com/webpro255/agentlock/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://pypi.org/project/agentlock/"><img src="https://img.shields.io/pypi/v/agentlock.svg" alt="PyPI"></a>
    <a href="https://pypi.org/project/agentlock/"><img src="https://img.shields.io/pypi/pyversions/agentlock.svg" alt="Python"></a>
    <a href="https://github.com/webpro255/agentlock/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  </p>
</p>

<div align="center">

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22681594.svg)](https://doi.org/10.5281/zenodo.22681594)
[![Paper 1 DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21270300.svg)](https://doi.org/10.5281/zenodo.21270300)
[![Paper 2 DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21363120.svg)](https://doi.org/10.5281/zenodo.21363120)

</div>

---

Pre-action authorization for LLM agent tool calls. The gate decides from
provenance, not content: there is nothing for an attacker to phrase around.

## The problem

Tool-using agents read attacker-reachable content: inboxes, channels, web
pages, retrieved documents. Indirect prompt injection turns that content
into control. Content filters classify strings, but the harmful thing
about an agent action is usually a relationship the tool-call text never
expresses: who the recipient is, what sequence of reads preceded a write,
whether the user ever asked for this action at all. The full argument is
in the paper (DOI below). AgentLock gates actions on where the session's
content came from instead of what it says.

## What it does

Every item entering the context window is recorded with a provenance
authority: authoritative (the user's request), derived (benign system
data), or untrusted (anything a third party can influence). Three
mechanisms enforce on that record:

- Session write-gate. Once untrusted content enters the session,
  consequential writes are blocked. The gate never reads the payload, so
  there is no wording that gets around it.
- Parameter lineage, opt-in per tool. Register a tool at permissions
  version 1.3 or later with param_lineage_enabled set on its lineage
  policy, and every parameter of a call to that tool is checked for
  values that trace to untrusted content but not to the user's own
  request. An attacker-planted URL or email is denied even when the call
  looks legitimate. It is off by default, and it only sees what a caller
  has recorded: a write reported without an untrusted context source
  produces no untrusted entry, so there is nothing to trace to and the
  check returns no match.
- Deferred commit. Consequential actions are queued and re-decided at end
  of turn against the complete session provenance, so content that
  arrives after the call can still deny it.

v1.4 adds selective action-class gating: instead of blocking every
consequential write on taint, you declare which action classes each tool
belongs to, and the gate blocks exactly the classes where blocking is the
only sound defense. Deletion and membership changes stay gated, because
their malice needs no distinctive parameter value for lineage to catch.
Value-carrying writes can be released to parameter lineage, which covers
them. Declarations that add gating are free; the declaration that removes
it (is_value_carrying) can only come from the tool's trusted registration
block, never from a caller, because a wrong addition over-blocks and a
wrong removal fails open.

## Measured on AgentDojo

Most security tools show you their wins. Here is the whole table
(gpt-4o-mini, tool_knowledge attack, single runs at the benchmark's
default sampling; the attacked cells are 140 episodes on travel and 105
on slack, and the benign ceilings are 20 and 21 tasks):

| suite  | undefended, attacked | uniform gate (v1.3) | selective gate (v1.4) | benign ceiling |
|--------|---------------------|---------------------|----------------------|----------------|
| travel | 36.43%              | 30.00%              | 51.43%               | 65.00%         |
| slack  | 52.38%              | 4.76%               | 4.76%                | 76.19%         |

Defense-effective attack success is 0.00% in every defended cell above
except travel under the uniform gate, which sits at 2.14%. That residual
is persuasion: three episodes whose injection goal is met in the model's
text output, with no tool call to gate. Selective gating takes it to
0.00%. Banking and workspace hold 0.00% defense-effective attack success
across two models in the v1.3 evaluation (paper, Table 3).

Travel is the win. Selective gating restores utility to 79% of the benign
ceiling, from 46% under the uniform gate, and the defended agent beats the
undefended one under attack, because blocked injections stop derailing it.

Slack is the cost, stated plainly. The defense floors utility at 4.76%
whether or not an attack is present, and on slack it costs more utility
than the attack it prevents. Every benign slack task reads a channel
before writing, so the write-gate denies the write. Selective gating
cannot fix this: slack's floor comes from taint-gated outbound and
membership writes plus lineage blocks on reads, not from value-carrying
writes.

The sign of the effect is set by workload shape. If your agent's benign
workflow is read-then-write over attacker-reachable content, this gate is
expensive, and you should know that before deploying. v1.4 ships
audit_action_classes() so you can find out which case you are in from
your own traffic instead of guessing.

The attack-success numbers above use defense-effective ASR, which excludes
verified benchmark scoring artifacts (episodes where a blocked call is
scored as a success). We reported the underlying checker issue upstream
(agentdojo #168) and disclose official ASR alongside it in the paper.
Single-run rates on this benchmark carry sampling noise; we measured the
spread across replicates and report it in the benchmark notes.

## Papers

1. Grice, D. (2026). Provenance-Based Pre-Action Authorization for LLM Agents: A Structural Defense Evaluated on AgentDojo with AgentLock. Zenodo. https://doi.org/10.5281/zenodo.21270300
2. Grice, D. (2026). Selective Provenance Gating: Recovering Agent Utility Where Recovery Is Sound. Zenodo. https://doi.org/10.5281/zenodo.21363120

Paper 2 builds on Paper 1. Each record pins the engine commit it measured.

## Install

```bash
pip install agentlock
```

Framework integrations and Ed25519 receipts are optional extras:

```bash
pip install "agentlock[autogen]"     # also: mcp, fastapi, flask
pip install "agentlock[crypto]"      # Ed25519 signed receipts
pip install "agentlock[all]"         # everything
```

## Quickstart

Register a tool with a lineage policy, then authorize the same call before
and after untrusted content enters the session. The tool call is identical
both times. Only the provenance of the session changed.

```python
from agentlock import (
    AgentLockPermissions,
    AuthorizationGate,
    ContextSource,
    LineagePolicyConfig,
)

gate = AuthorizationGate()

gate.register_tool("send_email", AgentLockPermissions(
    risk_level="high",
    allowed_roles=["user"],
    lineage_policy=LineagePolicyConfig(enabled=True, decision="deny"),
))

session = gate.create_session(user_id="alice", role="user")

# The user's own instruction is authoritative.
gate.notify_context_write(
    session.session_id, ContextSource.USER_MESSAGE, "hash-of-user-request",
)

first = gate.authorize(
    "send_email", user_id="alice", role="user",
    parameters={"to": "bob@corp.com"}, is_external=True,
)
print(first.decision.value, first.allowed)     # allow True

# A web page enters the session. Nothing about the tool call changes.
gate.notify_context_write(
    session.session_id, ContextSource.WEB_CONTENT, "hash-of-web-page",
    tool_name="fetch_url",
)

second = gate.authorize(
    "send_email", user_id="alice", role="user",
    parameters={"to": "bob@corp.com"}, is_external=True,
)
print(second.decision.value, second.allowed)   # deny False
print(second.denial["reason"])                 # untrusted_lineage
```

## Declaring action classes (v1.4)

Turn off the blanket consequential gate, declare each tool's class, and
audit what you did.

```python
from agentlock import (
    ActionClassConfig,
    AgentLockPermissions,
    AuthorizationGate,
    LineagePolicyConfig,
    format_action_class_audit,
)

# Release value-carrying writes to parameter lineage; keep the taint gate
# on the value-free classes.
policy = LineagePolicyConfig(enabled=True, gate_consequential=False, decision="deny")

gate = AuthorizationGate()

gate.register_tool("reserve_hotel", AgentLockPermissions(
    risk_level="high", allowed_roles=["user"], lineage_policy=policy,
    action_class=ActionClassConfig(is_value_carrying=True),
))

gate.register_tool("delete_email", AgentLockPermissions(
    risk_level="high", allowed_roles=["user"], lineage_policy=policy,
    action_class=ActionClassConfig(is_deletion=True),
))

gate.register_tool("append_to_file", AgentLockPermissions(
    risk_level="high", allowed_roles=["user"], lineage_policy=policy,
))

print(format_action_class_audit(gate.audit_action_classes()))
```

```text
UNDECLARED -- no action_class in the trusted permission block

  append_to_file  [high risk, selective]
    why:       no action_class, and gate_consequential=False. A call that
               asserts no class at all matches no disjunct and is never
               taint-gated. This is the residual hazard.
    >> REQUIRES HUMAN DECISION (no suggestion available)

NOT COVERED -- the session write-gate cannot block these tools

  reserve_hotel  [high risk, selective]
    declared:  is_value_carrying
    why:       declares is_value_carrying with gate_consequential=False,
               DELIBERATELY un-gated. Parameter/novel lineage is the
               covering control. This is the intended configuration.

DECLARED -- action class on the trusted side

  delete_email  [high risk, selective]
    declared:  is_deletion
    why:       declared and taint-gated via is_deletion
```

Run the audit before flipping any gate flag. It reports every tool as
DECLARED, UNDECLARED, or NOT_COVERED, backed by what your own traffic
actually asserted, and it will never confidently suggest the one
declaration that weakens gating: that one requires a human.

## What the gate cannot do

- Persuasion. If the injection's goal is achieved in the model's text
  output, there is no tool call to gate. Travel's entire residual in our
  evaluation is this mechanism.
- Read goals. If the goal is achieved by a read, a write-gate cannot
  block it; parameter lineage covers the subset with distinctive values.
- Misclassification. The gate is only as correct as the authority labels
  on your tools. A single mislabeled tool accounted for the entire slack
  residual before we found it. Classification auditing is a deployment
  requirement, not an afterthought, which is why v1.4 ships the audit.
- Laundering that breaks carriage. As of 1.7, enforcement is bounded by
  carriage rather than by hop count: a value relayed through an
  intermediate tool is denied `param_lineage` citing the relay entry,
  because the relaying write records the untrusted entry as its parent
  and decision-time checks walk the recorded link. The link is
  established only when the ingesting call's parameters carry the prior
  entry's whole content, at or above the containment floor. A value that
  the intermediate tool rewrites, paraphrases, or truncates below the
  floor, or that never reaches that call's parameters, does not link,
  and the chain stops there.
- Recognizing an encoding of something it never saw. v1.6 matches encoded
  forms by encoding the untrusted values it already has and looking for
  them, never by decoding your parameters. That is what keeps a benign
  value that merely looks like base64 from being misread. The price is
  that a payload whose plaintext never entered the session as untrusted
  content has nothing to match against.
- Selection influence. Untrusted content that merely chooses among values
  the user already supplied plants nothing, so there is nothing for a
  provenance match to fire on. The session write-gate covers the gated
  case; parameter lineage does not.
- Guessing which call you meant. An execution token is bound to the
  parameters the gate authorized, the empty call included. As of 1.9,
  `execute()` must be handed the same parameters `authorize()` saw or it
  raises `TokenInvalidError`; the gate has no way to tell which of two
  differing parameter sets was the honest one, so it refuses both.
- Telling a legitimate quotation from an attack. A summary that genuinely
  quotes an attacker-supplied address really does carry that value, so it
  is denied. Deciding it was benign would mean judging what the value is
  for, which is the content judgement this gate refuses to make.

The v1.6 encoding claim is measured at the engine, with a lineage policy
configured and untrusted sources declared. It is not a claim about any
adapter's defaults. The novelty branch has a real false-positive cost, it
is measured on a frozen corpus rather than estimated, and it is off by
default.

Full statement, both registers, every number with its corpus and
denominator: [docs/LIMITATIONS_v16.md](docs/LIMITATIONS_v16.md). How the
v1.6 work was predicted, measured and corrected, and where the raw
amendment chain is: [docs/DESIGN_NOTES_v16.md](docs/DESIGN_NOTES_v16.md).

We found two defects in our own engine during v1.4 development: a version
comparison that failed open at schema version 1.10, and a deferred-commit
path that ignored action-class declarations. Both were caught by our own
verification gates before release, both are fixed, and both are in the
changelog. That is how we intend to keep working.

## Versions

| version | highlights | tests |
|---------|-----------|-------|
| 1.10.2  | verified identity and one denial predicate: a bearer token carries identity only once it has been verified against a configured key, a token that fails verification is refused rather than falling back to the identity headers, and a configured key refuses a request that presents no token at all rather than identifying it by header; an execution reported after a TIMEOUT denial is classified as one rather than as an ordinary completion | 1746 with the `crypto` and `mcp` extras plus `fastapi`, `flask` and `python-jose`, 9 skipped |
| 1.10.1  | recheck: the reviewer re-ran the oracle against the published 1.10.0 wheel and added 32 cases; resolved path containment resolves before it normalizes and returns the path it checked; one MCP payload walker serving both the declared transformation and the data policy, covering embedded resources; recipient restriction parses the whole value rather than its first address | 1688 with the `crypto` and `mcp` extras plus `fastapi` and `flask`, 9 skipped |
| 1.10.0  | integration hardening: one execution contract, so a declared transformation reaches the tool and the caller on every path, in every shape it returns and in both payloads of an MCP result; the authenticated session's role authoritative over the caller's claim; resolved path containment; server identity and route mapping authoritative over the client; parameter and novel lineage re-checked at deferred commit; terminal deferral states; tokens consumed before async calls | 1616 with the `crypto` and `mcp` extras plus `fastapi` and `flask`, 9 skipped |
| 1.9.1   | binding completeness: a `**kwargs` key that names another parameter is refused rather than flattened over it; partials bound through to the function underneath; recipients read for the characters they hold; an unobservable declared recipient parameter refused | 1520 with the `crypto` and `mcp` extras, 9 skipped |
| 1.9.0   | enforcement completeness: all call arguments reach the gate, tokens bind the empty call, MCP wrapper fails closed and supports both SDK majors | 1503 with the `crypto` and `mcp` extras, 9 skipped |
| 1.8.0   | recipient policy enforcement at pipeline Step 8; declared recipient parameter read from the trusted permission block; recipient sets | 1495 with the `crypto` and `mcp` extras, 8 skipped |
| 1.7.0   | cross-hop provenance linking; parent attribution at ingestion by whole-content carriage; taint-reachability walk at decision time | 1418 with optional extras, 7 skipped |
| 1.6.0   | value-identity normalization; encoded-form attribution, bare and composite, base64/hex/natural-URL, zero decode | 1364 (1351 without optional extras) |
| 1.5.0   | grant basis, execution confirmation, provenance on denials, deferred-resolution logging; LangChain and CrewAI adapters moved out of core | 1141 |
| 1.4.0   | selective action-class gating, novel lineage, action-class audit, needs_approval surfacing | 1041 |
| 1.3.0   | provenance-lineage gating, parameter lineage, deferred commit, AgentDojo evaluation | 868 |
| 1.2.x   | adaptive hardening, decision types (final Apache 2.0 line) | 847 |

Both counts are measured with the `crypto` and `mcp` extras installed
(`pip install -e ".[crypto,mcp]"`). For 1.6.0 that is 1364 passing and 0
skipped; a bare install runs 1351 passed and skips the 13 optional-extra
tests, 12 of which need PyNaCl and 1 of which needs `mcp`. For 1.7.0 it
is 1418 passing and 7 skipped, the 7 being pre-increment-3 baselines that
stand down once the broadened reachability predicate is present; a bare
install additionally skips the same 13 optional-extra tests. For 1.8.0 it
is 1495 passing and 8 skipped, the 8 being those 7 baselines plus the
AutoGen integration test, which needs the `autogen` extra and so runs
only on Python below 3.14; a bare install runs 1479 passed and 24
skipped. For 1.9.0 it is 1503 passing and 9 skipped under `mcp 2.x`, the
9 being those 8 plus the mcp 1.x test, which selects on the installed
SDK major; under `mcp 1.x` it is 1502 passing and 10 skipped, the two 2.x
tests taking the place of the 1.x one. For 1.9.1 it is 1520 passing and 9
skipped under `mcp 2.x` and 1519 passing and 10 skipped under `mcp 1.x`, the
seventeen added tests being the binding collision class and the binding red
pass class, none of which is guarded by an extra; a bare install runs 1515
passed and 14 skipped. For 1.10.0 it is 1616 passing and 9 skipped on
CPython 3.14.6 with `mcp 2.2.0`, `fastapi`, `flask` and PyNaCl present, the
96 added tests being the external review's 33-test oracle, the 30 engine
tests covering what the oracle reaches from outside cannot, and the 33 of
`TestRedPass` closing two pre-release red passes against the built wheel.
That figure needs the two web frameworks as well as the two extras, which
no earlier row did: four of `TestRedPass`'s cases drive the FastAPI and
Flask route mapping. Without `mcp`, and with `fastapi`, `flask` and PyNaCl
still present, it is 1595 passing and 30 skipped, the 30 being 22 guarded on
`mcp`, 1 on `autogen`, and the 7 pre-increment-3 baselines; sixteen of the
mcp-guarded ones are new in this release. Under `mcp 1.30.0`, on CPython
3.13.14 with neither web framework, the engine suite is 1595 passing and 26
skipped with the review file's four `mcp` cases deselected, which construct
the 2.x `Server` and cannot run against a 1.x SDK at all; the engine's 1.x
hook is covered in every environment by `tests/test_v110_hardening.py`,
`TestRedPass`'s own session-role and structured-content cases over that hook
included. On CPython 3.13.14 with all four present it is 1617 passing and 8
skipped. Nothing fails in any of these environments.

For 1.10.1 it is 1688 passing and 9 skipped on CPython 3.14.6 with `mcp
2.2.0`, `fastapi`, `flask` and PyNaCl present, the 72 added tests being the
32 cases the reviewer appended to the oracle in their 1.10.0 recheck, which
brings that file to 65, and the 40 engine tests covering what those 32 reach
from outside cannot: the same MCP shapes over the 1.x hook, the resolved path
a whitelisted callable actually receives, the recipient edge forms, and the 13
cases of the pre-release red pass against this release's own branch wheel.
Without `mcp`, and with `fastapi`, `flask` and PyNaCl still present but no
`autogen`, it is 1652 passing and 45 skipped; 19 of the 45 are new in this
release and all 19 are guarded on `mcp`, being 10 oracle cases and 9 engine
cases. Nothing fails.

For 1.10.2 it is 1746 passing and 9 skipped on CPython 3.14.6 with `mcp
2.2.0`, `fastapi` 0.141.1, `flask` 3.1.3, `python-jose` 3.5.0 and PyNaCl
present, the 58 added tests being the 31 cases the reviewer added in their
1.10.1 recheck, which arrived as a second oracle file rather than as an append
and brings the two files to 96 between them, and the 27 engine tests covering
what those 31 reach from outside cannot: both spellings of a denied deferral
through `confirm_execution`; the verified, unverified, wrong key, expired and
no key states of bearer identity over both HTTP adapters and both flask entry
points; the absent, differently spelled and non bearer forms of the
`Authorization` header under a configured key; and a configured key paired with
a disabled token path, which is refused when the dependency is built. Without
`mcp` and without `python-jose`, and with `fastapi`, `flask` and PyNaCl still
present, it is 1685 passing and 70 skipped; 25 of the 70 are new in this
release, being 9 oracle cases guarded on `mcp` and 16 engine cases guarded on
`python-jose`, which is the verification backend and cannot be faked. Nothing
fails.

The 1.9.0 argument binding, and the 1.9.1 binding rules that refuse a
`**kwargs` key naming another parameter, bind through a `functools.partial` to
the function underneath, read a recipient for the characters it holds rather
than for what its methods say, and refuse a declared recipient parameter the
signature can never carry, cover the engine's own decorators and in-repo
integrations, which is the whole of what those two releases change. The standalone adapters ship from their own
repositories and are updated separately. At their current releases,
`crewai-agentlock` 0.2.0 and `langchain-agentlock` 0.1.0 authorize keyword
arguments only, and of those two only `crewai-agentlock` carries positional
arguments past the gate into the wrapped call; `mcp-agentlock` 0.2.1,
`openai-agentlock` 0.1.0 and `openclaw-agentlock` 0.1.0 hand the gate the same
argument mapping they hand the tool and have no positional route. No standalone
adapter applies the wrapped function's defaults, so a parameter the caller
omits and the function defaults is not seen by the gate in any of them, and
none of them carries any of the 1.9.1 binding rules. 1.9.0 also makes an execution
token bind the empty call: the parameters passed to `execute()` must be the
parameters passed to `authorize()`, and `None` and `{}` are the same call.

1.10.0 closes the gap between a decision and its execution. Through 1.9.1 a
declared parameter or output transformation was computed by `authorize()` and
then reached the tool on no path and the caller on one. It now travels with
the grant: `AuthResult` carries `effective_parameters` beside
`modify_output_fn`, the execution token is bound to the effective parameters
rather than the requested ones, and `gate.call()`, both decorators, both MCP
hooks and the AutoGen map all apply both. 1.10.0 also makes the server, and
not the client, decide two things the client was deciding: which identity an
MCP call runs under when the host configured one, and which tool an HTTP
request is judged against when the route mapping names one. None of this
reaches the standalone adapters, which ship separately and apply no declared
transformation at all.

Over HTTP, 1.10.2 finishes the identity half of that, because 1.10.0 promoted a
claim it had never checked. Both adapters read a bearer token's payload without
verifying its signature, and E5 then made those claims outrank the
`X-AgentLock-*` identity headers, so a token any client could type outranked a
header a deployment could strip at its edge. Verification is now opt in and the
two states are exhaustive. Configure `jwt_key` and the verified bearer token is
the ONLY identity: it is checked with expiry enforced and `"none"` refused as an
algorithm however `jwt_algorithms` is written, the scheme is matched case
insensitively so `bearer` and `Bearer` are the same credential, a token that
verifies is authoritative, one that does not is 401 with reason `jwt_invalid`,
and a request carrying no bearer credential at all is 401 with reason
`jwt_required`. The identity headers are not consulted in any of those cases,
because a request shape that reaches them is a request shape a caller can aim
for, and the first draft of this fix left two of them: an absent header and a
scheme spelled another way both reached the headers under a configured key.
Leave `jwt_key` unset, the default, and a bearer token carries no identity at
all and the headers are the identity input. They are trusted-upstream inputs
either way: they prove nothing on their own, and a deployment facing untrusted
clients directly has to strip client-supplied `X-AgentLock-*` at its edge or
authenticate by verified token instead.

The contract every wrapper now follows is one sentence long: `authorize()`
returns the parameters the call will actually run with and the transformation
its return value will pass through, and the wrapper does both.
`AuthResult.effective_parameters` is the call after every declared parameter
transformation, and it is what the execution token's `parameters_hash` is taken
over, so the grant names the call rather than the request.
`AuthResult.modify_output_fn` is the declared output transformation, and
`agentlock.modify.apply_output_modifier` is the single applier that runs it over
whatever shape the tool returned: a `str`, and recursively a `dict`, `list`,
`tuple`, `set` or `frozenset` with the container type preserved, and `bytes`
through a UTF-8 round trip. Every route does those same two things. `gate.execute()`
validates the token against the effective parameters, calls the tool with them and
applies the modifier to what comes back; `gate.call()` forwards both into it; the
two decorators rebuild the call through `binding.apply_effective_parameters`, so
that even a positional-only parameter can be transformed, and then apply the
modifier; the AutoGen map goes through `gate.execute()`; and both MCP hooks pass
the effective parameters to the handler and walk both payloads of the result.
Because there is one applier and one binding inverse, adding an execution route
means calling them rather than reimplementing them, and the shape of a tool's
return no longer decides whether its declared policy runs. What the contract does
not cover is listed under Limits in the changelog: the two HTTP adapters authorize
a request without its body and so run none of the per-parameter checks, and
anything past a `__wrapped__` boundary is the application's own code.

Full feature history:
[v1.1](docs/history.md#v11-memory--context-permissions),
[v1.2](docs/history.md#v12-adaptive-hardening--new-decision-types),
[v1.3](docs/history.md#v13-provenance-lineage-gating--deferred-commit).
Changelog: [CHANGELOG.md](CHANGELOG.md).

## Citing

Provenance-Based Pre-Action Authorization for LLM Agents (Grice, 2026).
DOI: 10.5281/zenodo.21270300. The v1.4 selective-gating evaluation was
pre-registered before the benchmark runs; prediction files and the full
benchmark report ship with the release.

Selective Provenance Gating: Recovering Agent Utility Where Recovery Is
Sound (Grice, 2026). DOI: 10.5281/zenodo.21363120. It builds on the
first paper and evaluates the selective action-class gating introduced
in v1.4.

If you use AgentLock in your research, please cite the paper that
matches the mechanism you rely on:

> Grice, D. (2026). *Provenance-Based Pre-Action Authorization for LLM Agents:
> A Structural Defense Evaluated on AgentDojo with AgentLock.* Zenodo.
> https://doi.org/10.5281/zenodo.21270300

> Grice, D. (2026). *Selective Provenance Gating: Recovering Agent Utility
> Where Recovery Is Sound.* Zenodo.
> https://doi.org/10.5281/zenodo.21363120

Software archive (all versions): https://doi.org/10.5281/zenodo.22681594.
The version DOI for each release is minted at publication and added to
`CITATION.cff` and to this line in a follow-up commit.

```bibtex
@misc{grice2026agentlock,
  author       = {Grice, David},
  title        = {Provenance-Based Pre-Action Authorization for LLM Agents:
                  A Structural Defense Evaluated on AgentDojo with AgentLock},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21270300},
  url          = {https://doi.org/10.5281/zenodo.21270300}
}
```

```bibtex
@misc{grice2026selective,
  author       = {Grice, David},
  title        = {Selective Provenance Gating: Recovering Agent Utility
                  Where Recovery Is Sound},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21363120},
  url          = {https://doi.org/10.5281/zenodo.21363120}
}
```

`CITATION.cff` at the repository root carries the software citation.

*Research commits authored as `schen-analytics` were made under an alternate
GitHub identity of the author, configured on the research machine
(see paper, Appendix B).*

## License

AGPL-3.0-or-later for v1.3.0 and later, with commercial licenses for
closed-source use: see [COMMERCIAL.md](COMMERCIAL.md) or contact
licensing@agentlock.dev. Versions 1.2.x and earlier remain Apache 2.0.

## Security

Report vulnerabilities to security@agentlock.dev. Supported versions and
policy: [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The test suite must pass under
`-W error::UserWarning`.
