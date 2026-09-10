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
| 1.10.0  | integration hardening: one execution contract, so a declared transformation reaches the tool and the caller on every path; resolved path containment; server identity and route mapping authoritative over the client; parameter and novel lineage re-checked at deferred commit; terminal deferral states; tokens consumed before async calls | 1583 with the `crypto` and `mcp` extras plus `fastapi` and `flask`, 9 skipped |
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
passed and 14 skipped. For 1.10.0 it is 1583 passing and 9 skipped with
`mcp 2.x`, `fastapi`, `flask` and PyNaCl present, the 63 added tests being
the external review's 33-test oracle and the 30 engine tests covering what
the oracle reaches from outside cannot; a bare install runs 1568 passed and
24 skipped, the 24 being the 14 above plus the ten review and engine tests
guarded on `mcp`, `fastapi` or `flask`. Under `mcp 1.x` the engine suite is
1568 passing and 20 skipped with the review file's four `mcp` cases
deselected, which construct the 2.x `Server` and cannot run against a 1.x
SDK at all; the engine's 1.x hook is covered in every environment by
`tests/test_v110_hardening.py`. Nothing fails in any of these environments.

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
