# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.2.x   | Yes                |
| 1.1.x   | Yes                |
| 1.0.x   | Yes                |

## Reporting a Vulnerability

AgentLock is a security-critical library. We take vulnerability reports seriously and aim to respond within 48 hours.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via one of these channels:

1. **Email:** security@agentlock.dev
2. **GitHub Security Advisories:** Use the "Report a vulnerability" button on the [Security tab](https://github.com/webpro255/agentlock/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Step | Timeline |
|------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

### Severity Classification

We use CVSS v3.1 for severity scoring:

- **Critical (9.0-10.0):** Fix and release within 48 hours
- **High (7.0-8.9):** Fix and release within 7 days
- **Medium (4.0-6.9):** Fix in next scheduled release
- **Low (0.1-3.9):** Fix when resources allow

### Responsible Disclosure

We follow coordinated disclosure:

1. Reporter contacts us privately
2. We acknowledge and assess
3. We develop and test a fix
4. We release the fix and publish an advisory
5. Reporter may publish details 30 days after fix release

### Scope

The following are in scope for security reports:

- Authorization bypass in the gate or policy engine
- Token replay or forgery
- Receipt signature forgery or verification bypass
- Context chain integrity bypass (hash chain tampering)
- DEFER/STEP_UP bypass (tool executing when it should be deferred)
- Session hijacking or fixation
- Rate limit bypass
- Redaction bypass (prohibited data leaking through)
- Audit log tampering or omission
- Dependency vulnerabilities affecting core functionality

### Out of Scope

- Vulnerabilities in optional framework integrations caused by the framework itself
- Issues requiring physical access to the server
- Social engineering attacks against project maintainers
- Denial of service via resource exhaustion (unless trivially exploitable)

### Recognition

We maintain a security acknowledgments list. Reporters who follow responsible disclosure will be credited (with permission) in our CHANGELOG and security advisories.

## Security Design Principles

AgentLock is built on these security principles:

- **Deny by default** -- no permissions = no access
- **Infrastructure enforcement** -- agent cannot bypass the gate
- **Out-of-band authentication** -- credentials never touch the conversation
- **Single-use tokens** -- cannot be replayed
- **Mandatory audit** -- every call logged, no exceptions
- **Signed receipts** -- authorization decisions are cryptographically signed (Ed25519 or HMAC-SHA256) and verifiable offline
- **Tamper-evident context** -- hash-chained context entries detect modification of historical records
- **Monotonic trust degradation** -- session trust only goes down, never up

## Security Testing

AgentLock is tested against adversarial attack vectors across 35 categories including prompt injection, social engineering, data exfiltration, privilege escalation, tool chain attacks, memory poisoning, crisis exploitation, and refusal exhaustion.

v1.2.1 results (222 vectors, scored by AgentShield):

| Metric | Score |
|--------|-------|
| Overall | 88.7/B |
| Injection pass rate | 93%+ |
| PII protection | 100/A |
| Jailbreak resistance | 100% |
| Tool abuse prevention | 80%+ |

Remaining failures are concentrated in categories where the model's helpfulness is exploited through plausible narratives with zero injection language. These are model-layer behaviors that middleware alone cannot fully address.

## Defense Layers (v1.2.1)

| Layer | Component | What It Does |
|-------|-----------|-------------|
| Pre-LLM | Prompt scanner | Detects injection, authority claims, encoding, impersonation |
| Gate | Policy engine | Role, scope, rate limit, data classification checks |
| Gate | Injection filter | Blocks reconnaissance, command injection, social engineering patterns |
| Gate | PII filter | Blocks queries that would return data above caller clearance |
| Gate | DEFER engine | Suspends ambiguous calls pending review |
| Gate | STEP_UP engine | Requires human approval based on session risk |
| Gate | MODIFY engine | Transforms parameters and outputs (PII redaction, domain restriction) |
| Gate | Hardening engine | Monotonic risk scoring with targeted defensive instructions |
| Post-execution | Redaction engine | Pattern-based PII removal from tool outputs |
| Forensic | Signed receipts | Ed25519/HMAC-SHA256 signed authorization records |
| Forensic | Context chain | Hash-chained tamper-evident context log |

## Signal Detectors

| Detector | Signals |
|----------|---------|
| Velocity | Rapid calls, topic escalation, burst patterns |
| Combo | Suspicious tool pairs and sequences (16 pairs, 5 sequences) |
| Echo | Response echoing, tool disclosure, credential patterns |
| Prompt scan | 7 pattern categories with cross-turn repetition tracking |
| Compound | Bonus scoring when multiple signal types co-occur |
