# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
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

- **Deny by default** — no permissions = no access
- **Infrastructure enforcement** — agent cannot bypass the gate
- **Out-of-band authentication** — credentials never touch the conversation
- **Single-use tokens** — cannot be replayed
- **Mandatory audit** — every call logged, no exceptions
