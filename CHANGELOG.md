# Changelog

All notable changes to AgentLock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-18

### Added

- Core AgentLock permissions schema (v1.0)
- `AuthorizationGate` — central enforcement point with deny-by-default semantics
- `AgentLockPermissions` — Pydantic model for the `agentlock` permissions block
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
