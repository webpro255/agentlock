# Contributing to AgentLock

Thank you for your interest in contributing to AgentLock. This project aims to establish an open standard for authorization in AI agent systems.

## Getting Started

```bash
git clone https://github.com/webpro255/agentlock.git
cd agentlock
pip install -e ".[dev]"
pytest
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b my-feature`
3. **Make your changes** with tests
4. **Run the checks:**
   ```bash
   pytest -v                               # Tests pass
   ruff check agentlock/ tests/            # Zero lint errors
   mypy agentlock/ --ignore-missing-imports # Zero type errors
   ```
5. **Commit** with a clear message
6. **Open a Pull Request** against `main`

## Code Standards

- **Python 3.10+** - all code must support Python 3.10 and above
- **Type hints everywhere** - all function signatures must be annotated
- **`from __future__ import annotations`** - required in every module
- **Google-style docstrings** - for all public classes and functions
- **Pydantic v2** - for schema models
- **No unnecessary dependencies** - core library depends only on `pydantic`

## Testing

- All new features must include tests
- All bug fixes must include a regression test
- Tests go in `tests/` following the existing pattern
- Use `pytest` fixtures from `tests/conftest.py`
- Prefer monkeypatching `time.time()` over `time.sleep()` for expiry tests

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=agentlock --cov-report=term-missing

# Run a specific test file
pytest tests/test_gate.py -v
```

## What to Contribute

### High Priority

- **Real-world integration testing** - test with actual LangChain, CrewAI, AutoGen deployments
- **Additional audit backends** - Redis, PostgreSQL, CloudWatch, Datadog
- **Additional auth providers** - OAuth2 providers, SAML, OIDC
- **Performance benchmarks** - measure gate overhead at scale
- **Documentation improvements** - tutorials, guides, API reference

### Schema Extensions (v1.1+)

- Memory and context permissions
- Conditional permissions (time, location, context)
- Tool chain permissions for multi-step workflows
- Multi-agent identity delegation

### Reporting Issues

- Use [GitHub Issues](https://github.com/webpro255/agentlock/issues)
- Include Python version, OS, and agentlock version
- Include a minimal reproducible example
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## Pull Request Guidelines

- **One feature per PR** - keep changes focused
- **Update tests** - new code needs tests
- **Update docs** - if you change the API, update the docs
- **No breaking changes without discussion** - open an issue first
- **Keep commits clean** - squash fixup commits before merge

## Architecture Notes

- `agentlock/gate.py` - Central enforcement point. Changes here affect everything.
- `agentlock/schema.py` - Pydantic models for the spec. Changes here affect the standard.
- `agentlock/policy.py` - Policy evaluation. Check order matters.
- `agentlock/integrations/` - Framework wrappers. Must lazy-import framework dependencies.
- `schema/agentlock-v1.0.json` - Hand-written JSON schema. Must stay in sync with Pydantic models.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Code of Conduct

Be respectful, constructive, and professional. We're building infrastructure that protects people. Act accordingly.
