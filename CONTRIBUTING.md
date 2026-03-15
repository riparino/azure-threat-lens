# Contributing to Azure Threat Lens

Thank you for your interest in contributing. Azure Threat Lens is a security investigation tool for Microsoft Sentinel and Azure — contributions that improve accuracy, coverage, performance, or usability are welcome.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Adding a New Analysis Module](#adding-a-new-analysis-module)
- [Adding a New Threat Intel Provider](#adding-a-new-threat-intel-provider)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Code of Conduct](#code-of-conduct)

---

## Getting Started

1. **Fork** the repository and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/azure-threat-lens.git
   cd azure-threat-lens
   ```

2. **Install** the package in editable mode with dev dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

3. **Copy** the environment template and fill in your values (required for integration tests only):

   ```bash
   cp .env.example .env
   ```

4. Verify your setup:

   ```bash
   pytest tests/unit/ -q   # should pass with no Azure credentials
   ruff check threatlens/
   mypy threatlens/
   ```

---

## Development Workflow

- Create a branch from `main` for your change:

  ```bash
  git checkout -b feat/my-feature
  # or
  git checkout -b fix/issue-123
  ```

  Branch naming conventions:
  | Prefix | Use for |
  |--------|---------|
  | `feat/` | New features |
  | `fix/` | Bug fixes |
  | `refactor/` | Refactoring with no behaviour change |
  | `docs/` | Documentation only |
  | `test/` | Test additions or fixes |

- Make focused, atomic commits. Each commit should leave the test suite green.

- Before opening a PR, run the full local check:

  ```bash
  pytest tests/unit/ -q
  ruff check threatlens/
  mypy threatlens/
  ```

---

## Code Style

The project targets **Python 3.11+** with strict type checking.

| Tool | Config | Command |
|------|--------|---------|
| **ruff** | `pyproject.toml` `[tool.ruff]` | `ruff check threatlens/` |
| **mypy** | `pyproject.toml` `[tool.mypy]` | `mypy threatlens/` |

Key style rules (enforced by ruff rule sets `E`, `F`, `I`, `UP`, `B`, `SIM`):

- Line length: **100 characters**
- Imports: sorted and grouped (`I` rules)
- No unused imports or variables
- Prefer modern Python idioms (`UP` rules)
- Avoid mutable default arguments and bare `except` clauses (`B` rules)

Auto-fix most issues with:

```bash
ruff check --fix threatlens/
```

All public functions and methods should have type annotations. mypy runs in strict mode — avoid `# type: ignore` unless genuinely necessary, and add a comment explaining why.

---

## Running Tests

Unit tests run fully offline using mocked HTTP responses (via `pytest-httpx`):

```bash
# Run all unit tests
pytest tests/unit/ -q

# Run with verbose output
pytest tests/unit/ -v

# Run a single file
pytest tests/unit/test_triage_engine.py -v

# Run with coverage
pytest tests/unit/ --cov=threatlens --cov-report=term-missing
```

Integration tests require real Azure credentials in `.env` and are kept in `tests/integration/`. They are not expected to pass in CI without credentials and should be run manually before submitting changes that touch Azure API clients.

When adding new functionality, add unit tests in `tests/unit/` using mocked API responses. Follow the patterns in existing test files — use `pytest-httpx` to intercept outbound HTTP calls.

---

## Adding a New Analysis Module

1. Create `threatlens/analysis/my_analysis.py`. Implement an `async def analyse(...)` coroutine that accepts resolved entities and returns a structured result (use existing Pydantic models where possible or define new ones in `threatlens/models/`).

2. Register the module in `threatlens/core/investigation_engine.py` inside `InvestigationConfig` and wire it into the investigation pipeline.

3. Add unit tests in `tests/unit/test_analysis_my_analysis.py`.

4. Update the README's feature list and architecture diagram if the module adds user-visible capability.

---

## Adding a New Threat Intel Provider

1. Create `threatlens/intel/my_provider.py`. Follow the interface established by `VirusTotalClient` and `GreyNoiseClient` — implement an async `enrich(indicator)` method and return a normalised result dict.

2. Register the provider in `threatlens/intel/enricher.py`.

3. Add the API key variable to:
   - `.env.example` (with a comment describing the provider)
   - `threatlens/utils/config.py` (as an optional `SecretStr` field)

4. Add unit tests using a mocked HTTP response.

---

## Pull Request Guidelines

- **Title**: short and imperative — `Add GreyNoise enrichment for IPv6 addresses`, not `Added some stuff`.
- **Description**: explain *what* changed and *why*. Reference the issue number if one exists (`Fixes #123`).
- **Scope**: keep PRs focused. A PR that adds a feature and refactors unrelated code is harder to review.
- **Tests**: all new code should be covered by unit tests. PRs that reduce coverage without justification will be asked to add tests.
- **Docs**: update the README if your change affects CLI behaviour, configuration, or supported integrations.

PRs are reviewed on a best-effort basis. Maintainers may request changes before merging.

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Azure Threat Lens is itself a security tool, so responsible disclosure matters. If you find a vulnerability — particularly one involving credential handling, API key exposure, or injection risks — please report it privately via [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository.

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested mitigations

We aim to acknowledge reports within 72 hours and to publish a fix and advisory within 90 days.

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) Code of Conduct. By participating, you agree to uphold a welcoming and respectful environment for everyone. Harassment, discrimination, or abusive behaviour will not be tolerated.

Instances of unacceptable behaviour may be reported to the project maintainers via the repository's GitHub contact methods.
