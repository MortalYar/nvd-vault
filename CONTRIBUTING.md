# Contributing to NVD Vault

**English** · [Русский](CONTRIBUTING.ru.md)

Thanks for your interest in contributing! This document describes how to get a development environment running, the conventions we follow, and how to submit changes.

## Getting started

```bash
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault
python -m pip install -e ".[dev]"
```

This installs the project in editable mode along with `pytest`, `ruff`, and `pip-audit`.

## Running tests

```bash
pytest
```

The full test suite runs in seconds — there are no network calls (NVD/EPSS/KEV are mocked). If you add a feature, please add tests for it.

## Code style

We use [ruff](https://docs.astral.sh/ruff/) for both linting and formatting. Before committing:

```bash
ruff check . --fix
ruff format .
```

Both checks must pass in CI. Configuration lives in `pyproject.toml` under `[tool.ruff]`.

Type hints follow PEP 604 syntax — write `str | None`, not `Optional[str]`.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org). Common prefixes:

- `feat:` — new user-visible feature
- `fix:` — bug fix
- `refactor:` — code change that doesn't change behavior
- `docs:` — documentation only
- `test:` — adding or updating tests
- `ci:` — CI / GitHub Actions changes
- `chore:` — tooling, dependencies, repo housekeeping
- `style:` — formatting only (whitespace, quotes), no logic changes

Optional scope in parentheses: `feat(matcher): support pre-release versions`.

Keep the subject line under ~70 characters. Use the body for context if needed.

## Pull requests

1. **Open an issue first** for non-trivial changes so we can discuss the approach before you write the code. Bug fixes don't need an issue.
2. **Branch from `main`** and keep PRs focused — one logical change per PR.
3. **Update tests** for any code changes. New features without tests will be asked to add them.
4. **Update documentation** if behaviour or CLI changes. README is bilingual (EN + RU) — try to update both, but if you don't speak Russian, English-only is fine and we'll handle the rest.
5. **Make sure CI is green** before requesting review. All five checks (lint, audit, tests on Python 3.11/3.12/3.13) must pass.
6. **Squash before merge** is preferred — keeps `main` history readable.

## Project structure

```text
nvd_vault/
├── api/
│   └── bridge.py          # JS ↔ Python IPC for the GUI
├── core/
│   ├── nvd_client.py      # NVD API 2.0 HTTP client
│   ├── nvd_cache.py       # Disk cache for NVD responses
│   ├── enrichment.py      # EPSS + CISA KEV enrichment
│   ├── matcher.py         # CPE 2.3 version range matching
│   ├── vault_builder.py   # Orchestrates the full build
│   └── ...
└── webui/                 # HTML/CSS/JS frontend (no build step)
tests/                     # pytest suite
```

When in doubt about where new code belongs, look at imports in nearby modules — `core` is pure Python with no GUI dependencies, `api` is the bridge layer, `webui` is static assets.

## Reporting security issues

**Do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the private disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the MIT License (the same license as the project).