# Copilot Instructions for axa-fr-oidc

## Project Overview

This is a Python library for OpenID Connect (OIDC) authentication with DPoP support.
It uses `uv` as the package manager and `ruff` for linting/formatting.

## Code Style & Quality

- **Linter**: `ruff` (configured in `pyproject.toml`)
- **Formatter**: `ruff format`
- **Type checker**: `mypy`
- **Test framework**: `pytest` with `pytest-asyncio`

### After every code change, always run:

1. **Lint fix**: `uv run ruff check --fix --unsafe-fixes src tests`
2. **Format**: `uv run ruff format src tests`
3. **Tests**: `uv run pytest tests/ -q`

### Key ruff rules enforced:

- `I001` — Imports must be sorted (isort style)
- `RUF022` — `__all__` must be sorted
- `SIM102` — Use single `if` with `and` instead of nested `if` statements
- `D` — Google-style docstrings required on all public functions/classes

### Import ordering (isort)

Imports must be alphabetically sorted within each group. Use `ruff check --fix` to auto-sort.

### Conventions

- Python 3.10+ syntax (use `X | Y` for union types, not `Union[X, Y]`)
- All public methods must have Google-style docstrings
- Tests are in `tests/` and do not require docstrings or bandit checks
- Constants go in `src/axa_fr_oidc/constants.py`
- Public API is exported from `src/axa_fr_oidc/__init__.py` with a sorted `__all__`

