# Repository Guidelines

These instructions apply to the entire repository.

## Development Environment

- Use `uv` for dependency management and command execution.
- Install all development dependencies with `uv sync --group dev`.
- Do not introduce new linting, formatting, type-checking, or testing tools when the existing toolchain can do the job.

## Implementation Rules

- Keep every configuration setting typed. Prefer explicit typed constructor parameters or typed settings objects over untyped dictionaries or ad hoc environment lookups.
- Put reusable default values in `src/axa_fr_oidc/constants.py`.
- Propagate new settings through every relevant public and internal layer; do not read configuration implicitly in lower-level components.
- Keep `src/axa_fr_oidc/__init__.py` and its sorted `__all__` up to date for public APIs and constants.
- Use Python 3.10+ syntax, including `X | Y` unions.
- Add Google-style docstrings to all public functions, methods, and classes.
- Follow existing sync and async behavior consistently.
- Avoid broad exception handling, silent fallbacks, and untyped casts.

## Tests

- Always add or update unit tests with every behavior or configuration change.
- Cover defaults, custom values, invalid values, boundaries, and error paths.
- Cover both synchronous and asynchronous APIs when behavior can differ.
- Keep the configured test coverage at or above 95%.
- Run a focused test while iterating when useful, then run the complete suite before finishing.

## Required Checks

After every code change, run:

```bash
uv run ruff check --fix --unsafe-fixes src tests
uv run ruff format src tests
uv run mypy src
uv run pytest tests/ -q
```

Before finishing, also run the non-mutating checks:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
```

Do not consider a change complete while any required check or test fails.

## Documentation

- Update `README.md` whenever a public setting, default, or behavior changes.
- Keep examples typed and aligned with the current public API.
- Document whether configuration affects token retrieval, token validation, or both.
