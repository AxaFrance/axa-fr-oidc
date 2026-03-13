.PHONY: help install install-dev install-quality install-test lint format type-check security quality test test-cov clean all

# Default target
help:
	@echo "Available targets:"
	@echo "  install          - Install production dependencies"
	@echo "  install-dev      - Install all development dependencies"
	@echo "  install-quality  - Install quality check dependencies"
	@echo "  install-test     - Install test dependencies"
	@echo "  lint             - Run ruff linter (includes docstring checks)"
	@echo "  lint-fix         - Run ruff linter with auto-fix"
	@echo "  format           - Run ruff formatter"
	@echo "  format-check     - Check formatting without applying changes"
	@echo "  type-check       - Run mypy type checker"
	@echo "  security         - Run bandit security checks"
	@echo "  security-audit   - Run pip-audit for dependency vulnerabilities"
	@echo "  quality          - Run all quality checks (lint, format, type-check, security)"
	@echo "  test             - Run tests"
	@echo "  test-cov         - Run tests with coverage report"
	@echo "  clean            - Remove build artifacts and cache files"
	@echo "  all              - Run quality checks and tests"

# Installation targets
install:
	uv sync

install-dev:
	uv sync --group dev

install-quality:
	uv sync --group quality

install-test:
	uv sync --group test

# Linting and formatting
lint:
	uv run ruff check src tests

lint-fix:
	uv run ruff check --fix src tests

format:
	uv run ruff format src tests

format-check:
	uv run ruff format --check src tests

# Type checking
type-check:
	uv run mypy src

# Security checks
security:
	uv run bandit -r src -c pyproject.toml

security-audit:
	uv run pip-audit

# Combined quality target (docstrings are checked via ruff 'D' rules in lint)
quality: lint format-check type-check security security-audit
	@echo "✅ All quality checks passed!"

# Testing
test:
	uv run pytest

test-cov:
	uv run pytest --cov=src --cov-report=html --cov-report=term-missing

# Cleanup
clean:
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf htmlcov
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info
	rm -rf src/*.egg-info
	rm -f coverage-unittests.xml .coverage
	rm -f test-output.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Run everything
all: quality test
	@echo "✅ All checks and tests passed!"
