# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-03-11

### Added
- `auth_method` parameter on `OidcClient` and `OpenIdConnect` to explicitly select
  the client-secret authentication method used at the token endpoint.
  Supported values (also exported as constants):
  - `"client_secret_jwt"` *(default)* — signs an HS256 JWT assertion (RFC 7523).
    Automatically falls back to `"client_secret_post"` on a 401 response, so
    servers that do not have this method enabled for the client still work
    without any configuration change.
  - `"client_secret_post"` — sends `client_id` and `client_secret` in the POST body.
  - `"client_secret_basic"` — sends credentials as an HTTP Basic Auth header.

## [1.2.0] - 2026-03-02

### Added
- High-level `OidcClient` API for simplified OIDC operations with context manager support
- Comprehensive docstrings for all modules and functions following Google Python Style Guide
- Makefile for convenient development commands
- CHANGELOG.md, LICENSE and CODE_OF_CONDUCT.md files
- MyPy type checking support and fixed all type errors
- Proxy configuration support via `proxy` parameter in `OidcClient` for HTTP/HTTPS proxies
- SSL certificate verification control via `verify` parameter in `OidcClient`
- HTTP request timeout configuration via `timeout` parameter in `OidcClient`

### Changed
- Stricter ruff rules for better code quality
- Improved documentation in README with examples for the new OidcClient
- Updated README with custom HTTP configuration examples (proxy, SSL, timeout)
- HTTP clients (httpx.Client and httpx.AsyncClient) now accept proxy, verify, and timeout parameters
- Client secret flow support in the OIDC client library

## [1.1.1] - 2026-01-29

### Added
- Python 3.10 support alongside Python 3.11

### Changed
- Updated ruff target Python version to 3.10
- Fixed datetime imports for Python 3.10 compatibility

## [1.1.0] - 2026-01-29

### Added
- Comprehensive test coverage for OIDC module (100% coverage)
- Test coverage improvements for memory cache module
- Test coverage improvements for HTTP service module
- Test coverage improvements for authorization module
- Token exchange function exposed in the public API
- Proper `__init__.py` files with module documentation

### Changed
- Centralized magic values into constants file for better maintainability
- Mutualized Oauth2Client implementation to reduce code duplication
- Translated remaining French comments and strings to English
- Updated README with improved documentation and examples
- Raised code coverage failure threshold to 95%

### Fixed
- Refactored JWKS functions to avoid type checker confusion
- Fixed various ruff linting issues

## [1.0.0] - 2025-11-16

### Added
- Initial stable release of axa-fr-oidc library
- Full OpenID Connect (OIDC) authentication support
- DPoP (Demonstrating Proof-of-Possession) token support
- JWT validation with JWKS
- Built-in memory cache for tokens and JWKS
- Both synchronous and asynchronous operations
- `OidcAuthentication` class for token validation
- `OpenIdConnect` class for obtaining access tokens
- `MemoryCache` for caching tokens and JWKS
- `XHttpServiceGet` for HTTP operations
- `JWTAuthorization` utility for extracting JWT claims
- Comprehensive type hints throughout the codebase
- Ruff linting and formatting configuration
- CI/CD pipelines for testing, quality checks, and releases
- Security checks with bandit and pip-audit
- pytest test suite with coverage reporting
- Support for Python 3.11+

### Changed
- Module renamed to `axa_fr_oidc` for Python package naming conventions
- Added abstraction layer to OpenIdConnect class for better extensibility

### Security
- Implemented proper timeout for HTTP requests to prevent hanging
- Added security scanning with bandit

[Unreleased]: https://github.com/axa-france/axa-fr-oidc/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/axa-france/axa-fr-oidc/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/axa-france/axa-fr-oidc/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/axa-france/axa-fr-oidc/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/axa-france/axa-fr-oidc/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/axa-france/axa-fr-oidc/releases/tag/v1.0.0
