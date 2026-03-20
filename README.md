# axa-fr-oidc

<div align="center">

| Python                                                                                          | Project                                                                                                      |
|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| ![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white) | ![Axa France OIDC Badge](https://img.shields.io/badge/Axa_France-OIDC-blue?logo=apachekafka&logoColor=white) |

</div>

A Python library for OpenID Connect (OIDC) authentication with DPoP (Demonstrating Proof-of-Possession) support, featuring JWT validation, token caching, and both sync/async operations.

## Table of Contents (ToC)

- [Table of Contents (ToC)](#table-of-contents-toc)
- [Features](#features)
- [Installation](#installation)
  - [Using uv (recommended)](#using-uv-recommended)
  - [Using pip](#using-pip)
- [Quick Start](#quick-start)
  - [Simple Usage with OidcClient (Recommended)](#simple-usage-with-oidcclient-recommended)
    - [Using Context Managers](#using-context-managers)
    - [Async Operations](#async-operations)
    - [Private Key Authentication](#private-key-authentication)
    - [Validating DPoP Tokens](#validating-dpop-tokens)
    - [Token Exchange](#token-exchange)
    - [Custom HTTP Configuration (Proxies, SSL, Timeouts)](#custom-http-configuration-proxies-ssl-timeouts)
    - [Client Secret Authentication Methods](#client-secret-authentication-methods)
  - [Extract Properties from a JWT Token](#extract-properties-from-a-jwt-token)
- [Advanced Usage (Low-Level API)](#advanced-usage-low-level-api)
  - [Using OpenIdConnect and OidcAuthentication Directly](#using-openidconnect-and-oidcauthentication-directly)
  - [Async Operations with Low-Level API](#async-operations-with-low-level-api)
  - [Using Private Key Authentication (Low-Level)](#using-private-key-authentication-low-level)
  - [Custom Configuration](#custom-configuration)
    - [Using OidcClient](#using-oidcclient)
    - [Using Low-Level API](#using-low-level-api)
- [API Reference](#api-reference)
  - [High-Level Client (Recommended)](#high-level-client-recommended)
  - [Low-Level Classes](#low-level-classes)
  - [Interfaces](#interfaces)
  - [Constants](#constants)
- [Advanced Configuration](#advanced-configuration)
  - [Client Secret Authentication Methods](#client-secret-authentication-methods-1)
  - [Proxy, SSL, and Timeout Configuration](#proxy-ssl-and-timeout-configuration)
- [Development](#development)
  - [Setup Development Environment](#setup-development-environment)
  - [Using the Makefile](#using-the-makefile)
  - [Running Tests](#running-tests)
  - [Running Quality Checks](#running-quality-checks)
  - [Installing Specific Dependency Groups](#installing-specific-dependency-groups)
- [Contributing](#contributing)

## Features

- 🔐 **OIDC Authentication** - Full OpenID Connect authentication support
- 🔑 **DPoP Support** - Demonstrating Proof-of-Possession for enhanced security
- ✅ **JWT Validation** - Comprehensive token validation with JWKS
- 💾 **Token Caching** - Built-in memory cache for tokens and JWKS
- ⚡ **Async/Sync** - Supports both synchronous and asynchronous operations
- 🎯 **Type Safe** - Fully typed with Python type hints
- 🔒 **Flexible Auth Methods** - `client_secret_jwt`, `client_secret_post`, and `client_secret_basic` with automatic fallback

## Installation

### Using uv (recommended)

```bash
uv add axa-fr-oidc
```

### Using pip

```bash
pip install axa-fr-oidc
```

## Quick Start

### Simple Usage with OidcClient (Recommended)

The `OidcClient` provides a simplified, high-level API for common OIDC operations:

```python
from axa_fr_oidc import OidcClient

# Create a client with client credentials
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["openid", "profile"],
    audience="your-api-audience",
)

# Get an access token (automatically cached and refreshed)
access_token = client.get_access_token()

# Validate a token
result = client.validate_token(access_token)
if result.success:
    print(f"Token is valid! Subject: {result.payload['sub']}")
else:
    print(f"Token is invalid: {result.error}")

# Clean up resources
client.close_sync()
```

#### Using Context Managers

```python
from axa_fr_oidc import OidcClient

# Sync context manager
with OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
) as client:
    token = client.get_access_token()

# Async context manager
async with OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
) as client:
    token = await client.get_access_token_async()
```

#### Async Operations

```python
import asyncio
from axa_fr_oidc import OidcClient

async def main():
    async with OidcClient(
        issuer="https://issuer.url",
        client_id="your-client-id",
        client_secret="your-client-secret",
    ) as client:
        # Async token retrieval
        token = await client.get_access_token_async()
        
        # Async token validation
        result = await client.validate_token_async(token)
        print(result.success, result.payload)

asyncio.run(main())
```

#### Private Key Authentication

```python
from axa_fr_oidc import OidcClient

# Load your private key
with open("private_key.pem", "r") as f:
    private_key_pem = f.read()

client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    private_key=private_key_pem,
    algorithm="RS256",
    scopes=["openid", "profile"],
)

token = client.get_access_token()
```

#### Validating DPoP Tokens

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
)

# Validate a DPoP-bound token
result = client.validate_token(
    token=access_token,
    dpop=dpop_proof,
    path="/api/resource",
    http_method="POST",
)

print(result.success, result.error)
```

#### Token Exchange

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

# Exchange a token (RFC 8693)
new_token = client.token_exchange(
    subject_token=user_token,
    requested_token_type="urn:ietf:params:oauth:token-type:access_token",
)
```

#### Custom HTTP Configuration (Proxies, SSL, Timeouts)

The client supports custom HTTP configurations including proxy settings, SSL verification, and timeouts:

```python
from axa_fr_oidc import OidcClient

# Using a proxy
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://proxy.example.com:8080",
)

# Using an HTTPS proxy
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="https://secure-proxy.example.com:8443",
)

# Disable SSL verification (not recommended for production)
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    verify=False,
)

# Set custom timeout (in seconds)
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    timeout=30.0,
)

# Combine multiple HTTP configurations
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://proxy.example.com:8080",
    verify=True,
    timeout=10.0,
)

token = client.get_access_token()
```

#### Client Secret Authentication Methods

When using `client_secret`, you can control how the credentials are sent to the
token endpoint via the `auth_method` parameter.

| `auth_method` | Behaviour |
|---|---|
| `"client_secret_jwt"` *(default)* | Signs an HS256 JWT assertion (RFC 7523). **Automatically falls back to `client_secret_post` on 401** if the server does not have this method enabled for the client. |
| `"client_secret_post"` | Sends `client_id` + `client_secret` in the POST body. Broadly supported. |
| `"client_secret_basic"` | Sends credentials as an HTTP Basic Auth header. Broadly supported. |

```python
from axa_fr_oidc import OidcClient
from axa_fr_oidc.constants import (
    CLIENT_SECRET_AUTH_METHOD_JWT,    # "client_secret_jwt"  (default)
    CLIENT_SECRET_AUTH_METHOD_POST,   # "client_secret_post"
    CLIENT_SECRET_AUTH_METHOD_BASIC,  # "client_secret_basic"
)

# Default: tries client_secret_jwt, falls back to client_secret_post on 401
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

# Explicitly use client_secret_post (no fallback overhead)
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_POST,
)

# Explicitly use client_secret_basic
client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_BASIC,
)

token = client.get_access_token()
```

For more details, see the [Client Secret Auth Methods Guide](./docs/client-secret-auth-methods.md).


### Extract Properties from a JWT Token

```python
from axa_fr_oidc import JWTAuthorization

authorization_header = "<your-jwt-token>"
jwt_auth = JWTAuthorization(authorization_header)

print(jwt_auth.get_property("sub"))  # Print the subject of the token
print(jwt_auth.get_property("exp"))  # Print the expiration time of the token
```

## Advanced Usage (Low-Level API)

For users who need more control over the authentication process, the library provides
low-level components that can be customized individually.

### Using OpenIdConnect and OidcAuthentication Directly

```python
from axa_fr_oidc import OidcAuthentication, OpenIdConnect, MemoryCache, XHttpServiceGet
from httpx import AsyncClient, Client

# Create HTTP clients
http_client = Client()
http_async_client = AsyncClient()

# Create HTTP service
http_service = XHttpServiceGet(
    http_client=http_client,
    http_async_client=http_async_client
)

# Create cache
memory_cache = MemoryCache()

# Create authentication handler
auth = OidcAuthentication(
    issuer="https://issuer.url",
    scopes=["openid", "profile"],
    api_audience="your-api-audience",
    service=http_service,
    memory_cache=memory_cache,
    algorithms=["RS256", "ES256"],
)

# Create OpenID Connect client
oidc = OpenIdConnect(
    authentication=auth,
    memory_cache=memory_cache,
    client_id="your-client-id",
    client_secret="your-client-secret"
)

# Get access token
access_token = oidc.get_access_token()

# Validate token
result = auth.validate(access_token, None, None, None)
print(result.success, result.error)
```

### Async Operations with Low-Level API

All low-level components support async/await:

```python
from axa_fr_oidc import OidcAuthentication, OpenIdConnect, MemoryCache, XHttpServiceGet
from httpx import AsyncClient, Client

async def main():
    http_service = XHttpServiceGet(
        http_client=Client(),
        http_async_client=AsyncClient()
    )
    memory_cache = MemoryCache()
    
    auth = OidcAuthentication(
        issuer="https://issuer.url",
        scopes=["openid", "profile"],
        api_audience="your-api-audience",
        service=http_service,
        memory_cache=memory_cache
    )
    
    oidc = OpenIdConnect(
        authentication=auth,
        memory_cache=memory_cache,
        client_id="your-client-id",
        client_secret="your-client-secret"
    )
    
    # Async token retrieval
    access_token = await oidc.get_access_token_async()
    
    # Async token validation
    result = await auth.validate_async(access_token, None, None, None)
    print(result.success, result.payload)

# Run with asyncio
import asyncio
asyncio.run(main())
```

### Using Private Key Authentication (Low-Level)

For client credentials flow with private key (JWT bearer) using the low-level API:

```python
from axa_fr_oidc import OidcAuthentication, OpenIdConnect, MemoryCache, XHttpServiceGet
from httpx import AsyncClient, Client

# Load your private key
with open("private_key.pem", "r") as f:
    private_key_pem = f.read()

http_service = XHttpServiceGet(
    http_client=Client(),
    http_async_client=AsyncClient()
)
memory_cache = MemoryCache()

auth = OidcAuthentication(
    issuer="https://issuer.url",
    scopes=["openid", "profile"],
    api_audience="your-api-audience",
    service=http_service,
    memory_cache=memory_cache
)

oidc = OpenIdConnect(
    authentication=auth,
    memory_cache=memory_cache,
    client_id="your-client-id",
    private_key=private_key_pem,
    algorithm="RS256"  # or other supported algorithms
)

access_token = oidc.get_access_token()
```

> **Note:** For most use cases, consider using the simpler `OidcClient` instead.
> See the [Quick Start](#quick-start) section for examples.

### Custom Configuration

You can customize various timeouts and cache settings:

#### Using OidcClient

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://issuer.url",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["openid", "profile"],
    audience="your-api-audience",
    algorithms=["RS256", "ES256"],  # Allowed algorithms for validation
)
```

#### Using Low-Level API

```python
from axa_fr_oidc import (
    OidcAuthentication,
    MemoryCache,
    XHttpServiceGet,
)
from httpx import AsyncClient, Client

auth = OidcAuthentication(
    issuer="https://issuer.url",
    scopes=["openid", "profile"],
    api_audience="your-api-audience",
    service=XHttpServiceGet(
        http_client=Client(),
        http_async_client=AsyncClient()
    ),
    memory_cache=MemoryCache(),
    algorithms=["RS256", "ES256"],  # Supported algorithms
)
```

## API Reference

### High-Level Client (Recommended)

- **`OidcClient`** - Simplified, all-in-one client for OIDC operations
  - `get_access_token()` / `get_access_token_async()` - Get an access token
  - `validate_token()` / `validate_token_async()` - Validate an access token
  - `token_exchange()` - Exchange tokens (RFC 8693)
  - `get_token_endpoint()` / `get_token_endpoint_async()` - Get the token endpoint URL
  - `clear_cache()` - Clear all cached data
  - `close()` / `close_sync()` - Release resources
  - Supports context managers (`with`/`async with`)

### Low-Level Classes

- **`OidcAuthentication`** - OIDC token validation and JWKS management
- **`OpenIdConnect`** - Client for obtaining access tokens
- **`MemoryCache`** - In-memory cache for tokens and JWKS
- **`XHttpServiceGet`** - HTTP service wrapper for sync/async requests
- **`JWTAuthorization`** - Utility for extracting JWT claims
- **`AuthenticationResult`** - Result object from validation operations

### Interfaces

All main classes have corresponding interfaces for dependency injection:

- **`IOidcAuthentication`** - Interface for OidcAuthentication
- **`IOpenIdConnect`** - Interface for OpenIdConnect
- **`IMemoryCache`** - Interface for MemoryCache
- **`IHttpServiceGet`** - Interface for XHttpServiceGet
- **`IGenericAuthorization`** - Interface for JWTAuthorization

### Constants

The library exports useful constants for configuration:

```python
from axa_fr_oidc import (
    DEFAULT_DPOP_MAX_AGE_SECONDS,      # 300 (5 minutes)
    DEFAULT_CLOCK_SKEW_SECONDS,        # 300 (5 minutes)
    DEFAULT_JTI_LIFETIME_SECONDS,      # 300 (5 minutes)
    DEFAULT_JWT_ALGORITHM,             # "RS256"
    DEFAULT_JWT_EXPIRATION_SECONDS,    # 300 (5 minutes)
    DEFAULT_HTTP_TIMEOUT_SECONDS,      # 5 seconds
    SUPPORTED_ALGORITHMS,              # ["RS256", "HS256"]
    DPOP_TOKEN_TYPE,                   # "dpop+jwt"
    GRANT_TYPE_CLIENT_CREDENTIALS,     # "client_credentials"
    CLIENT_ASSERTION_TYPE_JWT_BEARER,  # "urn:ietf:params:oauth:..."
    CONTENT_TYPE_FORM_URLENCODED,      # "application/x-www-form-urlencoded"
    OIDC_WELL_KNOWN_PATH,              # "/.well-known/openid-configuration"
    CLIENT_SECRET_AUTH_METHOD_JWT,     # "client_secret_jwt"
    CLIENT_SECRET_AUTH_METHOD_POST,    # "client_secret_post"
    CLIENT_SECRET_AUTH_METHOD_BASIC,   # "client_secret_basic"
)
```

## Advanced Configuration

### Client Secret Authentication Methods

For detailed information on configuring the client-secret auth method
(`client_secret_jwt`, `client_secret_post`, `client_secret_basic`) and the
automatic fallback behaviour, see the
[Client Secret Auth Methods Guide](./docs/client-secret-auth-methods.md).

### Proxy, SSL, and Timeout Configuration

For detailed information on configuring HTTP proxies, SSL verification, and timeouts, see the [Proxy Configuration Guide](./docs/proxy-configuration.md).

Quick examples:

```python
# Using a proxy
client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://proxy.example.com:8080",
)

# With custom timeout
client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    timeout=30.0,
)
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/axa-fr-oidc.git
cd axa-fr-oidc

# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync --group dev
```

### Using the Makefile

The project includes a `Makefile` for convenient development commands:

```bash
# Show all available commands
make help

# Install dependencies
make install          # Production dependencies only
make install-dev      # All development dependencies
make install-quality  # Quality check tools only
make install-test     # Test dependencies only

# Code quality
make lint             # Run ruff linter (includes docstring checks)
make lint-fix         # Run ruff linter with auto-fix
make format           # Run ruff formatter
make format-check     # Check formatting without changes
make type-check       # Run mypy type checker

# Security
make security         # Run bandit security checks
make security-audit   # Run pip-audit for dependency vulnerabilities

# Testing
make test             # Run tests
make test-cov         # Run tests with coverage report

# Combined commands
make quality          # Run all quality checks (lint, format, type-check, security)
make all              # Run quality checks and tests

# Cleanup
make clean            # Remove build artifacts and cache files
```

### Running Tests

```bash
# Using make
make test

# Or directly with uv
uv run pytest
```

### Running Quality Checks

```bash
# Run all quality checks at once
make quality

# Or run individual checks
make lint
make type-check
make security
```

### Installing Specific Dependency Groups

```bash
# Install only test dependencies
uv sync --group test

# Install only linting tools
uv sync --group lint

# Install only security tools
uv sync --group security

# Install everything for development
uv sync --group dev
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
