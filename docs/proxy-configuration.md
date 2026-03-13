# Proxy Configuration Guide

This guide explains how to configure the `axa-fr-oidc` library to work with HTTP proxies, custom SSL verification, and timeouts.

## Overview

The `OidcClient` supports custom HTTP configurations through the following parameters:

- **`proxy`**: Configure HTTP/HTTPS proxy server
- **`verify`**: Control SSL certificate verification
- **`timeout`**: Set HTTP request timeout in seconds

**Note**: The underlying httpx library uses a single `proxy` parameter that handles all traffic. For protocol-specific routing, you would need to configure your proxy server accordingly or use environment variables.

## Proxy Configuration

### Simple Proxy (All Protocols)

Use a single proxy server for all HTTP/HTTPS traffic:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://proxy.example.com:8080",
)

# Use the client as normal
token = client.get_access_token()
```

### HTTPS Proxy

Use an HTTPS proxy for secure proxy connections:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="https://secure-proxy.example.com:8443",
)

token = client.get_access_token()
```

### Authenticated Proxy

Include credentials in the proxy URL:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://username:password@proxy.example.com:8080",
)

token = client.get_access_token()
```

### Environment Variables

You can also use environment variables for proxy configuration by setting `trust_env=True` (this requires customizing the httpx client directly):

```python
import os
from axa_fr_oidc import OidcClient

# Set proxy via environment
os.environ["HTTP_PROXY"] = "http://proxy.example.com:8080"
os.environ["HTTPS_PROXY"] = "https://secure-proxy.example.com:8443"

# trust_env is True by default in httpx
client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

token = client.get_access_token()
```

## SSL Verification

### Disable SSL Verification

**⚠️ Warning**: Disabling SSL verification is not recommended for production environments as it makes your application vulnerable to man-in-the-middle attacks.

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    verify=False,  # Disable SSL verification
)

token = client.get_access_token()
```

### Enable SSL Verification (Default)

SSL verification is enabled by default:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    verify=True,  # Explicitly enable (this is the default)
)

token = client.get_access_token()
```

## Timeout Configuration

### Set Custom Timeout

Configure a timeout in seconds for all HTTP requests:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    timeout=30.0,  # 30 seconds timeout
)

token = client.get_access_token()
```

### Default Behavior

By default, no timeout is set (None), which means requests will wait indefinitely:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    timeout=None,  # No timeout (default)
)

token = client.get_access_token()
```

## Combined Configuration

### All Options Together

You can combine all HTTP configuration options:

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    proxy="http://proxy.example.com:8080",
    verify=True,
    timeout=15.0,
)

# Use client as normal
token = client.get_access_token()
result = client.validate_token(token)
```

## Environment-Specific Configurations

### Development Environment

```python
from axa_fr_oidc import OidcClient

# More lenient settings for development
client = OidcClient(
    issuer="https://dev-auth.example.com",
    client_id="dev-client-id",
    client_secret="dev-secret",
    verify=False,  # May be needed for self-signed certificates
    timeout=60.0,  # Longer timeout for debugging
)
```

### Production Environment

```python
from axa_fr_oidc import OidcClient

# Secure settings for production
client = OidcClient(
    issuer="https://auth.example.com",
    client_id="prod-client-id",
    client_secret="prod-secret",
    proxy="http://corporate-proxy.example.com:8080",
    verify=True,  # Always verify SSL in production
    timeout=10.0,  # Reasonable timeout
)
```

## Using with Async Operations

All HTTP configurations work with both sync and async operations:

```python
import asyncio
from axa_fr_oidc import OidcClient

async def main():
    async with OidcClient(
        issuer="https://auth.example.com",
        client_id="your-client-id",
        client_secret="your-client-secret",
        proxy="http://proxy.example.com:8080",
        verify=True,
        timeout=10.0,
    ) as client:
        # Async operations use the same proxy configuration
        token = await client.get_access_token_async()
        result = await client.validate_token_async(token)
        print(f"Token valid: {result.success}")

asyncio.run(main())
```

