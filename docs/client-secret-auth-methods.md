# Client Secret Authentication Methods

This guide explains the three OAuth2 client-secret authentication methods supported
by `axa-fr-oidc` and how to choose the right one for your authorization server.

## Overview

When using a `client_secret`, the library needs to prove the client's identity to
the token endpoint. The OAuth2 specification (and RFC 7523) defines several ways to
do this. The method to use is controlled by the `auth_method` parameter on both
`OidcClient` and `OpenIdConnect`.

| `auth_method` constant | Value | Description |
|---|---|---|
| `CLIENT_SECRET_AUTH_METHOD_JWT` | `"client_secret_jwt"` | Signs a JWT assertion with the secret (HS256). Most secure; requires server-side registration per client. **Default.** |
| `CLIENT_SECRET_AUTH_METHOD_POST` | `"client_secret_post"` | Sends credentials in the POST body. Broadly supported. |
| `CLIENT_SECRET_AUTH_METHOD_BASIC` | `"client_secret_basic"` | Sends credentials as an HTTP Basic Auth header. Broadly supported. |

## Automatic Fallback

When `auth_method="client_secret_jwt"` (the default), the library first attempts a
JWT assertion. If the authorization server returns a **401** — which happens when
`client_secret_jwt` is not enabled for that specific client — the library
**automatically retries with `client_secret_post`** transparently, without raising
an exception. This means you never need to change your code just because a server
has a different default configuration.

```
client_secret_jwt  ──(401)──►  client_secret_post  ──(success)──►  access_token
                                                    ──(401)──►  HTTPError raised
```

If you already know which method your server supports, set it explicitly to avoid
the extra round-trip.

## Usage

### Default (client_secret_jwt with automatic fallback)

```python
from axa_fr_oidc import OidcClient

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    # auth_method defaults to CLIENT_SECRET_AUTH_METHOD_JWT
)

token = client.get_access_token()
```

### Explicit client_secret_post

Use this when you know the server only supports `client_secret_post`, or to avoid
the extra JWT round-trip:

```python
from axa_fr_oidc import OidcClient
from axa_fr_oidc.constants import CLIENT_SECRET_AUTH_METHOD_POST

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_POST,
)

token = client.get_access_token()
```

### Explicit client_secret_basic

Use this when the server requires credentials in an HTTP Basic Auth header:

```python
from axa_fr_oidc import OidcClient
from axa_fr_oidc.constants import CLIENT_SECRET_AUTH_METHOD_BASIC

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_BASIC,
)

token = client.get_access_token()
```

### Explicit client_secret_jwt (no fallback)

Use this when you are certain the server supports `client_secret_jwt` and you want
strict behaviour (raise immediately on failure instead of retrying):

```python
from axa_fr_oidc import OidcClient
from axa_fr_oidc.constants import CLIENT_SECRET_AUTH_METHOD_JWT

client = OidcClient(
    issuer="https://auth.example.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_JWT,
)

token = client.get_access_token()
```

> **Note:** Even when `CLIENT_SECRET_AUTH_METHOD_JWT` is set explicitly as the
> default value, the automatic fallback to `client_secret_post` on a 401 is still
> active. The fallback only triggers on a 401 — any other HTTP error is raised
> immediately.

## Low-Level API

The `auth_method` parameter is also available on `OpenIdConnect` directly:

```python
from axa_fr_oidc import OidcAuthentication, OpenIdConnect, MemoryCache, XHttpServiceGet
from axa_fr_oidc.constants import CLIENT_SECRET_AUTH_METHOD_POST
from httpx import AsyncClient, Client

memory_cache = MemoryCache()
http_service = XHttpServiceGet(
    http_client=Client(),
    http_async_client=AsyncClient(),
)

auth = OidcAuthentication(
    issuer="https://auth.example.com",
    scopes=["openid"],
    service=http_service,
    memory_cache=memory_cache,
)

oidc = OpenIdConnect(
    authentication=auth,
    memory_cache=memory_cache,
    client_id="your-client-id",
    client_secret="your-client-secret",
    auth_method=CLIENT_SECRET_AUTH_METHOD_POST,
)

token = oidc.get_access_token()
```

## Discovering Supported Methods

You can inspect the authorization server's OIDC discovery document to see which
methods it supports for your client:

```python
import requests

discovery = requests.get(
    "https://auth.example.com/.well-known/openid-configuration"
).json()

print(discovery.get("token_endpoint_auth_methods_supported"))
# e.g. ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt']
```

The actual methods enabled **per client** are configured on the authorization
server side (e.g., in PingFederate, Keycloak, Auth0, etc.). If your client is not
registered for `client_secret_jwt`, the library falls back automatically.

## Async Usage

All auth methods work identically with `get_access_token_async()`:

```python
import asyncio
from axa_fr_oidc import OidcClient
from axa_fr_oidc.constants import CLIENT_SECRET_AUTH_METHOD_POST

async def main():
    async with OidcClient(
        issuer="https://auth.example.com",
        client_id="your-client-id",
        client_secret="your-client-secret",
        auth_method=CLIENT_SECRET_AUTH_METHOD_POST,
    ) as client:
        token = await client.get_access_token_async()
        print(token)

asyncio.run(main())
```

