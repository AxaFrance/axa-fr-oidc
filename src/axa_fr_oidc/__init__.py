"""AXA France OIDC Authentication Library.

A Python library for OpenID Connect (OIDC) authentication with DPoP
(Demonstrating Proof-of-Possession) support, featuring JWT validation,
token caching, and both sync/async operations.
"""

# Authorization
from axa_fr_oidc.authorization import IGenericAuthorization, JWTAuthorization

# High-level client (simplified API)
from axa_fr_oidc.client import OidcClient

# Constants
from axa_fr_oidc.constants import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    CLIENT_SECRET_AUTH_METHOD_BASIC,
    CLIENT_SECRET_AUTH_METHOD_JWT,
    CLIENT_SECRET_AUTH_METHOD_POST,
    CONTENT_TYPE_FORM_URLENCODED,
    DEFAULT_CLOCK_SKEW_SECONDS,
    DEFAULT_DPOP_MAX_AGE_SECONDS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS,
    DEFAULT_JTI_LIFETIME_SECONDS,
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_JWT_EXPIRATION_SECONDS,
    DPOP_TOKEN_TYPE,
    ERROR_JWK_NOT_FOUND,
    GRANT_TYPE_CLIENT_CREDENTIALS,
    OIDC_WELL_KNOWN_PATH,
    SUPPORTED_ALGORITHMS,
)

# HTTP Service
from axa_fr_oidc.http_service import IHttpServiceGet, XHttpServiceGet

# Memory Cache
from axa_fr_oidc.memory_cache import IMemoryCache, MemoryCache
from axa_fr_oidc.oidc import (
    AuthenticationResult,
    BearerToken,
    IdToken,
    IOidcAuthentication,
    IOpenIdConnect,
    OidcAuthentication,
    OpenIdConnect,
)

__all__ = [
    # Constants
    "CLIENT_ASSERTION_TYPE_JWT_BEARER",
    "CLIENT_SECRET_AUTH_METHOD_BASIC",
    "CLIENT_SECRET_AUTH_METHOD_JWT",
    "CLIENT_SECRET_AUTH_METHOD_POST",
    "CONTENT_TYPE_FORM_URLENCODED",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "DEFAULT_DPOP_MAX_AGE_SECONDS",
    "DEFAULT_HTTP_TIMEOUT_SECONDS",
    "DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS",
    "DEFAULT_JTI_LIFETIME_SECONDS",
    "DEFAULT_JWT_ALGORITHM",
    "DEFAULT_JWT_EXPIRATION_SECONDS",
    "DPOP_TOKEN_TYPE",
    "ERROR_JWK_NOT_FOUND",
    "GRANT_TYPE_CLIENT_CREDENTIALS",
    "OIDC_WELL_KNOWN_PATH",
    "SUPPORTED_ALGORITHMS",
    # OIDC Authentication
    "AuthenticationResult",
    # Token Types
    "BearerToken",
    # Authorization
    "IGenericAuthorization",
    # HTTP Service
    "IHttpServiceGet",
    # Memory Cache
    "IMemoryCache",
    "IOidcAuthentication",
    "IOpenIdConnect",
    "IdToken",
    "JWTAuthorization",
    "MemoryCache",
    "OidcAuthentication",
    # High-level client (recommended for most use cases)
    "OidcClient",
    "OpenIdConnect",
    "XHttpServiceGet",
]
