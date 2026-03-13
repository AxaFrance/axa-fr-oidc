"""Constants for axa-fr-oidc library.

This module contains all configuration constants used throughout the library.
"""

# Time-related constants (in seconds)
DEFAULT_DPOP_MAX_AGE_SECONDS = 300  # 5 minutes
DEFAULT_CLOCK_SKEW_SECONDS = 300  # 5 minutes
DEFAULT_JTI_LIFETIME_SECONDS = 300  # 5 minutes
DEFAULT_JWT_EXPIRATION_SECONDS = 300  # 5 minutes
DEFAULT_HTTP_TIMEOUT_SECONDS = 5  # 5 seconds

# Algorithm constants
DEFAULT_JWT_ALGORITHM = "RS256"
DEFAULT_JWT_CLIENTSECRET_ALGORITHM = "HS256"
SUPPORTED_ALGORITHMS = ["RS256", "HS256"]

# DPoP constants
DPOP_TOKEN_TYPE = "dpop+jwt"  # nosec: B105 # noqa: S105

# HTTP constants
CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Client secret authentication methods (token_endpoint_auth_methods_supported)
CLIENT_SECRET_AUTH_METHOD_JWT = "client_secret_jwt"  # HS256 JWT assertion  # nosec: B105 # noqa: S105
CLIENT_SECRET_AUTH_METHOD_POST = "client_secret_post"  # credentials in POST body  # nosec: B105 # noqa: S105
CLIENT_SECRET_AUTH_METHOD_BASIC = "client_secret_basic"  # HTTP Basic Auth header  # nosec: B105 # noqa: S105

# OIDC constants
OIDC_WELL_KNOWN_PATH = "/.well-known/openid-configuration"

# Error messages
ERROR_JWK_NOT_FOUND = "JWK key not found in JWKS"
