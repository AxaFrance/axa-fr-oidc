"""OIDC authentication module.

This module provides OpenID Connect authentication with DPoP support.
"""

from requests_oauth2client import BearerToken, IdToken

from axa_fr_oidc.oidc.oidc_authentication import (
    AuthenticationResult,
    HandleValidationResult,
    IOidcAuthentication,
    OidcAuthentication,
)
from axa_fr_oidc.oidc.openid_connect import IOpenIdConnect, OpenIdConnect

__all__ = [
    "AuthenticationResult",
    "BearerToken",
    "HandleValidationResult",
    "IOidcAuthentication",
    "IOpenIdConnect",
    "IdToken",
    "OidcAuthentication",
    "OpenIdConnect",
]
