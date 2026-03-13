"""Authorization module for JWT token handling.

This module provides utilities for extracting and managing authorization data from JWT tokens.
"""

from axa_fr_oidc.authorization.generic_authorization import IGenericAuthorization
from axa_fr_oidc.authorization.jwt_authorization import JWTAuthorization

__all__ = [
    "IGenericAuthorization",
    "JWTAuthorization",
]
