"""HTTP service module for making async and sync HTTP requests.

This module provides an abstraction layer for HTTP operations used by OIDC authentication.
"""

from axa_fr_oidc.http_service.http_service import IHttpServiceGet, XHttpServiceGet

__all__ = [
    "IHttpServiceGet",
    "XHttpServiceGet",
]
