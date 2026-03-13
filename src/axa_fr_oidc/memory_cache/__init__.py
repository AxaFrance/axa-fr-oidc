"""In-memory cache module for storing tokens and JWKS.

This module provides a simple in-memory cache implementation with a singleton pattern.
"""

from axa_fr_oidc.memory_cache.memory_cache import IMemoryCache, MemoryCache

__all__ = [
    "IMemoryCache",
    "MemoryCache",
]
