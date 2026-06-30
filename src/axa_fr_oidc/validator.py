"""High-level OIDC token validator with simplified API.

This module exposes :class:`OidcValidator`, a focused, dependency-managed
facade for validating OAuth2/OIDC access tokens (and optional DPoP proofs).

It complements :class:`axa_fr_oidc.client.OidcClient` which is responsible for
retrieving tokens.  Splitting validation and token retrieval into two distinct
classes keeps each public interface small, easier to test, and obeys the
single-responsibility principle.
"""

from collections.abc import Callable
from typing import Any

from httpx import AsyncClient, Client

from axa_fr_oidc.constants import (
    DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS,
    SUPPORTED_ALGORITHMS,
)
from axa_fr_oidc.http_service import IHttpServiceGet, XHttpServiceGet
from axa_fr_oidc.memory_cache import IMemoryCache, MemoryCache
from axa_fr_oidc.oidc import (
    AuthenticationResult,
    IOidcAuthentication,
    OidcAuthentication,
)
from axa_fr_oidc.oidc.oidc_authentication import HandleValidationResult


class OidcValidator:
    """Simplified OIDC token validator focused exclusively on validation.

    This class provides a high-level, easy-to-use interface dedicated to
    validating OAuth2/OIDC access tokens and DPoP proofs.  Unlike
    :class:`axa_fr_oidc.client.OidcClient`, it does not require any client
    credentials (``client_id``, ``client_secret`` or ``private_key``) because
    token retrieval is intentionally out of scope.

    All required dependencies (HTTP service, memory cache, underlying
    :class:`OidcAuthentication`) are created lazily, but custom
    implementations may be injected for testing or for sharing dependencies
    with an :class:`OidcClient` instance.

    Example:
        Validate a token against an issuer:

        >>> validator = OidcValidator(
        ...     issuer="https://auth.example.com",
        ...     audience="my-api",
        ... )
        >>> result = validator.validate_token(access_token)
        >>> if result.success:
        ...     print(f"Token is valid! Subject: {result.payload['sub']}")

        Plug a custom callback to derive scopes/audience from the payload:

        >>> from axa_fr_oidc import HandleValidationResult
        >>> def per_payload(payload):
        ...     return HandleValidationResult(scopes=payload.get("scope", "").split(), aud="my-api")
        >>> validator = OidcValidator(
        ...     issuer="https://auth.example.com",
        ...     handle_validation=per_payload,
        ... )

    Attributes:
        issuer: The OIDC issuer URL whose tokens are validated.
        audience: The expected ``aud`` claim, or ``None`` to skip audience checks.
        scopes: List of scopes required when no ``handle_validation`` is set.
        algorithms: Allowed signing algorithms for the JWT.
    """

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        scopes: list[str] | None = None,
        algorithms: list[str] | None = None,
        http_service: IHttpServiceGet | None = None,
        memory_cache: IMemoryCache | None = None,
        proxy: str | None = None,
        verify: bool = True,
        timeout: float | None = None,
        issuer_cache_expiration_seconds: int = DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS,
        handle_validation: Callable[[dict[str, Any]], HandleValidationResult] | None = None,
    ) -> None:
        """Initialize the OIDC validator.

        Args:
            issuer: The OIDC issuer URL (e.g., ``"https://auth.example.com"``).
            audience: The expected ``aud`` claim.  ``None`` (the default) skips
                audience validation.  This can also be overridden per call via
                :meth:`validate_token`.
            scopes: List of required scopes.  When ``handle_validation`` is not
                provided, every scope in this list must be present in the
                token's ``scope`` claim.  Defaults to ``[]`` (no scope check).
            algorithms: Allowed signing algorithms for the access token JWT.
                Defaults to :data:`SUPPORTED_ALGORITHMS`.
            http_service: Custom HTTP service for OIDC discovery / JWKS
                requests.  When ``None``, a default ``httpx``-based service is
                created internally.
            memory_cache: Custom cache implementation.  When ``None``, a
                default in-memory cache is created.
            proxy: Proxy URL to route HTTP traffic through.  Supports both
                HTTP and HTTPS proxies.  Defaults to ``None``.
            verify: Whether to verify SSL certificates.  Defaults to ``True``.
            timeout: Timeout in seconds for HTTP requests.  Defaults to
                ``None`` (no timeout).
            issuer_cache_expiration_seconds: Time-to-live in seconds for the
                JWKS and ``token_endpoint`` cache.  Defaults to
                :data:`DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS` (1 hour).
            handle_validation: Optional callable invoked with the decoded
                (not-yet-verified) token claims that returns a
                :class:`HandleValidationResult` describing which scopes and
                which audience should be validated for that particular token.
                When omitted, ``scopes`` and ``audience`` from the constructor
                are used.
        """
        self.issuer = issuer
        self.audience = audience
        self.scopes = [] if scopes is None else scopes
        self.algorithms = algorithms or SUPPORTED_ALGORITHMS
        self.proxy = proxy
        self.verify = verify
        self.timeout = timeout
        self.issuer_cache_expiration_seconds = issuer_cache_expiration_seconds
        self._handle_validation = handle_validation

        self._http_client: Client | None = None
        self._http_async_client: AsyncClient | None = None
        self._http_service = http_service
        self._memory_cache = memory_cache
        self._authentication: IOidcAuthentication | None = None

    @property
    def http_service(self) -> IHttpServiceGet:
        """Get or lazily create the HTTP service used to fetch OIDC metadata.

        Returns:
            The HTTP service instance.
        """
        if self._http_service is None:
            self._http_client = Client(
                proxy=self.proxy,
                verify=self.verify,
                timeout=self.timeout,
            )
            self._http_async_client = AsyncClient(
                proxy=self.proxy,
                verify=self.verify,
                timeout=self.timeout,
            )
            self._http_service = XHttpServiceGet(
                http_client=self._http_client,
                http_async_client=self._http_async_client,
            )
        return self._http_service

    @property
    def memory_cache(self) -> IMemoryCache:
        """Get or lazily create the memory cache used for JWKS storage.

        Returns:
            The memory cache instance.
        """
        if self._memory_cache is None:
            self._memory_cache = MemoryCache()
        return self._memory_cache

    @property
    def authentication(self) -> IOidcAuthentication:
        """Get or lazily create the underlying :class:`OidcAuthentication`.

        Returns:
            The OIDC authentication instance.
        """
        if self._authentication is None:
            self._authentication = OidcAuthentication(
                issuer=self.issuer,
                scopes=self.scopes,
                api_audience=self.audience,
                service=self.http_service,
                memory_cache=self.memory_cache,
                algorithms=self.algorithms,
                issuer_cache_expiration_seconds=self.issuer_cache_expiration_seconds,
                handle_validation=self._handle_validation,
            )
        return self._authentication

    def validate_token(
        self,
        token: str,
        dpop: str | None = None,
        path: str | None = None,
        http_method: str | None = None,
        audience: str | None = None,
    ) -> AuthenticationResult:
        """Validate an access token synchronously.

        Validates the token signature, expiration, issuer, scopes and
        (optionally) the DPoP proof when provided.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT for DPoP-bound tokens, or ``None``.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.
            audience: Override the expected audience for this validation call.
                When provided, takes precedence over the audience configured at
                construction time.  When ``None``, the constructor audience
                (or a per-payload value derived by ``handle_validation``) is
                used.

        Returns:
            :class:`AuthenticationResult` indicating success or failure with
            details about the decoded payload or the validation error.

        Example:
            >>> result = validator.validate_token(access_token)
            >>> if result.success:
            ...     print(f"Valid! Subject: {result.payload['sub']}")
            ... else:
            ...     print(f"Invalid: {result.error}")
        """
        return self.authentication.validate(token, dpop, path, http_method, audience)

    async def validate_token_async(
        self,
        token: str,
        dpop: str | None = None,
        path: str | None = None,
        http_method: str | None = None,
        audience: str | None = None,
    ) -> AuthenticationResult:
        """Validate an access token asynchronously.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT for DPoP-bound tokens, or ``None``.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.
            audience: Override the expected audience for this validation call.

        Returns:
            :class:`AuthenticationResult` indicating success or failure.

        Example:
            >>> result = await validator.validate_token_async(access_token)
            >>> if result.success:
            ...     print(f"Valid! Subject: {result.payload['sub']}")
        """
        return await self.authentication.validate_async(token, dpop, path, http_method, audience)

    def get_token_endpoint(self) -> str:
        """Get the OAuth2 token endpoint URL synchronously.

        Retrieves the token endpoint from the OIDC discovery document.

        Returns:
            The token endpoint URL.
        """
        return self.authentication.get_token_endpoint()

    async def get_token_endpoint_async(self) -> str:
        """Get the OAuth2 token endpoint URL asynchronously.

        Returns:
            The token endpoint URL.
        """
        return await self.authentication.get_token_endpoint_async()

    def clear_cache(self) -> None:
        """Clear all cached data (JWKS, token endpoint, ...).

        Useful for testing or when you need to force a fresh discovery on the
        next validation call.
        """
        self.memory_cache.clear()

    async def close(self) -> None:
        """Close the underlying HTTP clients and release resources.

        Should be called when the validator is no longer needed, especially
        for async operations.  When custom HTTP clients were injected, this
        method is a no-op.
        """
        if self._http_async_client is not None:
            await self._http_async_client.aclose()
        if self._http_client is not None:
            self._http_client.close()

    def close_sync(self) -> None:
        """Close the synchronous HTTP client.

        Should be called when the validator is no longer needed for sync-only
        operations.
        """
        if self._http_client is not None:
            self._http_client.close()

    async def __aenter__(self) -> "OidcValidator":
        """Async context manager entry.

        Returns:
            The :class:`OidcValidator` instance.
        """
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit, closing internally managed HTTP clients."""
        await self.close()

    def __enter__(self) -> "OidcValidator":
        """Sync context manager entry.

        Returns:
            The :class:`OidcValidator` instance.
        """
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Sync context manager exit, closing internally managed HTTP clients."""
        self.close_sync()
