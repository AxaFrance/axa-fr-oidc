"""High-level OIDC client with simplified API.

This module provides a simplified interface for common OIDC operations,
reducing boilerplate code while still allowing customization when needed.
"""

from typing import Any

from httpx import AsyncClient, Client
from requests_oauth2client import BearerToken, IdToken

from axa_fr_oidc.constants import (
    CLIENT_SECRET_AUTH_METHOD_JWT,
    DEFAULT_JWT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
)
from axa_fr_oidc.http_service import IHttpServiceGet, XHttpServiceGet
from axa_fr_oidc.memory_cache import IMemoryCache, MemoryCache
from axa_fr_oidc.oidc import (
    AuthenticationResult,
    IOidcAuthentication,
    IOpenIdConnect,
    OidcAuthentication,
    OpenIdConnect,
)


class OidcClient:
    """Simplified OIDC client for common authentication operations.

    This class provides a high-level, easy-to-use interface for OIDC
    authentication, token retrieval, and validation. It creates and manages
    all required dependencies internally while still allowing customization.

    Example:
        Basic usage with client credentials:

        >>> client = OidcClient(
        ...     issuer="https://auth.example.com",
        ...     client_id="my-client-id",
        ...     client_secret="my-client-secret",
        ... )
        >>> token = client.get_access_token()

        With private key authentication:

        >>> client = OidcClient(
        ...     issuer="https://auth.example.com",
        ...     client_id="my-client-id",
        ...     private_key=private_key_pem,
        ...     algorithm="RS256",
        ... )
        >>> token = client.get_access_token()

        Async usage:

        >>> token = await client.get_access_token_async()

        Token validation:

        >>> result = client.validate_token(access_token)
        >>> if result.success:
        ...     print("Token is valid!")

    Attributes:
        issuer: The OIDC issuer URL.
        client_id: The OAuth2 client identifier.
        scopes: List of OAuth2 scopes to request.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        private_key: str | None = None,
        scopes: list[str] | None = None,
        audience: str | None = None,
        algorithm: str = DEFAULT_JWT_ALGORITHM,
        algorithms: list[str] | None = None,
        auth_method: str = CLIENT_SECRET_AUTH_METHOD_JWT,
        http_service: IHttpServiceGet | None = None,
        memory_cache: IMemoryCache | None = None,
        proxy: str | None = None,
        verify: bool = True,
        timeout: float | None = None,
        token_endpoint: str | None = None,
    ) -> None:
        """Initialize the OIDC client.

        Args:
            issuer: The OIDC issuer URL (e.g., "https://auth.example.com").
            client_id: The OAuth2 client identifier.
            client_secret: The client secret for client credentials flow.
                Either client_secret or private_key must be provided for
                token retrieval.
            private_key: PEM-encoded private key for JWT-based authentication.
                Either client_secret or private_key must be provided for
                token retrieval.
            scopes: List of OAuth2 scopes to request. Defaults to ["openid"].
            audience: The expected audience claim for token validation.
                If None, audience validation is skipped.
            algorithm: The JWT signing algorithm for private key auth.
                Defaults to "RS256".
            algorithms: List of allowed algorithms for token validation.
                Defaults to SUPPORTED_ALGORITHMS.
            auth_method: The authentication method to use with ``client_secret``.
                One of ``"client_secret_jwt"`` (default), ``"client_secret_post"``,
                or ``"client_secret_basic"``.  When ``"client_secret_jwt"`` is
                used and the server returns 401, the library automatically falls
                back to ``"client_secret_post"``.
            http_service: Custom HTTP service for requests. If None, a default
                httpx-based service is created.
            memory_cache: Custom cache implementation. If None, a default
                in-memory cache is created.
            proxy: Proxy URL where all traffic should be routed. Supports both
                HTTP and HTTPS proxies (e.g., "http://proxy.example.com:8080").
                For authenticated proxies, include credentials in the URL
                (e.g., "http://user:pass@proxy.example.com:8080"). Defaults to
                None (no proxy).
            verify: Whether to verify SSL certificates. Defaults to True.
            timeout: Timeout in seconds for HTTP requests. Defaults to None
                (no timeout).
            token_endpoint: Explicit token endpoint URL. When provided, skips
                OIDC discovery for the token endpoint. Defaults to None
                (auto-discover from issuer).
        """
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.scopes = scopes or ["openid"]
        self.audience = audience
        self.algorithm = algorithm
        self.algorithms = algorithms or SUPPORTED_ALGORITHMS
        self.auth_method = auth_method
        self.proxy = proxy
        self.verify = verify
        self.timeout = timeout
        self.token_endpoint = token_endpoint

        # Lazy initialization for HTTP clients
        self._http_client: Client | None = None
        self._http_async_client: AsyncClient | None = None
        self._http_service = http_service
        self._memory_cache = memory_cache

        # Lazy initialization for internal components
        self._authentication: IOidcAuthentication | None = None
        self._openid_connect: IOpenIdConnect | None = None

    @property
    def http_service(self) -> IHttpServiceGet:
        """Get or create the HTTP service.

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
        """Get or create the memory cache.

        Returns:
            The memory cache instance.
        """
        if self._memory_cache is None:
            self._memory_cache = MemoryCache()
        return self._memory_cache

    @property
    def authentication(self) -> IOidcAuthentication:
        """Get or create the OIDC authentication handler.

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
                token_endpoint=self.token_endpoint,
            )
        return self._authentication

    @property
    def openid_connect(self) -> IOpenIdConnect:
        """Get or create the OpenID Connect client.

        Returns:
            The OpenID Connect instance.

        Raises:
            ValueError: If neither client_secret nor private_key is provided, or if both are provided.
        """
        if self._openid_connect is None:
            if self.client_secret is None and self.private_key is None:
                raise ValueError("Either client_secret or private_key must be provided for token retrieval operations.")
            if self.client_secret is not None and self.private_key is not None:
                raise ValueError("Both client_secret and private_key cannot be provided at the same time.")
            self._openid_connect = OpenIdConnect(
                authentication=self.authentication,
                memory_cache=self.memory_cache,
                client_id=self.client_id,
                client_secret=self.client_secret,
                private_key=self.private_key,
                algorithm=self.algorithm,
                auth_method=self.auth_method,
            )
        return self._openid_connect

    def get_access_token(self) -> str:
        """Get an access token synchronously.

        Uses client credentials flow with either client_secret or private_key
        authentication.

        Returns:
            The access token string.

        Raises:
            ValueError: If neither client_secret nor private_key is provided.
            HTTPError: If the token request fails.

        Example:
            >>> client = OidcClient(
            ...     issuer="https://auth.example.com",
            ...     client_id="my-client",
            ...     client_secret="my-secret",
            ... )
            >>> token = client.get_access_token()
        """
        return self.openid_connect.get_access_token()

    async def get_access_token_async(self) -> str:
        """Get an access token asynchronously.

        Uses client credentials flow with either client_secret or private_key
        authentication.

        Returns:
            The access token string.

        Raises:
            ValueError: If neither client_secret nor private_key is provided.
            HTTPError: If the token request fails.

        Example:
            >>> client = OidcClient(
            ...     issuer="https://auth.example.com",
            ...     client_id="my-client",
            ...     client_secret="my-secret",
            ... )
            >>> token = await client.get_access_token_async()
        """
        return await self.openid_connect.get_access_token_async()

    def validate_token(
        self,
        token: str,
        dpop: str | None = None,
        path: str | None = None,
        http_method: str | None = None,
        audience: str | None = None,
    ) -> AuthenticationResult:
        """Validate an access token synchronously.

        Validates the token signature, expiration, issuer, and optionally
        the DPoP proof if provided.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT for DPoP-bound tokens, or None.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.
            audience: Override the audience for this validation call.
                If provided, takes precedence over the audience set at
                construction time. If None, falls back to the constructor
                audience (which may also be None to skip audience validation).

        Returns:
            AuthenticationResult indicating success or failure with details.

        Example:
            >>> result = client.validate_token(access_token)
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

        Validates the token signature, expiration, issuer, and optionally
        the DPoP proof if provided.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT for DPoP-bound tokens, or None.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.
            audience: Override the audience for this validation call.
                If provided, takes precedence over the audience set at
                construction time. If None, falls back to the constructor
                audience (which may also be None to skip audience validation).

        Returns:
            AuthenticationResult indicating success or failure with details.

        Example:
            >>> result = await client.validate_token_async(access_token)
            >>> if result.success:
            ...     print(f"Valid! Subject: {result.payload['sub']}")
        """
        return await self.authentication.validate_async(token, dpop, path, http_method, audience)

    def token_exchange(
        self,
        subject_token: str | BearerToken | IdToken,
        subject_token_type: str | None = None,
        actor_token: str | BearerToken | IdToken | None = None,
        actor_token_type: str | None = None,
        requested_token_type: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Exchange a token for another token.

        Implements OAuth2 Token Exchange (RFC 8693) for scenarios like
        impersonation or delegation.

        Args:
            subject_token: The subject token to exchange.
            subject_token_type: Token type identifier for the subject_token.
            actor_token: The actor token to include, if any.
            actor_token_type: Token type identifier for the actor_token.
            requested_token_type: Token type identifier for the requested token.
            requests_kwargs: Additional parameters for the HTTP request.
            **token_kwargs: Additional token exchange request parameters.

        Returns:
            A BearerToken containing the exchanged token.

        Example:
            >>> new_token = client.token_exchange(
            ...     subject_token=user_token,
            ...     requested_token_type="urn:ietf:params:oauth:token-type:access_token",
            ... )
        """
        return self.openid_connect.token_exchange(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
            requests_kwargs=requests_kwargs,
            **token_kwargs,
        )

    def get_token_endpoint(self) -> str:
        """Get the OAuth2 token endpoint URL.

        Retrieves the token endpoint from the OIDC discovery document.

        Returns:
            The token endpoint URL.

        Example:
            >>> endpoint = client.get_token_endpoint()
            >>> print(endpoint)
            'https://auth.example.com/oauth/token'
        """
        return self.authentication.get_token_endpoint()

    async def get_token_endpoint_async(self) -> str:
        """Get the OAuth2 token endpoint URL asynchronously.

        Retrieves the token endpoint from the OIDC discovery document.

        Returns:
            The token endpoint URL.
        """
        return await self.authentication.get_token_endpoint_async()

    def clear_cache(self) -> None:
        """Clear all cached data.

        Removes all cached tokens, JWKS, and other cached data.
        Useful for testing or when you need to force token refresh.

        Example:
            >>> client.clear_cache()
        """
        self.memory_cache.clear()

    async def close(self) -> None:
        """Close the HTTP clients and release resources.

        Should be called when the client is no longer needed,
        especially for async operations.

        Example:
            >>> await client.close()
        """
        if self._http_async_client is not None:
            await self._http_async_client.aclose()
        if self._http_client is not None:
            self._http_client.close()

    def close_sync(self) -> None:
        """Close the synchronous HTTP client.

        Should be called when the client is no longer needed
        for sync-only operations.

        Example:
            >>> client.close_sync()
        """
        if self._http_client is not None:
            self._http_client.close()

    async def __aenter__(self) -> "OidcClient":
        """Async context manager entry.

        Returns:
            The OidcClient instance.

        Example:
            >>> async with OidcClient(...) as client:
            ...     token = await client.get_access_token_async()
        """
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    def __enter__(self) -> "OidcClient":
        """Context manager entry.

        Returns:
            The OidcClient instance.

        Example:
            >>> with OidcClient(...) as client:
            ...     token = client.get_access_token()
        """
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close_sync()
