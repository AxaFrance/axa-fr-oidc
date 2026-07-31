"""OpenID Connect client for obtaining and exchanging access tokens."""

import abc
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt  # PyJWT
import requests
from requests_oauth2client import BearerToken, ClientSecretBasic, IdToken, InvalidClient, OAuth2Client

from axa_fr_oidc.constants import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    CLIENT_SECRET_AUTH_METHOD_BASIC,
    CLIENT_SECRET_AUTH_METHOD_JWT,
    CLIENT_SECRET_AUTH_METHOD_POST,
    CONTENT_TYPE_FORM_URLENCODED,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_JWT_CLIENTSECRET_ALGORITHM,
    DEFAULT_JWT_EXPIRATION_SECONDS,
    DEFAULT_TOKEN_EXPIRATION_MARGIN_SECONDS,
    GRANT_TYPE_CLIENT_CREDENTIALS,
)
from axa_fr_oidc.memory_cache.memory_cache import IMemoryCache
from axa_fr_oidc.oidc.oidc_authentication import AuthenticationResult, IOidcAuthentication


@dataclass(frozen=True)
class _ClientSecretAccessTokenResult:
    """Access token with the client-secret authentication method that produced it."""

    access_token: str
    auth_method: str


def _get_private_key_access_token(
    token_endpoint: str,
    client_id: str,
    private_key_pem: str,
    scopes: list[str],
    algorithm: str = DEFAULT_JWT_ALGORITHM,
) -> str:
    """Get an access token using private key JWT authentication.

    Args:
        token_endpoint: The OAuth2 token endpoint URL.
        client_id: The client identifier.
        private_key_pem: The PEM-encoded private key for signing.
        scopes: The list of scopes to request.
        algorithm: The JWT signing algorithm to use.

    Returns:
        The access token string.

    Raises:
        HTTPError: If the token request fails.
    """
    # Build JWT client assertion
    now = int(time.time())

    # Use a UUID4 for ``jti`` to guarantee uniqueness even when multiple
    # assertions are generated within the same second (RFC 7523 §3).
    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + DEFAULT_JWT_EXPIRATION_SECONDS,
    }

    client_assertion = jwt.encode(
        payload,
        private_key_pem,
        algorithm=algorithm,
    )

    response = requests.post(
        token_endpoint,
        data={
            "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
            "scope": " ".join(scopes),
            "client_id": client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
            "client_assertion": client_assertion,
        },
        headers={"Content-Type": CONTENT_TYPE_FORM_URLENCODED},
        timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
    )

    response.raise_for_status()
    token_response = response.json()
    return token_response["access_token"]  # type: ignore[no-any-return]


def _get_client_secret_access_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    scopes: list[str],
    auth_method: str = CLIENT_SECRET_AUTH_METHOD_JWT,
    algorithm: str = DEFAULT_JWT_CLIENTSECRET_ALGORITHM,
) -> str:
    """Get an access token using client secret authentication.

    Supports three auth methods defined by the OAuth2 spec:

    - ``client_secret_jwt``: Signs a JWT assertion with the secret (HS256).
      Most secure; requires the AS to have this method enabled for the client.
    - ``client_secret_post``: Sends ``client_id`` and ``client_secret`` in the
      POST body.  Broadly supported by all OAuth2 servers.
    - ``client_secret_basic``: Sends credentials as an HTTP Basic Auth header.
      Also broadly supported.

    If ``client_secret_jwt`` fails with a 401 the function automatically
    retries with ``client_secret_post`` so callers never need to know which
    method the AS actually supports.

    Args:
        token_endpoint: The OAuth2 token endpoint URL.
        client_id: The client identifier.
        client_secret: The client secret.
        scopes: The list of scopes to request.
        auth_method: One of ``"client_secret_jwt"``, ``"client_secret_post"``,
            or ``"client_secret_basic"``.  Defaults to ``"client_secret_jwt"``.
        algorithm: The HMAC algorithm used when ``auth_method`` is
            ``"client_secret_jwt"``.  Defaults to ``"HS256"``.

    Returns:
        The access token string.

    Raises:
        HTTPError: If the token request fails with the chosen (and fallback) method.
        ValueError: If an unsupported ``auth_method`` is supplied.
    """
    return _get_client_secret_access_token_result(
        token_endpoint,
        client_id,
        client_secret,
        scopes,
        auth_method,
        algorithm,
    ).access_token


def _get_client_secret_access_token_result(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    scopes: list[str],
    auth_method: str = CLIENT_SECRET_AUTH_METHOD_JWT,
    algorithm: str = DEFAULT_JWT_CLIENTSECRET_ALGORITHM,
) -> _ClientSecretAccessTokenResult:
    """Get an access token and the client-secret authentication method that succeeded."""
    scope_str = " ".join(scopes)

    if auth_method == CLIENT_SECRET_AUTH_METHOD_JWT:
        # Build a standards-compliant JWT assertion signed with the client
        # secret (RFC 7523 §2.2 / client_secret_jwt).
        now = int(time.time())
        # Use a UUID4 for ``jti`` to guarantee uniqueness even when multiple
        # assertions are generated within the same second (RFC 7523 §3).
        payload: dict[str, Any] = {
            "iss": client_id,
            "sub": client_id,
            "aud": token_endpoint,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + DEFAULT_JWT_EXPIRATION_SECONDS,
        }
        client_assertion = jwt.encode(payload, client_secret, algorithm=algorithm)

        response = requests.post(
            token_endpoint,
            data={
                "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
                "scope": scope_str,
                "client_id": client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion": client_assertion,
            },
            headers={"Content-Type": CONTENT_TYPE_FORM_URLENCODED},
            timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
        )

        # If the AS does not have client_secret_jwt enabled for this client it
        # returns 401.  Fall back transparently to client_secret_post.
        if response.status_code == 401:
            return _get_client_secret_access_token_result(
                token_endpoint,
                client_id,
                client_secret,
                scopes,
                auth_method=CLIENT_SECRET_AUTH_METHOD_POST,
            )

    elif auth_method == CLIENT_SECRET_AUTH_METHOD_POST:
        response = requests.post(
            token_endpoint,
            data={
                "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
                "scope": scope_str,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": CONTENT_TYPE_FORM_URLENCODED},
            timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
        )

    elif auth_method == CLIENT_SECRET_AUTH_METHOD_BASIC:
        response = requests.post(
            token_endpoint,
            data={
                "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
                "scope": scope_str,
            },
            auth=(client_id, client_secret),
            headers={"Content-Type": CONTENT_TYPE_FORM_URLENCODED},
            timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
        )

    else:
        raise ValueError(
            f"Unsupported auth_method '{auth_method}'. "
            f"Expected one of: '{CLIENT_SECRET_AUTH_METHOD_JWT}', "
            f"'{CLIENT_SECRET_AUTH_METHOD_POST}', '{CLIENT_SECRET_AUTH_METHOD_BASIC}'."
        )

    response.raise_for_status()
    token_response = response.json()
    return _ClientSecretAccessTokenResult(
        access_token=str(token_response["access_token"]),
        auth_method=auth_method,
    )


def _get_access_token(
    oauth2client: OAuth2Client,
    scopes: list[str],
) -> str:
    """Get an access token using OAuth2 client credentials flow.

    Args:
        oauth2client: The OAuth2Client instance to use.
        scopes: The list of scopes to request.

    Returns:
        str: The access token.

    """
    token = oauth2client.client_credentials(scope=scopes)
    return str(token.access_token)


class IOpenIdConnect(abc.ABC):
    """Abstract base class for OpenID Connect operations.

    This interface defines methods for obtaining and exchanging
    OAuth2/OIDC access tokens.
    """

    @abc.abstractmethod
    def get_access_token(self, force_renew_token: bool = False) -> str | None:
        """Get an access token synchronously.

        Args:
            force_renew_token: If True, bypass the cache and fetch a new token
                from the authorization server. Defaults to False.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        ...

    @abc.abstractmethod
    async def get_access_token_async(self, force_renew_token: bool = False) -> str | None:
        """Get an access token asynchronously.

        Args:
            force_renew_token: If True, bypass the cache and fetch a new token
                from the authorization server. Defaults to False.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        ...

    @abc.abstractmethod
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
        """Exchange a token for another token using OAuth2 Token Exchange.

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
        """
        ...


class OpenIdConnect(IOpenIdConnect):
    """OpenID Connect client implementation.

    This class provides methods to obtain access tokens using client credentials
    flow and to exchange tokens using OAuth2 Token Exchange.

    Attributes:
        client_id: The OAuth2 client identifier.
        client_secret: The client secret for authentication.
        private_key: The private key for asymmetric JWT-based authentication.
        algorithm: The JWT signing algorithm (only used for private key auth).
        auth_method: The client-secret authentication method to use.
            One of ``"client_secret_jwt"``, ``"client_secret_post"``, or
            ``"client_secret_basic"``.  When ``"client_secret_jwt"`` is used
            and the server returns 401, the function automatically falls back
            to ``"client_secret_post"`` and reuses it for later token renewals
            in the same instance.
        authentication: The OIDC authentication handler.
        memory_cache: Cache for storing tokens.
    """

    def __init__(
        self,
        authentication: IOidcAuthentication,
        memory_cache: IMemoryCache,
        client_id: str,
        client_secret: str | None = None,
        private_key: str | None = None,
        algorithm: str = DEFAULT_JWT_ALGORITHM,
        auth_method: str = CLIENT_SECRET_AUTH_METHOD_JWT,
        token_expiration_margin_seconds: int = DEFAULT_TOKEN_EXPIRATION_MARGIN_SECONDS,
    ) -> None:
        """Initialize the OpenID Connect client.

        Args:
            authentication: The OIDC authentication handler for token validation.
            memory_cache: Cache instance for storing tokens.
            client_id: The OAuth2 client identifier.
            client_secret: The client secret, or None for private key auth.
            private_key: The PEM-encoded private key, or None for secret auth.
            algorithm: The JWT signing algorithm for private key auth only.
                Ignored when using client_secret (always HS256 for JWT method).
            auth_method: The authentication method to use with ``client_secret``.
                One of ``"client_secret_jwt"`` (default), ``"client_secret_post"``,
                or ``"client_secret_basic"``. A successful fallback from
                ``"client_secret_jwt"`` to ``"client_secret_post"`` becomes the
                effective method for later token renewals in the same instance.
            token_expiration_margin_seconds: Number of seconds before the JWT
                ``exp`` claim when a cached access token is considered expired.
                Defaults to 90 seconds. Set to 0 to disable early expiration.

        Raises:
            ValueError: If credential configuration is invalid or
                token_expiration_margin_seconds is negative.
        """
        if client_secret is None and private_key is None:
            raise ValueError("Either client_secret or private_key must be provided for token retrieval operations.")
        if client_secret is not None and private_key is not None:
            raise ValueError("Both client_secret and private_key cannot be provided at the same time.")
        if token_expiration_margin_seconds < 0:
            raise ValueError("token_expiration_margin_seconds must be greater than or equal to 0.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.algorithm = algorithm
        self.auth_method = auth_method
        self.token_expiration_margin_seconds = token_expiration_margin_seconds

        self.authentication = authentication
        self.memory_cache = memory_cache
        self._oauth2client: OAuth2Client | None = None
        self._oauth2client_cache_key: tuple[str, str] | None = None

    def _get_oauth2_client_auth(self) -> str | ClientSecretBasic:
        """Build the OAuth2Client auth handler used by token-exchange requests."""
        if self.client_secret is None:
            return self.client_id

        if self.auth_method in {CLIENT_SECRET_AUTH_METHOD_JWT, CLIENT_SECRET_AUTH_METHOD_POST}:
            return self.client_id

        if self.auth_method == CLIENT_SECRET_AUTH_METHOD_BASIC:
            return ClientSecretBasic(self.client_id, self.client_secret)

        raise ValueError(
            f"Unsupported auth_method '{self.auth_method}'. "
            f"Expected one of: '{CLIENT_SECRET_AUTH_METHOD_JWT}', "
            f"'{CLIENT_SECRET_AUTH_METHOD_POST}', '{CLIENT_SECRET_AUTH_METHOD_BASIC}'."
        )

    def _get_oauth2_client(self) -> OAuth2Client:
        """Get or create a shared OAuth2Client instance.

        Returns:
            OAuth2Client: A configured OAuth2Client instance for this OpenIdConnect instance.

        """
        token_endpoint = self.authentication.get_token_endpoint()
        cache_key = (token_endpoint, self.auth_method if self.client_secret is not None else "private_key")

        if self._oauth2client is None or self._oauth2client_cache_key != cache_key:
            self._oauth2client = OAuth2Client(
                token_endpoint=token_endpoint,
                auth=self._get_oauth2_client_auth(),
            )
            self._oauth2client_cache_key = cache_key
        return self._oauth2client

    @staticmethod
    def _build_client_assertion(
        token_endpoint: str,
        client_id: str,
        signing_key: str,
        algorithm: str,
    ) -> str:
        """Build an RFC 7523 JWT client assertion for token endpoint auth."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": client_id,
            "sub": client_id,
            "aud": token_endpoint,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + DEFAULT_JWT_EXPIRATION_SECONDS,
        }
        return str(jwt.encode(payload, signing_key, algorithm=algorithm))

    def _build_token_exchange_auth_kwargs(self, token_endpoint: str) -> dict[str, Any]:
        """Build auth-related token-exchange parameters from configured client auth."""
        if self.private_key is not None:
            return {
                "client_id": self.client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion": self._build_client_assertion(
                    token_endpoint,
                    self.client_id,
                    self.private_key,
                    self.algorithm,
                ),
            }

        if self.client_secret is None:
            raise ValueError("Either client_secret or private_key must be provided.")

        if self.auth_method == CLIENT_SECRET_AUTH_METHOD_JWT:
            return {
                "client_id": self.client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion": self._build_client_assertion(
                    token_endpoint,
                    self.client_id,
                    self.client_secret,
                    DEFAULT_JWT_CLIENTSECRET_ALGORITHM,
                ),
            }

        if self.auth_method == CLIENT_SECRET_AUTH_METHOD_POST:
            return {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }

        if self.auth_method == CLIENT_SECRET_AUTH_METHOD_BASIC:
            return {}

        raise ValueError(
            f"Unsupported auth_method '{self.auth_method}'. "
            f"Expected one of: '{CLIENT_SECRET_AUTH_METHOD_JWT}', "
            f"'{CLIENT_SECRET_AUTH_METHOD_POST}', '{CLIENT_SECRET_AUTH_METHOD_BASIC}'."
        )

    def _build_token_exchange_request_kwargs(
        self,
        token_endpoint: str,
        token_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Build token-exchange request parameters without mutating caller-provided kwargs."""
        request_token_kwargs = dict(token_kwargs)
        auth_kwargs = self._build_token_exchange_auth_kwargs(token_endpoint)
        for key, value in auth_kwargs.items():
            request_token_kwargs.setdefault(key, value)
        return request_token_kwargs

    def _get_cache_key(self, token_endpoint: str) -> tuple[str, ...]:
        """Build a deterministic key for the token request and validation context."""
        audience = self.authentication.api_audience or ""
        scopes = sorted(set(self.authentication.get_scopes()))
        return ("oidc-v2", token_endpoint, self.client_id, audience, *scopes)

    def _get_token_cache_ttl_ms(self, validation_result: AuthenticationResult) -> int | None:
        """Calculate cache lifetime from a validated token's expiration.

        Args:
            validation_result: Successful token validation result.

        Returns:
            The remaining cache lifetime in milliseconds, zero when the token
            is inside the early-expiration window, or None when no usable
            numeric ``exp`` claim is available.
        """
        payload = validation_result.payload
        expiration = payload.get("exp") if payload is not None else None
        if not isinstance(expiration, (int, float)) or isinstance(expiration, bool) or not math.isfinite(expiration):
            return None

        remaining_seconds = expiration - time.time() - self.token_expiration_margin_seconds
        return max(int(remaining_seconds * 1000), 0)

    def _get_token(self, token_endpoint: str, force_renew_token: bool = False) -> str | None:
        """Get a valid access token, using cache if available.

        Args:
            token_endpoint: The OAuth2 token endpoint URL.
            force_renew_token: If True, bypass the cache and fetch a new token.

        Returns:
            The access token string, or None if token acquisition or validation fails.
        """
        cache_key = self._get_cache_key(token_endpoint)

        if not force_renew_token:
            access_token_cached: Any = self.memory_cache.get(cache_key)

            if access_token_cached is not None:
                validation_result = self.authentication.validate(str(access_token_cached), None)

                if validation_result.success:
                    ttl_ms = self._get_token_cache_ttl_ms(validation_result)
                    if ttl_ms is None or ttl_ms > 0:
                        return str(access_token_cached)
                self.memory_cache.delete(cache_key)

        access_token: str
        if self.private_key is not None:
            access_token = _get_private_key_access_token(
                token_endpoint,
                self.client_id,
                self.private_key,
                self.authentication.get_scopes(),
                self.algorithm,
            )
        elif self.client_secret is not None:
            token_result = _get_client_secret_access_token_result(
                token_endpoint,
                self.client_id,
                self.client_secret,
                self.authentication.get_scopes(),
                auth_method=self.auth_method,
            )
            access_token = token_result.access_token
            self.auth_method = token_result.auth_method
        else:
            raise ValueError("Either client_secret or private_key must be provided.")

        validation_result = self.authentication.validate(access_token, None)

        if validation_result.success:
            ttl_ms = self._get_token_cache_ttl_ms(validation_result)
            if ttl_ms == 0:
                return None
            if ttl_ms is None:
                self.memory_cache.set(cache_key, access_token)
            else:
                self.memory_cache.set(cache_key, access_token, ttl_ms=ttl_ms)

            return access_token

        return None

    def get_access_token(self, force_renew_token: bool = False) -> str | None:
        """Get an access token synchronously.

        Args:
            force_renew_token: If True, bypass the cache and fetch a new token
                from the authorization server. Defaults to False.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        token_endpoint = self.authentication.get_token_endpoint()

        return self._get_token(token_endpoint, force_renew_token)

    async def get_access_token_async(self, force_renew_token: bool = False) -> str | None:
        """Get an access token asynchronously.

        Args:
            force_renew_token: If True, bypass the cache and fetch a new token
                from the authorization server. Defaults to False.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        token_endpoint = await self.authentication.get_token_endpoint_async()

        return self._get_token(token_endpoint, force_renew_token)

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
        """Exchange a token for another token using OAuth2 Token Exchange.

        This method wraps the OAuth2Client.token_exchange() method to allow token exchange
        operations. Token Exchange (RFC 8693) allows clients to exchange one token for another,
        which is useful for scenarios like service-to-service authentication, token delegation,
        and impersonation.

        When ``client_secret_jwt`` is configured and the authorization server
        rejects that method with a 401 ``invalid_client`` response, this method
        falls back to ``client_secret_post`` and reuses it for later calls in the
        same instance.

        Args:
            subject_token: The subject token to exchange for a new token. Can be a string,
                BearerToken, or IdToken.
            subject_token_type: A token type identifier for the subject_token. If None,
                the type will be inferred from the token object type.
            actor_token: The actor token to include in the request, if any. Can be a string,
                BearerToken, IdToken, or None.
            actor_token_type: A token type identifier for the actor_token. If None,
                the type will be inferred from the token object type.
            requested_token_type: A token type identifier for the requested token.
            requests_kwargs: Additional parameters to pass to the underlying requests.post() call.
            **token_kwargs: Additional parameters to include in the token exchange request body.

        Returns:
            A BearerToken containing the exchanged token.

        Raises:
            UnknownSubjectTokenType: If the type of subject_token cannot be determined automatically.
            UnknownActorTokenType: If the type of actor_token cannot be determined automatically.
            InvalidClient: If client authentication fails without an applicable fallback.

        Example:
            ```python
            # Exchange an access token for a new token with different scope
            new_token = client.token_exchange(
                subject_token=current_access_token,
                requested_token_type="urn:ietf:params:oauth:token-type:access_token",
                scope="new_scope"
            )
            ```

        """
        token_endpoint = self.authentication.get_token_endpoint()

        try:
            return self._token_exchange_with_current_auth(
                token_endpoint=token_endpoint,
                subject_token=subject_token,
                subject_token_type=subject_token_type,
                actor_token=actor_token,
                actor_token_type=actor_token_type,
                requested_token_type=requested_token_type,
                requests_kwargs=requests_kwargs,
                token_kwargs=token_kwargs,
            )
        except InvalidClient as exc:
            if (
                self.client_secret is None
                or self.auth_method != CLIENT_SECRET_AUTH_METHOD_JWT
                or exc.response.status_code != 401
            ):
                raise

            self.auth_method = CLIENT_SECRET_AUTH_METHOD_POST
            return self._token_exchange_with_current_auth(
                token_endpoint=token_endpoint,
                subject_token=subject_token,
                subject_token_type=subject_token_type,
                actor_token=actor_token,
                actor_token_type=actor_token_type,
                requested_token_type=requested_token_type,
                requests_kwargs=requests_kwargs,
                token_kwargs=token_kwargs,
            )

    def _token_exchange_with_current_auth(
        self,
        token_endpoint: str,
        subject_token: str | BearerToken | IdToken,
        subject_token_type: str | None,
        actor_token: str | BearerToken | IdToken | None,
        actor_token_type: str | None,
        requested_token_type: str | None,
        requests_kwargs: dict[str, Any] | None,
        token_kwargs: dict[str, Any],
    ) -> BearerToken:
        """Exchange a token using the current client authentication method."""
        oauth2client = self._get_oauth2_client()
        request_token_kwargs = self._build_token_exchange_request_kwargs(token_endpoint, token_kwargs)

        return oauth2client.token_exchange(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
            requests_kwargs=requests_kwargs,
            **request_token_kwargs,
        )
