"""OpenID Connect client for obtaining and exchanging access tokens."""

import abc
import time
from typing import Any

import jwt  # PyJWT
import requests
from requests_oauth2client import BearerToken, IdToken, OAuth2Client

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
    GRANT_TYPE_CLIENT_CREDENTIALS,
)
from axa_fr_oidc.memory_cache.memory_cache import IMemoryCache
from axa_fr_oidc.oidc.oidc_authentication import IOidcAuthentication


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

    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "jti": str(now),
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
    scope_str = " ".join(scopes)

    if auth_method == CLIENT_SECRET_AUTH_METHOD_JWT:
        # Build a standards-compliant JWT assertion signed with the client
        # secret (RFC 7523 §2.2 / client_secret_jwt).
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": client_id,
            "sub": client_id,
            "aud": token_endpoint,
            "jti": str(now),
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
            return _get_client_secret_access_token(
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
    return token_response["access_token"]  # type: ignore[no-any-return]


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
    def get_access_token_raw(self) -> str:
        """Get an access token without post-fetch validation.

        Returns:
            The access token string.
        """
        ...

    @abc.abstractmethod
    def get_access_token(self) -> str | None:
        """Get an access token synchronously.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        ...

    @abc.abstractmethod
    async def get_access_token_async(self) -> str | None:
        """Get an access token asynchronously.

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
            to ``"client_secret_post"``.
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
                or ``"client_secret_basic"``.

        Raises:
            ValueError: If neither client_secret nor private_key is provided, or if both are provided
        """
        if client_secret is None and private_key is None:
            raise ValueError("Either client_secret or private_key must be provided for token retrieval operations.")
        if client_secret is not None and private_key is not None:
            raise ValueError("Both client_secret and private_key cannot be provided at the same time.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.algorithm = algorithm
        self.auth_method = auth_method

        self.authentication = authentication
        self.memory_cache = memory_cache
        self._oauth2client: OAuth2Client | None = None

    def _get_oauth2_client(self) -> OAuth2Client:
        """Get or create a shared OAuth2Client instance.

        Returns:
            OAuth2Client: A configured OAuth2Client instance for this OpenIdConnect instance.

        """
        if self._oauth2client is None:
            token_endpoint = self.authentication.get_token_endpoint()
            self._oauth2client = OAuth2Client(
                token_endpoint=token_endpoint,
                auth=(self.client_id, self.client_secret) if self.client_secret else self.client_id,
            )
        return self._oauth2client

    def _get_token(self, token_endpoint: str) -> str | None:
        """Get a valid access token, using cache if available.

        Args:
            token_endpoint: The OAuth2 token endpoint URL.

        Returns:
            The access token string, or None if token acquisition or validation fails.
        """
        access_token_cached: Any = self.memory_cache.get(("oidc", self.client_id))

        if access_token_cached is not None:
            validation_result = self.authentication.validate(str(access_token_cached), None)

            if validation_result.success:
                return str(access_token_cached)

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
            access_token = _get_client_secret_access_token(
                token_endpoint,
                self.client_id,
                self.client_secret,
                self.authentication.get_scopes(),
                auth_method=self.auth_method,
            )

        validation_result = self.authentication.validate(access_token, None)

        if validation_result.success:
            self.memory_cache.set(("oidc", self.client_id), access_token)

            return access_token

        return None

    def get_access_token_raw(self) -> str:
        """Get an access token without post-fetch validation.

        Returns:
            The access token string.

        Raises:
            HTTPError: If the token request fails.
        """
        token_endpoint = self.authentication.get_token_endpoint()

        if self.private_key is not None:
            return _get_private_key_access_token(
                token_endpoint,
                self.client_id,
                self.private_key,
                self.authentication.get_scopes(),
                self.algorithm,
            )
        if self.client_secret is not None:
            return _get_client_secret_access_token(
                token_endpoint,
                self.client_id,
                self.client_secret,
                self.authentication.get_scopes(),
                auth_method=self.auth_method,
            )
        raise ValueError("Either client_secret or private_key must be provided.")

    def get_access_token(self) -> str | None:
        """Get an access token synchronously.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        token_endpoint = self.authentication.get_token_endpoint()

        return self._get_token(token_endpoint)

    async def get_access_token_async(self) -> str | None:
        """Get an access token asynchronously.

        Returns:
            The access token string, or None if token acquisition fails.
        """
        token_endpoint = await self.authentication.get_token_endpoint_async()

        return self._get_token(token_endpoint)

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
        oauth2client = self._get_oauth2_client()

        return oauth2client.token_exchange(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
            requests_kwargs=requests_kwargs,
            **token_kwargs,
        )
