"""Tests for the OidcClient high-level client module."""

import pytest
from requests_oauth2client import BearerToken

from axa_fr_oidc.client import OidcClient
from axa_fr_oidc.constants import DEFAULT_JWT_ALGORITHM, SUPPORTED_ALGORITHMS
from axa_fr_oidc.http_service import IHttpServiceGet
from axa_fr_oidc.memory_cache import IMemoryCache, MemoryCache
from axa_fr_oidc.oidc import AuthenticationResult


class FakeHttpService(IHttpServiceGet):
    """Fake HTTP service for testing."""

    def get(self, url: str) -> dict:
        """Return fake OIDC configuration."""
        if ".well-known/openid-configuration" in url:
            return {
                "issuer": "https://test.issuer.com",
                "token_endpoint": "https://test.issuer.com/oauth/token",
                "jwks_uri": "https://test.issuer.com/.well-known/jwks.json",
            }
        if "jwks" in url:
            return {"keys": []}
        return {}

    async def get_async(self, url: str) -> dict:
        """Return fake OIDC configuration asynchronously."""
        return self.get(url)


class TestOidcClientInitialization:
    """Tests for OidcClient initialization."""

    def test_init_with_client_secret(self):
        """Test initialization with client secret."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
        )

        assert client.issuer == "https://test.issuer.com"
        assert client.client_id == "test-client-id"
        assert client.client_secret == "test-secret"
        assert client.private_key is None
        assert client.scopes == ["openid"]
        assert client.algorithm == DEFAULT_JWT_ALGORITHM
        assert client.algorithms == SUPPORTED_ALGORITHMS

    def test_init_with_private_key(self, fake_private_key_pem):
        """Test initialization with private key."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            private_key=fake_private_key_pem,
            algorithm="RS256",
        )

        assert client.issuer == "https://test.issuer.com"
        assert client.client_id == "test-client-id"
        assert client.client_secret is None
        assert client.private_key == fake_private_key_pem
        assert client.algorithm == "RS256"

    def test_init_with_custom_options(self):
        """Test initialization with custom options."""
        custom_scopes = ["openid", "profile", "email"]
        custom_algorithms = ["RS256", "ES256"]

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            scopes=custom_scopes,
            audience="test-audience",
            algorithms=custom_algorithms,
        )

        assert client.scopes == custom_scopes
        assert client.audience == "test-audience"
        assert client.algorithms == custom_algorithms

    def test_init_with_custom_dependencies(self):
        """Test initialization with custom HTTP service and cache."""
        custom_http_service = FakeHttpService()
        custom_cache = MemoryCache()

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=custom_http_service,
            memory_cache=custom_cache,
        )

        assert client.http_service is custom_http_service
        assert client.memory_cache is custom_cache

    def test_init_with_proxy_string(self):
        """Test initialization with proxy as string."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            proxy="http://proxy.example.com:8080",
        )

        assert client.proxy == "http://proxy.example.com:8080"

    def test_init_with_verify_false(self):
        """Test initialization with SSL verification disabled."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            verify=False,
        )

        assert client.verify is False

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            timeout=30.0,
        )

        assert client.timeout == 30.0

    def test_init_with_all_http_options(self):
        """Test initialization with all HTTP configuration options."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            proxy="http://proxy.example.com:8080",
            verify=False,
            timeout=15.0,
        )

        assert client.proxy == "http://proxy.example.com:8080"
        assert client.verify is False
        assert client.timeout == 15.0


class TestOidcClientProperties:
    """Tests for OidcClient lazy-loaded properties."""

    def test_http_service_lazy_creation(self):
        """Test that HTTP service is lazily created."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
        )

        # Initially no HTTP client
        assert client._http_client is None
        assert client._http_async_client is None

        # Access http_service to trigger creation
        http_service = client.http_service

        assert http_service is not None
        assert client._http_client is not None
        assert client._http_async_client is not None

        # Clean up
        client.close_sync()

    def test_memory_cache_lazy_creation(self):
        """Test that memory cache is lazily created."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
        )

        # Initially no cache
        assert client._memory_cache is None

        # Access memory_cache to trigger creation
        cache = client.memory_cache

        assert cache is not None
        assert isinstance(cache, IMemoryCache)

    def test_authentication_lazy_creation(self):
        """Test that authentication handler is lazily created."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Initially no authentication
        assert client._authentication is None

        # Access authentication to trigger creation
        auth = client.authentication

        assert auth is not None
        assert client._authentication is auth

        # Second access returns same instance
        assert client.authentication is auth

    def test_openid_connect_lazy_creation(self):
        """Test that OpenID Connect client is lazily created."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Initially no OpenID Connect
        assert client._openid_connect is None

        # Access openid_connect to trigger creation
        oidc = client.openid_connect

        assert oidc is not None
        assert client._openid_connect is oidc

        # Second access returns same instance
        assert client.openid_connect is oidc

    def test_openid_connect_raises_without_credentials(self):
        """Test that accessing openid_connect raises error without credentials."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            # No client_secret or private_key
            http_service=FakeHttpService(),
        )

        with pytest.raises(ValueError, match="Either client_secret or private_key"):
            _ = client.openid_connect

    def test_http_service_with_proxy_configuration(self):
        """Test that HTTP clients are created with proxy configuration."""
        proxy = "http://proxy.example.com:8080"
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            proxy=proxy,
            verify=False,
            timeout=10.0,
        )

        # Access http_service to trigger creation
        _ = client.http_service

        # Verify HTTP clients are configured correctly
        assert client._http_client is not None
        assert client._http_async_client is not None

        # Clean up
        client.close_sync()

    def test_openid_connect_raises_with_both_credentials(self):
        """Test that accessing openid_connect raises error with both credentials."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            private_key="test-private-key",
            http_service=FakeHttpService(),
        )

        with pytest.raises(ValueError, match="Both client_secret and private_key"):
            _ = client.openid_connect

        # Clean up
        client.close_sync()


class TestOidcClientTokenOperations:
    """Tests for OidcClient token operations."""

    def test_get_access_token(self, mocker):
        """Test getting access token synchronously."""
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.get_access_token.return_value = "test-access-token"

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        token = client.get_access_token()

        assert token == "test-access-token"
        mock_openid_connect.get_access_token.assert_called_once_with(False)

    def test_get_access_token_force_refresh(self, mocker):
        """Test getting access token with force_renew_token=True."""
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.get_access_token.return_value = "fresh-token"

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        token = client.get_access_token(force_renew_token=True)

        assert token == "fresh-token"
        mock_openid_connect.get_access_token.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_get_access_token_async(self, mocker):
        """Test getting access token asynchronously."""
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.get_access_token_async = mocker.AsyncMock(return_value="test-access-token-async")

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        token = await client.get_access_token_async()

        assert token == "test-access-token-async"
        mock_openid_connect.get_access_token_async.assert_called_once_with(False)

    @pytest.mark.asyncio
    async def test_get_access_token_async_force_refresh(self, mocker):
        """Test getting access token asynchronously with force_renew_token=True."""
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.get_access_token_async = mocker.AsyncMock(return_value="fresh-async-token")

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        token = await client.get_access_token_async(force_renew_token=True)

        assert token == "fresh-async-token"
        mock_openid_connect.get_access_token_async.assert_called_once_with(True)

    def test_get_access_token_raises_without_credentials(self):
        """Test that get_access_token raises error without credentials."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        with pytest.raises(ValueError, match="Either client_secret or private_key"):
            client.get_access_token()


class TestOidcClientTokenValidation:
    """Tests for OidcClient token validation."""

    def test_validate_token(self, mocker):
        """Test validating token synchronously."""
        mock_result = AuthenticationResult(True, "", {"sub": "user123"})
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=mock_result,
        )

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        result = client.validate_token("test-token")

        assert result.success is True
        assert result.payload == {"sub": "user123"}

    @pytest.mark.asyncio
    async def test_validate_token_async(self, mocker):
        """Test validating token asynchronously."""
        mock_result = AuthenticationResult(True, "", {"sub": "user123"})
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate_async",
            return_value=mock_result,
        )

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        result = await client.validate_token_async("test-token")

        assert result.success is True
        assert result.payload == {"sub": "user123"}

    def test_validate_token_with_dpop(self, mocker):
        """Test validating DPoP-bound token."""
        mock_result = AuthenticationResult(True, "", {"sub": "user123", "cnf": {}})
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=mock_result,
        )

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        result = client.validate_token(
            token="test-token",
            dpop="dpop-proof",
            path="/api/resource",
            http_method="POST",
        )

        assert result.success is True


class TestOidcClientTokenEndpoint:
    """Tests for OidcClient token endpoint operations."""

    def test_get_token_endpoint(self):
        """Test getting token endpoint URL."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        endpoint = client.get_token_endpoint()

        assert endpoint == "https://test.issuer.com/oauth/token"

    @pytest.mark.asyncio
    async def test_get_token_endpoint_async(self):
        """Test getting token endpoint URL asynchronously."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        endpoint = await client.get_token_endpoint_async()

        assert endpoint == "https://test.issuer.com/oauth/token"


class TestOidcClientCacheOperations:
    """Tests for OidcClient cache operations."""

    def test_clear_cache(self):
        """Test clearing cache."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            http_service=FakeHttpService(),
        )

        # Add something to cache
        client.memory_cache.set("test-key", "test-value")
        assert client.memory_cache.get("test-key") == "test-value"

        # Clear cache
        client.clear_cache()

        assert client.memory_cache.get("test-key") is None


class TestOidcClientResourceManagement:
    """Tests for OidcClient resource management."""

    def test_close_sync(self):
        """Test synchronous close."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
        )

        # Trigger HTTP client creation
        _ = client.http_service
        assert client._http_client is not None

        # Close should not raise
        client.close_sync()

    @pytest.mark.asyncio
    async def test_close_async(self):
        """Test asynchronous close."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
        )

        # Trigger HTTP client creation
        _ = client.http_service
        assert client._http_async_client is not None

        # Close should not raise
        await client.close()

    def test_sync_context_manager(self, mocker):
        """Test using OidcClient as sync context manager."""
        with OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        ) as client:
            # Inject mock OpenIdConnect
            mock_openid_connect = mocker.Mock()
            mock_openid_connect.get_access_token.return_value = "ctx-token"
            client._openid_connect = mock_openid_connect

            token = client.get_access_token()
            assert token == "ctx-token"

    @pytest.mark.asyncio
    async def test_async_context_manager(self, mocker):
        """Test using OidcClient as async context manager."""
        async with OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        ) as client:
            # Inject mock OpenIdConnect
            mock_openid_connect = mocker.Mock()
            mock_openid_connect.get_access_token_async = mocker.AsyncMock(return_value="async-ctx-token")
            client._openid_connect = mock_openid_connect

            token = await client.get_access_token_async()
            assert token == "async-ctx-token"


class TestOidcClientTokenExchange:
    """Tests for OidcClient token exchange operations."""

    def test_token_exchange(self, mocker):
        """Test token exchange functionality."""
        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            client_secret="test-secret",
            http_service=FakeHttpService(),
        )

        # Create mock OpenIdConnect with token_exchange
        mock_bearer = BearerToken("exchanged_token")
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.token_exchange.return_value = mock_bearer

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        result = client.token_exchange(
            subject_token="subject_token",
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
        )

        assert result == mock_bearer
        mock_openid_connect.token_exchange.assert_called_once()


class TestOidcClientWithPrivateKey:
    """Tests for OidcClient with private key authentication."""

    def test_get_access_token_with_private_key(self, mocker, fake_private_key_pem):
        """Test getting access token with private key authentication."""
        mock_openid_connect = mocker.Mock()
        mock_openid_connect.get_access_token.return_value = "PRIVATE_KEY_TOKEN"

        client = OidcClient(
            issuer="https://test.issuer.com",
            client_id="test-client-id",
            private_key=fake_private_key_pem,
            algorithm="RS256",
            http_service=FakeHttpService(),
        )

        # Inject mock OpenIdConnect
        client._openid_connect = mock_openid_connect

        token = client.get_access_token()

        assert token == "PRIVATE_KEY_TOKEN"
        mock_openid_connect.get_access_token.assert_called_once()


@pytest.mark.parametrize(
    "issuer,client_id,scopes,expected_scopes",
    [
        ("https://auth.example.com", "client-1", None, ["openid"]),
        ("https://auth.example.com", "client-2", ["openid"], ["openid"]),
        (
            "https://auth.example.com",
            "client-3",
            ["openid", "profile"],
            ["openid", "profile"],
        ),
        (
            "https://different.issuer.com",
            "client-4",
            ["custom", "scopes"],
            ["custom", "scopes"],
        ),
    ],
)
def test_oidc_client_scopes_parametrized(issuer, client_id, scopes, expected_scopes):
    """Test OidcClient initialization with various scope configurations."""
    client = OidcClient(
        issuer=issuer,
        client_id=client_id,
        client_secret="test-secret",
        scopes=scopes,
    )

    assert client.issuer == issuer
    assert client.client_id == client_id
    assert client.scopes == expected_scopes
