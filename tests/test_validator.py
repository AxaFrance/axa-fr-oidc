"""Tests for the OidcValidator high-level validator module."""

import pytest

import axa_fr_oidc as pkg
from axa_fr_oidc import (
    SUPPORTED_ALGORITHMS,
    AuthenticationResult,
    HandleValidationResult,
    OidcValidator,
)
from axa_fr_oidc.constants import DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS
from axa_fr_oidc.http_service import IHttpServiceGet
from axa_fr_oidc.memory_cache import IMemoryCache, MemoryCache


class FakeHttpService(IHttpServiceGet):
    """Fake HTTP service for testing."""

    def __init__(self, jwks=None):
        self.jwks = jwks if jwks is not None else {"keys": []}

    def get(self, url: str) -> dict:
        if ".well-known/openid-configuration" in url:
            return {
                "issuer": "https://test.issuer.com",
                "token_endpoint": "https://test.issuer.com/oauth/token",
                "jwks_uri": "https://test.issuer.com/.well-known/jwks.json",
            }
        if "jwks" in url:
            return self.jwks
        return {}

    async def get_async(self, url: str) -> dict:
        return self.get(url)


class TestOidcValidatorInitialization:
    """Tests for OidcValidator initialization."""

    def test_init_minimal(self):
        """OidcValidator can be created with only an issuer URL."""
        validator = OidcValidator(issuer="https://test.issuer.com")

        assert validator.issuer == "https://test.issuer.com"
        assert validator.audience is None
        assert validator.scopes == []
        assert validator.algorithms == SUPPORTED_ALGORITHMS
        assert validator.proxy is None
        assert validator.verify is True
        assert validator.timeout is None
        assert validator.issuer_cache_expiration_seconds == DEFAULT_ISSUER_CACHE_EXPIRATION_SECONDS

    def test_init_with_audience_and_scopes(self):
        """OidcValidator captures audience and scopes."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            audience="my-api",
            scopes=["openid", "profile"],
        )

        assert validator.audience == "my-api"
        assert validator.scopes == ["openid", "profile"]

    def test_init_with_custom_algorithms(self):
        """OidcValidator accepts a custom algorithms list."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            algorithms=["RS256", "ES256"],
        )

        assert validator.algorithms == ["RS256", "ES256"]

    def test_init_with_custom_dependencies(self):
        """OidcValidator accepts injected HTTP service and memory cache."""
        http_service = FakeHttpService()
        cache = MemoryCache()

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=http_service,
            memory_cache=cache,
        )

        assert validator.http_service is http_service
        assert validator.memory_cache is cache

    def test_init_with_http_options(self):
        """OidcValidator stores proxy / verify / timeout configuration."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            proxy="http://proxy.example.com:8080",
            verify=False,
            timeout=15.0,
        )

        assert validator.proxy == "http://proxy.example.com:8080"
        assert validator.verify is False
        assert validator.timeout == 15.0

    def test_init_custom_issuer_cache_expiration(self):
        """OidcValidator stores the issuer_cache_expiration_seconds value."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            issuer_cache_expiration_seconds=120,
        )

        assert validator.issuer_cache_expiration_seconds == 120


class TestOidcValidatorProperties:
    """Tests for OidcValidator lazy-loaded properties."""

    def test_http_service_lazy_creation(self):
        """The HTTP service is created on first access."""
        validator = OidcValidator(issuer="https://test.issuer.com")

        assert validator._http_client is None
        assert validator._http_async_client is None

        http_service = validator.http_service

        assert http_service is not None
        assert validator._http_client is not None
        assert validator._http_async_client is not None

        validator.close_sync()

    def test_memory_cache_lazy_creation(self):
        """The memory cache is created on first access."""
        validator = OidcValidator(issuer="https://test.issuer.com")

        assert validator._memory_cache is None
        cache = validator.memory_cache
        assert isinstance(cache, IMemoryCache)

    def test_authentication_lazy_creation(self):
        """The OidcAuthentication is created on first access and reused."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        assert validator._authentication is None

        auth = validator.authentication
        assert auth is not None
        # Second access returns the same instance.
        assert validator.authentication is auth

    def test_authentication_propagates_configuration(self):
        """audience, scopes, algorithms and cache TTL flow into OidcAuthentication."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            audience="my-api",
            scopes=["openid", "profile"],
            algorithms=["RS256"],
            issuer_cache_expiration_seconds=42,
            http_service=FakeHttpService(),
        )

        auth = validator.authentication

        assert auth.issuer == "https://test.issuer.com"
        assert auth.api_audience == "my-api"
        assert auth.scopes == ["openid", "profile"]
        assert auth.algorithms == ["RS256"]
        assert auth.issuer_cache_expiration_seconds == 42

    def test_authentication_propagates_handle_validation(self):
        """A custom handle_validation callback is forwarded to OidcAuthentication."""
        called = {}

        def handle(payload):
            called["payload"] = payload
            return HandleValidationResult(scopes=["openid"], aud="my-api")

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
            handle_validation=handle,
        )

        # Trigger the callback through the OidcAuthentication wrapper
        result = validator.authentication.handle_validation({"scope": "openid", "sub": "u1"})

        assert result.scopes == ["openid"]
        assert result.aud == "my-api"
        assert called["payload"] == {"scope": "openid", "sub": "u1"}


class TestOidcValidatorTokenValidation:
    """Tests for OidcValidator token validation methods."""

    def test_validate_token_sync(self, mocker):
        """validate_token delegates to OidcAuthentication.validate."""
        mock_result = AuthenticationResult(True, "", {"sub": "user123"})
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=mock_result,
        )

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        result = validator.validate_token("test-token")

        assert result.success is True
        assert result.payload == {"sub": "user123"}

    @pytest.mark.asyncio
    async def test_validate_token_async(self, mocker):
        """validate_token_async delegates to OidcAuthentication.validate_async."""
        mock_result = AuthenticationResult(True, "", {"sub": "user123"})
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate_async",
            return_value=mock_result,
        )

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        result = await validator.validate_token_async("test-token")

        assert result.success is True
        assert result.payload == {"sub": "user123"}

    def test_validate_token_with_dpop(self, mocker):
        """validate_token forwards DPoP-related parameters."""
        mock = mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=AuthenticationResult(True, "", {"sub": "user123"}),
        )

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        result = validator.validate_token(
            token="test-token",
            dpop="dpop-proof",
            path="/api/resource",
            http_method="POST",
        )

        assert result.success is True
        mock.assert_called_once_with("test-token", "dpop-proof", "/api/resource", "POST", None)

    def test_validate_token_with_audience_override(self, mocker):
        """The audience override is forwarded to OidcAuthentication.validate."""
        mock = mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=AuthenticationResult(True, "", None),
        )

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            audience="default-aud",
            http_service=FakeHttpService(),
        )

        validator.validate_token("test-token", audience="per-call-aud")

        mock.assert_called_once_with("test-token", None, None, None, "per-call-aud")

    def test_validate_token_failure_path(self, mocker):
        """Failures from the underlying authentication are surfaced verbatim."""
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=AuthenticationResult(False, "expired", None),
        )

        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        result = validator.validate_token("expired-token")

        assert result.success is False
        assert result.error == "expired"
        assert result.payload is None


class TestOidcValidatorTokenEndpoint:
    """Tests for OidcValidator token endpoint helpers."""

    def test_get_token_endpoint(self):
        """get_token_endpoint returns the URL from the discovery document."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        assert validator.get_token_endpoint() == "https://test.issuer.com/oauth/token"

    @pytest.mark.asyncio
    async def test_get_token_endpoint_async(self):
        """get_token_endpoint_async returns the URL from the discovery document."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        endpoint = await validator.get_token_endpoint_async()
        assert endpoint == "https://test.issuer.com/oauth/token"


class TestOidcValidatorCacheAndResources:
    """Tests for OidcValidator cache and resource-management helpers."""

    def test_clear_cache(self):
        """clear_cache empties the underlying memory cache."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )

        validator.memory_cache.set("k", "v")
        assert validator.memory_cache.get("k") == "v"

        validator.clear_cache()

        assert validator.memory_cache.get("k") is None

    def test_close_sync(self):
        """close_sync gracefully shuts down the sync HTTP client."""
        validator = OidcValidator(issuer="https://test.issuer.com")
        _ = validator.http_service
        assert validator._http_client is not None

        validator.close_sync()  # must not raise

    def test_close_sync_with_injected_http_service(self):
        """close_sync is a no-op when the HTTP service was injected."""
        validator = OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        )
        validator.close_sync()  # must not raise even without an internal client

    @pytest.mark.asyncio
    async def test_close_async(self):
        """close closes both sync and async HTTP clients."""
        validator = OidcValidator(issuer="https://test.issuer.com")
        _ = validator.http_service
        assert validator._http_async_client is not None

        await validator.close()  # must not raise

    def test_sync_context_manager(self, mocker):
        """OidcValidator works as a sync context manager."""
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate",
            return_value=AuthenticationResult(True, "", {"sub": "user1"}),
        )

        with OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        ) as validator:
            result = validator.validate_token("tok")
            assert result.success is True

    @pytest.mark.asyncio
    async def test_async_context_manager(self, mocker):
        """OidcValidator works as an async context manager."""
        mocker.patch(
            "axa_fr_oidc.oidc.oidc_authentication.OidcAuthentication.validate_async",
            return_value=AuthenticationResult(True, "", {"sub": "user1"}),
        )

        async with OidcValidator(
            issuer="https://test.issuer.com",
            http_service=FakeHttpService(),
        ) as validator:
            result = await validator.validate_token_async("tok")
            assert result.success is True


class TestOidcValidatorPublicSurface:
    """Tests describing the relationship between OidcValidator and OidcClient."""

    def test_validator_does_not_require_credentials(self):
        """A validator only needs an issuer (no client_id/secret/private_key)."""
        validator = OidcValidator(issuer="https://test.issuer.com")

        # No credential attributes at all
        assert not hasattr(validator, "client_id")
        assert not hasattr(validator, "client_secret")
        assert not hasattr(validator, "private_key")

    def test_validator_is_exported_from_top_level_package(self):
        """OidcValidator is importable from the top-level package."""
        assert pkg.OidcValidator is OidcValidator
        assert "OidcValidator" in pkg.__all__


@pytest.mark.parametrize(
    "scopes,expected",
    [
        (None, []),
        ([], []),
        (["openid"], ["openid"]),
        (["openid", "profile"], ["openid", "profile"]),
    ],
)
def test_oidc_validator_scopes_parametrized(scopes, expected):
    """Verify scope normalization for various inputs."""
    validator = OidcValidator(issuer="https://test.issuer.com", scopes=scopes)

    assert validator.scopes == expected
