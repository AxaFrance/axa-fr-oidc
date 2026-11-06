"""Tests for the OidcValidator high-level validator module."""

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

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


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("tampering", ["wrong-key", "claims", "signature"])
@pytest.mark.asyncio
async def test_dpop_forged_signature_is_rejected_without_consuming_jti(
    valid_dpop_test_data, asynchronous: bool, tampering: str
) -> None:
    """Reject forged proofs through both public APIs before recording replay state."""
    token, jwks, create_proof = valid_dpop_test_data
    validator = OidcValidator(issuer="fake_issuer", audience="my-api", http_service=FakeHttpService(jwks))
    proof = create_proof()
    claims = jwt.decode(proof, options={"verify_signature": False})
    if tampering == "wrong-key":
        forged = jwt.encode(
            claims,
            ec.generate_private_key(ec.SECP256R1()),
            algorithm="ES256",
            headers=jwt.get_unverified_header(proof),
        )
    else:
        parts = proof.split(".")
        if tampering == "claims":
            claims["iat"] -= 1
            parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        else:
            parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        forged = ".".join(parts)
    if asynchronous:
        invalid = await validator.validate_token_async(token, forged, "/api/resource", "GET")
        valid = await validator.validate_token_async(token, proof, "/api/resource", "GET")
    else:
        invalid = validator.validate_token(token, forged, "/api/resource", "GET")
        valid = validator.validate_token(token, proof, "/api/resource", "GET")
    assert not invalid.success
    assert invalid.payload is None
    assert invalid.error == "Invalid DPoP proof signature"
    assert valid.success


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    ("htu", "target", "expected"),
    [
        ("https://example.com/api/resource", "/api/resource", True),
        ("https://example.com/api/resource?limit=1", "/api/resource", True),
        ("https://example.com/api/resource?limit=1", "https://example.com/api/resource", True),
        ("https://example.com/api/resource", "https://other.example/api/resource", False),
        ("https://example.com/api/resource", "https://example.com/other", False),
        ("https://example.com/other/api/resource", "/api/resource", False),
        (
            "https://attacker.example/prefixhttps://example.com/api/resource",
            "https://example.com/api/resource",
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_dpop_target_compares_the_uri_without_query(
    valid_dpop_test_data, ec_key_pair, asynchronous: bool, htu: str, target: str, expected: bool
) -> None:
    """Match exact URI targets and support service workers that include query strings."""
    token, jwks, create_proof = valid_dpop_test_data
    original = create_proof()
    claims = jwt.decode(original, options={"verify_signature": False})
    claims["htu"] = htu
    proof = jwt.encode(claims, ec_key_pair, algorithm="ES256", headers=jwt.get_unverified_header(original))
    validator = OidcValidator(issuer="fake_issuer", audience="my-api", http_service=FakeHttpService(jwks))
    if asynchronous:
        result = await validator.validate_token_async(token, proof, target, "GET")
    else:
        result = validator.validate_token(token, proof, target, "GET")
    assert result.success is expected


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
