import uuid
from time import sleep
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from axa_fr_oidc.constants import ERROR_JWK_NOT_FOUND
from axa_fr_oidc.http_service.http_service import XHttpServiceGet
from axa_fr_oidc.memory_cache.memory_cache import MemoryCache
from axa_fr_oidc.oidc.oidc_authentication import OidcAuthentication


@pytest.mark.asyncio
async def test_validate_should_fail(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = Mock()

    token, jwks = token_and_jwks

    return_value = {"jwks_uri": "jwks_uri", "keys": jwks["keys"]}

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    bearer_token = token

    with pytest.raises(KeyError, match="token_endpoint"):
        await authentication.validate_async(bearer_token, None)

    with pytest.raises(KeyError, match="token_endpoint"):
        authentication.validate(bearer_token, None)


@pytest.mark.asyncio
async def test_validate_expired(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert not authenticate_result.success
    assert "token expired" in authenticate_result.error

    authenticate_result = authentication.validate(token, None)

    assert not authenticate_result.success
    assert "token expired" in authenticate_result.error


@pytest.mark.asyncio
async def test_validate_wrong_scopes(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["toto"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert not authenticate_result.success
    assert authenticate_result.error == "Scope 'toto' not found"

    authenticate_result = authentication.validate(token, None)

    assert not authenticate_result.success
    assert authenticate_result.error == "Scope 'toto' not found"


@pytest.mark.asyncio
async def test_validate_wrong_audience(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="toto",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert not authenticate_result.success
    assert "Unexpected audience" in authenticate_result.error

    authenticate_result = authentication.validate(token, None)

    assert not authenticate_result.success
    assert "Unexpected audience" in authenticate_result.error


@pytest.mark.asyncio
async def test_validate_invalid_jwks(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = token_and_jwks

    jwks["keys"][0]["kid"] = "youhou_RS256"

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert not authenticate_result.success
    assert authenticate_result.error == ERROR_JWK_NOT_FOUND

    authenticate_result = authentication.validate(token, None)

    assert not authenticate_result.success
    assert authenticate_result.error == ERROR_JWK_NOT_FOUND


def test_cached_jwks(token_and_jwks):
    http_service_get = Mock(XHttpServiceGet)
    issuer = str(uuid.uuid4())

    authentication = OidcAuthentication(
        issuer=issuer,
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    assert authentication._get_cached_jwks() is None

    memory_cache = MemoryCache()

    memory_cache.set(("auth", issuer), ("test", {}))

    cached_result = authentication._get_cached_jwks()

    assert cached_result is not None
    assert cached_result[0] == "test"


@pytest.mark.asyncio
async def test_validate_async_jwk_not_found_retries_with_fresh_jwks(valid_token_and_jwks):
    """Test that validate_async invalidates cache and retries when JWK key not found."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    token, jwks = valid_token_and_jwks

    # First call returns empty JWKS, second call returns valid JWKS
    empty_jwks = {"keys": []}
    wellknown_response = {"jwks_uri": "jwks_uri", "token_endpoint": "token_endpoint"}

    call_count = 0

    async def mock_get_async(url):
        nonlocal call_count
        if "well-known" in url:
            return wellknown_response
        call_count += 1
        if call_count == 1:
            return empty_jwks
        return jwks

    async_mock.side_effect = mock_get_async
    http_service_get.get_async = async_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Should fail first time, invalidate cache, retry, and succeed
    result = await authentication.validate_async(token, None)
    assert result.success
    assert call_count == 2  # JWKS was fetched twice


def test_validate_sync_jwk_not_found_retries_with_fresh_jwks(valid_token_and_jwks):
    """Test that validate invalidates cache and retries when JWK key not found."""
    http_service_get = Mock(XHttpServiceGet)

    token, jwks = valid_token_and_jwks

    # First call returns empty JWKS, second call returns valid JWKS
    empty_jwks = {"keys": []}
    wellknown_response = {"jwks_uri": "jwks_uri", "token_endpoint": "token_endpoint"}

    call_count = 0

    def mock_get(url):
        nonlocal call_count
        if "well-known" in url:
            return wellknown_response
        call_count += 1
        if call_count == 1:
            return empty_jwks
        return jwks

    http_service_get.get = mock_get

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Should fail first time, invalidate cache, retry, and succeed
    result = authentication.validate(token, None)
    assert result.success
    assert call_count == 2  # JWKS was fetched twice


def test_invalidate_cache():
    """Test that _invalidate_cache removes the cached JWKS."""
    http_service_get = Mock(XHttpServiceGet)
    issuer = "test_issuer"

    authentication = OidcAuthentication(
        issuer=issuer,
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Set cache
    authentication.memory_cache.set(("auth", issuer), ("token_endpoint", {"keys": []}))
    authentication.cache_token_endpoint = "token_endpoint"

    # Verify cache exists
    assert authentication._get_cached_jwks() is not None
    assert authentication.cache_token_endpoint == "token_endpoint"

    # Invalidate cache
    authentication._invalidate_cache()

    # Verify cache is cleared
    assert authentication._get_cached_jwks() is None
    assert authentication.cache_token_endpoint is None


def test_get_scopes():
    """Test that get_scopes returns the configured scopes."""
    http_service_get = Mock(XHttpServiceGet)
    scopes = ["scope1", "scope2", "scope3"]

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=scopes,
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    assert authentication.get_scopes() == scopes


def test_check_jti_replay_detection():
    """Test that JTI replay detection works correctly."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    jti = "unique-jti-123"

    # First use should succeed
    assert authentication._check_jti(jti) is True

    # Second use should fail (replay)
    assert authentication._check_jti(jti) is False


def test_check_jti_expiration():
    """Test that expired JTI entries are cleaned up."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    jti = "unique-jti-456"

    # Add JTI with very short lifetime
    assert authentication._check_jti(jti, lifetime=1) is True

    # Wait for expiration
    sleep(1.1)

    # Should succeed again after expiration
    assert authentication._check_jti(jti, lifetime=1) is True


@pytest.mark.asyncio
async def test_validate_wrong_algorithm(token_and_jwks_with_wrong_alg):
    """Test validation fails when token uses unsupported algorithm."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = token_and_jwks_with_wrong_alg

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
        algorithms=["RS256"],  # Only allow RS256
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert not authenticate_result.success
    assert "Wrong algorithm used" in authenticate_result.error

    authenticate_result = authentication.validate(token, None)

    assert not authenticate_result.success
    assert "Wrong algorithm used" in authenticate_result.error


@pytest.mark.asyncio
async def test_validate_no_audience(valid_token_and_jwks_no_audience):
    """Test validation works without audience when api_audience is None."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks = valid_token_and_jwks_no_audience

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience=None,  # No audience required
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    authenticate_result = await authentication.validate_async(token, None)

    assert authenticate_result.success

    authenticate_result = authentication.validate(token, None)

    assert authenticate_result.success


@pytest.mark.asyncio
async def test_get_token_endpoint(token_and_jwks):
    """Test getting token endpoint from JWKS."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    _, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "https://example.com/token",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Test async
    token_endpoint = await authentication.get_token_endpoint_async()
    assert token_endpoint == "https://example.com/token"

    # Test sync
    token_endpoint = authentication.get_token_endpoint()
    assert token_endpoint == "https://example.com/token"


@pytest.mark.asyncio
async def test_get_token_endpoint_async_missing_in_config(token_and_jwks):
    """Test get_token_endpoint_async raises KeyError when token_endpoint is missing in OIDC config."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    _, jwks = token_and_jwks

    # Return value without token_endpoint
    return_value = {
        "jwks_uri": "jwks_uri",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    http_service_get.get_async = async_mock

    memory_cache = MemoryCache()
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=memory_cache,
    )

    with pytest.raises(KeyError, match="token_endpoint"):
        await authentication.get_token_endpoint_async()


def test_get_token_endpoint_missing_in_config(token_and_jwks):
    """Test get_token_endpoint raises KeyError when token_endpoint is missing in OIDC config."""
    http_service_get = Mock(XHttpServiceGet)
    sync_mock = MagicMock()

    _, jwks = token_and_jwks

    # Return value without token_endpoint
    return_value = {
        "jwks_uri": "jwks_uri",
        "keys": jwks["keys"],
    }

    sync_mock.return_value = return_value
    http_service_get.get = sync_mock

    memory_cache = MemoryCache()
    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=memory_cache,
    )

    with pytest.raises(KeyError, match="token_endpoint"):
        authentication.get_token_endpoint()


@pytest.mark.asyncio
async def test_validate_with_valid_dpop(valid_dpop_test_data):
    """Test successful validation with a valid DPoP token."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()
    sync_mock = MagicMock()

    token, jwks, create_dpop_token = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    sync_mock.return_value = return_value

    http_service_get.get_async = async_mock
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Test async - create a fresh DPoP token
    dpop_token_async = create_dpop_token()
    result = await authentication.validate_async(token, dpop_token_async, "/api/resource", "GET")
    assert result.success

    # Test sync - create another fresh DPoP token to avoid replay detection
    dpop_token_sync = create_dpop_token()
    result = authentication.validate(token, dpop_token_sync, "/api/resource", "GET")
    assert result.success


def test_validate_dpop_missing_token():
    """Test DPoP validation fails when no DPoP token is provided."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop("", "/api/resource", "GET", "access_token")
    assert not result.success
    assert "No DPoP token provided" in result.error


def test_validate_dpop_wrong_typ_header(dpop_token_wrong_typ):
    """Test DPoP validation fails when typ header is not 'dpop+jwt'."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(dpop_token_wrong_typ, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "Invalid 'typ' header" in result.error


def test_validate_dpop_missing_jwk_header(dpop_token_no_jwk):
    """Test DPoP validation fails when jwk header is missing."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(dpop_token_no_jwk, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "No 'jwk' in DPoP header" in result.error


def test_validate_dpop_missing_claims(dpop_token_missing_claims):
    """Test DPoP validation fails when required claims are missing."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(dpop_token_missing_claims, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "Missing DPoP claim" in result.error


def test_validate_dpop_wrong_method(valid_dpop_token_for_post):
    """Test DPoP validation fails when HTTP method doesn't match."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(valid_dpop_token_for_post, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "does not match" in result.error


def test_validate_dpop_wrong_path(valid_dpop_token_wrong_path):
    """Test DPoP validation fails when path doesn't match."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(valid_dpop_token_wrong_path, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "does not match" in result.error


def test_validate_dpop_future_iat(dpop_token_future_iat):
    """Test DPoP validation fails when iat is too far in the future."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(dpop_token_future_iat, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "too far in the future" in result.error


def test_validate_dpop_expired(dpop_token_expired):
    """Test DPoP validation fails when DPoP token is too old."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(dpop_token_expired, "/api/resource", "GET", "access_token")
    assert not result.success
    assert "expired or is too old" in result.error


def test_validate_dpop_wrong_ath(valid_dpop_token_wrong_ath, valid_token_for_dpop):
    """Test DPoP validation fails when ath hash doesn't match."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(valid_dpop_token_wrong_ath, "/api/resource", "GET", valid_token_for_dpop)
    assert not result.success
    assert "does not match the Access Token" in result.error


def test_validate_dpop_missing_jkt(valid_dpop_token_for_no_jkt, access_token_no_jkt):
    """Test DPoP validation fails when access token doesn't contain cnf.jkt."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(valid_dpop_token_for_no_jkt, "/api/resource", "GET", access_token_no_jkt)
    assert not result.success
    assert "does not contain 'cnf.jkt'" in result.error


def test_validate_dpop_wrong_jkt(valid_dpop_token_for_wrong_jkt, access_token_wrong_jkt):
    """Test DPoP validation fails when JWK thumbprint doesn't match cnf.jkt."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    result = authentication._validate_dpop(
        valid_dpop_token_for_wrong_jkt, "/api/resource", "GET", access_token_wrong_jkt
    )
    assert not result.success
    assert "does not match 'cnf.jkt'" in result.error


def test_validate_dpop_replay_attack(valid_dpop_token_with_jti, valid_access_token_with_jkt):
    """Test DPoP validation fails on replay attack (same jti used twice)."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # First attempt should succeed
    result = authentication._validate_dpop(
        valid_dpop_token_with_jti, "/api/resource", "GET", valid_access_token_with_jkt
    )
    assert result.success

    # Second attempt with same jti should fail (replay)
    result = authentication._validate_dpop(
        valid_dpop_token_with_jti, "/api/resource", "GET", valid_access_token_with_jkt
    )
    assert not result.success
    assert "Replay detected" in result.error


@pytest.mark.asyncio
async def test_get_jwks_async_with_cache(token_and_jwks):
    """Test that _get_jwks_async uses cache when available."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    _, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "https://example.com/token",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    http_service_get.get_async = async_mock

    memory_cache = MemoryCache()
    issuer = "fake_issuer"

    authentication = OidcAuthentication(
        issuer=issuer,
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=memory_cache,
    )

    # First call - should fetch from service and cache
    result1 = await authentication._get_jwks_async()
    assert result1 is not None

    # Second call - should use cache (service mock not called again)
    call_count_before = async_mock.call_count
    result2 = await authentication._get_jwks_async()
    assert result2 is not None
    # The service should not be called again since we have cache
    assert async_mock.call_count == call_count_before


def test_get_jwks_sync_cache_miss(token_and_jwks):
    """Test that _get_jwks fetches from service when cache is empty."""
    http_service_get = Mock(XHttpServiceGet)
    sync_mock = MagicMock()

    _, jwks = token_and_jwks

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "https://example.com/token",
        "keys": jwks["keys"],
    }

    sync_mock.return_value = return_value
    http_service_get.get = sync_mock

    memory_cache = MemoryCache()

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=memory_cache,
    )

    # Cache is empty, should fetch from service
    result = authentication._get_jwks()
    assert result is not None
    # Service should have been called
    assert sync_mock.call_count >= 1


def test_validate_dpop_exception_handling():
    """Test DPoP validation handles exceptions gracefully."""
    http_service_get = Mock(XHttpServiceGet)

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Invalid JWT that will cause an exception during parsing
    invalid_dpop = "not.a.valid.jwt.token"
    result = authentication._validate_dpop(invalid_dpop, "/api/resource", "GET", "access_token")
    assert not result.success
    assert result.error != ""


@pytest.mark.asyncio
async def test_validate_async_dpop_failure(valid_dpop_test_data):
    """Test async validation returns DPoP failure when DPoP validation fails."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    token, jwks, create_dpop_token = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    http_service_get.get_async = async_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Use valid token but wrong path in DPoP - will fail DPoP validation
    dpop_token = create_dpop_token()
    result = await authentication.validate_async(token, dpop_token, "/wrong/path", "GET")
    assert not result.success
    assert "does not match" in result.error


def test_validate_sync_dpop_failure(valid_dpop_test_data):
    """Test sync validation returns DPoP failure when DPoP validation fails."""
    http_service_get = Mock(XHttpServiceGet)
    sync_mock = MagicMock()

    token, jwks, create_dpop_token = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    sync_mock.return_value = return_value
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Use valid token but wrong path in DPoP - will fail DPoP validation
    dpop_token = create_dpop_token()
    result = authentication.validate(token, dpop_token, "/wrong/path", "GET")
    assert not result.success
    assert "does not match" in result.error


@pytest.mark.asyncio
async def test_validate_async_dpop_without_path(valid_dpop_test_data):
    """Test async validation fails when DPoP is provided but path is None."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    token, jwks, _ = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    http_service_get.get_async = async_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Provide DPoP but omit path
    result = await authentication.validate_async(token, "some_dpop_token", None, "GET")
    assert not result.success
    assert "path and http_method are required for DPoP validation" in result.error


@pytest.mark.asyncio
async def test_validate_async_dpop_without_http_method(valid_dpop_test_data):
    """Test async validation fails when DPoP is provided but http_method is None."""
    http_service_get = Mock(XHttpServiceGet)
    async_mock = AsyncMock()

    token, jwks, _ = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    async_mock.return_value = return_value
    http_service_get.get_async = async_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Provide DPoP but omit http_method
    result = await authentication.validate_async(token, "some_dpop_token", "/api/resource", None)
    assert not result.success
    assert "path and http_method are required for DPoP validation" in result.error


def test_validate_sync_dpop_without_path(valid_dpop_test_data):
    """Test sync validation fails when DPoP is provided but path is None."""
    http_service_get = Mock(XHttpServiceGet)
    sync_mock = MagicMock()

    token, jwks, _ = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    sync_mock.return_value = return_value
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Provide DPoP but omit path
    result = authentication.validate(token, "some_dpop_token", None, "GET")
    assert not result.success
    assert "path and http_method are required for DPoP validation" in result.error


def test_validate_sync_dpop_without_http_method(valid_dpop_test_data):
    """Test sync validation fails when DPoP is provided but http_method is None."""
    http_service_get = Mock(XHttpServiceGet)
    sync_mock = MagicMock()

    token, jwks, _ = valid_dpop_test_data

    return_value = {
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_endpoint",
        "keys": jwks["keys"],
    }

    sync_mock.return_value = return_value
    http_service_get.get = sync_mock

    authentication = OidcAuthentication(
        issuer="fake_issuer",
        scopes=["my-api"],
        api_audience="my-api",
        service=http_service_get,
        memory_cache=MemoryCache(),
    )

    # Provide DPoP but omit http_method
    result = authentication.validate(token, "some_dpop_token", "/api/resource", None)
    assert not result.success
    assert "path and http_method are required for DPoP validation" in result.error
