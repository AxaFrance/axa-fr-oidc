import uuid

import pytest
import requests
from requests_oauth2client import BearerToken

from axa_fr_oidc.memory_cache.memory_cache import MemoryCache
from axa_fr_oidc.oidc.openid_connect import OpenIdConnect, _get_access_token

from .conftest import FakeAuthentication, FakeBadAuthentication


@pytest.mark.asyncio
async def test_oidc_success(mocker):
    mocker.patch("axa_fr_oidc.oidc.openid_connect._get_client_secret_access_token", return_value="test")

    oidc = OpenIdConnect(FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), "test")

    access_token = await oidc.get_access_token_async()

    assert access_token is not None
    assert access_token == "test"

    access_token = oidc.get_access_token()

    assert access_token is not None
    assert access_token == "test"


@pytest.mark.asyncio
async def test_oidc_failure(mocker):
    mocker.patch("axa_fr_oidc.oidc.openid_connect._get_client_secret_access_token", return_value="test")

    oidc = OpenIdConnect(FakeBadAuthentication(), MemoryCache(), str(uuid.uuid4()), "test")

    access_token = await oidc.get_access_token_async()

    assert access_token is None

    access_token = oidc.get_access_token()

    assert access_token is None


@pytest.mark.asyncio
async def test_oidc_cache(mocker):
    random_token = str(uuid.uuid4())
    mocker.patch("axa_fr_oidc.oidc.openid_connect._get_client_secret_access_token", return_value=random_token)

    oidc = OpenIdConnect(FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), "test")

    access_token = await oidc.get_access_token_async()

    assert access_token is not None
    assert access_token == random_token

    mocker.patch(
        "axa_fr_oidc.oidc.openid_connect._get_client_secret_access_token",
        return_value=str(uuid.uuid4()),
    )

    same_access_token = await oidc.get_access_token_async()

    assert same_access_token is not None
    assert same_access_token == random_token


def test_oidc_raises_without_credentials():
    """Test that accessing openid_connect raises error without credentials."""
    with pytest.raises(ValueError, match="Either client_secret or private_key"):
        _ = OpenIdConnect(FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), None, None)


def test_oidc_raises_with_both_credentials():
    """Test that accessing openid_connect raises error with both credentials."""
    with pytest.raises(ValueError, match="Both client_secret and private_key"):
        _ = OpenIdConnect(
            FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), "fake_client_secret", "fake_private_key"
        )


def test_oidc_private_key_token(monkeypatch, fake_private_key_pem):
    def fake_post(url, data, headers, timeout=None, auth=None):
        class Resp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"access_token": "FAKE_ACCESS_TOKEN"}

        return Resp()

    monkeypatch.setattr(requests, "post", fake_post)

    oidc = OpenIdConnect(
        authentication=FakeAuthentication(),
        memory_cache=MemoryCache(),
        client_id="client_id",
        private_key=fake_private_key_pem,
        algorithm="RS256",
    )

    token = oidc.get_access_token()
    assert token == "FAKE_ACCESS_TOKEN"


def test_oidc_private_key_token_failure(monkeypatch, fake_private_key_pem):
    """Test private key token acquisition with HTTP error."""

    def fake_post_failure(url, data, headers, timeout=None, auth=None):
        class Resp:
            status_code = 500

            def raise_for_status(self):
                raise requests.HTTPError("Token request failed")

            def json(self):
                return {"error": "invalid_request"}

        return Resp()

    monkeypatch.setattr(requests, "post", fake_post_failure)

    oidc = OpenIdConnect(
        authentication=FakeAuthentication(),
        memory_cache=MemoryCache(),
        client_id="client_id",
        private_key=fake_private_key_pem,
        algorithm="RS256",
    )

    try:
        oidc.get_access_token()
        raise AssertionError("Should have raised an exception")
    except requests.HTTPError:
        pass  # Expected


def test_oidc_token_exchange(mocker):
    """Test token exchange functionality."""

    mocker.patch("axa_fr_oidc.oidc.openid_connect._get_client_secret_access_token", return_value="test")

    oidc = OpenIdConnect(FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), "test")

    # Mock OAuth2Client.token_exchange
    mock_bearer = BearerToken("exchanged_token")
    mock_oauth2_client = mocker.Mock()
    mock_oauth2_client.token_exchange.return_value = mock_bearer

    oidc._oauth2client = mock_oauth2_client

    result = oidc.token_exchange(
        subject_token="subject_token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
    )

    assert result == mock_bearer
    mock_oauth2_client.token_exchange.assert_called_once()


def test_oidc_get_oauth2_client_cached():
    """Test that OAuth2Client is cached after first creation."""
    oidc = OpenIdConnect(FakeAuthentication(), MemoryCache(), str(uuid.uuid4()), "test_secret")

    # First call creates the client
    client1 = oidc._get_oauth2_client()
    assert client1 is not None

    # Second call returns the same instance
    client2 = oidc._get_oauth2_client()
    assert client1 is client2


def test_get_access_token_function(mocker):
    """Test the _get_access_token function directly."""

    # Create a mock OAuth2Client
    mock_oauth2_client = mocker.Mock()
    mock_token = mocker.Mock()
    mock_token.access_token = "test_token_from_client_credentials"
    mock_oauth2_client.client_credentials.return_value = mock_token

    # Call the function
    result = _get_access_token(mock_oauth2_client, ["scope1", "scope2"])

    assert result == "test_token_from_client_credentials"
    mock_oauth2_client.client_credentials.assert_called_once_with(scope=["scope1", "scope2"])


def test_oidc_get_access_token_without_private_key(monkeypatch):
    """Test get_access_token uses OAuth2Client when no private key is provided."""

    def fake_post(url, data, headers, timeout=None, auth=None):
        class Resp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"access_token": "FAKE_ACCESS_TOKEN"}

        return Resp()

    monkeypatch.setattr(requests, "post", fake_post)

    oidc = OpenIdConnect(
        authentication=FakeAuthentication(),
        memory_cache=MemoryCache(),
        client_id="client_id",
        client_secret="fake_client_secret",
        algorithm="HS256",
    )

    token = oidc.get_access_token()
    assert token == "FAKE_ACCESS_TOKEN"
