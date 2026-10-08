from unittest.mock import AsyncMock, Mock

import pytest

from axa_fr_oidc import OidcClient, OidcValidator
from axa_fr_oidc.memory_cache import MemoryCache
from axa_fr_oidc.oidc import OidcAuthentication


@pytest.fixture
def discovery_response() -> dict[str, str]:
    return {
        "jwks_uri": "https://discovery.example/jwks",
        "token_endpoint": "https://discovery.example/token",
    }


@pytest.mark.parametrize(
    "discovery_issuer",
    ["https://discovery.example", "https://discovery.example/"],
)
def test_authentication_uses_discovery_issuer_without_changing_validation_issuer(
    discovery_response: dict[str, str],
    discovery_issuer: str,
) -> None:
    service = Mock()
    service.get.side_effect = [discovery_response, {"keys": []}]
    authentication = OidcAuthentication(
        issuer="https://tokens.example/",
        discovery_issuer=discovery_issuer,
        scopes=[],
        api_audience=None,
        service=service,
        memory_cache=MemoryCache(),
    )

    authentication._get_jwks()

    assert authentication.issuer == "https://tokens.example/"
    assert service.get.call_args_list[0].args == ("https://discovery.example/.well-known/openid-configuration",)


@pytest.mark.parametrize(
    "discovery_issuer",
    ["https://discovery.example", "https://discovery.example/"],
)
@pytest.mark.asyncio
async def test_authentication_uses_discovery_issuer_asynchronously(
    discovery_response: dict[str, str],
    discovery_issuer: str,
) -> None:
    service = Mock()
    service.get_async = AsyncMock(side_effect=[discovery_response, {"keys": []}])
    authentication = OidcAuthentication(
        issuer="https://tokens.example/",
        discovery_issuer=discovery_issuer,
        scopes=[],
        api_audience=None,
        service=service,
        memory_cache=MemoryCache(),
    )

    await authentication._get_jwks_async()

    assert service.get_async.await_args_list[0].args == ("https://discovery.example/.well-known/openid-configuration",)


def test_client_propagates_discovery_issuer() -> None:
    client = OidcClient(
        issuer="https://tokens.example/",
        discovery_issuer="https://discovery.example",
        client_id="client",
        client_secret="secret",
    )

    assert client.authentication.discovery_issuer == "https://discovery.example"
    assert client.authentication.issuer == "https://tokens.example/"


def test_validator_propagates_discovery_issuer() -> None:
    validator = OidcValidator(
        issuer="https://tokens.example/",
        discovery_issuer="https://discovery.example",
    )

    assert validator.authentication.discovery_issuer == "https://discovery.example"
    assert validator.authentication.issuer == "https://tokens.example/"


def test_discovery_issuer_defaults_to_validation_issuer() -> None:
    authentication = OidcAuthentication(
        issuer="https://tokens.example/",
        scopes=[],
        api_audience=None,
        service=Mock(),
        memory_cache=MemoryCache(),
    )

    assert authentication.discovery_issuer == "https://tokens.example/"


@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.asyncio
async def test_trailing_slash_issuer_uses_slash_safe_discovery_url(
    discovery_response: dict[str, str],
    is_async: bool,
) -> None:
    service = Mock()
    service.get.side_effect = [discovery_response, {"keys": []}]
    service.get_async = AsyncMock(side_effect=[discovery_response, {"keys": []}])
    authentication = OidcAuthentication(
        issuer="https://openid.example/",
        scopes=[],
        api_audience=None,
        service=service,
        memory_cache=MemoryCache(),
    )

    if is_async:
        await authentication._get_jwks_async()
        discovery_call = service.get_async.await_args_list[0]
    else:
        authentication._get_jwks()
        discovery_call = service.get.call_args_list[0]

    assert authentication.issuer == "https://openid.example/"
    assert authentication.discovery_issuer == "https://openid.example/"
    assert discovery_call.args == ("https://openid.example/.well-known/openid-configuration",)
