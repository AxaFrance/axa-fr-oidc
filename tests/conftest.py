import base64
import datetime
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from axa_fr_oidc.memory_cache.memory_cache import MemoryCache
from axa_fr_oidc.oidc.oidc_authentication import (
    AuthenticationResult,
    IOidcAuthentication,
)

# Import DPoP fixtures
pytest_plugins = ["tests.dpop_fixtures"]


class FakeAuthentication(IOidcAuthentication):
    async def get_token_endpoint_async(self) -> str:
        return "https://test/token"

    def get_token_endpoint(self) -> str:
        return "https://test/token"

    async def validate_async(
        self,
        token,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        return AuthenticationResult(True, "", None)

    def validate(
        self,
        token,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        return AuthenticationResult(True, "", None)

    def get_scopes(self) -> list[str]:
        return ["test"]


class FakeBadAuthentication(IOidcAuthentication):
    async def get_token_endpoint_async(self) -> str:
        return "https://test/token"

    def get_token_endpoint(self) -> str:
        return "https://test/token"

    async def validate_async(
        self,
        token,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        return AuthenticationResult(False, "", None)

    def validate(
        self,
        token,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        return AuthenticationResult(False, "", None)

    def get_scopes(self) -> list[str]:
        return ["test"]


@pytest.fixture(scope="function", autouse=True)
def clear_cache():
    MemoryCache().clear()


def _to_base64url_uint(val: int) -> str:
    """Helper to convert an integer to base64url encoding (no padding)."""
    return base64.urlsafe_b64encode(val.to_bytes((val.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")


@pytest.fixture
def token_and_jwks():
    # 1. Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # 2. Create JWT payload
    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=-1),
    }

    # 3. Sign JWT with private key
    kid = "test-key-id"
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # 4. Build JWKS with public key
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_base64url_uint(numbers.n),
                "e": _to_base64url_uint(numbers.e),
            }
        ]
    }

    return token, jwks


@pytest.fixture
def fake_private_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_pem.decode("utf-8")


@pytest.fixture
def token_and_jwks_with_wrong_alg():
    """Create a token with HS256 algorithm (should be rejected when only RS256 is allowed)."""
    # 1. Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # 2. Create JWT payload
    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }

    # 3. Sign JWT with RS256 but we'll modify the header to say HS256
    kid = "test-key-id"
    # First create a valid RS256 token
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Decode it to get parts, then modify header
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "HS256"  # Change algorithm to HS256
    modified_header = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    token = f"{modified_header}.{parts[1]}.{parts[2]}"

    # 4. Build JWKS with public key
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_base64url_uint(numbers.n),
                "e": _to_base64url_uint(numbers.e),
            }
        ]
    }

    return token, jwks


@pytest.fixture
def valid_token_and_jwks():
    """Create a valid (non-expired) token with audience for testing successful validation."""
    # 1. Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # 2. Create JWT payload with valid expiration
    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }

    # 3. Sign JWT with private key
    kid = "test-key-id"
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # 4. Build JWKS with public key
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_base64url_uint(numbers.n),
                "e": _to_base64url_uint(numbers.e),
            }
        ]
    }

    return token, jwks


@pytest.fixture
def valid_token_and_jwks_no_audience():
    """Create a valid token without audience claim for testing no-audience validation."""
    # 1. Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # 2. Create JWT payload without audience
    payload = {
        "scope": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }

    # 3. Sign JWT with private key
    kid = "test-key-id"
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # 4. Build JWKS with public key
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_base64url_uint(numbers.n),
                "e": _to_base64url_uint(numbers.e),
            }
        ]
    }

    return token, jwks
