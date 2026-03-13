"""Fixtures for DPoP (Demonstrating Proof-of-Possession) testing."""

import base64
import datetime
import hashlib
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _to_base64url_uint(val: int) -> str:
    """Helper to convert an integer to base64url encoding (no padding)."""
    return base64.urlsafe_b64encode(val.to_bytes((val.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")


@pytest.fixture
def ec_key_pair():
    """Generate an EC key pair for DPoP testing."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def valid_dpop_token(ec_key_pair):
    """Create a valid DPoP token."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    access_token = "test_access_token"
    sha256_digest = hashlib.sha256(access_token.encode("ascii")).digest()
    ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti-dpop-1",
        "ath": ath,
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_token_and_jwks_with_dpop(ec_key_pair):
    """Create a valid access token with cnf.jkt for DPoP testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    ec_private = ec_key_pair
    ec_public = ec_private.public_key()
    ec_numbers = ec_public.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(ec_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(ec_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    canonical_jwk = {
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"],
    }
    jwk_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
    hash_bytes = hashlib.sha256(jwk_json.encode("utf-8")).digest()
    jkt = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "cnf": {"jkt": jkt},
    }

    kid = "test-key-id"
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

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
def valid_dpop_test_data(ec_key_pair):
    """Create a complete set of matching access token, JWKS, and a DPoP token factory for testing.

    Returns a tuple of (access_token, jwks, dpop_token_factory) where dpop_token_factory
    is a callable that creates new DPoP tokens with unique JTIs each time it's called.
    """
    # Generate RSA keypair for access token signing
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rsa_public_key = rsa_private_key.public_key()
    rsa_numbers = rsa_public_key.public_numbers()

    # Get EC key for DPoP
    ec_private = ec_key_pair
    ec_public = ec_private.public_key()
    ec_numbers = ec_public.public_numbers()

    # Create EC JWK
    ec_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(ec_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(ec_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    # Compute JKT from EC key
    canonical_jwk = {
        "crv": ec_jwk["crv"],
        "kty": ec_jwk["kty"],
        "x": ec_jwk["x"],
        "y": ec_jwk["y"],
    }
    jwk_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
    hash_bytes = hashlib.sha256(jwk_json.encode("utf-8")).digest()
    jkt = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    # Create access token with cnf.jkt
    access_payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "cnf": {"jkt": jkt},
    }

    kid = "test-key-id"
    access_token = jwt.encode(
        access_payload,
        rsa_private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Create JWKS
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_base64url_uint(rsa_numbers.n),
                "e": _to_base64url_uint(rsa_numbers.e),
            }
        ]
    }

    # Compute ath from access token
    sha256_digest = hashlib.sha256(access_token.encode("ascii")).digest()
    ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    ec_private_pem = ec_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    def create_dpop_token():
        """Factory function to create a new DPoP token with a unique JTI."""
        dpop_claims = {
            "htm": "GET",
            "htu": "https://example.com/api/resource",
            "iat": int(time.time()),
            "jti": f"unique-jti-dpop-test-{uuid.uuid4()}",
            "ath": ath,
        }

        return jwt.encode(
            dpop_claims,
            ec_private_pem,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": ec_jwk},
        )

    return access_token, jwks, create_dpop_token


@pytest.fixture
def dpop_token_wrong_typ(ec_key_pair):
    """Create a DPoP token with wrong typ header."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "JWT", "jwk": jwk},
    )


@pytest.fixture
def dpop_token_no_jwk(ec_key_pair):
    """Create a DPoP token without jwk header."""
    private_key = ec_key_pair

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt"},
    )


@pytest.fixture
def dpop_token_missing_claims(ec_key_pair):
    """Create a DPoP token missing required claims."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_dpop_token_for_post(ec_key_pair):
    """Create a DPoP token for POST method."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "POST",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_dpop_token_wrong_path(ec_key_pair):
    """Create a DPoP token with wrong path."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/different",
        "iat": int(time.time()),
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def dpop_token_future_iat(ec_key_pair):
    """Create a DPoP token with iat too far in the future."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()) + 1000,
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def dpop_token_expired(ec_key_pair):
    """Create an expired DPoP token."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()) - 10000,
        "jti": "unique-jti",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_token_for_dpop():
    """Create a simple access token for DPoP ath testing."""
    return "test_access_token"


@pytest.fixture
def valid_dpop_token_wrong_ath(ec_key_pair):
    """Create a DPoP token with wrong ath."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti",
        "ath": "wrong_hash_value",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def access_token_no_jkt():
    """Create an access token without cnf.jkt."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
def access_token_wrong_jkt():
    """Create an access token with wrong jkt."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "cnf": {"jkt": "wrong_jkt_value"},
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
def valid_dpop_token_for_no_jkt(ec_key_pair, access_token_no_jkt):
    """Create a valid DPoP token that matches access_token_no_jkt."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    # Compute ath from access_token_no_jkt
    sha256_digest = hashlib.sha256(access_token_no_jkt.encode("ascii")).digest()
    ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti-no-jkt-test",
        "ath": ath,
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_dpop_token_for_wrong_jkt(ec_key_pair, access_token_wrong_jkt):
    """Create a valid DPoP token that matches access_token_wrong_jkt."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    # Compute ath from access_token_wrong_jkt
    sha256_digest = hashlib.sha256(access_token_wrong_jkt.encode("ascii")).digest()
    ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti-wrong-jkt-test",
        "ath": ath,
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@pytest.fixture
def valid_access_token_with_jkt(ec_key_pair):
    """Create an access token with matching jkt for the EC key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    ec_private = ec_key_pair
    ec_public = ec_private.public_key()
    ec_numbers = ec_public.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(ec_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(ec_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    canonical_jwk = {
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"],
    }
    jwk_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
    hash_bytes = hashlib.sha256(jwk_json.encode("utf-8")).digest()
    jkt = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    payload = {
        "scope": "my-api",
        "aud": "my-api",
        "iss": "fake_issuer",
        "sub": "user123",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "cnf": {"jkt": jkt},
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
def valid_dpop_token_with_jti(ec_key_pair, valid_access_token_with_jkt):
    """Create a valid DPoP token with all required fields including matching jkt and correct ath."""
    private_key = ec_key_pair
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
        "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, byteorder="big")).rstrip(b"=").decode("utf-8"),
    }

    # Compute ath from the actual access token fixture
    sha256_digest = hashlib.sha256(valid_access_token_with_jkt.encode("ascii")).digest()
    ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    dpop_claims = {
        "htm": "GET",
        "htu": "https://example.com/api/resource",
        "iat": int(time.time()),
        "jti": "unique-jti-replay-test",
        "ath": ath,
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        dpop_claims,
        private_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
