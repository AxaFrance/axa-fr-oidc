"""Tests for the authorization module."""

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from axa_fr_oidc.authorization.generic_authorization import IGenericAuthorization
from axa_fr_oidc.authorization.jwt_authorization import JWTAuthorization


class ConcreteGenericAuthorization(IGenericAuthorization):
    """Concrete implementation for testing the abstract interface."""

    def __init__(self, name_id: str, member_of: list[str], properties: dict):
        self.name_id = name_id
        self.member_of_list = member_of
        self.properties = properties

    def get_name_identifier(self) -> str:
        return self.name_id

    def get_member_of(self) -> list[str]:
        return self.member_of_list

    def get_property(self, property_name: str) -> None | list[str] | str:
        return self.properties.get(property_name)

    def get_properties(self, property_name: str, separator: str = "") -> list[str]:
        value = self.properties.get(property_name)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return value.split(separator)


@pytest.fixture
def valid_jwt_token():
    """Generate a valid JWT token with standard claims."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "member_of": ["group1", "group2", "group3"],
        "email": "user@example.com",
        "roles": ["admin", "user"],
        "custom_claim": "custom_value",
        "space_separated": "value1 value2 value3",
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
def jwt_token_without_sub():
    """Generate a JWT token without 'sub' claim."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "email": "user@example.com",
        "roles": ["admin"],
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
def jwt_token_without_member_of():
    """Generate a JWT token without 'member_of' claim."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user456",
        "email": "user@example.com",
    }

    return jwt.encode(payload, private_pem, algorithm="RS256")


class TestIGenericAuthorization:
    """Tests for the IGenericAuthorization abstract interface."""

    def test_concrete_implementation(self):
        """Test that the abstract interface can be implemented."""
        auth = ConcreteGenericAuthorization(
            name_id="user123",
            member_of=["group1", "group2"],
            properties={"email": "user@example.com", "role": "admin"},
        )

        assert isinstance(auth, IGenericAuthorization)
        assert auth.get_name_identifier() == "user123"
        assert auth.get_member_of() == ["group1", "group2"]
        assert auth.get_property("email") == "user@example.com"
        assert auth.get_property("role") == "admin"

    def test_get_properties_with_separator(self):
        """Test get_properties with custom separator."""
        auth = ConcreteGenericAuthorization(
            name_id="user123",
            member_of=[],
            properties={"tags": "tag1,tag2,tag3"},
        )

        assert auth.get_properties("tags", ",") == ["tag1", "tag2", "tag3"]

    def test_get_properties_with_list(self):
        """Test get_properties with list value."""
        auth = ConcreteGenericAuthorization(
            name_id="user123",
            member_of=[],
            properties={"roles": ["admin", "user"]},
        )

        assert auth.get_properties("roles") == ["admin", "user"]

    def test_get_property_missing(self):
        """Test get_property for non-existent property."""
        auth = ConcreteGenericAuthorization(name_id="user123", member_of=[], properties={})

        assert auth.get_property("missing") is None

    def test_get_properties_missing(self):
        """Test get_properties for non-existent property."""
        auth = ConcreteGenericAuthorization(name_id="user123", member_of=[], properties={})

        assert auth.get_properties("missing") == []


class TestJWTAuthorization:
    """Tests for the JWTAuthorization class."""

    def test_init_with_valid_token(self, valid_jwt_token):
        """Test initialization with a valid JWT token."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.payload is not None
        assert auth.payload["sub"] == "user123"

    def test_init_with_empty_authorization(self):
        """Test initialization with empty authorization string."""
        auth = JWTAuthorization("")
        assert auth.payload is None

    def test_init_with_none_authorization(self):
        """Test initialization with None authorization."""
        auth = JWTAuthorization(None)
        assert auth.payload is None

    def test_init_with_invalid_token(self):
        """Test initialization with an invalid JWT token."""
        auth = JWTAuthorization("invalid.jwt.token")
        assert auth.payload is None

    def test_init_with_malformed_token(self):
        """Test initialization with a malformed token."""
        auth = JWTAuthorization("not_a_jwt")
        assert auth.payload is None

    def test_get_name_identifier_success(self, valid_jwt_token):
        """Test get_name_identifier with valid token containing 'sub' claim."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_name_identifier() == "user123"

    def test_get_name_identifier_missing_sub(self, jwt_token_without_sub):
        """Test get_name_identifier when 'sub' claim is missing."""
        auth = JWTAuthorization(jwt_token_without_sub)
        assert auth.get_name_identifier() == ""

    def test_get_name_identifier_no_payload(self):
        """Test get_name_identifier when payload is None."""
        auth = JWTAuthorization("")
        assert auth.get_name_identifier() == ""

    def test_get_member_of_success(self, valid_jwt_token):
        """Test get_member_of with valid token containing 'member_of' claim."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_member_of() == ["group1", "group2", "group3"]

    def test_get_member_of_missing(self, jwt_token_without_member_of):
        """Test get_member_of when 'member_of' claim is missing."""
        auth = JWTAuthorization(jwt_token_without_member_of)
        assert auth.get_member_of() == []

    def test_get_member_of_no_payload(self):
        """Test get_member_of when payload is None."""
        auth = JWTAuthorization("")
        assert auth.get_member_of() == []

    def test_get_property_success(self, valid_jwt_token):
        """Test get_property with existing property."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_property("email") == "user@example.com"
        assert auth.get_property("custom_claim") == "custom_value"

    def test_get_property_list_value(self, valid_jwt_token):
        """Test get_property with list value."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_property("roles") == ["admin", "user"]

    def test_get_property_missing(self, valid_jwt_token):
        """Test get_property for non-existent property."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_property("non_existent") is None

    def test_get_property_no_payload(self):
        """Test get_property when payload is None."""
        auth = JWTAuthorization("")
        assert auth.get_property("email") is None

    def test_get_properties_list_value(self, valid_jwt_token):
        """Test get_properties with list value."""
        auth = JWTAuthorization(valid_jwt_token)
        result = auth.get_properties("roles")
        assert result == ["admin", "user"]

    def test_get_properties_string_value_default_separator(self, valid_jwt_token):
        """Test get_properties with string value using default separator."""
        auth = JWTAuthorization(valid_jwt_token)
        result = auth.get_properties("space_separated")
        assert result == ["value1", "value2", "value3"]

    def test_get_properties_string_value_custom_separator(self, valid_jwt_token):
        """Test get_properties with string value using custom separator."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        payload = {
            "sub": "user123",
            "comma_separated": "value1,value2,value3",
        }

        token = jwt.encode(payload, private_pem, algorithm="RS256")
        auth = JWTAuthorization(token)
        result = auth.get_properties("comma_separated", ",")
        assert result == ["value1", "value2", "value3"]

    def test_get_properties_missing(self, valid_jwt_token):
        """Test get_properties for non-existent property."""
        auth = JWTAuthorization(valid_jwt_token)
        assert auth.get_properties("non_existent") == []

    def test_get_properties_no_payload(self):
        """Test get_properties when payload is None."""
        auth = JWTAuthorization("")
        assert auth.get_properties("roles") == []

    @pytest.mark.parametrize(
        "invalid_token",
        [
            "",
            None,
            "invalid",
            "not.a.jwt",
            "invalid.jwt.token.extra",
        ],
    )
    def test_invalid_tokens_all_methods(self, invalid_token):
        """Test all methods with various invalid tokens."""
        auth = JWTAuthorization(invalid_token)
        assert auth.get_name_identifier() == ""
        assert auth.get_member_of() == []
        assert auth.get_property("any_property") is None
        assert auth.get_properties("any_property") == []

    def test_get_properties_with_single_character_separator(self, valid_jwt_token):
        """Test get_properties with single character separator on string value."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        payload = {
            "sub": "user123",
            "text": "a|b|c|d",
        }

        token = jwt.encode(payload, private_pem, algorithm="RS256")
        auth = JWTAuthorization(token)
        result = auth.get_properties("text", "|")
        assert result == ["a", "b", "c", "d"]

    def test_jwt_authorization_implements_interface(self, valid_jwt_token):
        """Test that JWTAuthorization implements IGenericAuthorization."""
        auth = JWTAuthorization(valid_jwt_token)
        assert isinstance(auth, IGenericAuthorization)
