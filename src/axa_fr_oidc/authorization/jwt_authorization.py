"""JWT-based authorization implementation for extracting claims from JWT tokens."""

from typing import Any, cast

from jwskate import SignedJwt
from loguru import logger

from axa_fr_oidc.authorization.generic_authorization import IGenericAuthorization


class JWTAuthorization(IGenericAuthorization):
    """Authorization handler for JWT tokens.

    This class extracts claims from signed JWT tokens and provides
    convenient methods to access common authorization-related claims.

    Attributes:
        payload: The decoded JWT payload as a dictionary, or None if invalid.
    """

    def __init__(self, authorization: str) -> None:
        """Initialize the JWT authorization handler.

        Args:
            authorization: The raw JWT token string to parse.
        """
        self.payload: dict[str, Any] | None
        if not authorization:
            self.payload = None
            logger.warning(f"authorization jwt is None: {authorization}")
            return

        try:
            # Use SignedJwt which has a claims attribute
            jwt_obj = SignedJwt(authorization)
            self.payload = dict(jwt_obj.claims)
        except Exception as e:
            logger.error(f"error getting jwt payload: {e}")
            self.payload = None

    def get_name_identifier(self) -> str:
        """Get the name identifier (subject) from the JWT.

        Returns:
            The 'sub' claim value, or empty string if not found.
        """
        if not self.payload:
            return ""

        if "sub" in self.payload:
            return str(self.payload["sub"])

        return ""

    def get_member_of(self) -> list[str]:
        """Get the member_of claim from the JWT.

        Returns:
            A list of group memberships, or empty list if not found.
        """
        if not self.payload:
            return []

        if "member_of" in self.payload:
            value = self.payload["member_of"]
            if isinstance(value, list):
                return cast(list[str], value)
        return []

    def get_property(self, property_name: str) -> None | list[str] | str:
        """Get a specific property from the JWT payload.

        Args:
            property_name: The name of the claim to retrieve.

        Returns:
            The claim value as string, list of strings, or None if not found.
        """
        if not self.payload:
            return None
        if property_name in self.payload:
            value = self.payload[property_name]
            if value is None or isinstance(value, (str, list)):
                return cast(None | list[str] | str, value)
        return None

    def get_properties(self, property_name: str, separator: str = " ") -> list[str]:
        """Get a property as a list of strings, splitting if necessary.

        Args:
            property_name: The name of the claim to retrieve.
            separator: The separator to use when splitting string values.

        Returns:
            A list of strings extracted from the claim value.
        """
        if not self.payload:
            return []

        if property_name in self.payload:
            value = self.payload[property_name]
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                return value.split(separator)
        return []
