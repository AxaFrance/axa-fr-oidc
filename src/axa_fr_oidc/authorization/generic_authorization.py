"""Generic authorization interface for extracting claims from tokens."""

import abc


class IGenericAuthorization(abc.ABC):
    """Abstract base class for authorization token handling.

    This interface defines methods for extracting common claims from
    authorization tokens such as JWTs.
    """

    @abc.abstractmethod
    def get_name_identifier(self) -> str:
        """Get the name identifier (subject) from the token.

        Returns:
            The subject claim value, or empty string if not found.
        """
        ...

    @abc.abstractmethod
    def get_member_of(self) -> list[str]:
        """Get the member_of claim from the token.

        Returns:
            A list of group memberships, or empty list if not found.
        """
        ...

    @abc.abstractmethod
    def get_property(self, property_name: str) -> None | list[str] | str:
        """Get a specific property from the token payload.

        Args:
            property_name: The name of the property to retrieve.

        Returns:
            The property value as string, list of strings, or None if not found.
        """
        ...

    @abc.abstractmethod
    def get_properties(self, property_name: str, separator: str = "") -> list[str]:
        """Get a property as a list of strings, splitting if necessary.

        Args:
            property_name: The name of the property to retrieve.
            separator: The separator to use when splitting string values.

        Returns:
            A list of strings extracted from the property value.
        """
        ...
