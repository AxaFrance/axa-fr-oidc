"""HTTP service abstraction for making sync and async HTTP requests."""

import abc
from typing import Any

from httpx import AsyncClient, Client


class IHttpServiceGet(abc.ABC):
    """Abstract base class for HTTP GET services.

    This interface defines both synchronous and asynchronous methods
    for making HTTP GET requests that return JSON data.
    """

    @abc.abstractmethod
    async def get_async(self, url: str) -> dict[str, Any]:
        """Make an asynchronous HTTP GET request.

        Args:
            url: The URL to request.

        Returns:
            The JSON response parsed as a dictionary.
        """
        ...

    @abc.abstractmethod
    def get(self, url: str) -> dict[str, Any]:
        """Make a synchronous HTTP GET request.

        Args:
            url: The URL to request.

        Returns:
            The JSON response parsed as a dictionary.
        """
        ...


class XHttpServiceGet(IHttpServiceGet):
    """HTTP service implementation using httpx clients.

    This class provides both sync and async HTTP GET operations
    using the httpx library.

    Attributes:
        http_client: The synchronous httpx Client instance.
        http_async_client: The asynchronous httpx AsyncClient instance.
    """

    def __init__(self, http_client: Client, http_async_client: AsyncClient) -> None:
        """Initialize the HTTP service with sync and async clients.

        Args:
            http_client: The synchronous httpx Client to use.
            http_async_client: The asynchronous httpx AsyncClient to use.
        """
        self.http_async_client = http_async_client
        self.http_client = http_client

    async def get_async(self, url: str) -> dict[str, Any]:
        """Make an asynchronous HTTP GET request.

        Args:
            url: The URL to request.

        Returns:
            The JSON response parsed as a dictionary.
        """
        response = await self.http_async_client.get(url)
        return response.json()  # type: ignore[no-any-return]

    def get(self, url: str) -> dict[str, Any]:
        """Make a synchronous HTTP GET request.

        Args:
            url: The URL to request.

        Returns:
            The JSON response parsed as a dictionary.
        """
        response = self.http_client.get(url)
        return response.json()  # type: ignore[no-any-return]
