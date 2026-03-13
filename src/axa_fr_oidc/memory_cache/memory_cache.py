"""In-memory cache implementation with singleton pattern support."""

import abc
from abc import ABC
from typing import Any, ClassVar


class AbstractSingleton(abc.ABCMeta):
    """Metaclass that implements the singleton pattern.

    This metaclass ensures that only one instance of a class exists
    throughout the application lifecycle.

    Attributes:
        _instances: Class-level dictionary storing singleton instances.
    """

    _instances: ClassVar[dict[type, Any]] = {}

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        """Create or return the singleton instance.

        Args:
            *args: Positional arguments for instance creation.
            **kwargs: Keyword arguments for instance creation.

        Returns:
            The singleton instance of the class.
        """
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class IMemoryCache(ABC, metaclass=AbstractSingleton):
    """Abstract base class for in-memory cache operations.

    This interface defines standard cache operations with tuple keys
    and uses the singleton pattern to ensure a single cache instance.
    """

    @abc.abstractmethod
    def get(self, key: tuple[str, ...]) -> Any:
        """Retrieve a value from the cache.

        Args:
            key: The cache key as a tuple of strings.

        Returns:
            The cached value, or None if not found.
        """
        ...

    @abc.abstractmethod
    def set(self, key: tuple[str, ...], value: Any) -> None:
        """Store a value in the cache.

        Args:
            key: The cache key as a tuple of strings.
            value: The value to cache.
        """
        ...

    @abc.abstractmethod
    def delete(self, key: tuple[str, ...]) -> None:
        """Remove a value from the cache.

        Args:
            key: The cache key as a tuple of strings.
        """
        ...

    @abc.abstractmethod
    def clear(self) -> None:
        """Remove all values from the cache."""
        ...


class MemoryCache(IMemoryCache):
    """Simple in-memory cache implementation.

    This class provides a basic dictionary-based cache with
    singleton behavior inherited from IMemoryCache.

    Attributes:
        cache: The internal dictionary storing cached values.
    """

    def __init__(self) -> None:
        """Initialize an empty cache."""
        self.cache: dict[tuple[str, ...], Any] = {}

    def get(self, key: tuple[str, ...]) -> Any:
        """Retrieve a value from the cache.

        Args:
            key: The cache key as a tuple of strings.

        Returns:
            The cached value, or None if not found.
        """
        return self.cache.get(key, None)

    def set(self, key: tuple[str, ...], value: Any) -> None:
        """Store a value in the cache.

        Args:
            key: The cache key as a tuple of strings.
            value: The value to cache.
        """
        self.cache[key] = value

    def delete(self, key: tuple[str, ...]) -> None:
        """Remove a value from the cache.

        Args:
            key: The cache key as a tuple of strings.
        """
        if key in self.cache:
            del self.cache[key]

    def clear(self) -> None:
        """Remove all values from the cache."""
        self.cache.clear()
