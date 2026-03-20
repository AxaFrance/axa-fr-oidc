"""Tests for the memory_cache module."""

import time

import pytest

from axa_fr_oidc.memory_cache.memory_cache import (
    IMemoryCache,
    MemoryCache,
)


class TestAbstractSingleton:
    """Tests for the AbstractSingleton metaclass."""

    def test_singleton_pattern(self):
        """Test that AbstractSingleton enforces singleton pattern."""
        cache1 = MemoryCache()
        cache2 = MemoryCache()
        assert cache1 is cache2

    def test_singleton_persists_across_calls(self):
        """Test that singleton instance persists across multiple instantiations."""
        cache1 = MemoryCache()
        cache1.set(("test_key",), "test_value")

        cache2 = MemoryCache()
        assert cache2.get(("test_key",)) == "test_value"

        # Clean up
        cache1.clear()


class TestIMemoryCache:
    """Tests for the IMemoryCache interface."""

    def test_interface_is_abstract(self):
        """Test that IMemoryCache is an abstract interface."""
        assert hasattr(IMemoryCache, "get")
        assert hasattr(IMemoryCache, "set")
        assert hasattr(IMemoryCache, "delete")
        assert hasattr(IMemoryCache, "clear")

    def test_memory_cache_implements_interface(self):
        """Test that MemoryCache implements IMemoryCache."""
        cache = MemoryCache()
        assert isinstance(cache, IMemoryCache)


class TestMemoryCache:
    """Tests for the MemoryCache class."""

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        """Clear cache before and after each test."""
        cache = MemoryCache()
        cache.clear()
        yield
        cache.clear()

    def test_init_creates_empty_cache(self):
        """Test that initialization creates an empty cache."""
        cache = MemoryCache()
        assert cache.cache == {}

    def test_set_single_value(self):
        """Test setting a single value in cache."""
        cache = MemoryCache()
        key = ("test_key",)
        value = "test_value"

        cache.set(key, value)
        assert cache.cache[key] == value

    def test_get_existing_value(self):
        """Test getting an existing value from cache."""
        cache = MemoryCache()
        key = ("test_key",)
        value = "test_value"

        cache.set(key, value)
        result = cache.get(key)
        assert result == value

    def test_get_non_existent_value(self):
        """Test getting a non-existent value returns None."""
        cache = MemoryCache()
        result = cache.get(("non_existent",))
        assert result is None

    def test_set_overwrite_existing_value(self):
        """Test that setting an existing key overwrites the value."""
        cache = MemoryCache()
        key = ("test_key",)

        cache.set(key, "value1")
        cache.set(key, "value2")

        assert cache.get(key) == "value2"

    def test_delete_existing_key(self):
        """Test deleting an existing key from cache."""
        cache = MemoryCache()
        key = ("test_key",)

        cache.set(key, "test_value")
        cache.delete(key)

        assert cache.get(key) is None
        assert key not in cache.cache

    def test_delete_non_existent_key(self):
        """Test deleting a non-existent key does not raise error."""
        cache = MemoryCache()
        key = ("non_existent",)

        # Should not raise any exception
        cache.delete(key)
        assert cache.get(key) is None

    def test_clear_empty_cache(self):
        """Test clearing an already empty cache."""
        cache = MemoryCache()
        cache.clear()
        assert cache.cache == {}

    def test_clear_cache_with_items(self):
        """Test clearing cache removes all items."""
        cache = MemoryCache()

        cache.set(("key1",), "value1")
        cache.set(("key2",), "value2")
        cache.set(("key3",), "value3")

        cache.clear()
        assert cache.cache == {}
        assert cache.get(("key1",)) is None
        assert cache.get(("key2",)) is None
        assert cache.get(("key3",)) is None

    def test_multiple_keys_with_tuples(self):
        """Test using complex tuple keys."""
        cache = MemoryCache()

        key1 = ("namespace", "user123")
        key2 = ("namespace", "user456")
        key3 = ("config", "setting1")

        cache.set(key1, "value1")
        cache.set(key2, "value2")
        cache.set(key3, "value3")

        assert cache.get(key1) == "value1"
        assert cache.get(key2) == "value2"
        assert cache.get(key3) == "value3"

    def test_different_value_types(self):
        """Test storing different types of values."""
        cache = MemoryCache()

        cache.set(("string",), "text")
        cache.set(("int",), 42)
        cache.set(("float",), 3.14)
        cache.set(("list",), [1, 2, 3])
        cache.set(("dict",), {"key": "value"})
        cache.set(("bool",), True)
        cache.set(("none",), None)

        assert cache.get(("string",)) == "text"
        assert cache.get(("int",)) == 42
        assert cache.get(("float",)) == 3.14
        assert cache.get(("list",)) == [1, 2, 3]
        assert cache.get(("dict",)) == {"key": "value"}
        assert cache.get(("bool",)) is True
        assert cache.get(("none",)) is None

    def test_empty_tuple_as_key(self):
        """Test using empty tuple as key."""
        cache = MemoryCache()
        key = ()

        cache.set(key, "value")
        assert cache.get(key) == "value"

    def test_single_element_tuple_key(self):
        """Test using single element tuple as key."""
        cache = MemoryCache()
        key = ("single",)

        cache.set(key, "value")
        assert cache.get(key) == "value"

    def test_multi_element_tuple_key(self):
        """Test using multi-element tuple as key."""
        cache = MemoryCache()
        key = ("part1", "part2", "part3", "part4")

        cache.set(key, "value")
        assert cache.get(key) == "value"

    @pytest.mark.parametrize(
        "key,value",
        [
            (("test1",), "value1"),
            (("test2",), 123),
            (("test3", "sub"), {"data": "object"}),
            (("test4",), [1, 2, 3]),
            (("test5",), None),
        ],
    )
    def test_set_and_get_parametrized(self, key, value):
        """Test set and get operations with various key-value pairs."""
        cache = MemoryCache()
        cache.set(key, value)
        assert cache.get(key) == value

    def test_cache_isolation_between_operations(self):
        """Test that cache operations don't interfere with each other."""
        cache = MemoryCache()

        # Set multiple values
        cache.set(("key1",), "value1")
        cache.set(("key2",), "value2")
        cache.set(("key3",), "value3")

        # Delete one
        cache.delete(("key2",))

        # Verify others remain
        assert cache.get(("key1",)) == "value1"
        assert cache.get(("key2",)) is None
        assert cache.get(("key3",)) == "value3"

    def test_cache_persists_across_singleton_instances(self):
        """Test that cache data persists across singleton instances."""
        cache1 = MemoryCache()
        cache1.set(("persistent_key",), "persistent_value")

        cache2 = MemoryCache()
        assert cache2.get(("persistent_key",)) == "persistent_value"

        # Verify they're the same instance
        assert cache1 is cache2

    def test_delete_then_set_same_key(self):
        """Test deleting a key and then setting it again."""
        cache = MemoryCache()
        key = ("reusable_key",)

        cache.set(key, "value1")
        cache.delete(key)
        cache.set(key, "value2")

        assert cache.get(key) == "value2"

    def test_large_number_of_keys(self):
        """Test cache with a large number of keys."""
        cache = MemoryCache()
        num_keys = 1000

        # Set many keys
        for i in range(num_keys):
            cache.set((f"key{i}",), f"value{i}")

        # Verify a sample
        assert cache.get(("key0",)) == "value0"
        assert cache.get(("key500",)) == "value500"
        assert cache.get(("key999",)) == "value999"

        # Verify count
        assert len(cache.cache) == num_keys

    def test_complex_nested_data_structure(self):
        """Test storing complex nested data structures."""
        cache = MemoryCache()
        key = ("complex",)
        value = {
            "users": [
                {"id": 1, "name": "Alice", "roles": ["admin", "user"]},
                {"id": 2, "name": "Bob", "roles": ["user"]},
            ],
            "config": {"timeout": 30, "retry": True},
        }

        cache.set(key, value)
        retrieved = cache.get(key)

        assert retrieved == value
        assert retrieved["users"][0]["name"] == "Alice"
        assert retrieved["config"]["timeout"] == 30

    def test_set_with_ttl_returns_value_before_expiration(self):
        """Test that a value with TTL is returned before it expires."""
        cache = MemoryCache()
        key = ("ttl_key",)
        cache.set(key, "ttl_value", ttl_ms=60_000)
        assert cache.get(key) == "ttl_value"

    def test_set_with_ttl_returns_none_after_expiration(self):
        """Test that a value with TTL returns None after expiration."""
        cache = MemoryCache()
        key = ("ttl_expired",)
        cache.set(key, "ttl_value", ttl_ms=1)  # 1 ms TTL

        # Wait for expiration
        time.sleep(0.01)

        assert cache.get(key) is None
        assert key not in cache.cache
        assert key not in cache._expirations

    def test_set_without_ttl_never_expires(self):
        """Test that a value without TTL never expires."""
        cache = MemoryCache()
        key = ("no_ttl",)
        cache.set(key, "persistent")
        assert cache.get(key) == "persistent"
        assert key not in cache._expirations

    def test_set_overwrite_removes_ttl_when_none(self):
        """Test that overwriting a key without TTL removes previous expiration."""
        cache = MemoryCache()
        key = ("overwrite_ttl",)

        cache.set(key, "value1", ttl_ms=60_000)
        assert key in cache._expirations

        cache.set(key, "value2")  # No TTL
        assert key not in cache._expirations
        assert cache.get(key) == "value2"

    def test_delete_removes_expiration(self):
        """Test that deleting a key also removes its expiration."""
        cache = MemoryCache()
        key = ("delete_ttl",)

        cache.set(key, "value", ttl_ms=60_000)
        assert key in cache._expirations

        cache.delete(key)
        assert key not in cache._expirations
        assert key not in cache.cache

    def test_clear_removes_all_expirations(self):
        """Test that clearing the cache also removes all expirations."""
        cache = MemoryCache()

        cache.set(("key1",), "v1", ttl_ms=60_000)
        cache.set(("key2",), "v2", ttl_ms=120_000)

        cache.clear()
        assert len(cache._expirations) == 0
        assert len(cache.cache) == 0

