"""Tests for the http_service module."""

from unittest.mock import AsyncMock, Mock

import pytest
from httpx import AsyncClient, Client

from axa_fr_oidc.http_service.http_service import IHttpServiceGet, XHttpServiceGet


class TestIHttpServiceGet:
    """Test the IHttpServiceGet abstract base class."""

    def test_abstract_methods_exist(self):
        """Test that IHttpServiceGet has the required abstract methods."""
        assert hasattr(IHttpServiceGet, "get_async")
        assert hasattr(IHttpServiceGet, "get")

    def test_cannot_instantiate_abstract_class(self):
        """Test that IHttpServiceGet cannot be instantiated directly."""
        with pytest.raises(TypeError):
            IHttpServiceGet()

    def test_concrete_implementation(self):
        """Test that a concrete implementation can be created."""

        class ConcreteHttpService(IHttpServiceGet):
            async def get_async(self, url: str) -> dict:
                return {"test": "data"}

            def get(self, url: str) -> dict:
                return {"test": "data"}

        service = ConcreteHttpService()
        assert isinstance(service, IHttpServiceGet)
        assert service.get("test_url") == {"test": "data"}

    @pytest.mark.asyncio
    async def test_concrete_implementation_async(self):
        """Test that a concrete implementation can use async methods."""

        class ConcreteHttpService(IHttpServiceGet):
            async def get_async(self, url: str) -> dict:
                return {"test": "async_data"}

            def get(self, url: str) -> dict:
                return {"test": "data"}

        service = ConcreteHttpService()
        assert isinstance(service, IHttpServiceGet)
        result = await service.get_async("test_url")
        assert result == {"test": "async_data"}


class TestXHttpServiceGet:
    """Test the XHttpServiceGet implementation."""

    @pytest.fixture
    def mock_http_client(self):
        """Create a mock HTTP client."""
        return Mock(spec=Client)

    @pytest.fixture
    def mock_async_http_client(self):
        """Create a mock async HTTP client."""
        return Mock(spec=AsyncClient)

    @pytest.fixture
    def http_service(self, mock_http_client, mock_async_http_client):
        """Create an instance of XHttpServiceGet with mocked clients."""
        return XHttpServiceGet(mock_http_client, mock_async_http_client)

    @pytest.fixture
    def setup_sync_mock_response(self, mock_http_client):
        """Setup a synchronous mock response with configurable data."""

        def _setup(url: str, response_data: dict):
            mock_response = Mock()
            mock_response.json.return_value = response_data
            mock_http_client.get.return_value = mock_response
            return mock_response

        return _setup

    @pytest.fixture
    def setup_async_mock_response(self, mock_async_http_client):
        """Setup an asynchronous mock response with configurable data."""

        def _setup(url: str, response_data: dict):
            mock_response = Mock()
            mock_response.json.return_value = response_data
            mock_async_http_client.get = AsyncMock(return_value=mock_response)
            return mock_response

        return _setup

    def test_init(self, mock_http_client, mock_async_http_client):
        """Test initialization of XHttpServiceGet."""
        service = XHttpServiceGet(mock_http_client, mock_async_http_client)
        assert service.http_client == mock_http_client
        assert service.http_async_client == mock_async_http_client

    def test_get(self, http_service, mock_http_client, setup_sync_mock_response):
        """Test synchronous get method."""
        # Arrange
        url = "https://example.com/api/data"
        expected_data = {"key": "value", "status": "success"}
        setup_sync_mock_response(url, expected_data)

        # Act
        result = http_service.get(url)

        # Assert
        mock_http_client.get.assert_called_once_with(url)
        assert result == expected_data

    @pytest.mark.asyncio
    async def test_get_async(self, http_service, mock_async_http_client, setup_async_mock_response):
        """Test asynchronous get method."""
        # Arrange
        url = "https://example.com/api/data"
        expected_data = {"key": "value", "status": "success"}
        setup_async_mock_response(url, expected_data)

        # Act
        result = await http_service.get_async(url)

        # Assert
        mock_async_http_client.get.assert_called_once_with(url)
        assert result == expected_data

    @pytest.mark.parametrize(
        "url,expected_response",
        [
            ("https://api.example.com/users", {"users": [1, 2, 3]}),
            ("https://api.example.com/config", {"config": {"debug": True}}),
            ("https://api.example.com/empty", {}),
            ("https://api.example.com/null", None),
        ],
    )
    def test_get_with_different_urls(self, mock_http_client, mock_async_http_client, url, expected_response):
        """Test synchronous get method with different URLs and responses."""
        # Arrange
        service = XHttpServiceGet(mock_http_client, mock_async_http_client)
        mock_response = Mock()
        mock_response.json.return_value = expected_response
        mock_http_client.get.return_value = mock_response

        # Act
        result = service.get(url)

        # Assert
        mock_http_client.get.assert_called_once_with(url)
        assert result == expected_response

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url,expected_response",
        [
            ("https://api.example.com/users", {"users": [1, 2, 3]}),
            ("https://api.example.com/config", {"config": {"debug": True}}),
            ("https://api.example.com/empty", {}),
            ("https://api.example.com/null", None),
        ],
    )
    async def test_get_async_with_different_urls(
        self, mock_http_client, mock_async_http_client, url, expected_response
    ):
        """Test asynchronous get method with different URLs and responses."""
        # Arrange
        service = XHttpServiceGet(mock_http_client, mock_async_http_client)
        mock_response = Mock()
        mock_response.json.return_value = expected_response
        mock_async_http_client.get = AsyncMock(return_value=mock_response)

        # Act
        result = await service.get_async(url)

        # Assert
        mock_async_http_client.get.assert_called_once_with(url)
        assert result == expected_response

    def test_implements_interface(self, http_service):
        """Test that XHttpServiceGet implements IHttpServiceGet interface."""
        assert isinstance(http_service, IHttpServiceGet)

    def test_get_complex_json_response(self, http_service, mock_http_client, setup_sync_mock_response):
        """Test synchronous get method with complex JSON response."""
        # Arrange
        url = "https://api.example.com/complex"
        expected_data = {
            "nested": {"deep": {"value": 42}},
            "list": [1, 2, 3, 4, 5],
            "mixed": {"numbers": [1, 2], "strings": ["a", "b"]},
        }
        setup_sync_mock_response(url, expected_data)

        # Act
        result = http_service.get(url)

        # Assert
        assert result == expected_data
        assert result["nested"]["deep"]["value"] == 42

    @pytest.mark.asyncio
    async def test_get_async_complex_json_response(
        self, http_service, mock_async_http_client, setup_async_mock_response
    ):
        """Test asynchronous get method with complex JSON response."""
        # Arrange
        url = "https://api.example.com/complex"
        expected_data = {
            "nested": {"deep": {"value": 42}},
            "list": [1, 2, 3, 4, 5],
            "mixed": {"numbers": [1, 2], "strings": ["a", "b"]},
        }
        setup_async_mock_response(url, expected_data)

        # Act
        result = await http_service.get_async(url)

        # Assert
        assert result == expected_data
        assert result["nested"]["deep"]["value"] == 42
