from typing import Generator
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_getpass() -> Generator[None, None, None]:
    with patch("getpass.getpass", return_value="CorrectHorseBatteryStaple123!"):
        yield


@pytest.fixture
def mock_prompts() -> Generator[None, None, None]:
    with patch("click.prompt", return_value="testpass"):
        yield


@pytest.fixture
def mock_hibp_safe() -> Generator[None, None, None]:
    """Mock HIBP API to return that password is not breached."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\n"  # No match for password
        mock_get.return_value = mock_response
        yield


@pytest.fixture
def mock_hibp_breached() -> Generator[None, None, None]:
    """Mock HIBP API to return that password is breached."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"  # Match for 'password'
        mock_get.return_value = mock_response
        yield


@pytest.fixture
def mock_hibp_api_error() -> Generator[None, None, None]:
    """Mock HIBP API to return an error."""
    import requests
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Network error")
        yield
