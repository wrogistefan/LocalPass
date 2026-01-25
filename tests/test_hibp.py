import pytest
from unittest.mock import Mock, patch

from localpass.hibp import check_pwned_password, sha1_prefix


def test_sha1_prefix() -> None:
    """Test SHA-1 prefix generation."""
    password = "password"
    prefix, suffix = sha1_prefix(password)

    assert len(prefix) == 5
    assert len(suffix) == 35
    assert prefix + suffix == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_check_pwned_password_found() -> None:
    """Test checking a password that is found in breaches."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 42


def test_check_pwned_password_not_found() -> None:
    """Test checking a password that is not found in breaches."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\n"
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 0


def test_check_pwned_password_network_error() -> None:
    """Test network error handling."""
    import requests

    with patch("localpass.hibp.requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(requests.RequestException):
            check_pwned_password("password")


def test_check_pwned_password_timeout() -> None:
    """Test timeout handling."""
    import requests

    with patch("localpass.hibp.requests.get") as mock_get:
        mock_get.side_effect = requests.Timeout("Timeout")

        with pytest.raises(requests.RequestException):
            check_pwned_password("password")