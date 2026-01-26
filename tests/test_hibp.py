from unittest.mock import Mock, patch

import pytest

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
        mock_response.text = (
            "1234567890ABCDEF:1\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
        )
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 42

        mock_get.assert_called_once()
        assert mock_get.call_args[0][0].startswith(
            "https://api.pwnedpasswords.com/range/"
        )
        assert mock_get.call_args[1]["timeout"] == (2, 5)


def test_check_pwned_password_not_found() -> None:
    """Test checking a password that is not found in breaches."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\n"
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 0

        mock_get.assert_called_once()
        assert mock_get.call_args[0][0].startswith(
            "https://api.pwnedpasswords.com/range/"
        )
        assert mock_get.call_args[1]["timeout"] == (2, 5)


def test_check_pwned_password_network_error() -> None:
    """Test network error handling."""
    import requests  # type: ignore[import-untyped]

    with patch("localpass.hibp.requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(requests.RequestException):
            check_pwned_password("password")


def test_check_pwned_password_malformed_response() -> None:
    """Test handling of malformed response lines."""
    with patch("localpass.hibp.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\nmalformed_line\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 42  # Should skip malformed line and find the match


def test_check_pwned_password_timeout() -> None:
    """Test timeout handling."""
    import requests

    with patch("localpass.hibp.requests.get") as mock_get:
        mock_get.side_effect = requests.Timeout("Timeout")

        with pytest.raises(requests.RequestException):
            check_pwned_password("password")


def test_check_pwned_password_version_not_found() -> None:
    """Test handling when package version is not found."""
    import importlib.metadata

    with (
        patch("localpass.hibp.requests.get") as mock_get,
        patch("localpass.hibp.importlib.metadata.version") as mock_version,
    ):
        mock_version.side_effect = importlib.metadata.PackageNotFoundError("localpass")
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1234567890ABCDEF:1\n"
        mock_get.return_value = mock_response

        count = check_pwned_password("password")
        assert count == 0

        # Check that User-Agent contains "unknown"
        mock_get.assert_called_once()
        assert "User-Agent" in mock_get.call_args[1]["headers"]
        assert (
            mock_get.call_args[1]["headers"]["User-Agent"]
            == "localpass/unknown (manual HIBP check)"
        )
