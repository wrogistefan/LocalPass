from unittest.mock import patch

from localpass.prompts import prompt_required_field


def test_prompt_required_field_success() -> None:
    with patch("click.prompt", return_value="test"):
        result = prompt_required_field("Enter value: ")
        assert result == "test"


def test_prompt_required_field_empty_then_success() -> None:
    with patch("click.prompt", side_effect=["", "  ", "test"]):
        with patch("click.echo") as mock_echo:
            result = prompt_required_field("Enter value: ")
            assert result == "test"
            assert mock_echo.call_count == 2  # Two empty inputs
