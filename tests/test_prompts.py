from typing import List
from unittest.mock import patch

import click
import pytest

from localpass.prompts import prompt_password_with_confirmation, prompt_required_field


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


def test_prompt_required_field_normalizes_whitespace() -> None:
    """
    When the user enters text with surrounding whitespace, prompt_required_field
    should return the normalized value.
    """
    captured_prompt_args: List[str] = []

    def fake_prompt(text: str, **kwargs: object) -> str:
        captured_prompt_args.append(text)
        return "  some value  "

    with patch("click.prompt", fake_prompt):
        result = prompt_required_field("Test field")

    # We expect prompt_required_field to have actually prompted the user
    assert captured_prompt_args == ["Test field"]
    # And to normalize the whitespace around the input
    assert result == "some value"


def test_prompt_required_field_reprompts_on_empty_input() -> None:
    """
    When the user enters empty/whitespace input, prompt_required_field should:
    - Emit an error message
    - Re-prompt until a non-empty value is provided
    """
    calls: List[str] = []

    def fake_prompt(text: str, **kwargs: object) -> str:
        calls.append(text)
        # First response is whitespace-only, second is valid
        return "   " if len(calls) == 1 else " value "

    error_messages: List[str] = []

    def fake_echo(message: str, **kwargs: object) -> None:
        error_messages.append(message)

    with patch("click.prompt", fake_prompt), patch("click.echo", fake_echo):
        result = prompt_required_field("Test field")

    # Should have prompted twice: once for the empty value and once for the valid value
    assert calls == ["Test field", "Test field"]
    # Should ultimately return the normalized valid value
    assert result == "value"
    # Should have emitted at least one error message to stderr/stdout
    assert error_messages, "Expected an error message when empty input is provided"


def test_prompt_required_field_handles_cancel() -> None:
    """
    When the user cancels the prompt (click.Abort), prompt_required_field should:
    - Emit 'Operation cancelled.' message
    - Propagate the abort (e.g. via click.Abort or SystemExit)
    """

    def fake_prompt(text: str, **kwargs: object) -> str:
        raise click.Abort()

    echoed: List[str] = []

    def fake_echo(message: str, **kwargs: object) -> None:
        echoed.append(message)

    with patch("click.prompt", fake_prompt), patch("click.echo", fake_echo):
        with pytest.raises((click.Abort, SystemExit)):
            prompt_required_field("Test field")

    # Ensure our UX message was printed
    assert any("Operation cancelled." in msg for msg in echoed)


def test_prompt_password_with_confirmation_success() -> None:
    with patch("click.prompt", side_effect=["password", "password"]):
        result = prompt_password_with_confirmation("Enter password: ")
        assert result == "password"


def test_prompt_password_with_confirmation_empty_password() -> None:
    with patch("click.prompt", side_effect=["", "password", "password"]):
        with patch("click.echo") as mock_echo:
            result = prompt_password_with_confirmation("Enter password: ")
            assert result == "password"
            mock_echo.assert_called_with(
                "Error: This field cannot be empty. Please enter a value."
            )


def test_prompt_password_with_confirmation_mismatch() -> None:
    with patch("click.prompt", side_effect=["pass1", "pass2", "pass1", "pass1"]):
        with patch("click.echo") as mock_echo:
            result = prompt_password_with_confirmation("Enter password: ")
            assert result == "pass1"
            mock_echo.assert_called_with(
                "Error: Passwords do not match. Please try again."
            )


def test_prompt_password_with_confirmation_handles_abort() -> None:
    """
    When the user cancels the prompt (click.Abort), prompt_password_with_confirmation should
    propagate the abort without handling it.
    """

    def fake_prompt(text: str, **kwargs: object) -> str:
        raise click.Abort()

    with patch("click.prompt", fake_prompt):
        with pytest.raises(click.Abort):
            prompt_password_with_confirmation("Enter password: ")
