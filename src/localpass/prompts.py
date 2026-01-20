import getpass

import click

ERROR_EMPTY_FIELD = "Error: This field cannot be empty. Please enter a value."


def prompt_required_field(prompt_text: str) -> str:
    """Prompt for a required field, retrying until a non-empty value is provided."""
    while True:
        value: str = input(f"{prompt_text}: ")
        if value.strip():
            return value
        click.echo(ERROR_EMPTY_FIELD)


def prompt_password_with_confirmation(
    initial_prompt: str, confirm_prompt: str = "Confirm password: "
) -> str:
    """Prompt for password and confirmation, retrying until they match and password is not empty."""
    while True:
        password = getpass.getpass(initial_prompt)
        if not password.strip():
            click.echo(ERROR_EMPTY_FIELD)
            continue
        confirm = getpass.getpass(confirm_prompt)
        if password == confirm:
            return password
        click.echo("Error: Passwords do not match. Please try again.")
