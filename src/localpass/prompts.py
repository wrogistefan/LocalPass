import getpass

import click


def prompt_password_with_confirmation(
    initial_prompt: str, confirm_prompt: str = "Confirm password: "
) -> str:
    """Prompt for password and confirmation, retrying until they match."""
    while True:
        password = getpass.getpass(initial_prompt)
        confirm = getpass.getpass(confirm_prompt)
        if password == confirm:
            return password
        click.echo("Error: Passwords do not match. Please try again.")
