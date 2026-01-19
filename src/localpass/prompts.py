import getpass

import click


def confirm_password(password: str, confirm_prompt: str = "Confirm password: ") -> bool:
    """Prompt for password confirmation and return True if matches, False otherwise."""
    confirm = getpass.getpass(confirm_prompt)
    if password != confirm:
        click.echo("Error: Passwords do not match. Please try again.")
        return False
    return True