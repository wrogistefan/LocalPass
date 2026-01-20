import click

ERROR_EMPTY_FIELD = "Error: This field cannot be empty. Please enter a value."


def prompt_required_field(prompt_text: str) -> str:
    """Prompt for a required field, retrying until a non-empty value is provided.

    The prompt_text is normalized by stripping trailing colons and spaces to ensure
    consistent formatting. Uses Click's prompt for consistent CLI behavior and
    cancellation handling via click.Abort.
    """
    prompt_text = prompt_text.rstrip(":").rstrip()
    while True:
        try:
            value: str = click.prompt(prompt_text)
        except click.Abort:
            click.echo("\nOperation cancelled.")
            raise
        if value.strip():
            return value.strip()
        click.echo(ERROR_EMPTY_FIELD)


def prompt_password_with_confirmation(
    initial_prompt: str, confirm_prompt: str = "Confirm password: "
) -> str:
    """Prompt for password and confirmation, retrying until they match and password is not empty."""
    while True:
        password: str = click.prompt(initial_prompt, hide_input=True)
        if not password.strip():
            click.echo(ERROR_EMPTY_FIELD)
            continue
        confirm: str = click.prompt(confirm_prompt, hide_input=True)
        if password == confirm:
            return password
        click.echo("Error: Passwords do not match. Please try again.")
