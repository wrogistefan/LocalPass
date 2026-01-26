import importlib.metadata
from pathlib import Path

import click
import requests  # type: ignore[import-untyped]
from zxcvbn import zxcvbn

from .hibp import check_pwned_password
from .prompts import (
    ERROR_EMPTY_FIELD,
    prompt_password_with_confirmation,
    prompt_required_field,
)
from .vault.models import EntryNotFoundError, Vault
from .vault.repository import (
    CorruptedVaultError,
    EncryptedVaultRepository,
    IncorrectPasswordError,
)
from .vault.service import VaultService


def get_vault_service() -> tuple[EncryptedVaultRepository, VaultService]:
    """Create and return the vault repository and service instances."""
    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    return repo, service


def load_vault(
    path: str, password: str
) -> tuple[EncryptedVaultRepository, VaultService, Vault]:
    """Load a vault with consistent error handling."""
    repo, service = get_vault_service()
    try:
        vault = service.load_vault(path, password)
        return repo, service, vault
    except IncorrectPasswordError:
        raise click.ClickException("Error: Incorrect master password.")
    except CorruptedVaultError:
        raise click.ClickException("Error: Vault file is corrupted or unreadable.")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@click.group(invoke_without_command=True)
@click.version_option()
@click.pass_context
def cli(ctx: click.Context) -> None:
    """LocalPass CLI for managing encrypted password vaults."""
    if ctx.invoked_subcommand is None:
        version = importlib.metadata.version("localpass")
        click.echo(f"{ctx.info_name}, version {version}")


@cli.command()
@click.argument("path", type=click.Path())
def init(path: str) -> None:
    """Initialize a new vault at PATH."""
    path_obj = Path(path)
    if path_obj.exists():
        if not click.confirm(f"File {path} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    while True:
        password = click.prompt("Enter new master password", hide_input=True)
        if not password.strip():
            click.echo("Error: This field cannot be empty. Please enter a value.")
            continue
        result = zxcvbn(password)
        if result["score"] < 3:
            click.echo("Error: Master password is too weak.")
            feedback = result.get("feedback", {})
            if feedback.get("warning"):
                click.echo(f"Warning: {feedback['warning']}")
            suggestions = feedback.get("suggestions", [])
            if suggestions:
                click.echo(f"Suggestion: {suggestions[0]}")
            continue
        confirm = click.prompt("Confirm master password", hide_input=True)
        if password != confirm:
            click.echo("Error: Passwords do not match. Please try again.")
            continue
        break

    repo, service = get_vault_service()
    try:
        service.create_vault(path, password)
        click.echo("Vault initialized successfully.")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@cli.command()
@click.argument("path", type=click.Path())
@click.option("--id", "entry_id", help="Custom ID for the entry (optional)")
def add(path: str, entry_id: str | None) -> None:
    """Add a new entry to the vault at PATH."""
    if entry_id == "":
        entry_id = None
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    service_name = prompt_required_field("Service")
    username = prompt_required_field("Username")
    entry_password = prompt_password_with_confirmation("Enter password: ")
    notes = click.prompt("Notes (optional)", default="")

    try:
        entry = service.add_entry(
            vault, service_name, username, entry_password, notes or None, entry_id
        )
        repo.save(path, vault, password)
        click.echo(f"Entry added with ID: {entry.id}")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@cli.command()
@click.argument("path", type=click.Path())
def list(path: str) -> None:
    """List entries in the vault at PATH."""
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    click.echo("ID\tService\tUsername\tTags")
    entries = vault.list_entries()
    for entry in entries:
        tags_str = ", ".join(entry.tags) if entry.tags else ""
        click.echo(f"{entry.id}\t{entry.service}\t{entry.username}\t{tags_str}")


@cli.command()
@click.argument("path", type=click.Path())
@click.argument("id")
@click.option(
    "--show-password/--no-show-password",
    default=False,
    help="Display the password in clear text instead of hiding it.",
)
def show(path: str, id: str, show_password: bool) -> None:
    """Show details of entry ID in the vault at PATH."""
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    entry = vault.get_entry_by_id(id)
    if entry is None:
        raise click.ClickException(f"Error: Entry with ID '{id}' not found.")

    click.echo(f"Service: {entry.service}")
    click.echo(f"Username: {entry.username}")
    if show_password:
        click.echo(f"Password: {entry.password}")
    else:
        click.echo("Password: [hidden] (re-run with --show-password to display)")
    click.echo(f"Notes: {entry.notes or ''}")
    click.echo(f"Tags: {', '.join(entry.tags) if entry.tags else ''}")
    click.echo(f"Created at: {entry.created_at}")
    click.echo(f"Updated at: {entry.updated_at}")


@cli.command()
@click.argument("path", type=click.Path())
@click.argument("id")
def remove(path: str, id: str) -> None:
    """Remove entry ID from the vault at PATH."""
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    try:
        vault.remove_entry_by_id(id)
        try:
            repo.save(path, vault, password)
            click.echo("Entry removed successfully.")
        except ValueError as e:
            raise click.ClickException(f"Error: {e}")
    except EntryNotFoundError as e:
        raise click.ClickException(f"Error: {e}")


@cli.command()
@click.argument("path", type=click.Path())
@click.argument("id")
def edit(path: str, id: str) -> None:
    """Edit entry fields in the vault at PATH."""
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    # Prompt for new values, pre-filled with current
    entry = vault.get_entry_by_id(id)
    if entry is None:
        raise click.ClickException(f"Error: Entry with ID '{id}' not found.")

    service_name = click.prompt("Service", default=entry.service)
    username = click.prompt("Username", default=entry.username)

    # Only change the password if the user explicitly confirms
    if click.confirm("Change password?", default=False):
        entry_password = prompt_password_with_confirmation("Enter new password: ")
    else:
        entry_password = entry.password

    notes = click.prompt("Notes (optional)", default=entry.notes or "")

    try:
        service.edit_entry(
            vault, id, service_name, username, entry_password, notes or None
        )
        repo.save(path, vault, password)
        click.echo("Entry updated successfully.")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@cli.command()
def hibp_check() -> None:
    """Check if a password appears in known data breaches using HIBP."""
    click.echo(
        "This command checks whether a password appears in known data breaches\n"
        "using the Have I Been Pwned (HIBP) k‑anonymity API.\n"
        "\n"
        "LocalPass will send ONLY the first 5 characters of the SHA‑1 hash of your password.\n"
        "The full password never leaves your device.\n"
        "\n"
        "This is an optional, manual check. LocalPass never performs network requests automatically."
    )

    if not click.confirm(
        "This action will query the HIBP API. Continue? [y/N]:", default=False
    ):
        click.echo("Cancelled.")
        return

    while True:
        try:
            password = click.prompt("Enter password to check", hide_input=True)
        except click.Abort:
            click.echo("\nOperation cancelled.")
            return
        if password.strip():
            break
        click.echo(ERROR_EMPTY_FIELD)

    try:
        count = check_pwned_password(password)
    except requests.RequestException:
        raise click.ClickException("Network error: unable to reach the HIBP API.")
    except Exception:
        # Broad exception to catch any unexpected errors
        raise click.ClickException(
            "An unexpected error occurred while checking the password."
        )

    if count > 0:
        click.echo(f"⚠️  This password appears in known breaches: {count} times.")
        click.echo("It is strongly recommended to choose a different password.")
    else:
        click.echo("This password was not found in the HIBP breach database.")
        click.echo("Absence from the database does not guarantee the password is safe.")
