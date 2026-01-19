import getpass
import importlib.metadata
from pathlib import Path

import click
from zxcvbn import zxcvbn

from .prompts import prompt_password_with_confirmation
from .vault.models import EntryNotFoundError, Vault
from .vault.repository import EncryptedVaultRepository
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
        password = getpass.getpass("Enter new master password: ")
        if not password or password.isspace():
            click.echo("Error: Master password cannot be empty.")
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
        confirm = getpass.getpass("Confirm master password: ")
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
def add(path: str) -> None:
    """Add a new entry to the vault at PATH."""
    password = getpass.getpass("Enter master password: ")

    repo, service, vault = load_vault(path, password)

    service_name = click.prompt("Service")
    username = click.prompt("Username")
    entry_password = prompt_password_with_confirmation("Enter password: ")
    notes = click.prompt("Notes (optional)", default="")

    entry = service.add_entry(
        vault, service_name, username, entry_password, notes or None
    )
    try:
        repo.save(path, vault, password)
        click.echo(f"Entry added with ID: {entry.id}")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@cli.command()
@click.argument("path", type=click.Path())
def list(path: str) -> None:
    """List entries in the vault at PATH."""
    password = getpass.getpass("Enter master password: ")

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
    password = getpass.getpass("Enter master password: ")

    repo, service, vault = load_vault(path, password)

    entry = vault.get_entry_by_id(id)
    if entry is None:
        raise click.ClickException(f"Entry with ID {id} not found.")

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
    password = getpass.getpass("Enter master password: ")

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
