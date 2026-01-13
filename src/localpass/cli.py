import getpass
from pathlib import Path

import click

from .vault.repository import EncryptedVaultRepository
from .vault.service import VaultService


def get_vault_service() -> tuple[EncryptedVaultRepository, VaultService]:
    """Create and return the vault repository and service instances."""
    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    return repo, service


def load_vault(path: str, password: str) -> tuple:
    """Load a vault with consistent error handling."""
    repo, service = get_vault_service()
    try:
        vault = service.load_vault(path, password)
        return repo, service, vault
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")


@click.group()
def cli() -> None:
    """LocalPass CLI for managing encrypted password vaults."""
    pass


@cli.command()
@click.argument("path", type=click.Path())
def init(path: str) -> None:
    """Initialize a new vault at PATH."""
    path_obj = Path(path)
    if path_obj.exists():
        if not click.confirm(f"File {path} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    password = getpass.getpass("Enter master password: ")
    confirm_password = getpass.getpass("Confirm master password: ")
    if password != confirm_password:
        raise click.ClickException("Passwords do not match.")

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
    entry_password = getpass.getpass("Password: ")
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

    if vault.remove_entry_by_id(id):
        try:
            repo.save(path, vault, password)
            click.echo("Entry removed successfully.")
        except ValueError as e:
            raise click.ClickException(f"Error: {e}")
    else:
        raise click.ClickException(f"Entry with ID {id} not found.")
