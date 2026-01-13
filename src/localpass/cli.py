import getpass
import sys
from pathlib import Path

import click

from .vault.repository import EncryptedVaultRepository
from .vault.service import VaultService


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
        click.echo("Passwords do not match.", err=True)
        sys.exit(1)

    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    try:
        service.create_vault(path, password)
        click.echo("Vault initialized successfully.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path())
def add(path: str) -> None:
    """Add a new entry to the vault at PATH."""
    password = getpass.getpass("Enter master password: ")

    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    try:
        vault = service.load_vault(path, password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

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
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path())
def list(path: str) -> None:
    """List entries in the vault at PATH."""
    password = getpass.getpass("Enter master password: ")

    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    try:
        vault = service.load_vault(path, password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo("ID\tService\tUsername\tTags")
    for entry in vault.entries:
        tags_str = ", ".join(entry.tags) if entry.tags else ""
        click.echo(f"{entry.id}\t{entry.service}\t{entry.username}\t{tags_str}")


@cli.command()
@click.argument("path", type=click.Path())
@click.argument("id")
def show(path: str, id: str) -> None:
    """Show details of entry ID in the vault at PATH."""
    password = getpass.getpass("Enter master password: ")

    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    try:
        vault = service.load_vault(path, password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    entry = vault.get_entry_by_id(id)
    if entry is None:
        click.echo(f"Error: Entry with ID {id} not found.", err=True)
        sys.exit(1)

    click.echo(f"Service: {entry.service}")
    click.echo(f"Username: {entry.username}")
    click.echo(f"Password: {entry.password}")
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

    repo = EncryptedVaultRepository()
    service = VaultService(repo)
    try:
        vault = service.load_vault(path, password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if vault.remove_entry_by_id(id):
        try:
            repo.save(path, vault, password)
            click.echo("Entry removed successfully.")
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
    else:
        click.echo(f"Error: Entry with ID {id} not found.", err=True)
        sys.exit(1)
