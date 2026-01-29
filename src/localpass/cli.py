import importlib.metadata
from pathlib import Path
from typing import Any

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

VERSION = "0.3.0"

ZXCVBN_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}


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


def output_json(
    ctx: click.Context, status: str, action: str, data: dict[str, Any]
) -> None:
    """Output JSON response."""
    click.echo(
        ctx.invoke(
            _json_formatter,
            status=status,
            action=action,
            data=data,
        )
    )


def _json_formatter(
    status: str, action: str, data: dict[str, Any]
) -> str:
    """Format the JSON output."""
    import json

    output = {
        "status": status,
        "version": VERSION,
        "action": action,
        "data": data,
    }
    return json.dumps(output, indent=2)


def format_password_strength(score: int) -> str:
    """Format password strength score to human-friendly label."""
    return ZXCVBN_LABELS.get(score, "Unknown")


def print_error(ctx: click.Context, message: str, action: str) -> None:
    """Print error in the appropriate format (JSON or text)."""
    if ctx.obj.get("json", False):
        output_json(ctx, "error", action, {"message": message})
    else:
        raise click.ClickException(message)


def print_success(
    ctx: click.Context, action: str, data: dict[str, Any]
) -> None:
    """Print success message in the appropriate format."""
    if ctx.obj.get("json", False):
        output_json(ctx, "ok", action, data)
    else:
        if action == "init":
            path = data.get("path", "")
            click.echo(f"Vault initialized successfully at: {path}")
        elif action == "add":
            entry_id = data.get("entry_id", "")
            click.echo(f"Entry added: {entry_id}")
        elif action == "edit":
            entry_id = data.get("entry_id", "")
            click.echo(f"Entry updated: {entry_id}")
        elif action == "remove":
            entry_id = data.get("entry_id", "")
            click.echo(f"Entry removed: {entry_id}")


@click.group(invoke_without_command=True)
@click.version_option()
@click.option("--json", is_flag=True, help="Output results in JSON format.")
@click.pass_context
def cli(ctx: click.Context, json: bool) -> None:
    """LocalPass CLI for managing encrypted password vaults."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json
    if ctx.invoked_subcommand is None:
        version = importlib.metadata.version("localpass")
        if json:
            output_json(
                ctx,
                "ok",
                "version",
                {"version": version, "name": ctx.info_name},
            )
        else:
            click.echo(f"{ctx.info_name}, version {version}")


@cli.command()
@click.argument("path", type=click.Path())
@click.pass_context
def init(ctx: click.Context, path: str) -> None:
    """Initialize a new vault at PATH."""
    json_output = ctx.obj.get("json", False)
    path_obj = Path(path)
    if path_obj.exists():
        if not json_output:
            if not click.confirm(f"File {path} already exists. Overwrite?"):
                click.echo("Aborted.")
                return
        else:
            if not click.confirm(f"File {path} already exists. Overwrite?"):
                output_json(ctx, "ok", "init", {"aborted": True})
                return

    while True:
        password = click.prompt("Enter new master password", hide_input=True)
        if not password.strip():
            if json_output:
                print_error(ctx, "This field cannot be empty.", "init")
            else:
                click.echo("Error: This field cannot be empty.")
            continue
        result = zxcvbn(password)
        score = result["score"]
        strength_label = format_password_strength(score)

        if not json_output:
            click.echo(f"Password strength: {strength_label}")

        feedback = result.get("feedback", {})
        warning = feedback.get("warning", "")
        suggestions = feedback.get("suggestions", [])

        if not json_output:
            if warning:
                click.echo(f"Warning: {warning}")
            if suggestions:
                for suggestion in suggestions:
                    click.echo(f"Suggestion: {suggestion}")

        if score < 3:
            if not json_output:
                if not click.confirm(
                    "Password is weak. Do you want to continue anyway?"
                ):
                    click.echo("Aborted.")
                    return
            else:
                if not click.confirm(
                    "Password is weak. Do you want to continue anyway?"
                ):
                    output_json(ctx, "ok", "init", {"aborted": True})
                    return
            # User chose to continue with weak password, accept it
            confirm = password
        else:
            confirm = click.prompt("Confirm master password", hide_input=True)
            if password != confirm:
                if json_output:
                    print_error(ctx, "Passwords do not match.", "init")
                else:
                    click.echo("Error: Passwords do not match. Please try again.")
                continue
        break

    repo, service = get_vault_service()
    try:
        service.create_vault(path, password)
        if json_output:
            output_json(ctx, "ok", "init", {"path": str(path_obj.resolve())})
        else:
            click.echo(f"Vault initialized successfully at: {path}")
    except ValueError as e:
        print_error(ctx, str(e), "init")


@cli.command()
@click.argument("path", type=click.Path())
@click.option("--id", "entry_id", help="Custom ID for the entry (optional)")
@click.pass_context
def add(ctx: click.Context, path: str, entry_id: str | None) -> None:
    """Add a new entry to the vault at PATH."""
    json_output = ctx.obj.get("json", False)
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
        if json_output:
            output_json(
                ctx, "ok", "add", {"entry_id": entry.id, "service": entry.service}
            )
        else:
            click.echo(f"Entry added: {entry.id}")
    except ValueError as e:
        print_error(ctx, str(e), "add")


@cli.command()
@click.argument("path", type=click.Path())
@click.pass_context
def list(ctx: click.Context, path: str) -> None:
    """List entries in the vault at PATH."""
    json_output = ctx.obj.get("json", False)
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    entries = vault.list_entries()
    if json_output:
        entry_list = [
            {
                "id": entry.id,
                "service": entry.service,
                "username": entry.username,
                "tags": entry.tags,
            }
            for entry in entries
        ]
        output_json(ctx, "ok", "list", {"entries": entry_list})
    else:
        click.echo("ID\tService\tUsername\tTags")
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
@click.pass_context
def show(ctx: click.Context, path: str, id: str, show_password: bool) -> None:
    """Show details of entry ID in the vault at PATH."""
    json_output = ctx.obj.get("json", False)
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    entry = vault.get_entry_by_id(id)
    if entry is None:
        print_error(ctx, f"Entry with ID '{id}' not found.", "show")
        return

    if json_output:
        entry_data = {
            "id": entry.id,
            "service": entry.service,
            "username": entry.username,
            "password": entry.password if show_password else "[hidden]",
            "notes": entry.notes or "",
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }
        output_json(ctx, "ok", "show", entry_data)
    else:
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
@click.pass_context
def remove(ctx: click.Context, path: str, id: str) -> None:
    """Remove entry ID from the vault at PATH."""
    json_output = ctx.obj.get("json", False)
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    try:
        vault.remove_entry_by_id(id)
        try:
            repo.save(path, vault, password)
            if json_output:
                output_json(ctx, "ok", "remove", {"entry_id": id})
            else:
                click.echo(f"Entry removed: {id}")
        except ValueError as e:
            print_error(ctx, str(e), "remove")
    except EntryNotFoundError as e:
        print_error(ctx, str(e), "remove")


@cli.command()
@click.argument("path", type=click.Path())
@click.argument("id")
@click.pass_context
def edit(ctx: click.Context, path: str, id: str) -> None:
    """Edit entry fields in the vault at PATH."""
    json_output = ctx.obj.get("json", False)
    password = click.prompt("Enter master password", hide_input=True)

    repo, service, vault = load_vault(path, password)

    # Prompt for new values, pre-filled with current
    entry = vault.get_entry_by_id(id)
    if entry is None:
        print_error(ctx, f"Entry with ID '{id}' not found.", "edit")
        return

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
        if json_output:
            output_json(ctx, "ok", "edit", {"entry_id": id})
        else:
            click.echo(f"Entry updated: {id}")
    except ValueError as e:
        print_error(ctx, str(e), "edit")


@cli.command()
@click.pass_context
def hibp_check(ctx: click.Context) -> None:
    """Check if a password appears in known data breaches using HIBP."""
    json_output = ctx.obj.get("json", False)
    if not json_output:
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
        if json_output:
            output_json(ctx, "ok", "hibp_check", {"aborted": True})
        else:
            click.echo("Cancelled.")
        return

    while True:
        try:
            password = click.prompt("Enter password to check", hide_input=True)
        except click.Abort:
            if json_output:
                output_json(ctx, "ok", "hibp_check", {"aborted": True})
            else:
                click.echo("\nOperation cancelled.")
            return
        if password.strip():
            break
        if json_output:
            print_error(ctx, ERROR_EMPTY_FIELD, "hibp_check")
        else:
            click.echo(ERROR_EMPTY_FIELD)

    try:
        count = check_pwned_password(password)
    except requests.RequestException:
        print_error(ctx, "Network error: unable to reach the HIBP API.", "hibp_check")
        return
    except Exception:
        # Broad exception to catch any unexpected errors
        print_error(
            ctx,
            "An unexpected error occurred while checking the password.",
            "hibp_check",
        )
        return

    if json_output:
        output_json(ctx, "ok", "hibp_check", {"count": count, "breached": count > 0})
    else:
        if count > 0:
            click.echo(f"⚠️  This password appears in known breaches: {count} times.")
            click.echo("It is strongly recommended to choose a different password.")
        else:
            click.echo("This password was not found in the HIBP breach database.")
            click.echo("Absence from the database does not guarantee the password is safe.")
