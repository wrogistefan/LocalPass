import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from localpass.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_init_creates_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Test init command
        result = runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_overwrite_prompt(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create a dummy file first
        Path(test_vault).write_text("{}")

        # Test init command with overwrite prompt (answer no)
        result = runner.invoke(cli, ["init", test_vault], input="n\n")

        assert result.exit_code == 0
        assert "Aborted." in result.output

        # Test init command with overwrite prompt (answer yes)
        result = runner.invoke(
            cli, ["init", test_vault], input="y\npassword\npassword\n"
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output


def test_add_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        # Test add command
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="password\nMyService\nmyuser\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID:" in result.output


def test_list_entries(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")
        runner.invoke(
            cli, ["add", test_vault], input="password\nService1\nuser1\npass1\n\n"
        )
        runner.invoke(
            cli, ["add", test_vault], input="password\nService2\nuser2\npass2\n\n"
        )

        # Test list command
        result = runner.invoke(cli, ["list", test_vault], input="password\n")

        assert result.exit_code == 0
        assert "ID\tService\tUsername\tTags" in result.output
        assert "Service1" in result.output
        assert "Service2" in result.output
        assert "user1" in result.output
        assert "user2" in result.output


def test_show_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")
        add_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="password\nTestService\ntestuser\ntestpass\nTest notes\n",
        )

        # Extract the entry ID from the add result
        entry_id = add_result.output.split("ID: ")[1].strip()

        # Test show command
        result = runner.invoke(cli, ["show", test_vault, entry_id], input="password\n")

        assert result.exit_code == 0
        assert "Service: TestService" in result.output
        assert "Username: testuser" in result.output
        assert "Password: [hidden]" in result.output
        assert "Notes: Test notes" in result.output


def test_show_nonexistent_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        # Test show command with non-existent ID
        fake_id = str(uuid.uuid4())
        result = runner.invoke(cli, ["show", test_vault, fake_id], input="password\n")

        assert result.exit_code == 1
        assert f"Entry with ID {fake_id} not found." in result.stderr


def test_remove_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")
        add_result = runner.invoke(
            cli, ["add", test_vault], input="password\nServiceToRemove\nuser\npass\n\n"
        )

        # Extract the entry ID from the add result
        entry_id = add_result.output.split("ID: ")[1].strip()

        # Test remove command
        result = runner.invoke(
            cli, ["remove", test_vault, entry_id], input="password\n"
        )

        assert result.exit_code == 0
        assert "Entry removed successfully." in result.output

        # Verify entry is actually removed
        list_result = runner.invoke(cli, ["list", test_vault], input="password\n")
        assert "ServiceToRemove" not in list_result.output


def test_remove_nonexistent_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        # Test remove command with non-existent ID
        fake_id = str(uuid.uuid4())
        result = runner.invoke(cli, ["remove", test_vault, fake_id], input="password\n")

        assert result.exit_code == 1
        assert f"Entry with ID '{fake_id}' not found" in result.stderr


def test_init_password_confirmation_mismatch(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="password\nother-password\n",
        )

        assert result.exit_code != 0
        assert "passwords do not match" in result.stderr.lower()


def test_add_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault with a known master password
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        # Try to add using a wrong master password
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="wrongpassword\nService\nuser\npass\n\n",
        )

        assert result.exit_code != 0
        assert "invalid password" in result.stderr.lower()


def test_list_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        result = runner.invoke(
            cli,
            ["list", test_vault],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "invalid password" in result.stderr.lower()


def test_show_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry with the correct password
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")
        runner.invoke(
            cli,
            ["add", test_vault],
            input="password\nService\nuser\npass\n\n",
        )

        # Use any ID; decryption should fail before lookup matters
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli,
            ["show", test_vault, fake_id],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "invalid password" in result.stderr.lower()


def test_remove_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry with the correct password
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")
        runner.invoke(
            cli,
            ["add", test_vault],
            input="password\nService\nuser\npass\n\n",
        )

        # Use any ID; decryption should fail before lookup matters
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli,
            ["remove", test_vault, fake_id],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "invalid password" in result.stderr.lower()


def test_list_with_corrupted_vault_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create a valid vault, then corrupt it
        runner.invoke(cli, ["init", test_vault], input="password\npassword\n")

        # Overwrite the vault file with invalid / unreadable content
        with open(test_vault, "w", encoding="utf-8") as f:
            f.write("this is not valid vault data")

        result = runner.invoke(
            cli,
            ["list", test_vault],
            input="password\n",
        )

        assert result.exit_code != 0
        # The CLI should surface a predictable, user-friendly error
        assert "error" in result.stderr.lower()
        assert "vault" in result.stderr.lower()
