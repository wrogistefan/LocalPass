import uuid
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from localpass.cli import cli


def _setup_vault_with_entry(
    runner: CliRunner,
    vault_path: str,
    service: str = "TestService",
    username: str = "testuser",
    password: str = "testpass",
    notes: str = "Test notes",
) -> None:
    """Helper to initialize a vault and add a single entry for testing."""
    # Initialize vault
    init_result = runner.invoke(
        cli,
        ["init", vault_path],
        input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
    )
    assert init_result.exit_code == 0, f"Vault init failed: {init_result.output}"

    # Add entry
    add_result = runner.invoke(
        cli,
        ["add", vault_path],
        input=f"{service}\n{username}\n{password}\n{password}\n{notes}\n",
    )
    assert add_result.exit_code == 0, f"Entry add failed: {add_result.output}"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_init_creates_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Test init command
        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_overwrite_prompt(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create a dummy file first
        Path(test_vault).write_text("{}")

        # Test init command with overwrite (click.confirm not mocked, so provide y)
        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="y\nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output


def test_init_overwrite_abort(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create a dummy file first
        Path(test_vault).write_text("{}")

        # Test init command with no overwrite
        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="n\n",
        )

        assert result.exit_code == 0
        assert "Aborted." in result.output
        # File should still exist and be unchanged
        assert Path(test_vault).exists()
        assert Path(test_vault).read_text() == "{}"


def test_add_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add command
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID:" in result.output


def test_add_entry_handles_value_error(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        mock_repo = Mock()
        mock_service = Mock()
        mock_repo.save.side_effect = ValueError("Test save error")

        with patch(
            "localpass.cli.get_vault_service", return_value=(mock_repo, mock_service)
        ):
            # Test add command
            result = runner.invoke(
                cli,
                ["add", test_vault],
                input="Service\nUsername\ntestpass\ntestpass\nNotes\n",
            )

            assert result.exit_code != 0


def test_list_entries(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService1\nuser1\npass1\npass1\nnotes1\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService2\nuser2\npass2\npass2\nnotes2\n",
        )

        # Test list command
        result = runner.invoke(
            cli, ["list", test_vault], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 0
        assert "ID\tService\tUsername\tTags" in result.output
        assert "Service1" in result.output
        assert "Service2" in result.output


def test_show_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        add_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nTestService\nTestUser\nTestPass\nTestPass\nTestNotes\n",
        )

        # Extract the entry ID from the add result
        entry_id = add_result.output.split("ID: ")[1].strip()

        # Test show command
        result = runner.invoke(
            cli, ["show", test_vault, entry_id], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 0
        assert "Service: TestService" in result.output
        assert "Username: TestUser" in result.output
        assert "Password: [hidden]" in result.output
        assert "Notes: TestNotes" in result.output


def test_show_entry_with_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        add_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nTestService\nTestUser\nTestPass\nTestPass\nTestNotes\n",
        )
        assert add_result.exit_code == 0

        entry_id = None
        for line in add_result.output.splitlines():
            if "ID: " in line:
                entry_id = line.split("ID: ", 1)[1].strip()
                break

        assert entry_id is not None, "Failed to parse entry ID from add command output"

        # Test show command with --show-password
        result = runner.invoke(
            cli,
            ["show", test_vault, entry_id, "--show-password"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Service: TestService" in result.output
        assert "Username: TestUser" in result.output
        assert "Password: TestPass" in result.output
        assert "Notes: TestNotes" in result.output


def test_show_nonexistent_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test show command with non-existent ID
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli, ["show", test_vault, fake_id], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 1
        assert f"Error: Entry with ID '{fake_id}' not found." in result.stderr


def test_add_entry_password_confirmation_success(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add with matching passwords
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService\nuser\nentrypass\nentrypass\nnotes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID:" in result.output


def test_add_entry_password_confirmation_retry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add with mismatched passwords, then correct
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService\nuser\nentrypass\nwrong\nentrypass\nentrypass\nnotes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID:" in result.output
        assert "Error: Passwords do not match. Please try again." in result.output


def test_remove_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        add_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nServiceToRemove\nuser\npass\npass\n\n",
        )

        # Extract the entry ID from the add result
        entry_id = add_result.output.split("ID: ")[1].strip()

        # Test remove command
        result = runner.invoke(
            cli,
            ["remove", test_vault, entry_id],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Entry removed successfully." in result.output

        # Verify entry is actually removed
        list_result = runner.invoke(cli, ["list", test_vault], input="password\n")
        assert "ServiceToRemove" not in list_result.output


def test_remove_entry_handles_value_error(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        add_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nServiceToRemove\nuser\npass\npass\n\n",
        )

        # Extract the entry ID from the add result
        entry_id = add_result.output.split("ID: ")[1].strip()

        mock_repo = Mock()
        mock_service = Mock()
        mock_repo.save.side_effect = ValueError("Test save error")

        with patch(
            "localpass.cli.get_vault_service", return_value=(mock_repo, mock_service)
        ):

            # Test remove command
            result = runner.invoke(
                cli,
                ["remove", test_vault, entry_id],
                input="CorrectHorseBatteryStaple123!\n",
            )

            assert result.exit_code != 0


def test_remove_nonexistent_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test remove command with non-existent ID
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli,
            ["remove", test_vault, fake_id],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 1


def test_remove_entry_with_short_numeric_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry with short ID
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault, "--id", "1"],
            input="CorrectHorseBatteryStaple123!\nTestService\ntestuser\ntestpass\ntestpass\nTest notes\n",
        )

        # Remove entry using short ID
        result = runner.invoke(
            cli, ["remove", test_vault, "1"], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 0

        # Confirm subsequent show fails
        result = runner.invoke(
            cli,
            ["show", test_vault, "1"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 1
        assert "Error: Entry with ID '1' not found." in result.stderr


def test_init_empty_password_rejected(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Test init with empty password, then valid
        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="\nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output


def test_add_empty_service_rejected(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        init_result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        assert init_result.exit_code == 0
        assert "Vault initialized successfully." in init_result.output

        # Test add with empty service, then valid
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\n\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert result.output.count("Service: ") == 2
        assert "Entry added with ID:" in result.output


def test_add_empty_username_rejected(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        init_result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        assert init_result.exit_code == 0
        assert "Vault initialized successfully." in init_result.output

        # Test add with empty username, then valid
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nMyService\n\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert result.output.count("Username: ") == 2
        assert "Entry added with ID:" in result.output


def test_add_empty_password_rejected(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        init_result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        assert init_result.exit_code == 0
        assert "Vault initialized successfully." in init_result.output

        # Test add with empty password, then valid
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\n\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert result.output.count("Enter password: ") == 2
        assert "Entry added with ID:" in result.output


def test_init_password_confirmation_mismatch(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nother-password\n",
        )

        assert result.exit_code != 0
        assert "Error: Passwords do not match. Please try again." in result.output


def test_add_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault with a known master password
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Try to add using a wrong master password
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "incorrect master password" in result.stderr.lower()
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        result = runner.invoke(
            cli,
            ["list", test_vault],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "incorrect master password" in result.stderr.lower()


def test_show_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry with the correct password
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService\nuser\npass\npass\n\n",
        )

        # Use any ID; decryption should fail before lookup matters
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli,
            ["show", test_vault, fake_id],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "incorrect master password" in result.stderr.lower()


def test_remove_with_wrong_master_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry with the correct password
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService\nuser\npass\npass\n\n",
        )

        # Use any ID; decryption should fail before lookup matters
        fake_id = str(uuid.uuid4())
        result = runner.invoke(
            cli,
            ["remove", test_vault, fake_id],
            input="wrongpassword\n",
        )

        assert result.exit_code != 0
        assert "incorrect master password" in result.stderr.lower()


def test_list_with_corrupted_vault_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create a valid vault, then corrupt it
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

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


def test_list_nonexistent_vault_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        nonexistent_vault = "nonexistent.json"

        result = runner.invoke(
            cli,
            ["list", nonexistent_vault],
            input="password\n",
        )

        assert result.exit_code != 0
        assert "error" in result.stderr.lower()


def test_init_rejects_empty_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="\nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_rejects_whitespace_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="   \nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert (
            "Error: This field cannot be empty. Please enter a value." in result.output
        )
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_rejects_weak_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="123\nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Error: Master password is too weak." in result.output
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_shows_feedback_for_weak_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="password\nCorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Error: Master password is too weak." in result.output
        assert "Warning:" in result.output
        assert "Suggestion:" in result.output
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_accepts_strong_password(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Using a strong password (score >= 3)
        result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Vault initialized successfully." in result.output
        assert Path(test_vault).exists()


def test_init_handles_value_error(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        mock_repo = Mock()
        mock_service = Mock()
        mock_service.create_vault.side_effect = ValueError("Test error")

        with patch(
            "localpass.cli.get_vault_service", return_value=(mock_repo, mock_service)
        ):
            result = runner.invoke(
                cli,
                ["init", test_vault],
                input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
            )

            assert result.exit_code != 0
            assert "Error: Test error" in result.stderr


@patch("localpass.cli.importlib.metadata.version", return_value="1.0.0")
def test_cli_shows_version_when_no_args(mock_version: Mock, runner: CliRunner) -> None:
    result = runner.invoke(cli, [])

    assert result.exit_code == 0
    assert "version" in result.output.lower()
    assert "1.0.0" in result.output


def test_add_entry_assigns_numeric_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add command assigns ID 1
        result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID: 1" in result.output


def test_add_entry_with_custom_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add command with custom ID
        result = runner.invoke(
            cli,
            ["add", test_vault, "--id", "1"],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID: 1" in result.output


def test_add_entry_with_empty_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test add command with empty ID (should be treated as None)
        result = runner.invoke(
            cli,
            ["add", test_vault, "--id", ""],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert result.exit_code == 0
        assert "Entry added with ID:" in result.output


def test_add_entry_with_conflicting_custom_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Add first entry with custom ID
        runner.invoke(
            cli,
            ["add", test_vault, "--id", "1"],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        # Attempt to add another entry with the same ID
        result = runner.invoke(
            cli,
            ["add", test_vault, "--id", "1"],
            input="CorrectHorseBatteryStaple123!\nOtherService\notheruser\notherpass\notherpass\nOther notes\n",
        )

        assert result.exit_code == 1
        assert "Error: Entry with ID '1' already exists." in result.stderr


def test_add_entry_with_custom_non_numeric_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        init_result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        assert init_result.exit_code == 0

        # Add an entry with a non-numeric custom ID
        add_result = runner.invoke(
            cli,
            ["add", test_vault, "--id", "abc"],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert add_result.exit_code == 0
        assert "Entry added with ID: abc" in add_result.output

        # Show the entry and verify it exists
        show_result = runner.invoke(
            cli,
            ["show", test_vault, "abc"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert show_result.exit_code == 0
        assert "MyService" in show_result.output


def test_add_entry_with_non_numeric_then_auto_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # First create a vault
        init_result = runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        assert init_result.exit_code == 0

        # Add an entry with a non-numeric custom ID
        custom_id_result = runner.invoke(
            cli,
            ["add", test_vault, "--id", "abc"],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        assert custom_id_result.exit_code == 0
        assert "Entry added with ID: abc" in custom_id_result.output

        # Add another entry without specifying an ID to ensure next_id is still numeric (starting at 1)
        auto_id_result = runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nAnotherService\nanotheruser\nanotherpass\nanotherpass\nMore notes\n",
        )

        assert auto_id_result.exit_code == 0
        assert "Entry added with ID: 1" in auto_id_result.output


def test_show_entry_with_numeric_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nTestService\ntestuser\ntestpass\ntestpass\nTest notes\n",
        )

        # Test show command with ID 1
        result = runner.invoke(
            cli, ["show", test_vault, "1"], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 0
        assert "Service: TestService" in result.output


def test_show_entry_with_nonexistent_numeric_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test show command with non-existent ID
        result = runner.invoke(
            cli, ["show", test_vault, "999"], input="CorrectHorseBatteryStaple123!\n"
        )

        assert result.exit_code == 1
        assert "Error: Entry with ID '999' not found." in result.stderr


def test_edit_entry_handles_value_error(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nService\nuser\npass\npass\nnotes\n",
        )

        # Mock the service.edit_entry to raise ValueError
        with patch(
            "localpass.cli.VaultService.edit_entry",
            side_effect=ValueError("Mock error"),
        ):
            result = runner.invoke(
                cli,
                ["edit", test_vault, "1"],
                input="CorrectHorseBatteryStaple123!\nNewService\nnewuser\nn\nNew notes\n",
            )

        assert result.exit_code == 1
        assert "Error: Mock error" in result.stderr


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_success_zero(mock_check: Mock, runner: CliRunner) -> None:
    mock_check.return_value = 0

    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="y\ntestpassword\n",
    )

    assert result.exit_code == 0
    assert (
        "This command checks whether a password appears in known data breaches"
        in result.output
    )
    assert "This password was not found in the HIBP breach database." in result.output
    assert (
        "Absence from the database does not guarantee the password is safe."
        in result.output
    )
    mock_check.assert_called_once_with("testpassword")


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_success_pwned(mock_check: Mock, runner: CliRunner) -> None:
    mock_check.return_value = 42

    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="y\ntestpassword\n",
    )

    assert result.exit_code == 0
    assert "⚠️  This password appears in known breaches: 42 times." in result.output
    assert "It is strongly recommended to choose a different password." in result.output
    mock_check.assert_called_once_with("testpassword")


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_cancelled(mock_check: Mock, runner: CliRunner) -> None:
    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="n\n",
    )

    assert result.exit_code == 0
    assert "Cancelled." in result.output
    mock_check.assert_not_called()


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_network_error(mock_check: Mock, runner: CliRunner) -> None:
    import requests  # type: ignore[import-untyped]

    mock_check.side_effect = requests.RequestException("Network error")

    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="y\ntestpassword\n",
    )

    assert result.exit_code == 1
    assert "Network error: unable to reach the HIBP API." in result.output
    mock_check.assert_called_once_with("testpassword")


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_unexpected_error(mock_check: Mock, runner: CliRunner) -> None:
    mock_check.side_effect = ValueError("Unexpected error")

    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="y\ntestpassword\n",
    )

    assert result.exit_code == 1
    assert "An unexpected error occurred while checking the password." in result.output
    mock_check.assert_called_once_with("testpassword")


@patch("localpass.cli.check_pwned_password")
def test_hibp_check_empty_password_then_success(
    mock_check: Mock, runner: CliRunner
) -> None:
    mock_check.return_value = 0

    result = runner.invoke(
        cli,
        ["hibp-check"],
        input="y\n\n\ntestpassword\n",
    )

    assert result.exit_code == 0
    assert "This password was not found in the HIBP breach database." in result.output
    mock_check.assert_called_once_with("testpassword")


def test_remove_entry_with_numeric_id_success(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nMyService\nmyuser\nmypass\nmypass\nMy notes\n",
        )

        # Remove entry using a short numeric ID string
        result = runner.invoke(
            cli,
            ["remove", test_vault, "1"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 0
        assert "Entry removed successfully." in result.output

        # Confirm the entry is no longer shown
        show_result = runner.invoke(
            cli,
            ["show", test_vault, "1"],
            input="CorrectHorseBatteryStaple123!\n",
        )
        assert show_result.exit_code != 0


def test_remove_entry_with_nonexistent_numeric_id_fails(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create an empty vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Attempt to remove a non-existent numeric ID
        result = runner.invoke(
            cli,
            ["remove", test_vault, "999"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 1
        assert "Error: Entry with ID '999' not found." in result.stderr


def test_edit_entry_with_defaults(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Initialize vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nTestService\noriginal_user\noriginal_password\noriginal_password\nOriginal notes\n",
        )

        # First edit: change all fields so we know the current state
        result = runner.invoke(
            cli,
            ["edit", test_vault, "1"],
            input=(
                "CorrectHorseBatteryStaple123!\n"  # master
                "UpdatedService\n"  # service
                "updated_user\n"  # username
                "y\n"  # change password
                "updated_password\n"  # password
                "updated_password\n"  # confirm
                "Updated notes\n"  # notes
            ),
        )
        assert result.exit_code == 0

        # Second edit: keep service the same (press Enter), change only username
        result = runner.invoke(
            cli,
            ["edit", test_vault, "1"],
            input=(
                "CorrectHorseBatteryStaple123!\n"  # master
                "\n"  # keep service default (UpdatedService)
                "second_user\n"  # change username
                "n\n"  # don't change password
                "\n"  # keep notes default (Updated notes)
            ),
        )
        assert result.exit_code == 0

        # Show the entry and verify only username changed while defaults held
        show_result = runner.invoke(
            cli,
            ["show", test_vault, "1", "--show-password"],
            input="CorrectHorseBatteryStaple123!\n",
        )
        assert show_result.exit_code == 0
        output = show_result.output

        assert "Service: UpdatedService" in output
        assert "Username: second_user" in output
        assert "Password: updated_password" in output
        assert "Notes: Updated notes" in output


def test_edit_entry(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault and add an entry
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )
        runner.invoke(
            cli,
            ["add", test_vault],
            input="CorrectHorseBatteryStaple123!\nOldService\nolduser\noldpass\noldpass\nOld notes\n",
        )

        # Test edit command
        result = runner.invoke(
            cli,
            ["edit", test_vault, "1"],
            input="CorrectHorseBatteryStaple123!\nNewService\nnewuser\nn\nNew notes\n",
        )

        assert result.exit_code == 0
        assert "Entry updated successfully." in result.output

        # Verify the changes
        show_result = runner.invoke(
            cli, ["show", test_vault, "1"], input="CorrectHorseBatteryStaple123!\n"
        )
        assert "Service: NewService" in show_result.output
        assert "Username: newuser" in show_result.output


def test_edit_entry_with_nonexistent_short_id(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        test_vault = "test_vault.json"

        # Create vault
        runner.invoke(
            cli,
            ["init", test_vault],
            input="CorrectHorseBatteryStaple123!\nCorrectHorseBatteryStaple123!\n",
        )

        # Test edit command with non-existent short ID
        result = runner.invoke(
            cli,
            ["edit", test_vault, "999"],
            input="CorrectHorseBatteryStaple123!\n",
        )

        assert result.exit_code == 1
        assert "Error: Entry with ID '999' not found." in result.stderr
