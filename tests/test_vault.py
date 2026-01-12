import pytest
from localpass.vault import Vault


def test_vault_add_entry():
    vault = Vault()
    vault.add_entry("test", "user", "pass")
    assert len(vault.entries) == 1
    assert vault.entries[0]["name"] == "test"


def test_vault_list_entries():
    vault = Vault()
    vault.add_entry("test", "user", "pass")
    entries = vault.list_entries()
    assert len(entries) == 1


def test_vault_remove_entry():
    vault = Vault()
    vault.add_entry("test", "user", "pass")
    vault.remove_entry("test")
    assert len(vault.entries) == 0