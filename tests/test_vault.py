from localpass.vault import Vault


def test_add_entry() -> None:
    vault = Vault()
    vault.add_entry("gmail", "lukasz", "secret123")

    entries = vault.list_entries()

    assert len(entries) == 1
    assert entries[0]["name"] == "gmail"
    assert entries[0]["username"] == "lukasz"
    assert entries[0]["password"] == "secret123"
