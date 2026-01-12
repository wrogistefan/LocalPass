from localpass.vault import Vault, VaultEntry, VaultMetadata


def test_add_entry() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("gmail", "lukasz", "secret123")
    vault.add_entry(entry)

    assert len(vault.entries) == 1
    assert vault.entries[0].service == "gmail"
    assert vault.entries[0].username == "lukasz"
    assert vault.entries[0].password == "secret123"
