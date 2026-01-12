from localpass.vault.models import Vault, VaultEntry, VaultMetadata


def test_add_entry_updates_metadata():
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("github.com", "lukasz", "secret")

    vault.add_entry(entry)

    assert len(vault.entries) == 1
    assert vault.metadata.updated_at >= vault.metadata.created_at
