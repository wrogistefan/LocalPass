class Vault:
    def __init__(self) -> None:
        self.entries: list[dict[str, str]] = []

    def add_entry(self, name: str, username: str, password: str) -> None:
        entry = {"name": name, "username": username, "password": password}
        self.entries.append(entry)

    def list_entries(self) -> list[dict[str, str]]:
        return self.entries

    def remove_entry(self, name: str) -> None:
        self.entries = [e for e in self.entries if e["name"] != name]
