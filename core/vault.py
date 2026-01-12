class Vault:
    def __init__(self):
        self.entries = []

    def add_entry(self, name: str, username: str, password: str):
        entry = {
            "name": name,
            "username": username,
            "password": password
        }
        self.entries.append(entry)

    def list_entries(self):
        return self.entries

    def remove_entry(self, name: str):
        self.entries = [e for e in self.entries if e["name"] != name]
