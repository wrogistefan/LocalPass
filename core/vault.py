class Vault:
    def __init__(self):
        self.entries = []

    def remove_entry(self, name: str):
        self.entries = [e for e in self.entries if e["name"] != name]
