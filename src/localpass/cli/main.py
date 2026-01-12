import argparse

from localpass.vault.models import Vault, VaultEntry, VaultMetadata


def main() -> None:
    parser = argparse.ArgumentParser(description="LocalPass CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new entry")
    add_parser.add_argument("--service", required=True, help="Service name")
    add_parser.add_argument("--username", required=True, help="Username")
    add_parser.add_argument("--password", required=True, help="Password")

    # List command
    subparsers.add_parser("list", help="List all entries")

    # Remove command
    remove_parser = subparsers.add_parser("remove", help="Remove an entry")
    remove_parser.add_argument("--service", required=True, help="Service name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    vault = Vault(metadata=VaultMetadata())

    if args.command == "add":
        vault.add_entry(VaultEntry.create(args.service, args.username, args.password))
        print(f"Added entry: {args.service}")

    elif args.command == "list":
        entries = vault.list_entries()
        for entry in entries:
            print(f"Service: {entry.service}, Username: {entry.username}")

    elif args.command == "remove":
        vault.remove_entry(args.service)
        print(f"Removed entry: {args.service}")


if __name__ == "__main__":
    main()
