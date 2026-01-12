import argparse

from localpass.vault import Vault


def main() -> None:
    parser = argparse.ArgumentParser(description="LocalPass CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new entry")
    add_parser.add_argument("--name", required=True, help="Entry name")
    add_parser.add_argument("--username", required=True, help="Username")
    add_parser.add_argument("--password", required=True, help="Password")

    # List command
    subparsers.add_parser("list", help="List all entries")

    # Remove command
    remove_parser = subparsers.add_parser("remove", help="Remove an entry")
    remove_parser.add_argument("--name", required=True, help="Entry name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    vault = Vault()

    if args.command == "add":
        vault.add_entry(args.name, args.username, args.password)
        print(f"Added entry: {args.name}")

    elif args.command == "list":
        entries = vault.list_entries()
        for entry in entries:
            print(f"Name: {entry['name']}, Username: {entry['username']}")

    elif args.command == "remove":
        vault.remove_entry(args.name)
        print(f"Removed entry: {args.name}")


if __name__ == "__main__":
    main()
