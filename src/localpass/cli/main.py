import argparse

from localpass.vault import Vault


def main() -> None:
    parser = argparse.ArgumentParser(description="LocalPass CLI")
    parser.add_argument(
        "command", choices=["add", "list", "remove"], help="Command to execute"
    )
    parser.add_argument("--name", help="Entry name")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password")

    args = parser.parse_args()

    vault = Vault()

    if args.command == "add":
        if not all([args.name, args.username, args.password]):
            print("Error: --name, --username, and --password required for add")
            return
        vault.add_entry(args.name, args.username, args.password)
        print(f"Added entry: {args.name}")

    elif args.command == "list":
        entries = vault.list_entries()
        for entry in entries:
            print(f"Name: {entry['name']}, Username: {entry['username']}")

    elif args.command == "remove":
        if not args.name:
            print("Error: --name required for remove")
            return
        vault.remove_entry(args.name)
        print(f"Removed entry: {args.name}")


if __name__ == "__main__":
    main()
