#!/usr/bin/env python3
"""
ARIA User Management — run this to create/reset users.
Usage:
  python3 manage_users.py                    # interactive
  python3 manage_users.py --list             # list all users
  python3 manage_users.py --add <username>   # add a user
  python3 manage_users.py --reset <username> # reset password
  python3 manage_users.py --remove <username># remove a user
"""
import json, secrets, string, argparse, getpass
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("Run: venv/bin/pip install bcrypt")
    exit(1)

USERS_FILE = Path(__file__).parent / "config" / "users.json"

TECH_DISPLAY = {
    "bob":     "Bob Giordano",
    "robert":  "Robert Saunders",
    "scott":   "Scott Midkiff",
    "deanna":  "Deanna McLean",
    "ellen":   "Ellen Paul",
    "michal":  "Michal Dudzinski",
    "danica":  "Danica Gibson",
}

def load_users():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())

def save_users(users):
    USERS_FILE.parent.mkdir(exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def gen_temp_password(length=12) -> str:
    chars = string.ascii_letters + string.digits + "!@#$"
    return ''.join(secrets.choice(chars) for _ in range(length))

def add_user(username, role="tech", display_name=None, password=None):
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists. Use --reset to change password.")
        return
    if not password:
        password = gen_temp_password()
        print(f"\n  Temp password for {username}: {password}")
        print("  Give this to the tech — they'll be prompted to change it on first login.\n")
    display = display_name or TECH_DISPLAY.get(username, username.title())
    users[username] = {
        "display_name": display,
        "role": role,
        "password_hash": hash_password(password),
        "must_change_password": True,
    }
    save_users(users)
    print(f"✓ User '{username}' ({display}) added as {role}.")

def reset_user(username):
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found.")
        return
    password = gen_temp_password()
    users[username]["password_hash"] = hash_password(password)
    users[username]["must_change_password"] = True
    save_users(users)
    print(f"\n✓ Password reset for '{username}'")
    print(f"  Temp password: {password}")
    print("  Give this to the tech — they'll be prompted to change it on first login.\n")

def remove_user(username):
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found.")
        return
    confirm = input(f"Remove '{username}' ({users[username]['display_name']})? [y/N] ")
    if confirm.lower() == 'y':
        del users[username]
        save_users(users)
        print(f"✓ User '{username}' removed.")

def list_users():
    users = load_users()
    if not users:
        print("No users configured.")
        return
    print(f"\n{'Username':<12} {'Display Name':<22} {'Role':<8} {'Must Change PW'}")
    print("-" * 60)
    for u, d in users.items():
        print(f"{u:<12} {d['display_name']:<22} {d['role']:<8} {'Yes' if d.get('must_change_password') else 'No'}")
    print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARIA User Management")
    parser.add_argument("--list",   action="store_true")
    parser.add_argument("--add",    metavar="USERNAME")
    parser.add_argument("--reset",  metavar="USERNAME")
    parser.add_argument("--remove", metavar="USERNAME")
    parser.add_argument("--role",   default="tech", choices=["tech","admin"])
    parser.add_argument("--name",   metavar="DISPLAY_NAME")
    args = parser.parse_args()

    if args.list:   list_users()
    elif args.add:  add_user(args.add, role=args.role, display_name=args.name)
    elif args.reset: reset_user(args.reset)
    elif args.remove: remove_user(args.remove)
    else:
        print("\nARIA User Management")
        print("====================")
        list_users()
        print("Commands: --add <user>  --reset <user>  --remove <user>  --list")
