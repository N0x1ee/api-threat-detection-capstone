"""Manage dashboard accounts (SRS v1.1 SEC-009, SEC-010, SEC-012).

    python manage_users.py add alice --role admin      (asks for the password twice)
    python manage_users.py add bob                     (role analyst)
    python manage_users.py passwd alice
    python manage_users.py disable bob
    python manage_users.py list
    python manage_users.py events                      (last 50 login attempts)

Uses the same database as the app (audit.db, or the AUDIT_DB environment variable).
Passwords are never shown or stored in plain text.
"""
import argparse
import getpass
import os
import sys
import time

from app.auth import ROLES, Auth, AuthError
from app.config import load_config

ROOT = os.path.dirname(os.path.abspath(__file__))


def ask_password(min_len):
    while True:
        p1 = getpass.getpass(f"  Password (at least {min_len} characters): ")
        p2 = getpass.getpass("  Repeat password: ")
        if p1 != p2:
            print("  Passwords do not match, try again.")
            continue
        return p1


def create_interactive(auth, role="admin", username=None):
    while True:
        name = username or input("  Username: ").strip()
        try:
            auth.add_user(name, ask_password(auth.cfg["min_password_length"]), role)
            print(f"  Account {name!r} created ({role}).")
            return name
        except AuthError as e:
            print(f"  {e}")
            if username:
                raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser(description="Manage dashboard accounts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("username")
    a.add_argument("--role", choices=ROLES, default="analyst")
    sub.add_parser("passwd").add_argument("username")
    sub.add_parser("disable").add_argument("username")
    sub.add_parser("list")
    sub.add_parser("events")
    args = ap.parse_args()

    cfg = load_config()
    auth = Auth(os.environ.get("AUDIT_DB", os.path.join(ROOT, "audit.db")), cfg["auth"])
    try:
        if args.cmd == "add":
            create_interactive(auth, args.role, args.username)
        elif args.cmd == "passwd":
            auth.set_password(args.username, ask_password(auth.cfg["min_password_length"]))
            print("  Password changed. Existing sessions for this user were ended.")
        elif args.cmd == "disable":
            auth.deactivate(args.username)
            print(f"  {args.username!r} can no longer sign in.")
        elif args.cmd == "list":
            for u in auth.list_users():
                print(f"  {u['username']:<20} {u['role']:<8} {'active' if u['active'] else 'disabled'}")
        elif args.cmd == "events":
            for e in auth.recent_events():
                print(f"  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['ts']))}  {e['outcome']:<13} "
                      f"{e['username']:<20} {e['ip']}")
    except AuthError as e:
        sys.exit(f"  {e}")


if __name__ == "__main__":
    main()
