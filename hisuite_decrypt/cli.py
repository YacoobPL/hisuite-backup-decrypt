"""Command line interface: ``python -m hisuite_decrypt <command> ...``."""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import os
import sys
from pathlib import Path

from . import backup, crypto, export, export_other
from .names import STYLES, ContactNames

NAMES_HELP = ("how MMS attachment folders are named: 'both' = 'Name (number)' (default), 'name' = 'Name', "
              "'number'; the CSV files always get a name column when the number matches a contact")
VCF_HELP = ("an extra vCard file (e.g. exported from Google Contacts) used to name numbers that are not in the "
            "backup's own contacts; may be given several times. HiSuite backs up only the phone's local contacts")
SECRETS_HELP = ("also export Wi-Fi passwords and the smartcare database (which may contain card numbers); "
                "off by default")


def _password(args: argparse.Namespace) -> bytes:
    """Password from --password-file, $HISUITE_PASSWORD or an interactive prompt.

    There is deliberately no ``--password`` flag: command-line arguments end up in shell
    history and process listings.
    """
    if args.password_file:
        return Path(args.password_file).read_text(encoding="utf-8").rstrip("\r\n").encode("utf-8")
    env = os.environ.get("HISUITE_PASSWORD")
    if env:
        return env.encode("utf-8")
    return getpass.getpass("Backup password: ").encode("utf-8")


def _tz(name: str | None) -> dt.tzinfo | None:
    if not name:
        return None  # system local time
    from zoneinfo import ZoneInfo
    return ZoneInfo(name)


def cmd_info(args: argparse.Namespace) -> int:
    info = backup.describe(Path(args.backup))
    print(f"Model:          {info['model']}")
    print(f"HiSuite:        {info['hisuite_version']}")
    print(f"Backup time:    {info['backup_time']}")
    print(f"Encrypted:      {info['encrypted']}")
    print("Modules:")
    for name, total in info["modules"]:
        print(f"  {name:<20} {total if total is not None else '?'} records")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    checks = backup.verify_password(Path(args.backup), _password(args))
    for name, ok in checks.items():
        print(f"  {name:<20} {'password OK' if ok else 'WRONG PASSWORD' if ok is False else 'cannot check'}")
    return 0 if all(v is not False for v in checks.values()) and any(v for v in checks.values()) else 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    out = Path(args.output)
    if out.exists() and any(out.iterdir()):
        print(f"error: {out} already exists and is not empty", file=sys.stderr)
        return 2
    try:
        results = backup.decrypt_backup(Path(args.backup), out, _password(args))
    except crypto.WrongPasswordError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for r in results:
        print(f"  [{r.status:<13}] {r.module:<20} {r.source.name}  ({r.detail})")
    failed = sum(r.status == "failed" for r in results)
    skipped = sum(r.status == "skipped" for r in results)
    print(f"{len(results) - failed - skipped} decrypted, {skipped} skipped, {failed} failed -> {out}")
    if results and failed == len(results):
        print("hint: every module failed. The password may be wrong, or the backup may come from an "
              "unsupported HiSuite version (10.x and older: use kobackupdec).", file=sys.stderr)
    if args.export:
        _export_from(out, out / "export", _tz(args.timezone), args.include_secrets, args.names, args.contacts_vcf)
    return 1 if failed and failed == len(results) else 0


def _export_from(folder: Path, out: Path, tz: dt.tzinfo | None, include_secrets: bool = False,
                 name_style: str = "both", contact_files: list[str] | None = None) -> None:
    """Export every database we know how to turn into an open format."""
    contact_db = next(folder.rglob("contact.db"), None)
    contacts = ContactNames.from_contact_db(contact_db) if contact_db is not None else None
    for vcf in contact_files or []:
        contacts = contacts if contacts is not None else ContactNames()
        print(f"{'contacts file:':<17} {contacts.add_vcard(Path(vcf))} contacts read from {vcf}")
    jobs = (
        ("Memo.db", "notes", lambda p: export.export_notes(p, out, tz)),
        ("calendar.db", "calendar events", lambda p: export.export_calendar(p, out, tz)),
        ("contact.db", "contacts", lambda p: export.export_contacts(p, out)),
        ("calllog.db", "calls", lambda p: export.export_calls(p, out, tz, names=contacts)),
        ("sms.db", "messages", lambda p: export.export_messages(p, out, tz, names=contacts, folder_style=name_style)),
    )
    done = 0
    for filename, label, run in jobs:
        db = next(folder.rglob(filename), None)
        if db is not None:
            print(f"{label + ':':<17} {run(db)} -> {out}")
            done += 1
    memo = next(folder.rglob("Memo.db"), None)
    if memo is not None:
        files = export_other.extract_attachments(memo, out / "note_attachments")
        if files:
            print(f"{'note attachments:':<17} {len(files)} files -> {out / 'note_attachments'}")
    for line in export_other.export_others(folder, out, include_secrets):
        print(line)
        done += 1
    if not done:
        print("nothing to export (no known database found)")


def cmd_export(args: argparse.Namespace) -> int:
    folder = Path(args.decrypted)
    _export_from(folder, Path(args.output), _tz(args.timezone), args.include_secrets, args.names, args.contacts_vcf)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hisuite-decrypt", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def add_pw(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--password-file", help="file whose first line is the backup password "
                        "(otherwise $HISUITE_PASSWORD or an interactive prompt is used)")

    sp = sub.add_parser("info", help="show non-secret metadata of a backup folder")
    sp.add_argument("backup")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("verify", help="check the password against checkMsgV3 (decrypts nothing)")
    sp.add_argument("backup")
    add_pw(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("decrypt", help="decrypt all modules into a new folder")
    sp.add_argument("backup")
    sp.add_argument("output")
    sp.add_argument("--export", action="store_true", help="also export everything to open formats")
    sp.add_argument("--timezone", help="IANA zone for CSV/TXT timestamps, e.g. Europe/Warsaw (default: system)")
    sp.add_argument("--include-secrets", action="store_true", help=SECRETS_HELP)
    sp.add_argument("--names", choices=STYLES, default="both", help=NAMES_HELP)
    sp.add_argument("--contacts-vcf", action="append", metavar="FILE", help=VCF_HELP)
    add_pw(sp)
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("export", help="export Memo.db / calendar.db found in a decrypted folder")
    sp.add_argument("decrypted")
    sp.add_argument("output")
    sp.add_argument("--timezone", help="IANA zone, e.g. Europe/Warsaw (default: system)")
    sp.add_argument("--include-secrets", action="store_true", help=SECRETS_HELP)
    sp.add_argument("--names", choices=STYLES, default="both", help=NAMES_HELP)
    sp.add_argument("--contacts-vcf", action="append", metavar="FILE", help=VCF_HELP)
    sp.set_defaults(func=cmd_export)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
