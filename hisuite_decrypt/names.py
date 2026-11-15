"""Resolve phone numbers to contact names using the backup's ``contact.db``.

Numbers are compared by their digits only. The full digit string is tried first, then the last
9 digits (so ``+48 600 100 200``, ``0048600100200`` and ``600100200`` all match the same contact).
A number that belongs to two different contacts is treated as unknown rather than guessed.
Non-numeric senders such as ``ORANGE`` are left alone.
"""
from __future__ import annotations

import contextlib
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .export import _connect, _safe_name

STYLES = ("both", "name", "number")
_NON_DIGITS = re.compile(r"\D")
TAIL = 9


def _digits(number: str) -> str:
    return _NON_DIGITS.sub("", number or "")


def _keys(number: str) -> list[str]:
    d = _digits(number)
    if len(d) < 3:                      # too short to be a reliable phone number
        return []
    keys = [d]
    if len(d) > TAIL:
        keys.append(d[-TAIL:])
    return keys


def _compact(number: str) -> str:
    return re.sub(r"[\s\-()]", "", number or "")


def _vcard_unescape(value: str) -> str:
    return (value.replace("\\n", " ").replace("\\N", " ").replace("\\,", ",")
            .replace("\\;", ";").replace("\\\\", "\\"))


def preferred_forms(addresses) -> dict[str, str]:
    """Map the last digits of every plain phone number to its most complete spelling
    (preferring ``+48...`` over ``48...`` over ``600...``), so that all spellings of one number
    can share a single folder name."""
    best: dict[str, str] = {}
    for address in addresses:
        if not address or "~" in address or not any(ch.isdigit() for ch in address):
            continue
        digits = _digits(address)
        if len(digits) < TAIL:
            continue
        key = digits[-TAIL:]
        rank = (address.lstrip().startswith("+"), len(digits))
        current = best.get(key)
        if current is None or rank > (current.lstrip().startswith("+"), len(_digits(current))):
            best[key] = _compact(address)
    return best


class ContactNames:
    """Lookup table ``number -> contact name``."""

    def __init__(self, entries: dict[str, set[str]] | None = None, primary: dict[str, str] | None = None):
        self._by_key: dict[str, set[str]] = entries or {}
        self._primary: dict[str, str] = primary or {}     # contact name -> its first stored number

    def __len__(self) -> int:
        return len({name for names in self._by_key.values() for name in names})

    @classmethod
    def from_contact_db(cls, path: Path) -> "ContactNames":
        entries: dict[str, set[str]] = defaultdict(set)
        with contextlib.closing(_connect(path)) as con:
            names: dict[int, str] = {}
            phones: dict[int, list[str]] = defaultdict(list)
            for r in con.execute("SELECT raw_contact_id, mimetype, data1, data2, data3 FROM data_tb"):
                kind = (r["mimetype"] or "").rsplit("/", 1)[-1]
                if kind == "name":
                    full = (r["data1"] or "").strip() or f"{r['data2'] or ''} {r['data3'] or ''}".strip()
                    if full:
                        names[r["raw_contact_id"]] = full
                elif kind == "phone_v2" and r["data1"]:
                    phones[r["raw_contact_id"]].append(r["data1"])
        primary: dict[str, str] = {}
        for cid, numbers in sorted(phones.items()):
            name = names.get(cid)
            if not name:
                continue
            primary.setdefault(name, _compact(numbers[0]))
            for number in numbers:
                for key in _keys(number):
                    entries[key].add(name)
        return cls(dict(entries), primary)

    def add_vcard(self, path: Path) -> int:
        """Add contacts from a vCard file (e.g. exported from Google Contacts).

        Contacts already known from ``contact.db`` win: a number that is already present keeps its
        name. Returns the number of contacts read from the file."""
        text = Path(path).read_bytes().decode("utf-8-sig", errors="replace")
        text = text.replace("\r\n", "\n").replace("\r", "\n")      # any line-ending style
        text = re.sub(r"\n[ \t]", "", text)                        # unfold continued lines
        added = 0
        for card in re.findall(r"BEGIN:VCARD(.*?)END:VCARD", text, re.S | re.I):
            name, numbers = "", []
            for line in card.splitlines():
                key, _, value = line.partition(":")
                prop = key.split(";")[0].rsplit(".", 1)[-1].upper()      # drops 'item1.' prefixes
                value = _vcard_unescape(value.strip())
                if prop == "FN" and value:
                    name = value
                elif prop == "N" and not name:
                    family, _, given = value.partition(";")
                    name = f"{given.split(';')[0]} {family}".strip()
                elif prop == "TEL" and value:
                    numbers.append(value)
            if not (name and numbers):
                continue
            added += 1
            self._primary.setdefault(name, _compact(numbers[0]))
            for number in numbers:
                for key in _keys(number):
                    if key not in self._by_key:                 # contact.db wins over the extra file
                        self._by_key[key] = {name}
        return added

    def _single(self, number: str) -> str | None:
        for key in _keys(number):
            found = self._by_key.get(key)
            if found and len(found) == 1:
                return next(iter(found))
            if found and len(found) > 1:
                return None            # ambiguous: do not guess
        return None

    def lookup(self, address: str) -> str:
        """Name(s) for *address* (``a~b`` for group messages); empty string if unknown."""
        parts = [p for p in (address or "").split("~") if p]
        if not parts:
            return ""
        resolved = [self._single(p) for p in parts]
        if not any(resolved):
            return ""
        return ", ".join(name or number for name, number in zip(resolved, parts))

    def label(self, address: str, style: str = "both", preferred: dict[str, str] | None = None) -> str:
        """A path-safe label for *address*: ``Name (number)``, ``Name`` or the bare number.

        All spellings of one number give the same label: a known contact is shown with the number
        stored in the contact, an unknown number with its most complete spelling (*preferred*,
        see :func:`preferred_forms`)."""
        address = address or "unknown"
        if style not in STYLES:
            raise ValueError(f"style must be one of {STYLES}")
        name = self.lookup(address) if style != "number" else ""
        digits = _digits(address)
        plain = "~" not in address and len(digits) >= TAIL
        shown = (preferred or {}).get(digits[-TAIL:], address) if plain else address
        if not name:
            return _safe_name(shown)
        if style == "name":
            return _safe_name(name)
        if name in self._primary:                               # a single known contact
            return _safe_name(f"{name} ({self._primary[name]})")
        return _safe_name(f"{name} ({address.replace('~', ', ')})")   # a group message
