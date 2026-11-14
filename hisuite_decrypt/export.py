"""Export decrypted Huawei Notepad (Memo.db) and Calendar (calendar.db) to open formats."""
from __future__ import annotations

import contextlib
import csv
import datetime as dt
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from defusedxml import ElementTree as ET

NOTES_T = "comhuaweiproviderNotePadbackupnote_items_tb"
NOTES_NEW = "comhuaweiproviderNotePadbackupnote_items_new_tb"
_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _local(ms: int | str, tz: dt.tzinfo | None) -> dt.datetime:
    return dt.datetime.fromtimestamp(int(ms) / 1000, tz).replace(tzinfo=None)


def _note_text(html_content: str | None, content: str | None) -> str:
    """Plain text of a note: from the structured XML if possible, else the raw content."""
    if html_content:
        try:
            root = ET.fromstring(html_content)
            lines = []
            for el in root:
                text = "".join(el.itertext())
                kind = (el.get("type") or "").lower()
                if kind.startswith("bullet"):
                    text = "\u2022 " + text
                elif kind.startswith(("todo", "check")):
                    text = ("[x] " if el.get("checked") in ("true", "1") else "[ ] ") + text
                lines.append(text)
            joined = "\n".join(lines).strip()
            if joined:
                return joined
        except ET.ParseError:
            pass
    return re.sub(r"^(Text|Bullet)\|", "", content or "").strip()


def export_notes(memo_db: Path, out_dir: Path, tz: dt.tzinfo | None = None) -> int:
    """Write ``notes.txt`` and ``notes.csv``; return the number of notes."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(memo_db)) as con:
        rows = con.execute(
            f"""SELECT t._id, t.content, t.created, t.modified, t.favorite, t.has_attachment,
                       n.html_content, n.has_todo
                FROM {NOTES_T} t JOIN {NOTES_NEW} n ON n._id = t._id
                WHERE n.delete_flag = '0' ORDER BY t.modified DESC"""
        ).fetchall()
    notes = []
    for r in rows:
        body = _note_text(r["html_content"], r["content"])
        title = (body.splitlines() or [""])[0][:80]
        notes.append((title, body, _local(r["created"], tz), _local(r["modified"], tz),
                      r["favorite"] == "1", r["has_todo"] == "1", r["has_attachment"] == "1"))
    with (out_dir / "notes.txt").open("w", encoding="utf-8") as f:
        f.write(f"NOTES: {len(notes)}\n{'=' * 70}\n\n")
        for i, (title, body, created, modified, fav, _todo, att) in enumerate(notes, 1):
            f.write(f"[{i}] {title or '(untitled)'}\nCreated: {created:%Y-%m-%d %H:%M}   "
                    f"Modified: {modified:%Y-%m-%d %H:%M}{'   *' if fav else ''}"
                    f"{'   [attachment]' if att else ''}\n{'-' * 70}\n{body}\n\n\n")
    with (out_dir / "notes.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["title", "body", "created", "modified", "favorite", "todo_list", "has_attachment"])
        for title, body, created, modified, fav, todo, att in notes:
            w.writerow([_ILLEGAL.sub("", title), _ILLEGAL.sub("", body), f"{created:%Y-%m-%d %H:%M}",
                        f"{modified:%Y-%m-%d %H:%M}", int(fav), int(todo), int(att)])
    return len(notes)


CALL_TYPES = {1: "incoming", 2: "outgoing", 3: "missed", 4: "voicemail", 5: "rejected", 6: "blocked"}
PHONE_TYPES = {"1": "HOME", "2": "CELL", "3": "WORK", "4": "WORK,FAX", "5": "HOME,FAX", "6": "PAGER", "7": "OTHER"}


def export_calls(calllog_db: Path, out_dir: Path, tz: dt.tzinfo | None = None) -> int:
    """Write ``calls.csv`` (date, number, type, duration in seconds); return row count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(calllog_db)) as con:
        rows = con.execute("SELECT number, date, duration, type FROM calls_tb ORDER BY date DESC").fetchall()
    with (out_dir / "calls.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["date", "number", "type", "duration_seconds"])
        for r in rows:
            w.writerow([f"{_local(r['date'], tz):%Y-%m-%d %H:%M:%S}", r["number"] or "",
                        CALL_TYPES.get(int(r["type"]), f"other({r['type']})"), r["duration"] or 0])
    return len(rows)


def _vcard_escape(s: str | None) -> str:
    return (s or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r", "").replace("\n", "\\n")


def export_contacts(contact_db: Path, out_dir: Path) -> int:
    """Write ``contacts.vcf`` (vCard 3.0) and ``contacts.csv``; return number of contacts."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(contact_db)) as con:
        raw = [r["_id"] for r in con.execute("SELECT _id FROM raw_contacts_tb ORDER BY _id")]
        data: dict[int, list[sqlite3.Row]] = defaultdict(list)
        for r in con.execute("SELECT * FROM data_tb"):
            data[r["raw_contact_id"]].append(r)
    cards, rows = [], []
    for cid in raw:
        name = given = family = org = title = note = ""
        phones: list[tuple[str, str]] = []
        emails: list[str] = []
        addresses: list[str] = []
        for d in data.get(cid, ()):
            kind = (d["mimetype"] or "").rsplit("/", 1)[-1]
            if kind == "name":
                name, given, family = d["data1"] or "", d["data2"] or "", d["data3"] or ""
            elif kind == "phone_v2" and d["data1"]:
                phones.append((str(d["data2"]), d["data1"]))
            elif kind == "email_v2" and d["data1"]:
                emails.append(d["data1"])
            elif kind == "organization":
                org, title = d["data1"] or "", d["data4"] or ""
            elif kind == "note":
                note = d["data1"] or ""
            elif kind == "postal-address_v2" and d["data1"]:
                addresses.append(d["data1"])
        if not (name or phones or emails or org):
            continue
        card = ["BEGIN:VCARD", "VERSION:3.0", f"FN:{_vcard_escape(name or (phones[0][1] if phones else org))}",
                f"N:{_vcard_escape(family)};{_vcard_escape(given)};;;"]
        card += [f"TEL;TYPE={PHONE_TYPES.get(t, 'VOICE')}:{n}" for t, n in phones]
        card += [f"EMAIL:{e}" for e in emails]
        if org or title:
            card.append(f"ORG:{_vcard_escape(org)}")
        if title:
            card.append(f"TITLE:{_vcard_escape(title)}")
        card += [f"ADR;TYPE=HOME:;;{_vcard_escape(a)};;;;" for a in addresses]
        if note:
            card.append(f"NOTE:{_vcard_escape(note)}")
        card.append("END:VCARD")
        cards.append("\r\n".join(_ics_fold(x) for x in card))
        rows.append([name, given, family, "; ".join(n for _, n in phones), "; ".join(emails), org, title, note])
    (out_dir / "contacts.vcf").write_bytes(("\r\n".join(cards) + "\r\n").encode("utf-8"))
    with (out_dir / "contacts.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "given_name", "family_name", "phones", "emails", "organization", "title", "note"])
        w.writerows(rows)
    return len(cards)


def _safe_name(name: str, limit: int = 80) -> str:
    """Make *name* safe as a single path component (no separators, no reserved characters)."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")[:limit] or "unnamed"


def export_messages(sms_db: Path, out_dir: Path, tz: dt.tzinfo | None = None, attachments: bool = True) -> int:
    """Write ``messages.csv`` (SMS and MMS text) and, unless *attachments* is False, extract MMS
    attachments to ``mms_attachments/<number>/``. The ``attachments`` column lists their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[int, list]] = []
    with contextlib.closing(_connect(sms_db)) as con:
        for r in con.execute("SELECT address, date, type, body FROM sms_tb"):
            direction = {1: "received", 2: "sent"}.get(int(r["type"]), f"other({r['type']})")
            rows.append((int(r["date"]), ["SMS", direction, r["address"] or "", _local(r["date"], tz), r["body"] or "", ""]))
        addr: dict[int, dict[int, str]] = defaultdict(dict)
        for a in con.execute("SELECT msg_id, address, type FROM addr_tb"):
            addr[a["msg_id"]][int(a["type"])] = a["address"]
        parts = defaultdict(list)
        for p in con.execute("SELECT _id, mid, ct, text, name, cl FROM part_tb"):
            parts[p["mid"]].append(p)
        has_blobs = con.execute("SELECT 1 FROM sqlite_master WHERE name = 'files_mms_tb'").fetchone() is not None
        for m in con.execute("SELECT _id, date, msg_box FROM pdu_tb"):
            incoming = int(m["msg_box"]) == 1
            direction = "received" if incoming else "sent"
            who = addr.get(m["_id"], {}).get(137 if incoming else 151, "") or ""
            text = "\n".join(p["text"] for p in parts.get(m["_id"], ()) if p["ct"] == "text/plain" and p["text"])
            ms = int(m["date"]) * 1000  # MMS dates are stored in seconds
            when = _local(ms, tz)
            saved: list[str] = []
            for p in parts.get(m["_id"], ()):
                if p["ct"] in ("text/plain", "application/smil"):
                    continue
                label = p["name"] or p["cl"] or "attachment"
                blob = con.execute("SELECT file_data FROM files_mms_tb WHERE _id = ?", (p["_id"],)).fetchone() \
                    if (attachments and has_blobs) else None
                if blob is not None and blob[0] is not None:
                    folder = out_dir / "mms_attachments" / _safe_name(who or "unknown")
                    folder.mkdir(parents=True, exist_ok=True)
                    path = folder / f"{when:%Y-%m-%d_%H-%M-%S}_{direction}_{p['_id']}_{_safe_name(label)}"
                    path.write_bytes(bytes(blob[0]))
                    os.utime(path, (ms / 1000, ms / 1000))
                    saved.append(path.relative_to(out_dir).as_posix())
                else:
                    saved.append(f"{label} [not extracted]")
            rows.append((ms, ["MMS", direction, who, when, text, "; ".join(saved)]))
    rows.sort(key=lambda x: x[0], reverse=True)
    with (out_dir / "messages.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "direction", "address", "date", "body", "attachments"])
        for _, (kind, direction, who, when, body, files) in rows:
            w.writerow([kind, direction, who, f"{when:%Y-%m-%d %H:%M:%S}", _ILLEGAL.sub("", body), files])
    return len(rows)


def _ics_escape(s: str | None) -> str:
    return (s or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r", "").replace("\n", "\\n")


def _ics_fold(line: str) -> str:
    raw, parts = line.encode("utf-8"), []
    while len(raw) > 74:
        cut = 74
        while (raw[cut] & 0xC0) == 0x80:  # never split a UTF-8 sequence
            cut -= 1
        parts.append(raw[:cut].decode("utf-8"))
        raw = raw[cut:]
    parts.append(raw.decode("utf-8"))
    return "\r\n ".join(parts)


def export_calendar(calendar_db: Path, out_dir: Path, tz: dt.tzinfo | None = None) -> int:
    """Write ``calendar.ics`` (importable anywhere) and ``calendar.csv``; return event count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(calendar_db)) as con:
        events = con.execute("SELECT * FROM Events_tb WHERE deleted = 0 ORDER BY dtstart").fetchall()
        reminders: dict[int, set[int]] = defaultdict(set)
        for r in con.execute("SELECT event_id, minutes FROM Reminds_tb"):
            if r["minutes"] is not None and r["minutes"] >= 0:
                reminders[r["event_id"]].add(r["minutes"])

    utc = dt.timezone.utc
    stamp = dt.datetime.now(utc).strftime("%Y%m%dT%H%M%SZ")
    ics = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//hisuite-backup-decrypt//EN", "CALSCALE:GREGORIAN"]
    csv_rows = []
    for r in events:
        allday = bool(r["allDay"])
        start = dt.datetime.fromtimestamp(int(r["dtstart"]) / 1000, utc)
        end = dt.datetime.fromtimestamp(int(r["dtend"]) / 1000, utc) if r["dtend"] else None
        ics += ["BEGIN:VEVENT", f"UID:hisuite-{r['_id']}@backup", f"DTSTAMP:{stamp}"]
        if allday:
            ics.append(f"DTSTART;VALUE=DATE:{start:%Y%m%d}")
            if end:
                ics.append(f"DTEND;VALUE=DATE:{end:%Y%m%d}")
            elif r["duration"]:
                ics.append(f"DURATION:{r['duration']}")
        else:
            ics.append(f"DTSTART:{start:%Y%m%dT%H%M%SZ}")
            if r["rrule"] and r["duration"]:
                ics.append(f"DURATION:{r['duration']}")
            elif end:
                ics.append(f"DTEND:{end:%Y%m%dT%H%M%SZ}")
        ics.append(f"SUMMARY:{_ics_escape(r['title'])}")
        if r["eventLocation"]:
            ics.append(f"LOCATION:{_ics_escape(r['eventLocation'])}")
        if r["description"]:
            ics.append(f"DESCRIPTION:{_ics_escape(r['description'])}")
        if r["rrule"]:
            ics.append(f"RRULE:{r['rrule']}")
        for minutes in sorted(reminders.get(r["_id"], ())):
            ics += ["BEGIN:VALARM", "ACTION:DISPLAY", "DESCRIPTION:Reminder", f"TRIGGER:-PT{minutes}M", "END:VALARM"]
        ics.append("END:VEVENT")
        csv_rows.append([
            _ILLEGAL.sub("", r["title"] or ""),
            f"{start:%Y-%m-%d}" if allday else f"{_local(r['dtstart'], tz):%Y-%m-%d %H:%M}",
            (f"{end:%Y-%m-%d}" if allday else f"{_local(r['dtend'], tz):%Y-%m-%d %H:%M}") if end else "",
            int(allday), r["eventLocation"] or "", _ILLEGAL.sub("", r["description"] or ""), r["rrule"] or "",
        ])
    ics.append("END:VCALENDAR")
    (out_dir / "calendar.ics").write_bytes(("\r\n".join(_ics_fold(x) for x in ics) + "\r\n").encode("utf-8"))
    with (out_dir / "calendar.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["title", "start", "end", "all_day", "location", "description", "rrule"])
        w.writerows(csv_rows)
    return len(events)
