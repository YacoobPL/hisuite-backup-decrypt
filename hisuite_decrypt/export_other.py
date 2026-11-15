"""Readable exports for the remaining (settings-like) databases of a HiSuite backup.

* ``alarm.db``      -> ``alarms.csv``
* ``wifiConfig.db`` -> ``wifi.csv`` (passwords only with ``include_secrets``)
* every other database -> one CSV per table in ``other/<database>/`` (blobs become ``<N bytes>``)
* ``*_attachment`` tables (files stored in chunks) are reassembled into real files;
  ZIP archives are unpacked safely.

Databases that may hold secrets (``wifiConfig.db``, ``smartcare.db``) are only dumped in full when
``include_secrets`` is True.
"""
from __future__ import annotations

import contextlib
import csv
import re
import sqlite3
import zipfile
from pathlib import Path

from .export import _ILLEGAL, _connect, _safe_name, fit_filename

HANDLED_BY_OTHER_EXPORTERS = {"memo.db", "calendar.db", "contact.db", "calllog.db", "sms.db"}
SECRET_DBS = {"wificonfig.db", "smartcare.db"}
_BORING_TABLE = re.compile(r"(_uri_info|_version_info|_open_file_info|_copy_file_list_info|_default_file_list_info)$")
MAX_UNPACKED_BYTES = 1 << 30  # refuse ZIP bombs larger than 1 GiB


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{len(bytes(value))} bytes>"
    return _ILLEGAL.sub("", str(value))


def _tables(con: sqlite3.Connection) -> list[str]:
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _is_attachment_table(con: sqlite3.Connection, table: str) -> bool:
    cols = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
    return {"file_data", "data_index", "file_length"} <= cols


def dump_tables(db: Path, out_dir: Path) -> int:
    """Write one CSV per table (skipping bookkeeping and attachment tables); return the count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    with contextlib.closing(_connect(db)) as con:
        for table in _tables(con):
            if _BORING_TABLE.search(table) or _is_attachment_table(con, table):
                continue
            cur = con.execute(f'SELECT * FROM "{table}"')
            rows = cur.fetchall()
            if not rows:
                continue
            headers = [d[0] for d in cur.description]
            with (out_dir / fit_filename(out_dir, f"{_safe_name(table, 100)}.csv")).open(
                    "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(headers)
                for r in rows:
                    w.writerow([_cell(v) for v in r])
            written += 1
    return written


def _guess_extension(data: bytes) -> str:
    for magic, ext in ((b"\x89PNG", ".png"), (b"\xff\xd8\xff", ".jpg"), (b"GIF8", ".gif"),
                       (b"SQLite format 3\x00", ".db"), (b"%PDF", ".pdf"), (b"PK\x03\x04", ".zip")):
        if data.startswith(magic):
            return ext
    return ".bin"


def extract_attachments(db: Path, out_dir: Path) -> list[str]:
    """Reassemble chunked ``*_attachment`` tables into files; unpack ZIPs. Returns relative paths."""
    produced: list[str] = []
    with contextlib.closing(_connect(db)) as con:
        for table in _tables(con):
            if not _is_attachment_table(con, table):
                continue
            chunks = [bytes(r[0]) for r in con.execute(
                f'SELECT file_data FROM "{table}" WHERE file_data IS NOT NULL ORDER BY data_index')]
            if not chunks:
                continue
            data = b"".join(chunks)
            out_dir.mkdir(parents=True, exist_ok=True)
            ext = _guess_extension(data)
            target = out_dir / fit_filename(out_dir, f"{_safe_name(table, 100)}{ext}")
            target.write_bytes(data)
            produced.append(target.relative_to(out_dir).as_posix())
            if ext == ".zip" and zipfile.is_zipfile(target):
                produced += _unpack_zip(target, out_dir / fit_filename(out_dir, _safe_name(table, 100)), out_dir)
    return produced


def _unpack_zip(archive: Path, dest: Path, root: Path) -> list[str]:
    """Extract only file names (never paths), with a total-size cap."""
    produced: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
            return produced
        dest.mkdir(parents=True, exist_ok=True)
        used: set[str] = set()
        for n, info in enumerate(infos, 1):
            data = zf.read(info)
            name = _safe_name(Path(info.filename.replace("\\", "/")).name.split("$")[-1])
            kind = ".hwgraffi" if data.startswith(b"HWGRAFFI") else _guess_extension(data)
            if kind != ".bin" and Path(name).suffix.lower() != kind:
                name = Path(name).stem + kind          # trust the content, not the stored extension
            if name.lower() in used:
                name = f"{n}_{name}"
            used.add(name.lower())
            path = dest / name
            path.write_bytes(data)
            produced.append(path.relative_to(root).as_posix())
    return produced


def export_alarms(db: Path, out_dir: Path) -> int:
    """Write ``alarms.csv``; ``days_raw`` is the stored bit mask (not interpreted)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(db)) as con:
        rows = con.execute("SELECT * FROM deskclock_alarm_tb").fetchall()
    rows.sort(key=lambda r: (int(r["hour"] or 0), int(r["minutes"] or 0)))
    keys = lambda r: set(r.keys())  # noqa: E731
    with (out_dir / "alarms.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "enabled", "days_raw", "message", "vibrate", "snooze_times", "snooze_duration", "ring_duration"])
        for r in rows:
            get = lambda k: r[k] if k in keys(r) else ""  # noqa: E731
            w.writerow([f"{int(r['hour']):02d}:{int(r['minutes']):02d}", get("enabled"), get("daysofweek"),
                        _cell(get("message")), get("vibrate"), get("snoozetimes"), get("snoozeduration"),
                        get("ringduration")])
    return len(rows)


def export_wifi(db: Path, out_dir: Path, include_secrets: bool = False) -> int:
    """Write ``wifi.csv``. The ``password`` column stays empty unless *include_secrets* is set."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(_connect(db)) as con:
        rows = con.execute("SELECT * FROM wifiConfig").fetchall()
    strip = lambda v: (v or "").strip('"')  # noqa: E731
    with (out_dir / "wifi.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ssid", "security", "hidden", "password", "static_ip", "gateway", "dns1", "dns2", "proxy"])
        for r in rows:
            keys = set(r.keys())
            get = lambda k: r[k] if k in keys else ""  # noqa: E731
            secret = strip(get("psk")) or strip(get("wep_key0"))
            proxy = f"{get('Host')}:{get('Port')}" if get("Host") else ""
            w.writerow([strip(get("ssid")), get("key_mgmt") or "", get("hiddenSSID") or 0,
                        secret if include_secrets else "", get("IPAddress") or "", get("GateWay") or "",
                        get("DNS1") or "", get("DNS2") or "", proxy])
    return len(rows)


def export_others(folder: Path, out_dir: Path, include_secrets: bool = False) -> list[str]:
    """Export every database in *folder* that has no dedicated exporter. Returns summary lines."""
    summary: list[str] = []
    seen: set[str] = set()
    for db in sorted(folder.rglob("*.db")):
        key = db.name.lower()
        if key in HANDLED_BY_OTHER_EXPORTERS or key in seen:
            continue
        if {"attachments", "note_attachments", "other"} & set(db.relative_to(folder).parts[:-1]):
            continue  # a database extracted from an attachment by an earlier export, not part of the backup
        seen.add(key)
        stem = db.stem
        if key == "alarm.db":
            summary.append(f"alarms:           {export_alarms(db, out_dir)} -> alarms.csv")
            continue
        if key == "wificonfig.db":
            n = export_wifi(db, out_dir, include_secrets)
            note = "" if include_secrets else " (passwords left out; use --include-secrets)"
            summary.append(f"wifi networks:    {n} -> wifi.csv{note}")
            continue  # never dump this database in full without a dedicated, secret-aware exporter
        if key in SECRET_DBS and not include_secrets:
            summary.append(f"{db.name}: skipped (may contain card numbers or other secrets; use --include-secrets)")
            continue
        target = out_dir / "other" / stem
        tables = dump_tables(db, target)
        files = extract_attachments(db, target / "attachments")
        if tables or files:
            summary.append(f"{db.name + ':':<17} {tables} tables, {len(files)} files -> other/{stem}/")
    return summary
