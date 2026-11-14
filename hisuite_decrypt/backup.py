"""Reading a HiSuite backup folder and decrypting its modules."""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree as ET

from . import crypto

MODULE_TABLES = (
    "BackupFileModuleInfo",
    "BackupFileModuleInfo_SystemData",
    "BackupFileModuleInfo_Media",
)
SQLITE_MAGIC = b"SQLite format 3\x00"


@dataclass
class Module:
    name: str
    table: str
    enc_msg: str
    check_msg: str | None
    record_total: int | None = None


@dataclass
class Result:
    module: str
    source: Path
    target: Path | None
    status: str  # "ok", "ok-legacy-ctr", "skipped", "failed"
    detail: str = ""


def _columns(row) -> dict[str, str]:
    cols: dict[str, str] = {}
    for col in row.findall("column"):
        value = col.find("value")
        if value is None:
            continue
        for attr in ("String", "Integer", "Long", "Boolean"):
            if value.get(attr) is not None:
                cols[col.get("name", "")] = value.get(attr)
                break
    return cols


def parse_info_xml(path: Path) -> list[Module]:
    """Return modules that carry encryption material (``encMsgV3``)."""
    modules: list[Module] = []
    root = ET.parse(path).getroot()
    if root is None:
        raise ValueError(f"{path} has no root element")
    for row in root.iter("row"):
        if row.get("table") not in MODULE_TABLES:
            continue
        cols = _columns(row)
        if cols.get("name") and cols.get("encMsgV3"):
            total = cols.get("recordTotal")
            modules.append(Module(
                name=cols["name"],
                table=row.get("table", ""),
                enc_msg=cols["encMsgV3"].strip(),
                check_msg=(cols.get("checkMsgV3") or "").strip() or None,
                record_total=int(total) if total and total.lstrip("-").isdigit() else None,
            ))
    return modules


def read_ini(path: Path) -> dict[str, dict[str, str]]:
    """Read ``backupinfo.ini`` (raw values, no interpolation)."""
    class _CaseSensitiveParser(configparser.RawConfigParser):
        def optionxform(self, optionstr: str) -> str:  # keep key case
            return optionstr

    parser = _CaseSensitiveParser(strict=False)
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):  # HiSuite 14 writes UTF-16 with BOM
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    parser.read_string(text)
    return {s: dict(parser.items(s)) for s in parser.sections()}


def describe(backup: Path) -> dict:
    """Non-secret summary of a backup folder (never includes salts or key material)."""
    ini = read_ini(backup / "backupinfo.ini") if (backup / "backupinfo.ini").is_file() else {}
    head = ini.get("headerinfo", {})
    return {
        "hisuite_version": head.get("hisuiteversion"),
        "model": head.get("protuct_model") or head.get("product_model"),
        "backup_time": head.get("backup_time"),
        "encrypted": head.get("isencypt") == "1",
        "modules": [(m.name, m.record_total) for m in parse_info_xml(backup / "info.xml")],
    }


def locate_files(backup: Path, module: Module) -> list[Path]:
    """Find encrypted files that belong to *module* (``<name>.db``, ``<name>/...``, ...)."""
    by_lower = {p.name.lower(): p for p in backup.iterdir() if not _is_junk(p)}
    found: list[Path] = []
    for suffix in (".db", ".tar", ".zip", ""):
        p = by_lower.get((module.name + suffix).lower())
        if p is not None and p.is_file():
            found.append(p)
    folder = by_lower.get(module.name.lower())
    if folder is not None and folder.is_dir():
        found.extend(sorted(f for f in folder.rglob("*") if f.is_file() and not _is_junk(f)))
    return found


JUNK_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}


def _is_junk(path: Path) -> bool:
    """OS metadata that is not part of the backup (macOS ``._*`` AppleDouble files, thumbnails)."""
    name = path.name.lower()
    return name.startswith("._") or name in JUNK_NAMES


def verify_password(backup: Path, password: bytes) -> dict[str, bool | None]:
    """Check *password* against ``checkMsgV3`` of every module. None = cannot tell."""
    out: dict[str, bool | None] = {}
    for module in parse_info_xml(backup / "info.xml"):
        files = locate_files(backup, module)
        if not module.check_msg or not files:
            out[module.name] = None
            continue
        out[module.name] = crypto.verify_check_msg(password, module.check_msg, files[0].read_bytes())
    return out


def decrypt_backup(backup: Path, out_dir: Path, password: bytes, *, allow_legacy: bool = True) -> list[Result]:
    """Decrypt every module found in *backup* into *out_dir*.

    Raises :class:`crypto.WrongPasswordError` if the password fails ``checkMsgV3`` for
    every module that can be checked, so that a typo gives a clear error up front.
    """
    checks = verify_password(backup, password)
    checked = [v for v in checks.values() if v is not None]
    if checked and not any(checked):
        raise crypto.WrongPasswordError(
            "the password does not match checkMsgV3 of any module: either it is wrong, or the backup "
            "comes from an unsupported HiSuite version (for HiSuite 10.x and older use kobackupdec)")

    results: list[Result] = []
    for module in parse_info_xml(backup / "info.xml"):
        for src in locate_files(backup, module):
            if src.name.lower().endswith(".enc"):
                # Multimedia archives use a different key scheme that is not understood yet.
                results.append(Result(module.name, src, None, "skipped", "multimedia (.enc) is not supported"))
                continue
            rel = src.relative_to(backup)
            dst = out_dir / (rel if len(rel.parts) > 1 else Path(src.name))
            data = src.read_bytes()
            try:
                plain = crypto.decrypt_gcm(password, module.enc_msg, data)
                status, detail = "ok", "AES-GCM, tag verified"
            except (crypto.WrongPasswordError, ValueError) as exc:
                plain = None
                status, detail = "failed", str(exc)
                if allow_legacy and src.suffix.lower() == ".db":
                    candidate = crypto.decrypt_ctr_legacy(password, module.enc_msg, data)
                    if candidate.startswith(SQLITE_MAGIC):
                        plain, status, detail = candidate, "ok-legacy-ctr", "AES-CTR (unauthenticated), SQLite header found"
            if plain is None:
                results.append(Result(module.name, src, None, "failed", detail))
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(plain)
            results.append(Result(module.name, src, dst, status, detail))
    return results
