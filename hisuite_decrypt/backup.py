"""Reading a HiSuite backup folder and decrypting its modules."""
from __future__ import annotations

import configparser
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

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
                continue  # multimedia: different scheme, handled by decrypt_media() below
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
    results.extend(decrypt_media(backup, out_dir, password))
    return results


TAR_MAGIC = b"ustar"
TAR_MAGIC_OFFSET = 257


def _media_ivs(backup: Path, header: dict[str, str]) -> dict[Path, bytes]:
    """Map every encrypted multimedia file to its IV (from ``<module>.xml`` and ``backupinfo.ini``)."""
    root = backup.resolve()
    ivs: dict[Path, bytes] = {}
    for xml in sorted(backup.glob("*.xml")):
        if _is_junk(xml) or xml.name.lower() == "info.xml":
            continue
        try:
            tree = ET.parse(xml).getroot()
        except Exception:  # unreadable / not a multimedia list: ignore
            continue
        if tree is None:
            continue
        for entry in tree.iter("File"):
            rel, iv = (entry.findtext("Path") or "").strip(), (entry.findtext("Iv") or "").strip()
            if not rel or not iv:
                continue
            parts = [p for p in PureWindowsPath(rel).parts if p not in ("\\", "/")]
            target = (backup / xml.stem / Path(*parts)).with_name(PureWindowsPath(rel).name + ".enc").resolve()
            try:
                target.relative_to(root)           # never follow a crafted Path out of the backup
                ivs[target] = bytes.fromhex(iv)
            except ValueError:
                continue
    for kind in ("image", "video"):
        iv = header.get(f"{kind}_iv", "").strip()
        if iv:
            try:
                ivs[(backup / f"{kind}_MediaInfo.db.enc").resolve()] = bytes.fromhex(iv)
            except ValueError:
                continue
    return ivs


def decrypt_media(backup: Path, out_dir: Path, password: bytes) -> list[Result]:
    """Decrypt ``*.tar.enc`` archives and ``*_MediaInfo.db.enc`` (see :mod:`crypto` for the scheme).

    The files carry no authentication tag, so the password is checked by looking at the
    decrypted header: ``ustar`` for a tar, the SQLite magic for a database.
    """
    enc_files = sorted(p for p in backup.rglob("*") if p.is_file() and p.name.lower().endswith(".enc") and not _is_junk(p))
    if not enc_files:
        return []
    ini_path = backup / "backupinfo.ini"
    header = read_ini(ini_path).get("headerinfo", {}) if ini_path.is_file() else {}
    ivs = _media_ivs(backup, header)
    try:
        key = crypto.derive_media_key(password, bytes.fromhex(header.get("derivedSalt", "").strip()))
    except ValueError:
        key = None
    results: list[Result] = []
    for src in enc_files:
        rel = src.relative_to(backup)
        module = rel.parts[0] if len(rel.parts) > 1 else src.name.split(".")[0]
        iv = ivs.get(src.resolve())
        lower = src.name.lower()
        if key is None:
            results.append(Result(module, src, None, "skipped", "backupinfo.ini has no usable derivedSalt"))
        elif iv is None:
            results.append(Result(module, src, None, "skipped", "no IV found for this file (<module>.xml / backupinfo.ini)"))
        elif not lower.endswith((".tar.enc", ".db.enc")):
            results.append(Result(module, src, None, "skipped", "unknown multimedia file type"))
        else:
            head = crypto.decrypt_media_head(key, iv, src, TAR_MAGIC_OFFSET + 8)
            good = (head[TAR_MAGIC_OFFSET:TAR_MAGIC_OFFSET + 5] == TAR_MAGIC if lower.endswith(".tar.enc")
                    else head.startswith(SQLITE_MAGIC))
            if not good:
                results.append(Result(module, src, None, "failed",
                                      "header check failed: wrong password or a scheme this tool does not know"))
                continue
            dst = out_dir / rel.with_name(src.name[:-4])
            crypto.decrypt_media_file(key, iv, src, dst)
            results.append(Result(module, src, dst, "ok", "AES-256-CTR (scrypt key), header verified"))
    return results


def extract_archives(results: list[Result], out_dir: Path, *, keep_archives: bool = False) -> list[Result]:
    """Unpack the decrypted ``*.tar`` archives into ``<out_dir>/media/<module>/``.

    Only regular files are written; absolute paths, ``..`` and links are refused, so a crafted
    archive cannot write outside the target folder. The intermediate ``.tar`` is deleted unless
    *keep_archives* is true.
    """
    done: list[Result] = []
    for r in results:
        if r.status != "ok" or r.target is None or r.target.suffix.lower() != ".tar":
            continue
        dest = out_dir / "media" / r.module
        count = skipped = 0
        try:
            with tarfile.open(r.target) as tar:
                for member in tar:
                    parts = PurePosixPath(member.name.replace("\\", "/")).parts
                    if (not member.isreg() or not parts or parts[0] == "/" or ".." in parts
                            or PureWindowsPath(*parts).anchor):     # drive letters / UNC: refuse
                        skipped += 1
                        continue
                    target = dest.joinpath(*parts)
                    src = tar.extractfile(member)
                    if src is None:
                        skipped += 1
                        continue
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with src, open(target, "wb") as fh:
                            while block := src.read(1 << 20):
                                fh.write(block)
                        os.utime(target, (member.mtime, member.mtime))
                    except OSError:
                        skipped += 1       # e.g. Windows path too long
                        continue
                    count += 1
        except tarfile.TarError as exc:
            done.append(Result(r.module, r.target, None, "failed", f"cannot read tar: {exc}"))
            continue
        if not keep_archives:
            r.target.unlink()
        detail = f"{count} files" + (f", {skipped} entries not written" if skipped else "")
        done.append(Result(r.module, r.target, dest, "ok", f"extracted: {detail}"))
    return done
