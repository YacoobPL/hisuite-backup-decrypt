"""Tests for the multimedia (*.tar.enc, *_MediaInfo.db.enc) scheme, on synthetic data only."""
import contextlib
import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from hisuite_decrypt import backup, cli, crypto
from test_roundtrip import PASSWORD, make_backup   # tests are run with `-s tests`, so this is a sibling module

DERIVED_SALT = bytes(range(200, 216))
IMAGE_IV = bytes(range(16))
VIDEO_IV = bytes(range(16, 32))
TAR_IV = bytes(range(60, 76))
PHOTO = os.urandom(5000)


def _encrypt(password: bytes, iv: bytes, plain: bytes) -> bytes:
    key = crypto.derive_media_key(password, DERIVED_SALT)
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(plain)


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name: str, data: bytes, **kw):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            for k, v in kw.items():
                setattr(info, k, v)
            tar.addfile(info, io.BytesIO(data))
        add("DCIM/Camera/photo.jpg", PHOTO)
        add("../escaped.txt", b"x")            # path traversal
        add("/abs_escaped.txt", b"x")          # absolute path
        add("C:/drive_escaped.txt", b"x")      # Windows drive letter
        link = tarfile.TarInfo("DCIM/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tar.addfile(link)
    return buf.getvalue()


def add_media(src: Path, password: bytes = PASSWORD) -> None:
    (src / "backupinfo.ini").write_bytes(
        ("[headerinfo]\r\nhisuiteversion=14.0.0.370\r\nisencypt=1\r\nprotuct_model=TEST PHONE\r\n"
         f"derivedSalt={DERIVED_SALT.hex().upper()}\r\nimage_iv={IMAGE_IV.hex().upper()}\r\n"
         f"video_iv={VIDEO_IV.hex().upper()}\r\n").encode("utf-16"))
    folder = src / "picture" / "storage" / "MediaTar" / "images"
    folder.mkdir(parents=True)
    (folder / "images0.tar.enc").write_bytes(_encrypt(password, TAR_IV, _tar_bytes()))
    (src / "picture.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><Multimedia><File>'
        f"<Path>\\storage\\MediaTar\\images\\images0.tar</Path><Iv>{TAR_IV.hex().upper()}</Iv>"
        "<FileCount>1</FileCount></File></Multimedia>", encoding="utf-8")
    (src / "image_MediaInfo.db.enc").write_bytes(_encrypt(password, IMAGE_IV, b"SQLite format 3\x00" + bytes(1000)))
    (src / "video_MediaInfo.db.enc").write_bytes(_encrypt(password, VIDEO_IV, b"SQLite format 3\x00" + bytes(500)))


class MediaKeyTests(unittest.TestCase):
    def test_key_depends_on_password_and_salt(self):
        key = crypto.derive_media_key(PASSWORD, DERIVED_SALT)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, crypto.derive_media_key(PASSWORD, DERIVED_SALT))
        self.assertNotEqual(key, crypto.derive_media_key(b"other", DERIVED_SALT))
        self.assertNotEqual(key, crypto.derive_media_key(PASSWORD, bytes(16)))

    def test_key_follows_the_documented_construction(self):
        expected = hashlib.scrypt(hashlib.sha256(PASSWORD).digest(), salt=DERIVED_SALT, n=2 ** 15, r=8, p=2,
                                  maxmem=2 ** 28, dklen=32)
        self.assertEqual(crypto.derive_media_key(PASSWORD, DERIVED_SALT), expected)

    def test_streaming_matches_one_shot_across_chunk_boundaries(self):
        key = crypto.derive_media_key(PASSWORD, DERIVED_SALT)
        data = os.urandom(crypto.CHUNK * 2 + 17)
        encrypted = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=IMAGE_IV).encrypt(data)
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "a.enc", Path(tmp) / "out" / "a"
            src.write_bytes(encrypted)
            self.assertEqual(crypto.decrypt_media_file(key, IMAGE_IV, src, dst), len(data))
            self.assertEqual(dst.read_bytes(), data)

    def test_bad_iv_length(self):
        with self.assertRaises(ValueError):
            crypto.decrypt_media_head(bytes(32), bytes(8), Path(__file__))


class MediaBackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.src = make_backup(self.tmp / "backup")
        add_media(self.src)

    def test_decrypts_archives_and_media_databases(self):
        out = self.tmp / "out"
        results = backup.decrypt_backup(self.src, out, PASSWORD)
        media = {r.source.name: r for r in results if r.source.name.endswith(".enc")}
        self.assertEqual({r.status for r in media.values()}, {"ok"})
        self.assertEqual(set(media), {"images0.tar.enc", "image_MediaInfo.db.enc", "video_MediaInfo.db.enc"})
        self.assertTrue((out / "image_MediaInfo.db").read_bytes().startswith(b"SQLite format 3"))
        self.assertTrue((out / "picture" / "storage" / "MediaTar" / "images" / "images0.tar").is_file())

    def test_extract_writes_only_safe_regular_files(self):
        out = self.tmp / "out"
        results = backup.decrypt_backup(self.src, out, PASSWORD)
        extracted = backup.extract_archives(results, out)
        self.assertEqual([r.status for r in extracted], ["ok"])
        self.assertEqual((out / "media" / "picture" / "DCIM" / "Camera" / "photo.jpg").read_bytes(), PHOTO)
        self.assertEqual(os.stat(out / "media" / "picture" / "DCIM" / "Camera" / "photo.jpg").st_mtime, 1_700_000_000)
        written = sorted(p.name for p in out.rglob("*") if p.is_file() and "media" in p.parts)
        self.assertEqual(written, ["photo.jpg"])                 # traversal, absolute, drive and symlink refused
        for name in ("escaped.txt", "abs_escaped.txt", "drive_escaped.txt"):
            self.assertFalse(list(self.tmp.rglob(name)), name)
        self.assertIn("1 files, 4 entries not written", extracted[0].detail)  # 3 hostile names + the symlink
        self.assertFalse((out / "picture" / "storage" / "MediaTar" / "images" / "images0.tar").exists())

    def test_keep_archives(self):
        out = self.tmp / "out"
        results = backup.decrypt_backup(self.src, out, PASSWORD)
        backup.extract_archives(results, out, keep_archives=True)
        self.assertTrue((out / "picture" / "storage" / "MediaTar" / "images" / "images0.tar").is_file())

    def test_wrong_password_is_reported_by_the_header_check(self):
        results = backup.decrypt_media(self.src, self.tmp / "out", b"wrong password")
        self.assertEqual({r.status for r in results}, {"failed"})
        self.assertIn("header check failed", results[0].detail)
        self.assertFalse((self.tmp / "out").exists())            # nothing is written for a wrong key

    def test_crafted_xml_path_is_not_followed_out_of_the_backup(self):
        outside = self.tmp / "outside.tar.enc"
        outside.write_bytes(_encrypt(PASSWORD, TAR_IV, _tar_bytes()))
        (self.src / "picture.xml").write_text(
            '<?xml version="1.0"?><Multimedia><File><Path>\\..\\..\\outside.tar</Path>'
            f"<Iv>{TAR_IV.hex()}</Iv></File></Multimedia>", encoding="utf-8")
        results = backup.decrypt_media(self.src, self.tmp / "out", PASSWORD)
        by_name = {r.source.name: r.status for r in results}
        self.assertEqual(by_name["images0.tar.enc"], "skipped")  # its IV entry is gone, nothing guessed
        self.assertNotIn("outside.tar.enc", by_name)

    def test_cli_decrypt_extracts_by_default_and_honours_flags(self):
        def run(*extra: str) -> tuple[int, str]:
            out = self.tmp / ("out_" + "".join(extra).replace("-", ""))
            buf = io.StringIO()
            old = os.environ.get("HISUITE_PASSWORD")
            os.environ["HISUITE_PASSWORD"] = PASSWORD.decode()
            try:
                with contextlib.redirect_stdout(buf):
                    code = cli.main(["decrypt", str(self.src), str(out), *extra])
            finally:
                if old is None:
                    os.environ.pop("HISUITE_PASSWORD")
                else:
                    os.environ["HISUITE_PASSWORD"] = old
            self.assertNotIn(PASSWORD.decode(), buf.getvalue())
            return code, str(out)

        code, out = run()
        self.assertEqual(code, 0)
        self.assertTrue((Path(out) / "media" / "picture" / "DCIM" / "Camera" / "photo.jpg").is_file())
        code, out = run("--no-extract")
        self.assertFalse((Path(out) / "media").exists())
        self.assertTrue((Path(out) / "picture" / "storage" / "MediaTar" / "images" / "images0.tar").is_file())


if __name__ == "__main__":
    unittest.main()
