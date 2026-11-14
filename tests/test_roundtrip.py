"""Round-trip tests on a *synthetic* backup: no real user data is involved."""
import contextlib
import datetime as dt
import io
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from xml.sax.saxutils import quoteattr

from hisuite_decrypt import backup, cli, crypto, export

PASSWORD = b"correct horse battery staple"
SEED_A = bytes(range(32))
NONCE_A = bytes(range(100, 116))
ENC_MSG = (SEED_A + NONCE_A).hex()


def _memo_db(path: Path) -> None:
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE comhuaweiproviderNotePadbackupnote_items_tb(
            _id INTEGER, content TEXT, created TEXT, modified TEXT, favorite TEXT, has_attachment TEXT);
        CREATE TABLE comhuaweiproviderNotePadbackupnote_items_new_tb(
            _id INTEGER, html_content TEXT, has_todo TEXT, delete_flag TEXT);
    """)
    notes = [
        (1, "Text|Zażółć gęślą jaźń", "1700000000000", "1700000100000", "1", "0",
         '<note><element type="Text">Zażółć gęślą jaźń</element></note>', "0", "0"),
        (2, "Bullet|milk", "1700000200000", "1700000300000", "0", "0",
         '<note><element type="Bullet">milk</element><element type="Bullet">eggs</element></note>', "0", "0"),
        (3, "Text|deleted", "1700000400000", "1700000500000", "0", "0",
         '<note><element type="Text">deleted</element></note>', "0", "1"),
    ]
    for n in notes:
        con.execute("INSERT INTO comhuaweiproviderNotePadbackupnote_items_tb VALUES(?,?,?,?,?,?)", n[:6])
        con.execute("INSERT INTO comhuaweiproviderNotePadbackupnote_items_new_tb VALUES(?,?,?,?)", (n[0], n[6], n[7], n[8]))
    con.commit()
    con.close()


def _calendar_db(path: Path) -> None:
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE Events_tb(_id INTEGER, title TEXT, dtstart INTEGER, dtend INTEGER, allDay INTEGER,
            eventLocation TEXT, description TEXT, rrule TEXT, duration TEXT, deleted INTEGER);
        CREATE TABLE Reminds_tb(event_id INTEGER, minutes INTEGER, method INTEGER);
    """)
    con.execute("INSERT INTO Events_tb VALUES(1,'Dentist; 10, sharp',1700000000000,1700003600000,0,'Main St','Bring card, ID',NULL,NULL,0)")
    con.execute("INSERT INTO Events_tb VALUES(2,'Birthday',1700006400000,1700092800000,1,NULL,NULL,'FREQ=YEARLY',NULL,0)")
    con.execute("INSERT INTO Events_tb VALUES(3,'Gone',1700000000000,1700003600000,0,NULL,NULL,NULL,NULL,1)")
    con.execute("INSERT INTO Reminds_tb VALUES(1,30,1)")
    con.execute("INSERT INTO Reminds_tb VALUES(1,-1,1)")  # -1 = "default", must be skipped
    con.commit()
    con.close()


def make_backup(root: Path, password: bytes = PASSWORD) -> Path:
    """Create a fake HiSuite backup: info.xml, backupinfo.ini, Memo/Memo.db, calendar.db."""
    root.mkdir(parents=True)
    (root / "Memo").mkdir()
    plain_memo, plain_cal = root / "_memo.db", root / "_cal.db"
    _memo_db(plain_memo)
    _calendar_db(plain_cal)
    rows = []
    for name, table, plain, target in (
        ("Memo", "BackupFileModuleInfo_SystemData", plain_memo, root / "Memo" / "Memo.db"),
        ("calendar", "BackupFileModuleInfo", plain_cal, root / "calendar.db"),
    ):
        enc = crypto.encrypt_gcm(password, ENC_MSG, plain.read_bytes())
        target.write_bytes(enc)
        plain.unlink()
        check = crypto.make_check_msg(password, enc, seed=bytes(range(50, 82)))
        rows.append(
            f'<row table="{table}"><column name="name"><value String={quoteattr(name)} /></column>'
            f'<column name="encMsgV3"><value String="{ENC_MSG}" /></column>'
            f'<column name="checkMsgV3"><value String="{check}" /></column>'
            f'<column name="recordTotal"><value Integer="2" /></column></row>'
        )
    (root / "info.xml").write_text("<?xml version='1.0' encoding='UTF-8'?><info.xml>" + "".join(rows) + "</info.xml>", encoding="utf-8")
    # HiSuite 14 writes backupinfo.ini as UTF-16 with a BOM.
    (root / "backupinfo.ini").write_bytes(
        ("[headerinfo]\r\nhisuiteversion=14.0.0.370\r\nbackup_time=2026-01-01 00:00:00\r\nisencypt=1\r\n"
         "protuct_model=TEST PHONE\r\npassword=abc%def==\r\n").encode("utf-16"))
    return root


class CryptoTests(unittest.TestCase):
    def test_gcm_roundtrip_and_wrong_password(self):
        blob = crypto.encrypt_gcm(PASSWORD, ENC_MSG, b"hello")
        self.assertEqual(crypto.decrypt_gcm(PASSWORD, ENC_MSG, blob), b"hello")
        with self.assertRaises(crypto.WrongPasswordError):
            crypto.decrypt_gcm(b"nope", ENC_MSG, blob)

    def test_gcm_detects_tampering(self):
        blob = bytearray(crypto.encrypt_gcm(PASSWORD, ENC_MSG, b"hello world"))
        blob[0] ^= 1
        with self.assertRaises(crypto.WrongPasswordError):
            crypto.decrypt_gcm(PASSWORD, ENC_MSG, bytes(blob))

    def test_check_msg(self):
        data = os.urandom(5000)
        check = crypto.make_check_msg(PASSWORD, data)
        self.assertTrue(crypto.verify_check_msg(PASSWORD, check, data))
        self.assertFalse(crypto.verify_check_msg(b"nope", check, data))
        with self.assertRaises(ValueError):
            crypto.verify_check_msg(PASSWORD, "short", data)

    def test_bad_enc_msg_length(self):
        with self.assertRaises(ValueError):
            crypto.split_enc_msg("00" * 47)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.src = make_backup(self.tmp / "backup")

    def test_describe_hides_secrets(self):
        info = backup.describe(self.src)
        self.assertEqual(info["model"], "TEST PHONE")
        self.assertTrue(info["encrypted"])
        self.assertEqual([m[0] for m in info["modules"]], ["Memo", "calendar"])
        self.assertNotIn("abc%def", repr(info))

    def test_verify_password(self):
        self.assertEqual(backup.verify_password(self.src, PASSWORD), {"Memo": True, "calendar": True})
        self.assertEqual(set(backup.verify_password(self.src, b"nope").values()), {False})

    def test_decrypt_and_export(self):
        out = self.tmp / "out"
        results = backup.decrypt_backup(self.src, out, PASSWORD)
        self.assertEqual({r.status for r in results}, {"ok"})
        self.assertTrue((out / "Memo" / "Memo.db").read_bytes().startswith(backup.SQLITE_MAGIC))

        self.assertEqual(export.export_notes(out / "Memo" / "Memo.db", out / "x"), 2)  # deleted note skipped
        text = (out / "x" / "notes.txt").read_text(encoding="utf-8")
        self.assertIn("Zażółć gęślą jaźń", text)
        self.assertIn("• milk\n• eggs", text)
        self.assertNotIn("deleted", text)

        self.assertEqual(export.export_calendar(out / "calendar.db", out / "x"), 2)  # deleted event skipped
        ics = (out / "x" / "calendar.ics").read_bytes().decode("utf-8")
        self.assertIn("SUMMARY:Dentist\\; 10\\, sharp", ics)
        self.assertIn("DTSTART;VALUE=DATE:", ics)       # all-day event
        self.assertIn("RRULE:FREQ=YEARLY", ics)
        self.assertEqual(ics.count("BEGIN:VALARM"), 1)  # the -1 "default" reminder is skipped
        self.assertNotIn("SUMMARY:Gone", ics)
        self.assertTrue(all(len(line.encode("utf-8")) <= 75 for line in ics.split("\r\n")))

    def test_wrong_password_fails_before_writing(self):
        out = self.tmp / "out"
        with self.assertRaises(crypto.WrongPasswordError):
            backup.decrypt_backup(self.src, out, b"nope")
        self.assertFalse(out.exists())

    def test_cli_flow(self):
        pw = self.tmp / "pw.txt"
        pw.write_text(PASSWORD.decode() + "\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["info", str(self.src)]), 0)
            self.assertEqual(cli.main(["verify", str(self.src), "--password-file", str(pw)]), 0)
            self.assertEqual(cli.main(["decrypt", str(self.src), str(self.tmp / "o"), "--password-file", str(pw), "--export"]), 0)
        self.assertTrue((self.tmp / "o" / "export" / "notes.csv").is_file())
        self.assertTrue((self.tmp / "o" / "export" / "calendar.ics").is_file())
        self.assertNotIn(PASSWORD.decode(), buf.getvalue())


class MediaSkipTest(unittest.TestCase):
    def test_enc_media_is_skipped_not_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = make_backup(Path(tmp) / "backup")
            media = src / "soundrecorder" / "storage" / "RecorderTar" / "soundrecorder"
            media.mkdir(parents=True)
            (media / "soundrecorder0.tar.enc").write_bytes(os.urandom(1024))
            info = (src / "info.xml").read_text(encoding="utf-8")
            row = ('<row table="BackupFileModuleInfo_SystemData"><column name="name"><value String="soundrecorder" /></column>'
                   f'<column name="encMsgV3"><value String="{ENC_MSG}" /></column></row>')
            (src / "info.xml").write_text(info.replace("</info.xml>", row + "</info.xml>"), encoding="utf-8")
            results = backup.decrypt_backup(src, Path(tmp) / "out", PASSWORD)
            by_status = {r.module: r.status for r in results}
            self.assertEqual(by_status["soundrecorder"], "skipped")
            self.assertEqual(by_status["Memo"], "ok")


class OtherExportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def test_calls(self):
        db = self.tmp / "calllog.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE calls_tb(number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
        con.executemany("INSERT INTO calls_tb VALUES(?,?,?,?)", [("+48123456789", 1700000000000, 61, 2), ("555", 1700000100000, 0, 3)])
        con.commit()
        con.close()
        self.assertEqual(export.export_calls(db, self.tmp / "o", dt.timezone.utc), 2)
        text = (self.tmp / "o" / "calls.csv").read_text(encoding="utf-8-sig")
        self.assertIn("missed", text)
        self.assertIn("2023-11-14 22:13:20,+48123456789,outgoing,61", text)

    def test_contacts(self):
        db = self.tmp / "contact.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE raw_contacts_tb(_id INTEGER);
            CREATE TABLE data_tb(mimetype TEXT, raw_contact_id INTEGER, data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT);
        """)
        con.executemany("INSERT INTO raw_contacts_tb VALUES(?)", [(1,), (2,)])
        con.executemany("INSERT INTO data_tb VALUES(?,?,?,?,?,?)", [
            ("vnd.android.cursor.item/name", 1, "Zoë Nowak", "Zoë", "Nowak", None),
            ("vnd.android.cursor.item/phone_v2", 1, "+48 600 100 200", "2", None, None),
            ("vnd.android.cursor.item/organization", 1, "ACME; Inc", None, None, "CTO"),
            ("vnd.sec.cursor.item/samsung_easysignup", 2, "x", None, None, None),  # ignored, contact 2 is empty
        ])
        con.commit()
        con.close()
        self.assertEqual(export.export_contacts(db, self.tmp / "o"), 1)
        vcf = (self.tmp / "o" / "contacts.vcf").read_bytes().decode("utf-8")
        self.assertIn("FN:Zoë Nowak", vcf)
        self.assertIn("TEL;TYPE=CELL:+48 600 100 200", vcf)
        self.assertIn("ORG:ACME\\; Inc", vcf)
        self.assertIn("TITLE:CTO", vcf)

    def test_messages(self):
        db = self.tmp / "sms.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE sms_tb(address TEXT, date INTEGER, type INTEGER, body TEXT);
            CREATE TABLE pdu_tb(_id INTEGER, date INTEGER, msg_box INTEGER);
            CREATE TABLE addr_tb(msg_id INTEGER, address TEXT, type INTEGER);
            CREATE TABLE part_tb(_id INTEGER, mid INTEGER, ct TEXT, text TEXT, name TEXT, cl TEXT);
            CREATE TABLE files_mms_tb(_id INTEGER, file_data BLOB);
        """)
        con.execute("INSERT INTO sms_tb VALUES('111', 1700000000000, 1, 'hi')")
        con.execute("INSERT INTO pdu_tb VALUES(7, 1700000100, 2)")       # outgoing MMS, date in seconds
        con.execute("INSERT INTO addr_tb VALUES(7, '222', 151)")
        con.execute("INSERT INTO addr_tb VALUES(7, 'insert-address-token', 137)")
        con.executemany("INSERT INTO part_tb VALUES(?,?,?,?,?,?)", [
            (10, 7, "application/smil", None, None, None),
            (11, 7, "text/plain", "photo!", None, None),
            (12, 7, "image/jpeg", None, "../evil/IMG_1.jpg", None),   # path-traversal attempt in the name
            (13, 7, "image/gif", None, "lost.gif", None),             # no blob stored for this part
        ])
        con.execute("INSERT INTO files_mms_tb VALUES(12, ?)", (b"\xff\xd8\xff-fake-jpeg",))
        con.commit()
        con.close()
        out = self.tmp / "o"
        self.assertEqual(export.export_messages(db, out, dt.timezone.utc), 2)
        text = (out / "messages.csv").read_text(encoding="utf-8-sig")
        self.assertIn("SMS,received,111,2023-11-14 22:13:20,hi,", text)
        self.assertIn("MMS,sent,222,2023-11-14 22:15:00,photo!,", text)
        self.assertIn("lost.gif [not extracted]", text)
        files = [p for p in (out / "mms_attachments").rglob("*") if p.is_file()]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), b"\xff\xd8\xff-fake-jpeg")
        self.assertEqual(files[0].parent, out / "mms_attachments" / "222")          # stayed inside the output dir
        self.assertTrue(files[0].name.startswith("2023-11-14_22-15-00_sent_12_"))
        self.assertNotIn("/", files[0].name)                                        # a single path component
        self.assertFalse((out / "evil").exists() or (out / "mms_attachments" / "evil").exists())
        # attachments can be switched off
        export.export_messages(db, self.tmp / "o2", dt.timezone.utc, attachments=False)
        self.assertFalse((self.tmp / "o2" / "mms_attachments").exists())


if __name__ == "__main__":
    unittest.main()
