"""Tests for resolving phone numbers to contact names (synthetic data only)."""
import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hisuite_decrypt import export
from hisuite_decrypt.names import ContactNames


def make_contacts(path: Path, people: list[tuple[str, list[str]]]) -> Path:
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE raw_contacts_tb(_id INTEGER);
        CREATE TABLE data_tb(mimetype TEXT, raw_contact_id INTEGER, data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT);
    """)
    for cid, (name, numbers) in enumerate(people, 1):
        con.execute("INSERT INTO raw_contacts_tb VALUES(?)", (cid,))
        con.execute("INSERT INTO data_tb VALUES('vnd.android.cursor.item/name',?,?,NULL,NULL,NULL)", (cid, name))
        for n in numbers:
            con.execute("INSERT INTO data_tb VALUES('vnd.android.cursor.item/phone_v2',?,?,'2',NULL,NULL)", (cid, n))
    con.commit()
    con.close()
    return path


class ContactNamesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.names = ContactNames.from_contact_db(make_contacts(self.tmp / "contact.db", [
            ("Mama", ["+48 600 100 200"]),
            ("Dad", ["601-200-300", "0048 602 300 400"]),
            ("Ola", ["700 000 001"]),
            ("Ola Praca", ["+48 700 000 001"]),         # same number as Ola -> ambiguous
        ]))

    def test_different_spellings_of_one_number_match(self):
        for spelling in ("+48600100200", "600100200", "0048 600 100 200", "(+48) 600-100-200"):
            self.assertEqual(self.names.lookup(spelling), "Mama", spelling)
        self.assertEqual(self.names.lookup("+48 601 200 300"), "Dad")
        self.assertEqual(self.names.lookup("602300400"), "Dad")       # second number of the same contact

    def test_unknown_ambiguous_and_non_numeric_senders_stay_unresolved(self):
        self.assertEqual(self.names.lookup("+48 999 999 999"), "")
        self.assertEqual(self.names.lookup("700000001"), "")           # belongs to two contacts: not guessed
        self.assertEqual(self.names.lookup("ORANGE"), "")
        self.assertEqual(self.names.lookup("55"), "")                  # too short to match anything
        self.assertEqual(self.names.lookup(""), "")

    def test_group_addresses(self):
        self.assertEqual(self.names.lookup("600100200~+48 999 999 999"), "Mama, +48 999 999 999")
        self.assertEqual(self.names.lookup("+48 998 000 000~+48 999 999 999"), "")

    def test_folder_labels(self):
        self.assertEqual(self.names.label("+48600100200"), "Mama (+48600100200)")
        self.assertEqual(self.names.label("+48600100200", "name"), "Mama")
        self.assertEqual(self.names.label("+48600100200", "number"), "+48600100200")
        self.assertEqual(self.names.label("+48 999 999 999"), "+48 999 999 999")   # unknown: just the number
        self.assertEqual(self.names.label("a/b:c*?"), "a_b_c__")                  # always path-safe
        with self.assertRaises(ValueError):
            self.names.label("1", "nope")

    def test_name_with_path_characters_is_sanitised(self):
        n = ContactNames.from_contact_db(make_contacts(self.tmp / "c2.db", [("A/B: ../evil", ["500 500 500"])]))
        label = n.label("500500500", "name")
        self.assertNotIn("/", label)
        self.assertNotIn("\\", label)
        self.assertNotIn(":", label)


class VcardTests(unittest.TestCase):
    VCF = (
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Dad\r\nitem1.TEL;type=CELL;type=pref:+48 700 123 456\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Smith;Grandma\\, Ann;;;\r\nTEL;TYPE=HOME:700-987-\r\n 654\r\nEND:VCARD\r\n"  # folded line
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Not Mama\r\nTEL:+48 600 100 200\r\nEND:VCARD\r\n"   # number already in contact.db
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:No Number\r\nEND:VCARD\r\n"
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.vcf = self.tmp / "google.vcf"
        self.vcf.write_bytes(self.VCF.encode("utf-8"))      # bytes: keep the \r\n exactly as written
        self.names = ContactNames.from_contact_db(make_contacts(self.tmp / "contact.db", [("Mama", ["+48 600 100 200"])]))

    def test_vcard_adds_names_but_does_not_override_contact_db(self):
        self.assertEqual(self.names.add_vcard(self.vcf), 3)               # the card without a number is skipped
        self.assertEqual(self.names.lookup("+48700123456"), "Dad")       # item1. prefix handled
        self.assertEqual(self.names.lookup("700987654"), "Grandma, Ann Smith")   # N fallback + folded TEL + escaped comma
        self.assertEqual(self.names.lookup("600100200"), "Mama")          # contact.db wins
        self.assertEqual(self.names.label("700 987 654"), "Grandma, Ann Smith (700987654)")

    def test_cli_uses_the_extra_vcard(self):
        import contextlib
        import io
        from hisuite_decrypt import cli
        src = self.tmp / "dec"
        src.mkdir()
        (src / "contact.db").write_bytes((self.tmp / "contact.db").read_bytes())
        con = sqlite3.connect(src / "calllog.db")
        con.execute("CREATE TABLE calls_tb(number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
        con.executemany("INSERT INTO calls_tb VALUES(?,?,?,?)", [("700123456", 1700000000000, 5, 1)])
        con.commit()
        con.close()
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["export", str(src), str(self.tmp / "o1")])
            cli.main(["export", str(src), str(self.tmp / "o2"), "--contacts-vcf", str(self.vcf)])
        self.assertIn(",700123456,,incoming", (self.tmp / "o1" / "calls.csv").read_text(encoding="utf-8-sig"))
        self.assertIn(",700123456,Dad,incoming", (self.tmp / "o2" / "calls.csv").read_text(encoding="utf-8-sig"))


class PreferredFormsTests(unittest.TestCase):
    def test_most_complete_spelling_wins(self):
        from hisuite_decrypt.names import preferred_forms
        best = preferred_forms(["700123456", "+48700123456", "48700123456", "ORANGE", "123", "a~b", ""])
        self.assertEqual(best, {"700123456": "+48700123456"})

    def test_labels_merge_spellings_of_known_and_unknown_numbers(self):
        from hisuite_decrypt.names import preferred_forms
        names = ContactNames.from_contact_db(make_contacts(Path(tempfile.mkdtemp()) / "c.db", [
            ("Dad", ["601 200 300", "602 300 400"])]))
        addresses = ["601200300", "+48 601 200 300", "0048602300400", "700123456", "+48700123456"]
        preferred = preferred_forms(addresses)
        labels = {names.label(a, "both", preferred) for a in addresses}
        # both numbers of one contact, in any spelling -> the contact's first number; unknown number -> one spelling
        self.assertEqual(labels, {"Dad (601200300)", "+48700123456"})
        self.assertEqual({names.label(a, "number", preferred) for a in addresses[:2]}, {"+48 601 200 300".replace(" ", "")})


class LongPathTests(unittest.TestCase):
    def test_fit_filename_keeps_extension_and_respects_the_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / ("d" * 60) / ("e" * 60)
            folder.mkdir(parents=True)
            name = "2021-12-31_16-26-26_received_978_" + "Screenshot_" * 20 + ".jpeg"
            fitted = export.fit_filename(folder, name)
            self.assertTrue(fitted.endswith(".jpeg"))
            self.assertLess(len(str(folder.resolve())) + 1 + len(fitted), export.MAX_PATH_BUDGET + 1)
            self.assertTrue(fitted.startswith("2021-12-31_16-26-26_received_978_"))   # unique id part kept
            (folder / fitted).write_bytes(b"x")                                      # really writable
            self.assertEqual(export.fit_filename(folder, "short.jpg"), "short.jpg")

    def test_attachment_with_very_long_name_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "sms.db"
            con = sqlite3.connect(db)
            con.executescript("""
                CREATE TABLE sms_tb(address TEXT, date INTEGER, type INTEGER, body TEXT);
                CREATE TABLE pdu_tb(_id INTEGER, date INTEGER, msg_box INTEGER);
                CREATE TABLE addr_tb(msg_id INTEGER, address TEXT, type INTEGER);
                CREATE TABLE part_tb(_id INTEGER, mid INTEGER, ct TEXT, text TEXT, name TEXT, cl TEXT);
                CREATE TABLE files_mms_tb(_id INTEGER, file_data BLOB);
            """)
            con.execute("INSERT INTO pdu_tb VALUES(7, 1700000100, 1)")
            con.execute("INSERT INTO addr_tb VALUES(7, '+48600100200', 137)")
            con.execute("INSERT INTO part_tb VALUES(12, 7, 'image/jpeg', NULL, ?, NULL)", ("Resized_" * 40 + ".jpeg",))
            con.execute("INSERT INTO files_mms_tb VALUES(12, ?)", (b"\xff\xd8\xff-jpeg",))
            con.commit()
            con.close()
            out = Path(tmp) / ("deep_" * 12) / "export"
            names = ContactNames.from_contact_db(make_contacts(Path(tmp) / "contact.db", [("Aunt Example", ["+48 600 100 200"])]))
            export.export_messages(db, out, dt.timezone.utc, names=names)
            files = [p for p in (out / "mms_attachments").rglob("*") if p.is_file()]
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"\xff\xd8\xff-jpeg")
            self.assertTrue(files[0].parent.name.startswith("Aunt Example ("))


class NamesInExportsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.names = ContactNames.from_contact_db(make_contacts(self.tmp / "contact.db", [("Mama", ["+48 600 100 200"])]))

    def test_calls_csv_has_names(self):
        db = self.tmp / "calllog.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE calls_tb(number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
        con.executemany("INSERT INTO calls_tb VALUES(?,?,?,?)",
                        [("600100200", 1700000000000, 5, 1), ("555000111", 1700000100000, 0, 3)])
        con.commit()
        con.close()
        export.export_calls(db, self.tmp / "o", dt.timezone.utc, names=self.names)
        text = (self.tmp / "o" / "calls.csv").read_text(encoding="utf-8-sig")
        self.assertIn("date,number,name,type,duration_seconds", text)
        self.assertIn(",600100200,Mama,incoming,5", text)
        self.assertIn(",555000111,,missed,0", text)

    def test_messages_csv_and_attachment_folders(self):
        db = self.tmp / "sms.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE sms_tb(address TEXT, date INTEGER, type INTEGER, body TEXT);
            CREATE TABLE pdu_tb(_id INTEGER, date INTEGER, msg_box INTEGER);
            CREATE TABLE addr_tb(msg_id INTEGER, address TEXT, type INTEGER);
            CREATE TABLE part_tb(_id INTEGER, mid INTEGER, ct TEXT, text TEXT, name TEXT, cl TEXT);
            CREATE TABLE files_mms_tb(_id INTEGER, file_data BLOB);
        """)
        con.execute("INSERT INTO sms_tb VALUES('+48600100200', 1700000000000, 1, 'hi')")
        con.execute("INSERT INTO pdu_tb VALUES(7, 1700000100, 1)")
        con.execute("INSERT INTO addr_tb VALUES(7, '600 100 200', 137)")
        con.execute("INSERT INTO part_tb VALUES(12, 7, 'image/jpeg', NULL, 'pic.jpg', NULL)")
        con.execute("INSERT INTO files_mms_tb VALUES(12, ?)", (b"\xff\xd8\xff-jpeg",))
        con.commit()
        con.close()
        # the same person is always one folder, whatever spelling the message used
        for style, expected in (("both", "Mama (+48600100200)"), ("name", "Mama"), ("number", "+48600100200")):
            out = self.tmp / f"o_{style}"
            export.export_messages(db, out, dt.timezone.utc, names=self.names, folder_style=style)
            self.assertEqual([p.name for p in (out / "mms_attachments").iterdir()], [expected], style)
            text = (out / "messages.csv").read_text(encoding="utf-8-sig")
            self.assertIn("SMS,received,+48600100200,Mama,", text)
            self.assertIn("MMS,received,600 100 200,Mama,", text)


if __name__ == "__main__":
    unittest.main()
