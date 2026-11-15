"""Tests for the readable exports of settings-like databases (synthetic data only)."""
import contextlib
import io
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from hisuite_decrypt import cli, export_other


def make_db(path: Path, script: str, rows=()):
    con = sqlite3.connect(path)
    con.executescript(script)
    for sql, params in rows:
        con.execute(sql, params)
    con.commit()
    con.close()


class OtherExportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.src = self.tmp / "decrypted"
        self.src.mkdir()

    def _wifi(self):
        make_db(self.src / "wifiConfig.db",
                "CREATE TABLE wifiConfig(ssid TEXT, key_mgmt TEXT, psk TEXT, wep_key0 TEXT, hiddenSSID INTEGER,"
                " IPAddress TEXT, GateWay TEXT, DNS1 TEXT, DNS2 TEXT, Host TEXT, Port TEXT);",
                [("INSERT INTO wifiConfig VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  ('"HomeNet"', "WPA_PSK", '"s3cret-pass"', None, 0, "192.168.1.5", "192.168.1.1", "8.8.8.8", "", "proxy", "3128"))])

    def test_wifi_hides_passwords_by_default(self):
        self._wifi()
        out = self.tmp / "o"
        self.assertEqual(export_other.export_wifi(self.src / "wifiConfig.db", out), 1)
        text = (out / "wifi.csv").read_text(encoding="utf-8-sig")
        self.assertIn("HomeNet,WPA_PSK,0,,192.168.1.5", text)    # quotes stripped, password column empty
        self.assertNotIn("s3cret-pass", text)
        self.assertIn("proxy:3128", text)

    def test_wifi_includes_passwords_on_request(self):
        self._wifi()
        export_other.export_wifi(self.src / "wifiConfig.db", self.tmp / "o", include_secrets=True)
        self.assertIn("s3cret-pass", (self.tmp / "o" / "wifi.csv").read_text(encoding="utf-8-sig"))

    def test_alarms(self):
        make_db(self.src / "alarm.db",
                "CREATE TABLE deskclock_alarm_tb(enabled INTEGER, hour INTEGER, minutes INTEGER, daysofweek INTEGER,"
                " message TEXT, vibrate INTEGER, snoozetimes INTEGER, snoozeduration INTEGER, ringduration INTEGER);",
                [("INSERT INTO deskclock_alarm_tb VALUES(1,7,5,31,'Wake up',1,3,10,5)", ()),
                 ("INSERT INTO deskclock_alarm_tb VALUES(0,6,30,0,NULL,0,0,0,0)", ())])
        export_other.export_alarms(self.src / "alarm.db", self.tmp / "o")
        lines = (self.tmp / "o" / "alarms.csv").read_text(encoding="utf-8-sig").splitlines()
        self.assertTrue(lines[1].startswith("06:30,0,0"))
        self.assertTrue(lines[2].startswith("07:05,1,31,Wake up"))

    def test_generic_dump_skips_bookkeeping_and_masks_blobs(self):
        make_db(self.src / "camera.db",
                "CREATE TABLE camera_pref_items_tb(key TEXT, value TEXT, icon BLOB);"
                "CREATE TABLE x_uri_info(need_count INTEGER, _id INTEGER, value TEXT);"
                "CREATE TABLE x_version_info(version INTEGER, extra_data TEXT);",
                [("INSERT INTO camera_pref_items_tb VALUES('flash','auto',?)", (b"\x00\x01\x02",)),
                 ("INSERT INTO x_uri_info VALUES(1,1,'content://x')", ()),
                 ("INSERT INTO x_version_info VALUES(1,'')", ())])
        self.assertEqual(export_other.dump_tables(self.src / "camera.db", self.tmp / "o"), 1)
        files = sorted(p.name for p in (self.tmp / "o").iterdir())
        self.assertEqual(files, ["camera_pref_items_tb.csv"])
        text = (self.tmp / "o" / "camera_pref_items_tb.csv").read_text(encoding="utf-8-sig")
        self.assertIn("flash,auto,<3 bytes>", text)

    def test_attachments_are_reassembled_and_zip_is_unpacked_safely(self):
        zpath = self.tmp / "a.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("abc$def_draw.png", b"\x89PNG-fake")
            zf.writestr("../../evil.txt", b"nope")            # path traversal attempt
            zf.writestr("x_graffiti.jpg", b"\x89PNG-really-a-png")    # extension does not match the content
            zf.writestr("vec.txt", b"HWGRAFFI\x00\x01")                # Huawei drawing data, not text
        blob = zpath.read_bytes()
        mid = len(blob) // 2
        make_db(self.src / "Memo.db",
                "CREATE TABLE attachment(file_data BLOB, data_index INTEGER, file_length INTEGER);",
                [("INSERT INTO attachment VALUES(?,?,?)", (blob[mid:], 1, len(blob) - mid)),   # inserted out of order
                 ("INSERT INTO attachment VALUES(?,?,?)", (blob[:mid], 0, mid))])
        out = self.tmp / "att"
        produced = export_other.extract_attachments(self.src / "Memo.db", out)
        self.assertIn("attachment.zip", produced)
        self.assertEqual((out / "attachment.zip").read_bytes(), blob)
        unpacked = sorted(p.relative_to(out).as_posix() for p in (out / "attachment").iterdir())
        self.assertEqual(unpacked, ["attachment/def_draw.png", "attachment/evil.txt",
                                    "attachment/vec.hwgraffi", "attachment/x_graffiti.png"])
        self.assertFalse((self.tmp / "evil.txt").exists())
        self.assertFalse((out.parent / "evil.txt").exists())
        self.assertTrue(all(p.parent == out / "attachment" for p in (out / "attachment").iterdir()))

    def test_secret_databases_need_the_flag(self):
        self._wifi()
        make_db(self.src / "smartcare.db", "CREATE TABLE intelligent_tb(creditcard_card_number TEXT);",
                [("INSERT INTO intelligent_tb VALUES('4111111111111111')", ())])
        make_db(self.src / "weather.db", "CREATE TABLE cityinfo_tb(city_name TEXT);",
                [("INSERT INTO cityinfo_tb VALUES('Warsaw')", ())])
        out = self.tmp / "o"
        summary = export_other.export_others(self.src, out)
        self.assertTrue((out / "other" / "weather" / "cityinfo_tb.csv").is_file())
        self.assertFalse((out / "other" / "smartcare").exists())
        self.assertFalse((out / "other" / "wifiConfig").exists())      # never dumped in full
        self.assertTrue(any("smartcare.db: skipped" in s for s in summary))
        everything = "".join(p.read_text(encoding="utf-8-sig", errors="ignore") for p in out.rglob("*.csv"))
        self.assertNotIn("4111111111111111", everything)
        self.assertNotIn("s3cret-pass", everything)

        out2 = self.tmp / "o2"
        export_other.export_others(self.src, out2, include_secrets=True)
        self.assertIn("4111111111111111", (out2 / "other" / "smartcare" / "intelligent_tb.csv").read_text(encoding="utf-8-sig"))
        self.assertIn("s3cret-pass", (out2 / "wifi.csv").read_text(encoding="utf-8-sig"))
        self.assertFalse((out2 / "other" / "wifiConfig").exists())

    def test_databases_extracted_from_attachments_are_not_treated_as_backup_databases(self):
        make_db(self.src / "weather.db", "CREATE TABLE cityinfo_tb(city_name TEXT);",
                [("INSERT INTO cityinfo_tb VALUES('Warsaw')", ())])
        nested = self.src / "export" / "other" / "smartcare" / "attachments"
        nested.mkdir(parents=True)
        make_db(nested / "hiboard_database_attachment.db", "CREATE TABLE t(x TEXT);", [("INSERT INTO t VALUES('junk')", ())])
        summary = export_other.export_others(self.src, self.tmp / "o")
        self.assertEqual(len(summary), 1)
        self.assertIn("weather.db", summary[0])

    def test_cli_export_flag(self):
        self._wifi()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["export", str(self.src), str(self.tmp / "e1")]), 0)
            self.assertEqual(cli.main(["export", str(self.src), str(self.tmp / "e2"), "--include-secrets"]), 0)
        self.assertNotIn("s3cret-pass", (self.tmp / "e1" / "wifi.csv").read_text(encoding="utf-8-sig"))
        self.assertIn("s3cret-pass", (self.tmp / "e2" / "wifi.csv").read_text(encoding="utf-8-sig"))
        self.assertIn("--include-secrets", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
