# hisuite-backup-decrypt

Decrypt **Huawei HiSuite 14** backups (the "KoBackup v3" format) when you know the backup
password, and export your notes, calendar, contacts, call log and SMS/MMS to open formats
(TXT, CSV, ICS, vCard).

HiSuite stores most data as encrypted SQLite databases (`Memo.db`, `calendar.db`, `sms.db`, ...).
Huawei's own docs say these files cannot be opened on a computer. Existing open-source tools
([kobackupdec][kobackupdec], [Huawei-Backup-V4-Decrypt][v4]) target older backups or the
phone-side KoBackup app and failed on a HiSuite 14 backup, which is why this project exists.
Forum posts agree: users report that `kobackupdec` works up to HiSuite 10.x and produces
undecryptable `.db`/`.tar` files from HiSuite 11 onwards. For HiSuite 10.x and older, use
`kobackupdec`.

> **This is not a password cracker.** It needs the password you chose when making the backup.
> Use it only on backups you own.

## Status

| | |
|---|---|
| Tested on | HiSuite `14.0.0.370`, backup of a HUAWEI P20 Pro (EMUI 10 / Android 10), Python 3.12, Windows 11 |
| Works | all 17 database modules in that backup decrypt with a verified authentication tag |
| Works | multimedia archives (`*.tar.enc`: photos, videos, music, documents, voice recordings) and `*_MediaInfo.db.enc`: decrypted and unpacked; every file was checked by its header (`ustar`, SQLite) and the unpacked files are valid JPEG, MP4, MP3, M4A and DOCX. Only a small backup (a handful of files) was tested, see [the scheme](#multimedia-the-scheme) |
| Export verified | notes, calendar, contacts, call log, SMS + MMS text and MMS attachments (record counts match the counts HiSuite stores in `info.xml`; extracted attachment bytes match the database exactly) |
| Untested | other HiSuite versions / devices. HiSuite 13.x probably works (publicly posted `backupinfo.ini` files from 13.0.0.310 and 14.0.0.320 have the same fields), but I have not tried it. An unauthenticated AES-CTR fallback for older backups exists but is untested on real old backups. Large multimedia backups (many archives, several GB) and archives split into `images1.tar`, `images2.tar`, ... are handled the same way but were not tried |
| Different format | HarmonyOS backups (an `info.json` with `backupKey`, `backupSalt` and per-module `encryptionIv`) are a different scheme and are **not** supported |

Reports and pull requests for other versions are very welcome (please **never** attach a real
backup to an issue). See [Contributing and help](#contributing-and-help).

## Install

```bash
git clone https://github.com/YacoobPL/hisuite-backup-decrypt
cd hisuite-backup-decrypt
pip install -r requirements.txt     # pycryptodome, defusedxml
```

Python 3.9+ (uses `zoneinfo`; on Windows also `pip install tzdata` if you pass `--timezone`).

## Usage

Point the tool at the backup folder, i.e. the one that contains `info.xml` and
`backupinfo.ini` (HiSuite names it like `HUAWEI P20 Pro_2026-01-01 12.00.00`).

```bash
# non-secret metadata and module list
python -m hisuite_decrypt info "HUAWEI P20 Pro_2026-01-01 12.00.00"

# check the password without decrypting anything
python -m hisuite_decrypt verify "HUAWEI P20 Pro_2026-01-01 12.00.00"

# decrypt everything into a NEW folder, and export to open formats
python -m hisuite_decrypt decrypt "HUAWEI P20 Pro_2026-01-01 12.00.00" decrypted --export --timezone Europe/Warsaw

# leave the multimedia archives packed (*.tar) instead of unpacking them into decrypted/media/
python -m hisuite_decrypt decrypt "HUAWEI P20 Pro_2026-01-01 12.00.00" decrypted --no-extract

# unpack, but also keep the decrypted .tar files (they are deleted by default to save space)
python -m hisuite_decrypt decrypt "HUAWEI P20 Pro_2026-01-01 12.00.00" decrypted --keep-archives

# export from an already decrypted folder
python -m hisuite_decrypt export decrypted export

# also include Wi-Fi passwords and the smartcare database (off by default)
python -m hisuite_decrypt export decrypted export --include-secrets

# name numbers that are not in the backup's contacts, using a vCard exported from Google Contacts
python -m hisuite_decrypt export decrypted export --contacts-vcf google-contacts.vcf

# MMS folders named just "Name" instead of "Name (number)"
python -m hisuite_decrypt export decrypted export --names name
```

### Contact names

Numbers in `calls.csv` and `messages.csv` are matched to `contact.db`, and the MMS attachment
folders are named after the contact. Matching ignores spaces, dashes and country-code
spellings (`+48 600 100 200`, `0048600100200` and `600100200` are the same number, compared by
their last 9 digits); a number that belongs to two different contacts is left unnamed instead of
guessed, and non-numeric senders such as `ORANGE` are left alone. All spellings of one number end
up in one folder.

**Only the phone's local contacts are in a HiSuite backup.** Contacts that live only in a Google
(or other) account are not included, so some numbers stay unnamed; on one real backup about half
of the messages could be named. Export those contacts from [Google Contacts](https://contacts.google.com)
as vCard and pass the file with `--contacts-vcf` (it may be given more than once). Names from
the backup's own contacts always win over the extra file.

`--names` sets how MMS folders are named: `both` (`Name (number)`, default), `name` or `number`.

The password is read from `--password-file`, from the `HISUITE_PASSWORD` environment variable,
or from an interactive prompt. There is deliberately **no `--password` flag**: command-line
arguments end up in shell history and process lists.

A wrong password is detected up front (via `checkMsgV3`) and nothing is written. The multimedia
files have no checksum, so a wrong password shows up there as `failed ... header check failed`
and nothing is written for that file.

### Exported files

| Module | Output |
|---|---|
| `picture`, `video`, `audio`, `document`, `soundrecorder` (multimedia) | `media/<module>/...`: the original files as they were on the phone, with their original modification times. Only regular files are unpacked; absolute paths, `..` and links inside an archive are refused |
| `image_MediaInfo.db.enc`, `video_MediaInfo.db.enc` | `image_MediaInfo.db`, `video_MediaInfo.db` (SQLite, an index of the pictures and videos) |
| `Memo` | `notes.txt`, `notes.csv` (bullet lists and to-do items preserved as text) |
| `calendar` | `calendar.ics` (importable into Google Calendar / Outlook, keeps recurrence and reminders), `calendar.csv` |
| `contact` | `contacts.vcf` (vCard 3.0), `contacts.csv` |
| `calllog` | `calls.csv` (with a `name` column, see *Contact names* below) |
| `sms` | `messages.csv` (SMS and MMS text, with a `name` column) and `mms_attachments/<Name (number)>/` with the MMS pictures, videos and vCards, named `date_direction_id_name` and dated like the message. File names are shortened where needed to stay under the Windows 260-character path limit |
| `Memo` attachments | `note_attachments/`: the pictures drawn in notes (unpacked from the stored archive; `.hwgraffi` is Huawei's own vector data) |
| `alarm` | `alarms.csv` |
| `wifiConfig` | `wifi.csv` (SSID, security, static IP, DNS, proxy). **Passwords are left out** unless you pass `--include-secrets` |
| everything else (`weather`, `phoneManager`, `HWlanucher`, `camera`, `clock`, `setting`, `harassment`, `wallpaper`, `soundrecorder`, ...) | `other/<database>/<table>.csv`, one CSV per table (blobs shown as `<N bytes>`; bookkeeping tables skipped); pictures stored in chunks (e.g. the wallpaper) are reassembled into real files |
| `smartcare` | skipped unless `--include-secrets` (it can hold card numbers and bookings) |

The decrypted `.db` files are always written as-is too, so you can open them with any SQLite
browser. These settings databases mostly describe how apps were configured on the phone; the
useful ones for most people are the Wi-Fi list, alarms and the wallpaper.

## How the encryption works

Verified against a real HiSuite 14 backup. Everything needed is in `info.xml` plus your password.

```text
encMsgV3  (per module, 96 hex chars = 48 bytes)
  seed  = encMsgV3[:32]
  nonce = encMsgV3[32:48]

key  = PBKDF2-HMAC-SHA256(password, seed, iterations=5000, dklen=32)

encrypted file = ciphertext || 16-byte tag      (AES-256-GCM, 16-byte nonce)

checkMsgV3 (128 hex chars) verifies the password without decrypting:
  hmac_key = hex( PBKDF2-HMAC-SHA256(password, bytes.fromhex(checkMsgV3[64:]), 5000, 32) )
  checkMsgV3[:64] == hex( HMAC-SHA256(key = hmac_key as ASCII, msg = encrypted file) )
```

Details that cost time: the extra 16 bytes at the end of each file (file size = n*4096 + 16)
are the GCM tag, so a plain AES-CTR attempt produces garbage that never looks like SQLite;
`backupinfo.ini` is UTF-16 with a BOM; the fields `derivedSalt`, `pwdsalt`, `pwdsalt_iv` and
`password` in it are **not** needed for the database modules.

## Multimedia: the scheme

The archives `<module>/storage/.../*.tar.enc` and `image_MediaInfo.db.enc` / `video_MediaInfo.db.enc`
use a different scheme from the databases. It is also verified against HiSuite 14.0.0.370:

```text
derivedSalt = bytes.fromhex(backupinfo.ini  [headerinfo]  derivedSalt)        # 16 bytes

key = scrypt( SHA-256(password), derivedSalt, N=2^15, r=8, p=2, dklen=32 )

plaintext = AES-256-CTR(key, counter block = IV, as a 128-bit big-endian integer)

IV of an archive   = <Iv> of its <File> entry in <module>.xml  (picture.xml, video.xml, audio.xml, ...)
IV of the MediaInfo = image_iv / video_iv in backupinfo.ini
```

There is no authentication tag. The password is therefore checked by the decrypted header: the
magic `ustar` at offset 257 of a tar, or `SQLite format 3` for the databases. A wrong key gives
random bytes, which this tool reports as `failed`.

How it was found: the earlier attempts (AES in every mode with keys from `SHA-256`, `MD5`,
`PBKDF2` over all the salts in `backupinfo.ini`, unwrapping the `password` blob, ...) all failed,
and the phone-side apps do not contain these fields. The key derivation lives in the native PC
program. Instead of disassembling it, the author ran HiSuite on their **own** backup and logged
the arguments of the OpenSSL calls (`PKCS5_PBKDF2_HMAC`, `EVP_PBE_scrypt`) while it prepared a restore.
There were two `scrypt` calls: the first one (the password with a 32-byte salt, 256 bytes of output) is not needed
here; the second one takes `SHA-256(password)` and `derivedSalt` and its output decrypts the media
files. No Huawei code or key material is included in this repository. HiSuite also calls PBKDF2
(300000 iterations, 8-digit input) while pairing with the phone; that is the verification code
shown on the phone and unrelated to backups.

Two details that cost time: `<Path>` in `picture.xml` names `...\images0.tar`, but the file on disk
is `images0.tar.enc`; and the PBKDF2 / GCM scheme of the database modules does **not** apply to
the media at all (no `encMsgV3` for them in `info.xml`).

HiSuite 14.0.0.380 (the version offered for download in November 2026) does not accept the folder
layout written by 370 as it is: it looks for the databases in `check/` and for `info.xml`,
`backupinfo.ini`, `cinfoset.dat` and `<module>.xml` inside every module folder. If you want to
restore an old backup with the official program, install the HiSuite version that made it.

## Troubleshooting

* **`wrong password ... unsupported HiSuite version`** - the password does not match
  `checkMsgV3`. Check it, or the backup is from a version this tool does not understand.
* **Special characters in the password** (`#`, `!`, spaces, non-ASCII) cause trouble when
  passed on a command line; that is why this tool takes the password from a prompt, a file or
  `$HISUITE_PASSWORD`. The password is used as UTF-8.
* **Forgot the password?** This tool cannot help, and I deliberately did not add a
  guessing/brute-force mode.
* Files that are not part of the backup (macOS `._*` files, `.DS_Store`, `Thumbs.db`) are
  ignored.

## Security notes

* Decrypted output is plaintext. `wifiConfig.db` contains Wi-Fi passwords, `sms.db` your
  messages. Do not commit or share it. The `.gitignore` in this repo excludes common names.
* The test-suite uses a synthetic backup generated on the fly; no real user data is included.

## Development

```bash
python -m unittest discover -s tests -v
```

## Credits

* [RealityNet/kobackupdec][kobackupdec] (MIT) by Francesco "dfirfpi" Picasso: the original
  analysis of the older KoBackup format.
* [irsl/Huawei-Hisuite-KobackupCipherTool](https://github.com/irsl/Huawei-Hisuite-KobackupCipherTool):
  decompiled reference for `checkMsgV3` and the PBKDF2 parameters.
* [mauronofrio/Huawei-Backup-V4-Decrypt][v4]: the newer phone-side variant, useful for comparison.

Not affiliated with or endorsed by Huawei. "HiSuite" and "Huawei" are trademarks of their owner.

## Contributing and help

Questions, bug reports and compatibility reports go to
[GitHub Issues](https://github.com/YacoobPL/hisuite-backup-decrypt/issues) (forms are provided).
This is a one-person hobby project, so replies are best-effort. A useful report contains the
output of `python -m hisuite_decrypt info "<backup folder>"` (no keys or password in it), the
command without the password, the error, and your Python version and OS. **Never post your
password, files from your backup, decrypted data or real phone numbers.**
See [CONTRIBUTING.md](CONTRIBUTING.md) for how to help (other HiSuite versions, the multimedia
archives, new exporters) and [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[MIT](LICENSE)

[kobackupdec]: https://github.com/RealityNet/kobackupdec
[v4]: https://github.com/mauronofrio/Huawei-Backup-V4-Decrypt
