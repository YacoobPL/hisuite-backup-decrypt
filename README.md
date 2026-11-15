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
| Export verified | notes, calendar, contacts, call log, SMS + MMS text and MMS attachments (record counts match the counts HiSuite stores in `info.xml`; extracted attachment bytes match the database exactly) |
| **Not supported** | multimedia archives (`*.tar.enc`, `*_MediaInfo.db.enc`): photos, videos, audio, documents, voice recordings. They use a different key scheme that I could not work out; they are reported as `skipped` |
| Untested | other HiSuite versions / devices. HiSuite 13.x probably works (publicly posted `backupinfo.ini` files from 13.0.0.310 and 14.0.0.320 have the same fields), but I have not tried it. An unauthenticated AES-CTR fallback for older backups exists but is untested on real old backups |
| Different format | HarmonyOS backups (an `info.json` with `backupKey`, `backupSalt` and per-module `encryptionIv`) are a different scheme and are **not** supported |

Reports and pull requests for other versions and for the multimedia format are very welcome
(please **never** attach a real backup to an issue).

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

A wrong password is detected up front (via `checkMsgV3`) and nothing is written.

### Exported files

| Module | Output |
|---|---|
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

## Multimedia (`*.enc`): what was tried

The multimedia archives (`<module>/storage/.../*.tar.enc`, with a 16-byte `<Iv>` in `picture.xml`,
`video.xml`, ...) and `image_MediaInfo.db.enc` / `video_MediaInfo.db.enc` (IV in `image_iv` /
`video_iv` of `backupinfo.ini`) are plain streams: their size is a multiple of 512 / 4096
bytes, there is no tag and no repeated 16-byte blocks (so not ECB). `info.xml` has no `encMsgV3`
for them. The oracle used was `ustar` at offset 257 of the decrypted tar (and the SQLite magic).
All of these failed with the correct password (not every mode/key combination was tried; the
list shows the families covered):

* AES-128/256 in CTR, CBC, CFB, OFB, ECB and GCM (streaming, no tag check), with the key taken as
  `SHA-256(password)` (full and first 16 bytes), `MD5`, the old `SHA1PRNG` derivation, or
  `PBKDF2-HMAC-SHA256(password, salt, n)` for `n` from 1 to 100000 and the salts
  `derivedSalt`, `pwdsalt` (whole / first 16 / first 32 bytes), `pwdsalt_iv`, the `<Iv>` or no salt;
* unwrapping the `password` blob of `backupinfo.ini` with those keys.

* PBKDF2 with SHA-1/224/384/512 and MD5 (not only SHA-256) over the same salts and iteration
  counts, with AES in CTR, CBC and CFB128, using the `<Iv>` / zero / `pwdsalt_iv` as IV, with the
  derived bytes used raw or as a hex string.

### Where the multimedia key is *not*

The phone app `KoBackup_N.apk` that ships with HiSuite (decompiled with jadx) contains the
`BackupSecurityV3` class: it encrypts with AES-GCM, derives the key as
`PBKDF2(password, seed given as a hex string)`, verifies passwords with `checkMsgV3`, and falls
back to AES-CTR for old backups. That matches what this tool does for the database modules.
The fields `derivedSalt`, `pwdsalt`, `image_iv`, `video_iv` and `mdataisencypt`, however, do not
appear in `KoBackup_N.apk`, `LocalBackup.apk` or `HiSuite.apk`; they only appear in the native
PC program `HiSuite.exe`. That program uses low-level OpenSSL (`AES_cbc_encrypt`,
`CRYPTO_ctr128_encrypt`; `CommBase.dll` also has `AES_cfb128_encrypt` and `PKCS5_PBKDF2_HMAC`),
so the multimedia key is most likely derived in native PC code. The next step would be
disassembling `HiSuite.exe` / `CommBase.dll` (for example with Ghidra).

Workarounds that users report: restoring the backup to a Huawei phone with HiSuite (decrypts
everything), or creating the backup with an old HiSuite (10.x) and decrypting it with
`kobackupdec`.

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

## License

[MIT](LICENSE)

[kobackupdec]: https://github.com/RealityNet/kobackupdec
[v4]: https://github.com/mauronofrio/Huawei-Backup-V4-Decrypt
