# Contributing and getting help

This is a small hobby project maintained by one person in their spare time, so replies are
best-effort. The way to reach me is through [GitHub Issues](https://github.com/YacoobPL/hisuite-backup-decrypt/issues);
there is deliberately no e-mail address.

## Reporting a problem

Open an issue and use the **Bug report** form. It asks for a few things that make a report
actionable and are **safe to share**:

* the output of `python -m hisuite_decrypt info "<your backup folder>"` (model, HiSuite
  version, list of modules; it never prints keys, salts or your password),
* the command you ran, **without the password**,
* the error message,
* your Python version and operating system.

### Never post

* your backup password, or any file from your backup (`info.xml` and `backupinfo.ini` contain
  salts and key material that are specific to your backup),
* decrypted databases or exports (messages, contacts, Wi-Fi passwords, ...),
* real phone numbers or names. Replace them with made-up ones before pasting output.

If you want to show the structure of a file, describe it (sizes, field names) rather than
attaching it.

## Security problems

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Helping with development

The most useful contributions:

1. **Other HiSuite versions and devices.** Tell me whether it worked (the `info` output above plus
   "worked / did not work" is enough). HiSuite 13.x is expected to work but is untested.
2. **Larger multimedia backups.** The multimedia scheme (see the README) was verified on a small
   backup only. Reports from backups with many or very large archives, split archives
   (`images1.tar`, ...) or other media types are valuable: say whether the files opened correctly.
3. **More exporters**, for example other modules or formats you need.

### Development setup

```bash
git clone https://github.com/YacoobPL/hisuite-backup-decrypt
cd hisuite-backup-decrypt
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Guidelines:

* Keep the runtime dependencies to `pycryptodome` and `defusedxml`; everything else uses the
  standard library.
* Tests use **synthetic data generated on the fly** (see `tests/test_roundtrip.py`). Never add real
  backups, numbers, names or passwords to the repository, not even in tests or comments.
* Add a test for every behaviour you add or change, and run the whole suite before opening a pull
  request.
* Do not add features meant for guessing or cracking backup passwords; the tool is for people who
  know their own password.
