# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Use GitHub's private reporting
instead: open the repository's **Security** tab, choose **Report a vulnerability**, and describe
the problem.

Examples of what is in scope: a way for a crafted backup folder to write files outside the output
directory, to execute code, or to make the tool leak a password or key; mistakes in how the
cryptography is used.

Please include the version (commit) you tested and, if possible, a minimal reproduction built
from synthetic data. **Never attach a real backup or real personal data.**

This is a one-person hobby project, so responses are best-effort and I cannot promise a
timeline. Only the latest commit on `main` is maintained.

## What the tool does with your data

* Everything runs locally; the tool makes no network connections.
* The password is read from a prompt, a file or the `HISUITE_PASSWORD` environment variable
  (there is intentionally no command-line flag) and is never written to disk.
* Decrypted output is plaintext. Wi-Fi passwords and the `smartcare` database are left out of the
  readable exports unless you pass `--include-secrets`, but the decrypted `.db` files themselves
  always contain everything. Protect and delete them accordingly.
