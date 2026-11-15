"""Cryptographic primitives for Huawei HiSuite / KoBackup "v3" encrypted backups.

Scheme (verified against a HiSuite 14.0.0.370 backup of a P20 Pro, EMUI 10):

* ``encMsgV3`` (96 hex chars = 48 bytes) is stored per module in ``info.xml``::

      seed  = encMsgV3[:32]
      nonce = encMsgV3[32:48]            # 16 bytes

* The file key is derived from the user's backup password::

      key = PBKDF2-HMAC-SHA256(password, seed, iterations=5000, dklen=32)

* Each encrypted file is ``ciphertext || tag`` using AES-256-GCM with the 16-byte
  nonce above and a 16-byte tag appended at the end of the file.

* ``checkMsgV3`` (128 hex chars) lets you verify the password *without* decrypting::

      hmac_key = hex(PBKDF2-HMAC-SHA256(password, checkMsgV3[64:] as bytes, 5000, 32))
      checkMsgV3[:64] == hex(HMAC-SHA256(key=hmac_key.encode('ascii'), msg=encrypted_file))

Older KoBackup versions use unauthenticated AES-CTR with the same key derivation;
:func:`decrypt_ctr_legacy` implements that as a fallback.

Multimedia (``*.tar.enc``, ``*_MediaInfo.db.enc``) uses a different scheme, also verified
against HiSuite 14.0.0.370 (the key derivation was found by observing the crypto calls of
HiSuite on the author's own backup)::

    derivedSalt = bytes.fromhex(backupinfo.ini [headerinfo] derivedSalt)      # 16 bytes
    key         = scrypt(SHA-256(password), derivedSalt, N=2**15, r=8, p=2, dklen=32)
    plaintext   = AES-256-CTR(key, counter block = IV as a 128-bit big-endian integer)

The IV is the ``<Iv>`` of the archive in ``<module>.xml`` (``picture.xml``, ...), or ``image_iv`` /
``video_iv`` of ``backupinfo.ini`` for the ``*_MediaInfo.db.enc`` files. There is no tag, so a
wrong password is only noticed by looking at the decrypted header (``ustar`` / ``SQLite``).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter

PBKDF2_ITERATIONS = 5000
KEY_LEN = 32
SEED_LEN = 32
NONCE_LEN = 16
TAG_LEN = 16

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 2
MEDIA_IV_LEN = 16
CHUNK = 1 << 20


class WrongPasswordError(ValueError):
    """Raised when authentication fails (wrong password or an unsupported scheme)."""


def derive_key(password: bytes, seed: bytes) -> bytes:
    """Derive the 256-bit file key from the backup password and a per-module seed."""
    return hashlib.pbkdf2_hmac("sha256", password, seed, PBKDF2_ITERATIONS, KEY_LEN)


def split_enc_msg(enc_msg_hex: str) -> tuple[bytes, bytes]:
    """Split ``encMsgV3`` into ``(seed, nonce)``."""
    raw = bytes.fromhex(enc_msg_hex.strip())
    if len(raw) != SEED_LEN + NONCE_LEN:
        raise ValueError(f"encMsgV3 must be {SEED_LEN + NONCE_LEN} bytes, got {len(raw)}")
    return raw[:SEED_LEN], raw[SEED_LEN:]


def make_check_msg(password: bytes, data: bytes, seed: bytes | None = None) -> str:
    """Build a ``checkMsgV3`` value for *data* (used by tests and for completeness)."""
    seed = seed if seed is not None else os.urandom(SEED_LEN)
    hmac_key = derive_key(password, seed).hex().encode("ascii")
    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest() + seed.hex()


def verify_check_msg(password: bytes, check_msg_hex: str, data: bytes) -> bool:
    """Return True if *password* matches ``checkMsgV3`` for the encrypted file *data*."""
    check_msg_hex = (check_msg_hex or "").strip()
    if len(check_msg_hex) != 128:
        raise ValueError("checkMsgV3 must be 128 hex characters")
    expected, seed = check_msg_hex[:64], bytes.fromhex(check_msg_hex[64:])
    calculated = make_check_msg(password, data, seed)[:64]
    return hmac.compare_digest(calculated, expected)


def decrypt_gcm(password: bytes, enc_msg_hex: str, data: bytes) -> bytes:
    """Decrypt ``ciphertext || tag`` (AES-256-GCM). Raises :class:`WrongPasswordError`."""
    if len(data) < TAG_LEN:
        raise ValueError("encrypted file is shorter than the GCM tag")
    seed, nonce = split_enc_msg(enc_msg_hex)
    cipher = AES.new(derive_key(password, seed), AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(data[:-TAG_LEN], data[-TAG_LEN:])
    except ValueError as exc:
        raise WrongPasswordError("GCM authentication failed") from exc


def encrypt_gcm(password: bytes, enc_msg_hex: str, plaintext: bytes) -> bytes:
    """Inverse of :func:`decrypt_gcm` (used by the test-suite to build fake backups)."""
    seed, nonce = split_enc_msg(enc_msg_hex)
    cipher = AES.new(derive_key(password, seed), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag


def derive_media_key(password: bytes, derived_salt: bytes) -> bytes:
    """Key for the multimedia archives: scrypt over ``SHA-256(password)`` and ``derivedSalt``."""
    if not derived_salt:
        raise ValueError("derivedSalt is empty")
    return hashlib.scrypt(hashlib.sha256(password).digest(), salt=derived_salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, maxmem=4 * 128 * SCRYPT_N * SCRYPT_R * SCRYPT_P, dklen=KEY_LEN)


def _media_cipher(key: bytes, iv: bytes):
    if len(iv) != MEDIA_IV_LEN:
        raise ValueError(f"IV must be {MEDIA_IV_LEN} bytes, got {len(iv)}")
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)


def decrypt_media_head(key: bytes, iv: bytes, path: Path, size: int = 512) -> bytes:
    """Decrypt only the first *size* bytes of a multimedia file (to check the key by its header)."""
    with open(path, "rb") as fh:
        return _media_cipher(key, iv).decrypt(fh.read(size))


def decrypt_media_file(key: bytes, iv: bytes, src: Path, dst: Path) -> int:
    """Stream-decrypt a multimedia file (AES-256-CTR, no tag). Returns the number of bytes written."""
    cipher = _media_cipher(key, iv)
    dst.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            block = fin.read(CHUNK)
            if not block:
                break
            fout.write(cipher.decrypt(block))
            total += len(block)
    return total


def decrypt_ctr_legacy(password: bytes, enc_msg_hex: str, data: bytes) -> bytes:
    """Unauthenticated AES-256-CTR used by older KoBackup versions (no tag, no check)."""
    seed, nonce = split_enc_msg(enc_msg_hex)
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
    return AES.new(derive_key(password, seed), AES.MODE_CTR, counter=counter).decrypt(data)
