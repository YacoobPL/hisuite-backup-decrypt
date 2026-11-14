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
"""
from __future__ import annotations

import hashlib
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Util import Counter

PBKDF2_ITERATIONS = 5000
KEY_LEN = 32
SEED_LEN = 32
NONCE_LEN = 16
TAG_LEN = 16


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


def decrypt_ctr_legacy(password: bytes, enc_msg_hex: str, data: bytes) -> bytes:
    """Unauthenticated AES-256-CTR used by older KoBackup versions (no tag, no check)."""
    seed, nonce = split_enc_msg(enc_msg_hex)
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
    return AES.new(derive_key(password, seed), AES.MODE_CTR, counter=counter).decrypt(data)
