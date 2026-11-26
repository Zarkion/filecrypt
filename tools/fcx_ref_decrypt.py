#!/usr/bin/env python3
"""Reference decryptor for .fcx version 1, written only from docs/FORMAT.md.

This file is deliberately independent of filecrypt: it does not import it, and
it was written from the specification without reading filecrypt's container
code. tests/test_reference_decryptor.py runs it over every test vector and
checks it agrees with filecrypt. A disagreement means the spec (or the code)
has a bug, so report it instead of changing this file to match.

It is small and holds the whole plaintext in memory before releasing it. It is
a cross-check, not a tool for real files.

Usage:
    python tools/fcx_ref_decrypt.py FILE (--passphrase TEXT | --key-hex HEX) [-o OUT]

Needs `cryptography`. Argon2id files also need cryptography 44 or later, or
argon2-cffi.
"""

import argparse
import struct
import sys
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# FORMAT.md, "Header"
MAGIC = b"FCX1"
VERSION = 1
MAX_SETTINGS_LEN = 1024
MIN_CHUNK, MAX_CHUNK = 1024, 16 * 1024 * 1024
SALT_LEN, WRAPPED_LEN, PREFIX_LEN, TAG_LEN = 16, 48, 7, 16

KDF_ARGON2ID, KDF_SCRYPT, KDF_HKDF = 1, 2, 3
HKDF_INFO = b"filecrypt v1 key-encryption key"

GIB = 1024 ** 3


class RefError(Exception):
    """A rejected file. ``stage`` is header, kdf, key or body (vectors.json)."""

    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage}: {message}")
        self.stage = stage


class Unsupported(Exception):
    """No KDF implementation is installed (not a property of the file)."""


# --- header -------------------------------------------------------------------

def parse_header(data: bytes) -> dict:
    """FORMAT.md "Parsing rules". No key derivation happens here."""
    if len(data) < 8:
        raise RefError("header", "shorter than 8 bytes")
    if data[0:4] != MAGIC:
        raise RefError("header", "magic is not FCX1")
    if data[4] != VERSION:
        raise RefError("header", f"version {data[4]} is not 1")
    kdf_id = data[5]
    (settings_len,) = struct.unpack("<H", data[6:8])
    if settings_len > MAX_SETTINGS_LEN:
        raise RefError("header", f"settings_len {settings_len} > {MAX_SETTINGS_LEN}")
    L = settings_len
    header_len = 83 + L
    if len(data) < header_len:
        raise RefError("header", "header cut short")
    (chunk_size,) = struct.unpack("<I", data[79 + L:83 + L])
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise RefError("header", f"chunk_size {chunk_size} out of range")
    return {
        "kdf_id": kdf_id,
        "settings": data[8:8 + L],
        "salt": data[8 + L:24 + L],
        "wrap_aad": data[0:24 + L],
        "wrapped_key": data[24 + L:72 + L],
        "nonce_prefix": data[72 + L:79 + L],
        "chunk_size": chunk_size,
        "header_len": header_len,
    }


# --- KDFs ---------------------------------------------------------------------

def check_kdf(kdf_id: int, settings: bytes) -> tuple:
    """FORMAT.md "Caps for decryption". Returns parsed params; runs no KDF."""
    if kdf_id == KDF_ARGON2ID:
        if len(settings) != 9:
            raise RefError("kdf", "Argon2id settings must be 9 bytes")
        memory_kib, iterations, lanes = struct.unpack("<IIB", settings)
        if not 1 <= lanes <= 16:
            raise RefError("kdf", f"Argon2id lanes {lanes}")
        if not 1 <= iterations <= 16:
            raise RefError("kdf", f"Argon2id iterations {iterations}")
        if not 8 * lanes <= memory_kib <= 4 * 1024 * 1024:
            raise RefError("kdf", f"Argon2id memory {memory_kib} KiB")
        if memory_kib * 1024 * iterations > 16 * GIB:
            raise RefError("kdf", "Argon2id total work over 16 GiB")
        return memory_kib, iterations, lanes
    if kdf_id == KDF_SCRYPT:
        if len(settings) != 9:
            raise RefError("kdf", "scrypt settings must be 9 bytes")
        log2n, r, p = struct.unpack("<BII", settings)
        if not 1 <= log2n <= 22:
            raise RefError("kdf", f"scrypt log2n {log2n}")
        if not 1 <= r <= 32:
            raise RefError("kdf", f"scrypt r {r}")
        if not 1 <= p <= 16:
            raise RefError("kdf", f"scrypt p {p}")
        mem = 128 * r * (1 << log2n)
        if mem > 4 * GIB or mem * p > 16 * GIB:
            raise RefError("kdf", "scrypt memory or total work over the cap")
        return log2n, r, p
    if kdf_id == KDF_HKDF:
        if settings:
            raise RefError("kdf", "HKDF settings must be empty")
        return ()
    raise RefError("kdf", f"unknown kdf_id {kdf_id}")


def argon2id(secret: bytes, salt: bytes, memory_kib: int, iterations: int, lanes: int) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        pass
    else:
        return Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes,
                        memory_cost=memory_kib).derive(secret)
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise Unsupported("Argon2id needs cryptography >= 44 or argon2-cffi") from None
    return hash_secret_raw(secret, salt, time_cost=iterations, memory_cost=memory_kib,
                           parallelism=lanes, hash_len=32, type=Type.ID, version=19)


def argon2id_available() -> bool:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ImportError:
        return False


def derive_kek(kdf_id: int, params: tuple, secret: bytes, salt: bytes) -> bytes:
    if kdf_id == KDF_ARGON2ID:
        return argon2id(secret, salt, *params)
    if kdf_id == KDF_SCRYPT:
        log2n, r, p = params
        return Scrypt(salt=salt, length=32, n=1 << log2n, r=r, p=p).derive(secret)
    if len(secret) < 32:
        raise RefError("kdf", "HKDF secret shorter than 32 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(secret)


# --- secrets ------------------------------------------------------------------

def candidates(secret: bytes, is_passphrase: bool) -> list:
    """FORMAT.md "Secrets": NFC bytes first, then the exact bytes if different."""
    if not is_passphrase:
        return [secret]
    try:
        text = secret.decode("utf-8")
    except UnicodeDecodeError:
        return [secret]
    nfc = unicodedata.normalize("NFC", text).encode("utf-8")
    return [nfc] if nfc == secret else [nfc, secret]


# --- decryption ---------------------------------------------------------------

def unwrap(h: dict, params: tuple, secret: bytes, is_passphrase: bool) -> bytes:
    """FORMAT.md "Key block"."""
    for candidate in candidates(secret, is_passphrase):
        kek = derive_kek(h["kdf_id"], params, candidate, h["salt"])
        try:
            return AESGCM(kek).decrypt(b"\x00" * 12, h["wrapped_key"], h["wrap_aad"])
        except InvalidTag:
            continue
    raise RefError("key", "wrong key or passphrase")


def decrypt_body(body: bytes, file_key: bytes, prefix: bytes, chunk_size: int) -> bytes:
    """FORMAT.md "Body" and "Decrypting the body"."""
    aead = AESGCM(file_key)
    aad = MAGIC + bytes([VERSION]) + prefix + struct.pack("<I", chunk_size)
    piece = chunk_size + TAG_LEN
    out = []
    pos, i = 0, 0
    while True:
        chunk = body[pos:pos + piece]
        pos += len(chunk)
        last = pos == len(body)
        if len(chunk) < TAG_LEN:
            raise RefError("body", "truncated (piece shorter than 16 bytes)")
        if i >= 1 << 32:
            raise RefError("body", "more than 2^32 chunks")
        nonce = prefix + struct.pack(">I", i) + (b"\x01" if last else b"\x00")
        try:
            out.append(aead.decrypt(nonce, chunk, aad))
        except InvalidTag:
            raise RefError("body", f"chunk {i} failed authentication") from None
        if last:
            return b"".join(out)
        i += 1


def decrypt(data: bytes, secret: bytes, is_passphrase: bool) -> bytes:
    """Decrypt a whole .fcx file, or raise RefError naming the failing stage."""
    h = parse_header(data)
    params = check_kdf(h["kdf_id"], h["settings"])
    file_key = unwrap(h, params, secret, is_passphrase)
    return decrypt_body(data[h["header_len"]:], file_key, h["nonce_prefix"], h["chunk_size"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--passphrase", help="passphrase text (NFC, then exact bytes)")
    group.add_argument("--key-hex", help="raw key bytes in hex")
    ap.add_argument("-o", "--output", help="output file (default: stdout)")
    args = ap.parse_args(argv)
    with open(args.file, "rb") as f:
        data = f.read()
    if args.passphrase is not None:
        secret, is_passphrase = args.passphrase.encode("utf-8", "surrogateescape"), True
    else:
        secret, is_passphrase = bytes.fromhex(args.key_hex), False
    try:
        plain = decrypt(data, secret, is_passphrase)
    except RefError as e:
        print(f"rejected at {e}", file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "wb") as f:
            f.write(plain)
    else:
        sys.stdout.buffer.write(plain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
