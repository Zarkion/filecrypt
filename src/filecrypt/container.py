"""The .fcx container: envelope encryption with a chunked AES-256-GCM body.

Layout (integers little-endian unless noted):

    magic "FCX1" | version u8 | kdf_id u8 | settings_len u16 | settings
    | salt[16] | wrapped_file_key[48] | nonce_prefix[7] | chunk_size u32
    | chunk* (ciphertext || 16-byte tag)

Each file gets a fresh random 32-byte file key. It is wrapped once with
AES-256-GCM under a key-encryption key (KEK) derived from the user's secret.
The wrap uses an all-zero nonce: that is safe because every wrap uses a fresh
random salt, so every KEK is used exactly once. The container generates that
salt itself and only asks the caller to derive a KEK from it, so no caller can
reuse a salt by mistake.

Chunk nonces follow the STREAM construction:
    nonce_prefix[7] | counter u32 big-endian | last_flag u8 (0x00 / 0x01)

Associated data deliberately splits the header in two so that rekeying only
rewrites the key block and leaves the body byte-identical:
  * wrapped key AAD = magic | version | kdf_id | settings_len | settings | salt
  * chunk AAD       = magic | version | nonce_prefix | chunk_size
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable

DeriveKEK = Callable[[bytes], bytes]

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FCX1"
VERSION = 1
SALT_LEN = 16
FILE_KEY_LEN = 32
TAG_LEN = 16
WRAPPED_KEY_LEN = FILE_KEY_LEN + TAG_LEN
NONCE_PREFIX_LEN = 7
DEFAULT_CHUNK_SIZE = 64 * 1024
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_SETTINGS_LEN = 1024
MAX_CHUNKS = 2**32

_WRAP_NONCE = b"\x00" * 12


class FormatError(Exception):
    """The input is not a well-formed .fcx file."""


class AuthenticationError(Exception):
    """Wrong key, or the file has been modified or truncated."""


class WrongKeyError(AuthenticationError):
    """The file key could not be unwrapped: wrong passphrase or key.

    A modified salt, KDF id or KDF settings also end up here, since the key
    block's authentication can't tell those apart from a wrong key.
    """


class CorruptedFileError(AuthenticationError):
    """The key was right but the body failed authentication: the file is
    damaged, truncated, reordered or was tampered with."""


class TrailingDataError(CorruptedFileError, FormatError):
    """Extra bytes follow the final chunk."""


@dataclass(frozen=True)
class Header:
    version: int
    kdf_id: int
    settings: bytes
    salt: bytes
    wrapped_key: bytes
    nonce_prefix: bytes
    chunk_size: int
    header_len: int

    def key_aad(self) -> bytes:
        return _key_aad(self.kdf_id, self.settings, self.salt)

    def chunk_aad(self) -> bytes:
        return _chunk_aad(self.nonce_prefix, self.chunk_size)


def _key_aad(kdf_id: int, settings: bytes, salt: bytes) -> bytes:
    return MAGIC + bytes([VERSION, kdf_id]) + struct.pack("<H", len(settings)) + settings + salt


def _chunk_aad(nonce_prefix: bytes, chunk_size: int) -> bytes:
    return MAGIC + bytes([VERSION]) + nonce_prefix + struct.pack("<I", chunk_size)


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= MAX_CHUNKS:
        raise ValueError("file too large: chunk counter overflow")
    return prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")


def _check_key_params(kek: bytes, kdf_id: int, settings: bytes, salt: bytes) -> None:
    if len(kek) != 32:
        raise ValueError("KEK must be 32 bytes")
    if not 0 <= kdf_id <= 255:
        raise ValueError("kdf_id must fit in one byte")
    if len(settings) > MAX_SETTINGS_LEN:
        raise ValueError("KDF settings too long")
    if len(salt) != SALT_LEN:
        raise ValueError("salt must be 16 bytes")


def _build_key_block(file_key: bytes, derive_kek: DeriveKEK, kdf_id: int, settings: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    kek = derive_kek(salt)
    _check_key_params(kek, kdf_id, settings, salt)
    aad = _key_aad(kdf_id, settings, salt)
    wrapped = AESGCM(kek).encrypt(_WRAP_NONCE, file_key, aad)
    assert len(wrapped) == WRAPPED_KEY_LEN
    return aad + wrapped


def encrypt_stream(src: BinaryIO, dst: BinaryIO, *, derive_kek: DeriveKEK, kdf_id: int,
                   settings: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    """Encrypt everything readable from ``src`` into ``dst``.

    ``derive_kek(salt)`` is called once with a fresh random 16-byte salt and
    must return the 32-byte KEK for that salt.
    """
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}")
    file_key = os.urandom(FILE_KEY_LEN)
    nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
    key_block = _build_key_block(file_key, derive_kek, kdf_id, settings)
    dst.write(key_block + nonce_prefix + struct.pack("<I", chunk_size))

    aead = AESGCM(file_key)
    aad = _chunk_aad(nonce_prefix, chunk_size)
    counter = 0
    current = _read_exact(src, chunk_size)
    while True:
        nxt = _read_exact(src, chunk_size) if len(current) == chunk_size else b""
        last = not nxt
        dst.write(aead.encrypt(_nonce(nonce_prefix, counter, last), current, aad))
        if last:
            return
        counter += 1
        current = nxt


def read_header(src: BinaryIO) -> Header:
    """Parse and sanity-check the header. Nothing here is authenticated yet."""
    fixed = _read_exact(src, 8)
    if len(fixed) < 8:
        raise FormatError("file too short to be .fcx")
    if fixed[:4] != MAGIC:
        raise FormatError("not an .fcx file (bad magic)")
    version, kdf_id = fixed[4], fixed[5]
    if version != VERSION:
        raise FormatError(f"unsupported .fcx version {version}")
    (settings_len,) = struct.unpack("<H", fixed[6:8])
    if settings_len > MAX_SETTINGS_LEN:
        raise FormatError("KDF settings too long")
    rest_len = settings_len + SALT_LEN + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN + 4
    rest = _read_exact(src, rest_len)
    if len(rest) < rest_len:
        raise FormatError("truncated .fcx header")
    o = 0
    settings = rest[o:o + settings_len]; o += settings_len
    salt = rest[o:o + SALT_LEN]; o += SALT_LEN
    wrapped = rest[o:o + WRAPPED_KEY_LEN]; o += WRAPPED_KEY_LEN
    prefix = rest[o:o + NONCE_PREFIX_LEN]; o += NONCE_PREFIX_LEN
    (chunk_size,) = struct.unpack("<I", rest[o:o + 4])
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatError(f"invalid chunk size {chunk_size}")
    return Header(version, kdf_id, settings, salt, wrapped, prefix, chunk_size, 8 + rest_len)


def unwrap_file_key(header: Header, kek: bytes) -> bytes:
    if len(kek) != 32:
        raise ValueError("KEK must be 32 bytes")
    try:
        return AESGCM(kek).decrypt(_WRAP_NONCE, header.wrapped_key, header.key_aad())
    except InvalidTag:
        raise WrongKeyError("wrong key or passphrase (or the file's header was modified)") from None


def decrypt_body(header: Header, file_key: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    """Decrypt chunks from ``src`` (positioned just after the header) into ``dst``.

    Each chunk is authenticated before it is written. Truncation, reordering
    and trailing data are all detected; the caller must discard ``dst`` on error.
    """
    aead = AESGCM(file_key)
    aad = header.chunk_aad()
    full = header.chunk_size + TAG_LEN
    counter = 0
    current = _read_exact(src, full)
    while True:
        if len(current) < TAG_LEN:
            raise CorruptedFileError("the file is damaged: it ends early (truncated)")
        nxt = _read_exact(src, full) if len(current) == full else b""
        last = not nxt
        try:
            plain = aead.decrypt(_nonce(header.nonce_prefix, counter, last), current, aad)
        except InvalidTag:
            if not last and _is_valid_final(aead, header, counter, current, aad):
                raise TrailingDataError("the file is damaged: trailing data after the final chunk") from None
            raise CorruptedFileError(
                "the file is damaged or was tampered with (chunk %d failed authentication)" % counter
            ) from None
        dst.write(plain)
        if last:
            return
        counter += 1
        current = nxt


def _is_valid_final(aead: AESGCM, header: Header, counter: int, chunk: bytes, aad: bytes) -> bool:
    try:
        aead.decrypt(_nonce(header.nonce_prefix, counter, True), chunk, aad)
        return True
    except InvalidTag:
        return False


def rewrap_header(header: Header, file_key: bytes, *, derive_kek: DeriveKEK, kdf_id: int,
                  settings: bytes) -> bytes:
    """Return a new header with the file key wrapped under a new KEK.

    ``derive_kek(salt)`` is called with a fresh random salt. The body that
    follows the old header can be copied unchanged.
    """
    block = _build_key_block(file_key, derive_kek, kdf_id, settings)
    return block + header.nonce_prefix + struct.pack("<I", header.chunk_size)


def _read_exact(f: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        piece = f.read(n - len(buf))
        if not piece:
            break
        buf += piece
    return bytes(buf)
