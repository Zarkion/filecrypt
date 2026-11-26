"""Random key generation and keyfile handling."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from pathlib import Path
from typing import Union

from .kdf import MIN_KEY_BYTES

FORMATS = ("raw", "base64")


def generate_key(nbytes: int = 32) -> bytes:
    if nbytes < MIN_KEY_BYTES:
        raise ValueError(f"keys must be at least {MIN_KEY_BYTES} bytes")
    return secrets.token_bytes(nbytes)


def encode_key(key: bytes, fmt: str) -> bytes:
    if fmt == "raw":
        return key
    if fmt == "base64":
        return base64.b64encode(key) + b"\n"
    raise ValueError(f"unknown key format {fmt!r} (choose raw or base64)")


def load_key_material(data: bytes) -> bytes:
    """Return the key bytes from keyfile contents.

    A file holding standard base64 that decodes to at least 32 bytes (what
    ``keygen --format base64`` writes) is decoded, so raw and base64 copies of
    the same key are interchangeable and a trailing newline doesn't matter.
    Anything else is used exactly as stored.
    """
    stripped = data.strip()
    if stripped and len(stripped) % 4 == 0:
        try:
            decoded = base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError):
            return data
        if len(decoded) >= MIN_KEY_BYTES:
            return decoded
    return data


def write_keyfile(path: Union[str, Path], data: bytes, *, force: bool = False) -> None:
    """Write a keyfile readable only by the owner (mode 0600 on POSIX).

    Without ``force`` the file is created exclusively and an existing file is
    never touched. With ``force`` a temp file is written and renamed over it.
    On Windows the mode only controls the read-only flag; the file inherits
    the folder's ACL (normally owner-only under your user profile).
    """
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    target = path if not force else path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if force:
            os.replace(target, path)
    except BaseException:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
