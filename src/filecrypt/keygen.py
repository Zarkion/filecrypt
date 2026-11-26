"""Random key generation and keyfile handling."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import sys
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
    On Windows, where mode bits don't apply, the file is created with a
    protected DACL granting only the current user and SYSTEM, so it is never
    readable by anyone else, even for an instant. If that can't be done the
    file is created normally and restricted before any key bytes are written;
    if that fails too a warning is printed and the file keeps the folder's
    inherited ACL.
    """
    path = Path(path)
    target = path if not force else path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = _create_exclusive(target, path)
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


def _create_exclusive(target: Path, shown: Path) -> int:
    """Create ``target`` (which must not exist) owner-only and return its fd."""
    if os.name != "nt":
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        return os.open(target, flags, 0o600)
    from . import _winacl
    fd = _winacl.create_owner_only(target)
    if fd is not None:
        return fd
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)
    try:
        restricted = _winacl.restrict_to_owner(target)
    except BaseException:
        os.close(fd)
        os.unlink(target)
        raise
    if not restricted:
        print(f"filecrypt: warning: could not restrict {shown} to your user account; "
              f"it has the folder's permissions", file=sys.stderr)
    return fd
