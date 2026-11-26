"""Carry the Windows "Mark of the Web" from an input file to its output.

Windows records where a downloaded file came from in an NTFS alternate data
stream named ``Zone.Identifier``. SmartScreen, Office Protected View and
others read it before they open the file. If ``invoice.exe`` came from the
internet, encrypting it to ``invoice.exe.fcx`` and decrypting it again must
not hand back an ``invoice.exe`` that looks local, so the stream is copied
from each input onto its output.

On other systems, or when the input has no mark, nothing happens.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Optional

STREAM = ":Zone.Identifier"

# A real Zone.Identifier is a few hundred bytes of INI text. Anything larger is
# not something we want to copy around.
MAX_SIZE = 64 * 1024

Opener = Callable[[str, str], "object"]


def read_zone_identifier(path: "os.PathLike[str] | str", *,
                         opener: Optional[Opener] = None) -> Optional[bytes]:
    """The raw ``Zone.Identifier`` stream of ``path``, or None if it has none."""
    if opener is None:
        if sys.platform != "win32":
            return None
        opener = open
    try:
        with opener(os.fspath(path) + STREAM, "rb") as f:   # type: ignore[attr-defined]
            data = f.read(MAX_SIZE + 1)
    except OSError:
        return None
    if not data or len(data) > MAX_SIZE:
        return None
    return data


def copy_zone_identifier(src: "os.PathLike[str] | str", dest: "os.PathLike[str] | str", *,
                         opener: Optional[Opener] = None) -> Optional[bool]:
    """Copy the mark from ``src`` onto ``dest``.

    Returns None when there was nothing to copy (no mark, or not Windows),
    True when the mark was copied and False when ``src`` has a mark that could
    not be written to ``dest`` (for example on a FAT32 USB stick, which has no
    alternate data streams). Callers should tell the person about False.
    """
    data = read_zone_identifier(src, opener=opener)
    if data is None:
        return None
    if opener is None:
        opener = open
    try:
        with opener(os.fspath(dest) + STREAM, "wb") as f:   # type: ignore[attr-defined]
            f.write(data)
    except OSError:
        return False
    return True
