"""Toggle Windows delete-on-close on an open file.

A temp file opened delete-on-close (``_winacl.create_owner_only`` with
``delete_on_close=True``, like ``os.O_TEMPORARY``) is deleted by Windows when its
last handle closes, even if the process is killed or the console window is
closed. Clearing the flag just before commit lets us keep and rename it.
This needs FileDispositionInfoEx (Windows 10 1709 or later); callers fall
back to an ordinary temp file when it isn't available.
"""

from __future__ import annotations

import ctypes
import msvcrt
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD]

_FILE_DISPOSITION_INFO_EX = 21
_FLAG_DO_NOT_DELETE = 0x0
_FLAG_DELETE = 0x1
_FLAG_ON_CLOSE = 0x8


def set_delete_on_close(fd: int, enabled: bool) -> bool:
    """Set or clear delete-on-close for ``fd``. Returns False if unsupported."""
    flags = wintypes.DWORD((_FLAG_DELETE if enabled else _FLAG_DO_NOT_DELETE) | _FLAG_ON_CLOSE)
    try:
        handle = msvcrt.get_osfhandle(fd)
    except OSError:
        return False
    return bool(_kernel32.SetFileInformationByHandle(
        handle, _FILE_DISPOSITION_INFO_EX, ctypes.byref(flags), ctypes.sizeof(flags)))
