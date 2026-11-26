"""Owner-only file permissions on Windows.

POSIX mode bits don't exist on Windows: ``os.open(path, ..., 0o600)`` only
controls the read-only flag, and the file inherits its folder's ACL. The
owner-only DACL used here is protected (no inheritance) and grants full
control to the current user and SYSTEM only.

:func:`create_owner_only` creates a new file with that DACL already in place,
so there is no moment when the file exists with the folder's ACL and another
account could open it. :func:`restrict_to_owner` replaces the DACL of an
existing file and is the fallback when that isn't possible.
"""

from __future__ import annotations

import ctypes
import msvcrt
import os
import subprocess
from ctypes import wintypes
from typing import Optional

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_CREATE_NEW = 1
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_TEMPORARY = 0x100
_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
_advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
_advapi32.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(wintypes.ULONG)]
_kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(_SecurityAttributes), wintypes.DWORD,
                                  wintypes.DWORD, wintypes.HANDLE]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def _check(ok) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def current_user_sid() -> str:
    token = wintypes.HANDLE()
    _check(_advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)))
    try:
        size = wintypes.DWORD()
        _advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        _check(_advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, buf, size, ctypes.byref(size)))
        sid_ptr = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_USER.User.Sid
        out = wintypes.LPWSTR()
        _check(_advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)))
        try:
            return out.value
        finally:
            _kernel32.LocalFree(out)
    finally:
        _kernel32.CloseHandle(token)


def _owner_only_sddl() -> str:
    return f"D:P(A;;FA;;;{current_user_sid()})(A;;FA;;;SY)"


def _owner_only_sd() -> ctypes.c_void_p:
    """A self-relative security descriptor holding the owner-only DACL.

    The caller frees it with ``LocalFree``.
    """
    sd = ctypes.c_void_p()
    _check(_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        _owner_only_sddl(), _SDDL_REVISION_1, ctypes.byref(sd), None))
    return sd


def create_owner_only(path, *, delete_on_close: bool = False) -> Optional[int]:
    """Create ``path`` with the owner-only DACL applied as it is created.

    Returns a binary, non-inheritable file descriptor open for reading and
    writing, like ``os.open(path, O_RDWR | O_CREAT | O_EXCL | O_BINARY |
    O_NOINHERIT)``. With ``delete_on_close`` the file is also opened like
    ``O_TEMPORARY``: Windows deletes it when the last handle closes.

    Raises ``FileExistsError`` if ``path`` exists, and ``OSError`` for other
    failures to create the file. Returns None, without creating anything,
    when the security descriptor can't be built; callers then fall back to
    creating the file and calling :func:`restrict_to_owner`.
    """
    path = os.fspath(path)
    try:
        sd = _owner_only_sd()
    except OSError:
        return None
    try:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), sd, False)
        access = _GENERIC_READ | _GENERIC_WRITE
        attrs = _FILE_ATTRIBUTE_NORMAL
        if delete_on_close:
            access |= _DELETE
            attrs = _FILE_ATTRIBUTE_TEMPORARY | _FILE_FLAG_DELETE_ON_CLOSE
        handle = _kernel32.CreateFileW(path, access, _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                                       ctypes.byref(sa), _CREATE_NEW, attrs, None)
        if handle is None or handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise OSError(None, ctypes.FormatError(err), path, err)
    finally:
        _kernel32.LocalFree(sd)
    try:
        fd = msvcrt.open_osfhandle(handle, 0)  # handle is already non-inheritable
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise
    msvcrt.setmode(fd, os.O_BINARY)
    return fd


def _set_dacl_ctypes(path: str) -> bool:
    try:
        sd = _owner_only_sd()
        try:
            _check(_advapi32.SetFileSecurityW(
                path, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION, sd))
        finally:
            _kernel32.LocalFree(sd)
        return True
    except OSError:
        return False


def _set_dacl_icacls(path: str) -> bool:
    user = os.environ.get("USERNAME")
    if not user:
        return False
    try:
        r = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
                           capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def restrict_to_owner(path) -> bool:
    """Make ``path`` accessible only to the current user and SYSTEM.

    Tries the Win32 API first, then ``icacls``. Returns False if both fail.
    """
    path = os.fspath(path)
    return _set_dacl_ctypes(path) or _set_dacl_icacls(path)


def dacl_sddl(path) -> str:
    """The file's DACL in SDDL form (used by tests and for diagnostics)."""
    path = os.fspath(path)
    size = wintypes.DWORD()
    _advapi32.GetFileSecurityW(path, _DACL_SECURITY_INFORMATION, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    _check(_advapi32.GetFileSecurityW(path, _DACL_SECURITY_INFORMATION, buf, size, ctypes.byref(size)))
    out = wintypes.LPWSTR()
    _check(_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buf, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(out), None))
    try:
        return out.value
    finally:
        _kernel32.LocalFree(out)
