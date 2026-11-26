"""Owner-only file permissions on Windows.

POSIX mode bits don't exist on Windows: ``os.open(path, ..., 0o600)`` only
controls the read-only flag, and the file inherits its folder's ACL. These
helpers replace a file's DACL with a protected one (no inheritance) that
grants full control to the current user and SYSTEM only.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from ctypes import wintypes

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1

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


def _set_dacl_ctypes(path: str) -> bool:
    try:
        sddl = f"D:P(A;;FA;;;{current_user_sid()})(A;;FA;;;SY)"
        sd = ctypes.c_void_p()
        _check(_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(sd), None))
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
