"""Explorer integration: per-user right-click and double-click entries.

``filecrypt-gui --register`` writes these keys under
``HKEY_CURRENT_USER\\Software\\Classes`` (no administrator rights needed)::

    *\\shell\\filecrypt.encrypt              "Encrypt with filecrypt"
        command  "<app>" --encrypt -- "%1"
    .fcx\\OpenWithProgids  filecrypt.fcx
    .fcx  (default) = filecrypt.fcx         only if .fcx had no handler yet
    filecrypt.fcx                            "filecrypt encrypted file"
        shell (default) = decrypt            what double-click does
        shell\\decrypt  command  "<app>" --decrypt -- "%1"
        shell\\test     command  "<app>" --test -- "%1"

Windows 10 and later don't let programs make themselves the default app for
a file type once the person has picked one, so if ``.fcx`` already opens with
something else, the person picks filecrypt once from "Open with".

``--unregister`` removes only the keys and values listed above, and the
``.fcx`` default only while it still points at filecrypt.

Every function takes the registry module as ``reg`` (``winreg`` by default),
so tests can pass a fake and never touch the real registry.
"""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

CLASSES = r"Software\Classes"
ENCRYPT_VERB = r"*\shell\filecrypt.encrypt"
PROGID = "filecrypt.fcx"
EXTENSION = ".fcx"
OPEN_WITH = EXTENSION + r"\OpenWithProgids"

ENCRYPT_LABEL = "Encrypt with filecrypt"
DECRYPT_LABEL = "Decrypt with filecrypt"
TEST_LABEL = "Test with filecrypt"
TYPE_NAME = "filecrypt encrypted file"


class ShellError(Exception):
    """Registration can't be done (wrong platform, unusable install, ...)."""


# --- the command Explorer runs -------------------------------------------------------

def _quote(arg: str) -> str:
    if '"' in arg:
        # Windows paths can't contain a double quote, so this isn't a real path.
        raise ShellError(f"can't register a path containing a double quote: {arg}")
    return f'"{arg}"'


def launcher(*, frozen: Optional[bool] = None, executable: Optional[str] = None,
             scripts_dirs: Optional[Sequence[str]] = None,
             package_file: Optional[str] = None,
             user_site: Optional[str] = None) -> List[str]:
    """The program (and leading arguments) Explorer should start.

    * A PyInstaller build: the build's own exe.
    * A pip install: the ``filecrypt-gui.exe`` launcher pip put in Scripts.
      It runs the app without putting the clicked file's folder on
      ``sys.path``, which ``python -m`` would do.
    * Otherwise ``pythonw.exe -I -m filecrypt.gui``. ``-I`` keeps the
      current folder off ``sys.path``, but it also hides per-user
      site-packages, so a ``pip install --user`` without the launcher is
      refused rather than registered broken.
    """
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    executable = executable or sys.executable
    if frozen:
        return [os.path.abspath(executable)]
    if scripts_dirs is None:
        scripts_dirs = [d for d in (sysconfig.get_path("scripts"),
                                    _user_scripts_dir()) if d]
    for d in scripts_dirs:
        exe = Path(d) / "filecrypt-gui.exe"
        if exe.is_file():
            return [os.path.abspath(exe)]
    exe = Path(executable)
    pythonw = exe.with_name("pythonw.exe")
    if not pythonw.is_file():
        raise ShellError(f"can't find pythonw.exe next to {executable}")
    if package_file is None:
        from .. import __file__ as package_file
    if user_site is None:
        import site
        user_site = site.getusersitepackages() if site.ENABLE_USER_SITE else ""
    if user_site and _is_within(package_file, user_site):
        raise ShellError("filecrypt is installed per user (pip install --user) and its "
                         "filecrypt-gui.exe launcher wasn't found; reinstall it so the "
                         "launcher exists, or install it without --user")
    return [os.path.abspath(pythonw), "-I", "-m", "filecrypt.gui"]


def _user_scripts_dir() -> Optional[str]:
    try:
        return sysconfig.get_path("scripts", f"{os.name}_user")
    except KeyError:
        return None


def _is_within(path: str, folder: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(folder).resolve())
    except ValueError:
        return False
    return True


def command(action: str, program: Sequence[str]) -> str:
    """The registry command line: ``"<app>" [args] --<action> -- "%1"``.

    ``--`` makes sure a file whose name starts with ``-`` is read as a file.
    """
    if action not in ("encrypt", "decrypt", "test"):
        raise ValueError(action)
    exe, *args = program
    parts = [_quote(exe)] + [a if a.startswith("-") else _quote(a) for a in args]
    return " ".join(parts + [f"--{action}", "--", '"%1"'])


# --- what gets written -------------------------------------------------------------------

Entries = List[Tuple[str, Optional[str], Any]]   # (subkey, value name or None, data)


def entries(program: Sequence[str]) -> Entries:
    """Every key and value we write, relative to ``Software\\Classes``."""
    icon = f"{program[0]},0"
    return [
        (ENCRYPT_VERB, None, ENCRYPT_LABEL),
        (ENCRYPT_VERB, "Icon", icon),
        # Show the verb however many files are selected (the default stops at 15).
        (ENCRYPT_VERB, "MultiSelectModel", "Player"),
        (ENCRYPT_VERB + r"\command", None, command("encrypt", program)),
        (PROGID, None, TYPE_NAME),
        (PROGID, "FriendlyTypeName", TYPE_NAME),
        (PROGID + r"\DefaultIcon", None, icon),
        (PROGID + r"\shell", None, "decrypt"),
        (PROGID + r"\shell\decrypt", None, DECRYPT_LABEL),
        (PROGID + r"\shell\decrypt", "MultiSelectModel", "Player"),
        (PROGID + r"\shell\decrypt\command", None, command("decrypt", program)),
        (PROGID + r"\shell\test", None, TEST_LABEL),
        (PROGID + r"\shell\test", "MultiSelectModel", "Player"),
        (PROGID + r"\shell\test\command", None, command("test", program)),
        (OPEN_WITH, PROGID, ""),
    ]


def _winreg(reg: Any) -> Any:
    if reg is not None:
        return reg
    if sys.platform != "win32":
        raise ShellError("Explorer integration is only available on Windows")
    import winreg
    return winreg


def _get(reg: Any, subkey: str, name: Optional[str]) -> Optional[Any]:
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{subkey}") as k:
            return reg.QueryValueEx(k, name or "")[0]
    except OSError:
        return None


def register(program: Optional[Sequence[str]] = None, *, reg: Any = None) -> bool:
    """Add the right-click and double-click entries for the current user.

    Only values that are missing or different are written, and Explorer is
    told about the change only if something was written, so running the
    installer again (or upgrading in place) doesn't make every Explorer
    window refresh. Returns whether anything changed.
    """
    reg = _winreg(reg)
    program = list(program) if program is not None else launcher()
    changed = False
    for subkey, name, data in entries(program):
        if _get(reg, subkey, name) == data:
            continue
        with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{subkey}", 0,
                             reg.KEY_WRITE) as k:
            reg.SetValueEx(k, name or "", 0, reg.REG_SZ, data)
        changed = True
    # Claim double-click for .fcx only if nothing else has.
    if not _get(reg, EXTENSION, None):
        with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{EXTENSION}", 0,
                             reg.KEY_WRITE) as k:
            reg.SetValueEx(k, "", 0, reg.REG_SZ, PROGID)
        changed = True
    if changed:
        notify_shell()
    return changed


def _delete_tree(reg: Any, path: str) -> bool:
    """Delete ``HKCU\\path`` and everything below it; missing keys are fine.

    Returns whether the key was there.
    """
    try:
        k = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ)
    except OSError:
        return False
    with k:
        children = []
        i = 0
        while True:
            try:
                children.append(reg.EnumKey(k, i))
            except OSError:
                break
            i += 1
    for child in children:
        _delete_tree(reg, f"{path}\\{child}")
    try:
        reg.DeleteKey(reg.HKEY_CURRENT_USER, path)
    except OSError:
        pass
    return True


def _is_empty(reg: Any, path: str) -> bool:
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ) as k:
            subkeys, values, _ = reg.QueryInfoKey(k)
    except OSError:
        return False
    return subkeys == 0 and values == 0


def unregister(*, reg: Any = None) -> bool:
    """Remove what :func:`register` added, and nothing else.

    Explorer is told only if something was removed. Returns whether anything
    changed.
    """
    reg = _winreg(reg)
    changed = _delete_tree(reg, f"{CLASSES}\\{ENCRYPT_VERB}")
    changed = _delete_tree(reg, f"{CLASSES}\\{PROGID}") or changed
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{OPEN_WITH}", 0,
                         reg.KEY_SET_VALUE) as k:
            reg.DeleteValue(k, PROGID)
        changed = True
    except OSError:
        pass
    if _get(reg, EXTENSION, None) == PROGID:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{EXTENSION}", 0,
                         reg.KEY_SET_VALUE) as k:
            reg.DeleteValue(k, "")
        changed = True
    # Tidy up keys we may have created, but only if nothing else lives there.
    for path in (OPEN_WITH, EXTENSION, r"*\shell"):
        if _is_empty(reg, f"{CLASSES}\\{path}"):
            try:
                reg.DeleteKey(reg.HKEY_CURRENT_USER, f"{CLASSES}\\{path}")
            except OSError:
                pass
    if changed:
        notify_shell()
    return changed


def registered_commands(*, reg: Any = None) -> Dict[str, Optional[str]]:
    """The command lines currently registered (None where missing)."""
    reg = _winreg(reg)
    return {
        "encrypt": _get(reg, ENCRYPT_VERB + r"\command", None),
        "decrypt": _get(reg, PROGID + r"\shell\decrypt\command", None),
        "test": _get(reg, PROGID + r"\shell\test\command", None),
    }


def notify_shell() -> None:
    """Tell Explorer, once, that file associations changed, so menus and icons refresh.

    ``SHCNE_ASSOCCHANGED`` makes Explorer drop its icon cache and repaint
    every open folder window, which is noticeable on a busy desktop, so the
    callers send it only when they really changed something, and send it
    exactly once. No ``SHCNF_FLUSH`` flag: the event is queued and this call
    returns without waiting for Explorer (or any other window) to process it.
    Nothing here broadcasts ``WM_SETTINGCHANGE``.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        SHCNE_ASSOCCHANGED, SHCNF_IDLIST = 0x08000000, 0
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:   # cosmetic only; Explorer catches up on its own
        pass
