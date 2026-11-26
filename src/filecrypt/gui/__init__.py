"""A desktop window for filecrypt (needs the ``gui`` extra: ``pip install filecrypt[gui]``).

Start it with ``filecrypt-gui [FILE...]`` or ``python -m filecrypt.gui [FILE...]``.

Explorer integration (Windows)::

    filecrypt-gui --register            add "Encrypt with filecrypt" and .fcx entries
    filecrypt-gui --unregister          remove them again
    (add --quiet to either to skip the message box; the exit code still tells)
    filecrypt-gui --encrypt -- PATH...  what the right-click entries run
    filecrypt-gui --decrypt -- PATH...
    filecrypt-gui --test -- PATH...
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Launch:
    """What the command line asked for."""
    action: str = "open"          # "open", "encrypt", "decrypt", "test", "register", "unregister"
    paths: List[str] = field(default_factory=list)
    quiet: bool = False           # --register/--unregister: no message box (installers)

    @property
    def from_shell(self) -> bool:
        """Started by an Explorer verb (one process per selected file)."""
        return self.action in ("encrypt", "decrypt", "test")


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):   # don't print and exit; the GUI may have no console
        raise UsageError(message)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="filecrypt-gui", add_help=False,
                description="Encrypt and decrypt files in a window.")
    g = p.add_mutually_exclusive_group()
    for name in ("encrypt", "decrypt", "test", "register", "unregister"):
        g.add_argument(f"--{name}", dest="action", action="store_const", const=name)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("paths", nargs="*")
    return p


def usage() -> str:
    return _parser().format_usage().strip()


def parse_args(argv: List[str], cwd: Optional[str] = None) -> Launch:
    """Parse the command line. Paths are made absolute against ``cwd``.

    Everything after ``--`` is a path, even if it starts with ``-``.
    """
    ns = _parser().parse_args(argv)
    if ns.help:
        raise UsageError(usage())
    action = ns.action or "open"
    if action in ("register", "unregister"):
        if ns.paths:
            raise UsageError(f"--{action} takes no files")
        return Launch(action, quiet=ns.quiet)
    if ns.quiet:
        raise UsageError("--quiet only goes with --register or --unregister")
    if action != "open" and not ns.paths:
        raise UsageError(f"--{action} needs at least one file after --")
    base = cwd or os.getcwd()
    paths = [os.path.normpath(os.path.join(base, p)) for p in ns.paths]
    return Launch(action, paths)


def harden_startup(app_dir: Optional[str] = None, restrict_dlls: bool = True) -> None:
    """Keep the clicked file's folder out of DLL and module searches.

    Explorer starts verbs with the current directory set to the folder of the
    clicked file, often Downloads. A DLL or ``.py`` file planted there must
    never be loaded, so: no DLLs from the current directory or PATH, no
    imports from the current directory, and change to the app's own folder.
    Call after the paths on the command line have been made absolute.
    """
    cwd = os.getcwd()
    sys.path[:] = [p for p in sys.path
                   if p not in ("", ".") and os.path.normcase(os.path.abspath(p))
                   != os.path.normcase(cwd)]
    if restrict_dlls and sys.platform == "win32":
        import ctypes
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.SetDefaultDllDirectories.argtypes = [ctypes.c_uint32]
            k32.SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
            k32.SetDllDirectoryW.argtypes = [ctypes.c_wchar_p]
            k32.SetDllDirectoryW("")        # also drop the current directory
        except (AttributeError, OSError):
            pass
    if app_dir is None:
        if getattr(sys, "frozen", False):
            app_dir = os.path.dirname(os.path.abspath(sys.executable))
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        os.chdir(app_dir)
    except OSError:
        pass


def _message(text: str, error: bool = True) -> None:
    """Show ``text`` on stderr, or in a message box when there is no console."""
    stream = sys.stderr
    if stream is not None and getattr(stream, "isatty", lambda: False)():
        print(text, file=stream)
        return
    if sys.platform == "win32":
        try:
            import ctypes
            MB_ICONERROR, MB_ICONINFORMATION = 0x10, 0x40
            ctypes.windll.user32.MessageBoxW(None, text, "filecrypt",
                                             MB_ICONERROR if error else MB_ICONINFORMATION)
            return
        except Exception:
            pass
    if stream is not None:
        print(text, file=stream)


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        launch = parse_args(argv)
    except UsageError as e:
        _message(str(e))
        return 2

    if launch.action in ("register", "unregister"):
        from . import shell
        say = (lambda text, error=True: None) if launch.quiet else _message
        try:
            if launch.action == "register":
                shell.register()
                say("filecrypt was added to Explorer's right-click menu. To make .fcx "
                         "files open with filecrypt on double-click, pick filecrypt once "
                         "under \"Open with\" if Windows asks.", error=False)
            else:
                shell.unregister()
                say("filecrypt was removed from Explorer.", error=False)
        except (shell.ShellError, OSError) as e:
            say(f"filecrypt-gui: {e}")
            return 1
        return 0

    harden_startup()
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        _message("filecrypt-gui needs PySide6: pip install \"filecrypt[gui]\"")
        return 2

    from .. import __version__

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName("filecrypt")
    app.setApplicationVersion(__version__)

    lock = server = None
    if launch.from_shell:
        from . import single_instance
        try:
            role, lock = single_instance.hand_off(launch.action, launch.paths)
        except OSError:
            role = "alone"
        if role == "sent":
            return 0

    from .window import MainWindow
    window = MainWindow()
    if launch.paths:
        window.open_request(launch.action, launch.paths)
    if lock is not None:
        from . import single_instance
        server = single_instance.make_server(parent=window)
        if server is not None:
            server.received.connect(window.open_request)
    window.show()
    try:
        return app.exec()
    finally:
        if server is not None:
            server.close()
        if lock is not None:
            lock.release()
