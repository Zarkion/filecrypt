"""Explorer registration (with a fake winreg) and the filecrypt-gui command line.

Nothing here needs Qt or Windows, and nothing touches a real registry.
"""

import os
import sys
from pathlib import Path

import pytest

from filecrypt.gui import Launch, UsageError, harden_startup, parse_args, shell


class FakeKey:
    def __init__(self, reg, path):
        self.reg, self.path = reg, path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeWinreg:
    """Just enough of winreg, case-insensitive like the real registry."""

    HKEY_CURRENT_USER = "HKCU"
    KEY_READ, KEY_WRITE, KEY_SET_VALUE = 1, 2, 4
    REG_SZ = 1

    def __init__(self):
        self.keys = {}       # lower-case path -> {lower-case value name: data}
        self.names = {}      # lower-case path -> path as first written

    @staticmethod
    def _norm(path):
        return path.lower()

    def _parent_chain(self, path):
        parts = path.split("\\")
        return ["\\".join(parts[:i]) for i in range(1, len(parts) + 1)]

    def CreateKeyEx(self, root, path, reserved=0, access=0):
        assert root == self.HKEY_CURRENT_USER
        for p in self._parent_chain(path):
            self.keys.setdefault(self._norm(p), {})
            self.names.setdefault(self._norm(p), p)
        return FakeKey(self, self._norm(path))

    def OpenKey(self, root, path, reserved=0, access=1):
        assert root == self.HKEY_CURRENT_USER
        if self._norm(path) not in self.keys:
            raise FileNotFoundError(path)
        return FakeKey(self, self._norm(path))

    def QueryValueEx(self, key, name):
        values = self.keys[key.path]
        if name.lower() not in values:
            raise FileNotFoundError(name)
        return values[name.lower()], self.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, data):
        assert kind == self.REG_SZ and isinstance(data, str)
        self.keys[key.path][name.lower()] = data

    def DeleteValue(self, key, name):
        if name.lower() not in self.keys[key.path]:
            raise FileNotFoundError(name)
        del self.keys[key.path][name.lower()]

    def _children(self, path):
        prefix = path + "\\"
        return sorted({k[len(prefix):].split("\\")[0] for k in self.keys if k.startswith(prefix)})

    def EnumKey(self, key, i):
        children = self._children(key.path)
        if i >= len(children):
            raise OSError("no more keys")
        return children[i]

    def QueryInfoKey(self, key):
        return len(self._children(key.path)), len(self.keys[key.path]), 0

    def DeleteKey(self, root, path):
        p = self._norm(path)
        if p not in self.keys:
            raise FileNotFoundError(path)
        if self._children(p):
            raise PermissionError("key has subkeys")
        del self.keys[p]

    # helpers for tests
    def get(self, path, name=""):
        return self.keys.get(self._norm(path), {}).get(name.lower())

    def exists(self, path):
        return self._norm(path) in self.keys


C = shell.CLASSES
EXE = r"C:\Program Files\filecrypt\filecrypt-gui.exe"


@pytest.fixture
def reg(monkeypatch):
    monkeypatch.setattr(shell, "notify_shell", lambda: None)
    return FakeWinreg()


# --- command lines ---------------------------------------------------------------------

def test_command_quotes_and_ends_options():
    assert shell.command("encrypt", [EXE]) == f'"{EXE}" --encrypt -- "%1"'
    assert (shell.command("decrypt", [r"C:\Py\pythonw.exe", "-I", "-m", "filecrypt.gui"])
            == r'"C:\Py\pythonw.exe" -I -m "filecrypt.gui" --decrypt -- "%1"')


def test_command_refuses_quotes_and_unknown_actions():
    with pytest.raises(shell.ShellError):
        shell.command("encrypt", ['C:\\a"b\\x.exe'])
    with pytest.raises(ValueError):
        shell.command("open", [EXE])


def test_launcher_for_a_frozen_build():
    assert shell.launcher(frozen=True, executable=EXE) == [os.path.abspath(EXE)]


def test_launcher_prefers_the_pip_gui_script(tmp_path):
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    (scripts / "filecrypt-gui.exe").write_bytes(b"MZ")
    assert shell.launcher(frozen=False, executable=str(tmp_path / "python.exe"),
                          scripts_dirs=[str(tmp_path / "missing"), str(scripts)]) \
        == [os.path.abspath(scripts / "filecrypt-gui.exe")]


def test_launcher_falls_back_to_isolated_pythonw(tmp_path):
    (tmp_path / "pythonw.exe").write_bytes(b"MZ")
    got = shell.launcher(frozen=False, executable=str(tmp_path / "python.exe"),
                         scripts_dirs=[], package_file=str(tmp_path / "lib" / "x.py"),
                         user_site=str(tmp_path / "user"))
    assert got == [os.path.abspath(tmp_path / "pythonw.exe"), "-I", "-m", "filecrypt.gui"]


def test_launcher_refuses_isolated_mode_for_a_user_install(tmp_path):
    (tmp_path / "pythonw.exe").write_bytes(b"MZ")
    user = tmp_path / "user"
    (user / "filecrypt").mkdir(parents=True)
    with pytest.raises(shell.ShellError, match="--user"):
        shell.launcher(frozen=False, executable=str(tmp_path / "python.exe"), scripts_dirs=[],
                       package_file=str(user / "filecrypt" / "__init__.py"),
                       user_site=str(user))


def test_launcher_needs_pythonw(tmp_path):
    with pytest.raises(shell.ShellError, match="pythonw"):
        shell.launcher(frozen=False, executable=str(tmp_path / "python.exe"), scripts_dirs=[],
                       package_file=str(tmp_path / "x.py"), user_site="")


# --- registering ------------------------------------------------------------------------

def test_register_writes_the_verbs(reg):
    shell.register([EXE], reg=reg)
    assert reg.get(rf"{C}\*\shell\filecrypt.encrypt") == "Encrypt with filecrypt"
    assert reg.get(rf"{C}\*\shell\filecrypt.encrypt\command") == f'"{EXE}" --encrypt -- "%1"'
    assert reg.get(rf"{C}\filecrypt.fcx\shell") == "decrypt"          # double-click
    assert reg.get(rf"{C}\filecrypt.fcx\shell\decrypt\command") == f'"{EXE}" --decrypt -- "%1"'
    assert reg.get(rf"{C}\filecrypt.fcx\shell\test\command") == f'"{EXE}" --test -- "%1"'
    assert reg.get(rf"{C}\filecrypt.fcx\DefaultIcon") == f"{EXE},0"
    assert reg.get(rf"{C}\.fcx\OpenWithProgids", "filecrypt.fcx") == ""
    assert reg.get(rf"{C}\.fcx") == "filecrypt.fcx"
    assert shell.registered_commands(reg=reg)["test"] == f'"{EXE}" --test -- "%1"'


def test_register_writes_only_under_classes(reg):
    shell.register([EXE], reg=reg)
    written = [k for k, values in reg.keys.items() if values]
    assert written and all(k.startswith(C.lower() + "\\") for k in written)


def test_register_keeps_another_apps_fcx_default(reg):
    reg.SetValueEx(reg.CreateKeyEx(reg.HKEY_CURRENT_USER, rf"{C}\.fcx"), "", 0, reg.REG_SZ,
                   "Other.App")
    shell.register([EXE], reg=reg)
    assert reg.get(rf"{C}\.fcx") == "Other.App"
    assert reg.get(rf"{C}\.fcx\OpenWithProgids", "filecrypt.fcx") == ""


def test_register_twice_is_harmless(reg):
    shell.register([EXE], reg=reg)
    first = {k: dict(v) for k, v in reg.keys.items()}
    shell.register([EXE], reg=reg)
    assert reg.keys == first


def test_register_tells_explorer_once_and_only_when_something_changed(monkeypatch):
    calls = []
    monkeypatch.setattr(shell, "notify_shell", lambda: calls.append(1))
    reg = FakeWinreg()
    assert shell.register([EXE], reg=reg) is True
    assert calls == [1]
    # Reinstalling or upgrading in place: nothing to write, no shell-wide refresh.
    assert shell.register([EXE], reg=reg) is False
    assert calls == [1]
    # Moved install: the commands change, so Explorer hears about it once more.
    assert shell.register([r"D:\apps\filecrypt-gui.exe"], reg=reg) is True
    assert calls == [1, 1]


def test_unregister_tells_explorer_only_when_something_was_removed(monkeypatch):
    calls = []
    monkeypatch.setattr(shell, "notify_shell", lambda: calls.append(1))
    reg = FakeWinreg()
    assert shell.unregister(reg=reg) is False
    assert calls == []
    shell.register([EXE], reg=reg)
    calls.clear()
    assert shell.unregister(reg=reg) is True
    assert calls == [1]
    assert shell.unregister(reg=reg) is False
    assert calls == [1]


def test_unregister_removes_everything_we_added(reg):
    shell.register([EXE], reg=reg)
    shell.unregister(reg=reg)
    assert reg.keys == {k: {} for k in reg.keys}   # no values left
    assert not reg.exists(rf"{C}\filecrypt.fcx")
    assert not reg.exists(rf"{C}\*\shell\filecrypt.encrypt")
    assert not reg.exists(rf"{C}\.fcx")
    assert shell.registered_commands(reg=reg) == {"encrypt": None, "decrypt": None,
                                                  "test": None}


def test_unregister_leaves_other_apps_alone(reg):
    other = reg.CreateKeyEx(reg.HKEY_CURRENT_USER, rf"{C}\*\shell\OtherApp\command")
    reg.SetValueEx(other, "", 0, reg.REG_SZ, "other.exe %1")
    ow = reg.CreateKeyEx(reg.HKEY_CURRENT_USER, rf"{C}\.fcx\OpenWithProgids")
    reg.SetValueEx(ow, "Other.App", 0, reg.REG_SZ, "")
    fcx = reg.OpenKey(reg.HKEY_CURRENT_USER, rf"{C}\.fcx")
    reg.SetValueEx(fcx, "", 0, reg.REG_SZ, "Other.App")
    shell.register([EXE], reg=reg)
    shell.unregister(reg=reg)
    assert reg.get(rf"{C}\*\shell\OtherApp\command") == "other.exe %1"
    assert reg.get(rf"{C}\.fcx\OpenWithProgids", "Other.App") == ""
    assert reg.get(rf"{C}\.fcx\OpenWithProgids", "filecrypt.fcx") is None
    assert reg.get(rf"{C}\.fcx") == "Other.App"


def test_unregister_when_nothing_is_registered(reg):
    shell.unregister(reg=reg)
    assert reg.keys == {}


@pytest.mark.skipif(sys.platform == "win32", reason="checks the refusal on other systems")
def test_register_needs_windows_without_a_fake():
    with pytest.raises(shell.ShellError):
        shell.register([EXE])


# --- the command line --------------------------------------------------------------------

def test_no_arguments_opens_an_empty_window():
    assert parse_args([], cwd=os.sep) == Launch("open", [])


def test_plain_file_argument_is_kept(tmp_path):
    got = parse_args(["a.txt"], cwd=str(tmp_path))
    assert got == Launch("open", [os.path.join(str(tmp_path), "a.txt")])


def test_shell_verbs_take_paths_after_double_dash(tmp_path):
    got = parse_args(["--encrypt", "--", "-weird name.txt", "b.txt"], cwd=str(tmp_path))
    assert got.action == "encrypt" and got.from_shell
    assert got.paths == [os.path.join(str(tmp_path), "-weird name.txt"),
                         os.path.join(str(tmp_path), "b.txt")]


def test_absolute_paths_stay_as_they_are(tmp_path):
    p = str(tmp_path / "x.fcx")
    assert parse_args(["--decrypt", "--", p], cwd=os.sep).paths == [p]
    assert parse_args(["--test", "--", p], cwd=os.sep).action == "test"


def test_dash_file_without_double_dash_is_an_error_not_dropped():
    with pytest.raises(UsageError):
        parse_args(["-x.txt"])


@pytest.mark.parametrize("argv", [
    ["--encrypt"], ["--encrypt", "--"], ["--decrypt", "--encrypt", "--", "a"],
    ["--register", "a.txt"], ["--unknown"], ["--help"],
    ["--quiet"], ["--quiet", "a.txt"], ["--encrypt", "--quiet", "--", "a"],
])
def test_bad_command_lines(argv):
    with pytest.raises(UsageError):
        parse_args(argv, cwd=os.sep)


def test_register_and_unregister_flags():
    assert parse_args(["--register"]) == Launch("register", [])
    assert parse_args(["--unregister"]) == Launch("unregister", [])
    assert not Launch("register").from_shell and not Launch("open").from_shell


def test_main_register_uses_shell(monkeypatch):
    import filecrypt.gui as gui
    called = []
    monkeypatch.setattr(shell, "register", lambda: called.append("register"))
    monkeypatch.setattr(shell, "unregister", lambda: called.append("unregister"))
    monkeypatch.setattr(gui, "_message", lambda text, error=True: called.append(error))
    assert gui.main(["--register"]) == 0
    assert gui.main(["--unregister"]) == 0
    assert called == ["register", False, "unregister", False]


def test_quiet_register_shows_nothing_but_keeps_the_exit_code(monkeypatch):
    import filecrypt.gui as gui
    assert parse_args(["--register", "--quiet"]) == Launch("register", [], quiet=True)
    shown = []
    monkeypatch.setattr(gui, "_message", lambda text, error=True: shown.append(text))
    monkeypatch.setattr(shell, "register", lambda: None)
    assert gui.main(["--register", "--quiet"]) == 0

    def fail():
        raise shell.ShellError("no")
    monkeypatch.setattr(shell, "unregister", fail)
    assert gui.main(["--unregister", "--quiet"]) == 1
    assert shown == []


def test_main_reports_usage_errors(monkeypatch):
    import filecrypt.gui as gui
    shown = []
    monkeypatch.setattr(gui, "_message", lambda text, error=True: shown.append(text))
    assert gui.main(["--encrypt"]) == 2
    assert "needs at least one file" in shown[0]


# --- startup hardening ----------------------------------------------------------------------

def test_harden_startup_drops_cwd_from_sys_path_and_moves(tmp_path, monkeypatch):
    work, app = tmp_path / "Downloads", tmp_path / "app"
    work.mkdir()
    app.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(sys, "path", ["", ".", str(work), "/some/lib"])
    harden_startup(app_dir=str(app), restrict_dlls=False)
    assert sys.path == ["/some/lib"]
    assert Path.cwd().resolve() == app.resolve()


def test_harden_startup_defaults_to_the_package_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", list(sys.path))
    harden_startup(restrict_dlls=False)
    import filecrypt.gui as gui
    assert Path.cwd().resolve() == Path(gui.__file__).parent.resolve()


def test_restricted_dll_search_still_starts_qt(tmp_path):
    """The real startup order: harden first, then import Qt and open a window."""
    pytest.importorskip("PySide6.QtWidgets", reason="needs PySide6")
    import subprocess
    code = ("import sys; from filecrypt.gui import harden_startup; harden_startup(); "
            "from PySide6.QtWidgets import QApplication, QLabel; "
            "from PySide6 import QtNetwork; "
            "import cryptography.hazmat.primitives.ciphers.aead; "
            "app = QApplication([]); w = QLabel('x'); w.show(); app.processEvents(); "
            "print('ok')")
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=120,
                         stdin=subprocess.DEVNULL)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("ok")
