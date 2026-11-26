# PyInstaller spec for the portable (onedir) Windows build of filecrypt.
#
#   pip install --require-hashes -r packaging/requirements-build.txt
#   pip install --no-deps --no-build-isolation .
#   pyinstaller --noconfirm --clean packaging/filecrypt.spec
#
# The result is one folder, dist/filecrypt/, holding:
#   filecrypt-gui.exe       the desktop window (no console)
#   filecrypt.exe           the command line tool
#   filecrypt-selftest.exe  the frozen self-test (packaging/selftest.py); CI
#                           runs it and deletes it before zipping the folder
# All three share one copy of Python, Qt and cryptography in _internal/.
#
# The build is unsigned. UPX stays off: packed executables trip antivirus
# heuristics and make crash dumps harder to read.

import os

HERE = SPECPATH  # noqa: F821 (set by PyInstaller)
ROOT = os.path.dirname(HERE)

# Small launcher scripts, written into the build folder so the source tree
# stays untouched. Each one calls the same function the pip entry point does.
os.makedirs(workpath, exist_ok=True)  # noqa: F821 (set by PyInstaller)
LAUNCHERS = {
    "filecrypt-gui": "from filecrypt.gui import main\nraise SystemExit(main())\n",
    "filecrypt": "from filecrypt.cli import main\nraise SystemExit(main())\n",
}
scripts = {}
for name, body in LAUNCHERS.items():
    path = os.path.join(workpath, name.replace("-", "_") + "_launcher.py")  # noqa: F821
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    scripts[name] = path
scripts["filecrypt-selftest"] = os.path.join(HERE, "selftest.py")

# Never bundle these. argon2-cffi in particular must stay out, so the frozen
# app can only use cryptography's native Argon2id (the self-test checks it).
EXCLUDES = ["argon2", "_argon2_cffi_bindings", "keyring", "tkinter"]
GUI_MODULES = ["filecrypt.gui.window", "filecrypt.gui.worker", "filecrypt.gui.strength"]


def analysis(script, hiddenimports=()):
    return Analysis(  # noqa: F821
        [script],
        pathex=[os.path.join(ROOT, "src")],
        hiddenimports=list(hiddenimports),
        excludes=EXCLUDES,
        noarchive=False,
    )


def exe(a, name, console):
    pyz = PYZ(a.pure)  # noqa: F821
    return EXE(  # noqa: F821
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=name,
        console=console,
        upx=False,
        strip=False,
        debug=False,
    )


gui = analysis(scripts["filecrypt-gui"], GUI_MODULES)
cli = analysis(scripts["filecrypt"])
selftest = analysis(scripts["filecrypt-selftest"], GUI_MODULES)

coll = COLLECT(  # noqa: F821
    exe(gui, "filecrypt-gui", console=False), gui.binaries, gui.datas,
    exe(cli, "filecrypt", console=True), cli.binaries, cli.datas,
    exe(selftest, "filecrypt-selftest", console=True), selftest.binaries, selftest.datas,
    upx=False,
    strip=False,
    name="filecrypt",
)
