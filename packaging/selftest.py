"""Self-test for the frozen (PyInstaller) build of filecrypt.

Two modes:

    selftest.py inside --vectors tests/vectors
        Runs inside the bundle, as dist/filecrypt/filecrypt-selftest.exe. It
        checks that Argon2id comes from cryptography's native code (never the
        argon2-cffi or scrypt fallback), that Qt loads with the offscreen
        platform and that the Windows platform plugin and the main window load,
        then decrypts every valid vector in-process and round-trips a new file
        with the default settings.

    python packaging/selftest.py dist --dist dist/filecrypt --vectors tests/vectors
        Runs from an ordinary Python, using only the standard library. It runs
        the frozen self-test above, then drives the real filecrypt.exe: every
        valid vector must decrypt to its plaintext and a wrong passphrase must
        fail. Finally it starts filecrypt-gui.exe offscreen and checks that it
        stays up.

Exit status 0 means every check passed. Each check prints one line.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXE = ".exe" if sys.platform == "win32" else ""


class CheckFailed(Exception):
    pass


def ok(message: str) -> None:
    print(f"ok    {message}", flush=True)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailed(message)
    ok(message)


def load_manifest(vectors: Path) -> list:
    manifest = json.loads((vectors / "vectors.json").read_text(encoding="ascii"))
    valid = [v for v in manifest["vectors"] if v["valid"]]
    if not valid:
        raise CheckFailed(f"no valid vectors listed in {vectors / 'vectors.json'}")
    return valid


# --- inside the bundle ---------------------------------------------------------

def inside(vectors: Path, allow_unfrozen: bool) -> None:
    # Before anything imports Qt.
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

    if not allow_unfrozen:
        check(bool(getattr(sys, "frozen", False)), "running from the frozen bundle")

    check_argon2()
    check_qt()
    check_vectors_in_process(vectors)
    check_round_trip()


def check_argon2() -> None:
    from filecrypt import kdf

    check(kdf._native_argon2_available(), "cryptography provides native Argon2id")
    check(not kdf._cffi_argon2_available(), "argon2-cffi is not bundled")

    # Make any fallback path fail loudly for the rest of the run.
    def no_cffi(*_args, **_kwargs):
        raise CheckFailed("the argon2-cffi backend was called")

    kdf._argon2_cffi = no_cffi

    import cryptography
    major = int(cryptography.__version__.split(".")[0])
    check(major >= 44, f"cryptography {cryptography.__version__} is 44 or newer")


def check_qt() -> None:
    from PySide6.QtCore import QLibraryInfo, QPluginLoader
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([sys.argv[0]])
    check(app.platformName() == "offscreen",
          f"Qt started with the offscreen platform (got {app.platformName()!r})")

    plugins = Path(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath)) / "platforms"
    if sys.platform == "win32":
        found = sorted(plugins.glob("qwindows*.dll"))
        check(bool(found), f"Windows platform plugin is bundled in {plugins}")
        loader = QPluginLoader(str(found[0]))
        loaded = loader.load()
        check(loaded, f"Windows platform plugin loads ({loader.errorString() or 'no error'})")
        loader.unload()
    else:
        check(plugins.is_dir(), f"Qt platform plugins are bundled in {plugins}")

    from filecrypt.gui.window import MainWindow

    window = MainWindow()
    window.show()
    app.processEvents()
    check(window.isVisible(), "the main window opens")
    window.close()
    app.processEvents()


def check_vectors_in_process(vectors: Path) -> None:
    from filecrypt import engine
    from filecrypt.kdf import Secret

    with tempfile.TemporaryDirectory() as tmp:
        for v in load_manifest(vectors):
            expected = (vectors / v["plaintext"]).read_bytes()
            for i, entry in enumerate(v["secrets"]):
                if entry["kind"] == "passphrase":
                    secret = Secret(entry["utf8"].encode("utf-8"), "passphrase")
                else:
                    secret = Secret(bytes.fromhex(entry["hex"]), "key")
                out = Path(tmp) / f"{v['name']}-{i}"
                engine.decrypt_file(vectors / v["file"], out, secret)
                check(out.read_bytes() == expected,
                      f"in-process: {v['name']} (secret {i}, {v['kdf']}) decrypts")


def check_round_trip() -> None:
    from filecrypt import engine
    from filecrypt.kdf import Secret

    data = os.urandom(300_000)
    secret = Secret(b"frozen self-test passphrase", "passphrase")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "plain.bin"
        src.write_bytes(data)
        fcx = engine.encrypt_file(src, Path(tmp) / "plain.bin.fcx", secret)
        info = engine.inspect_file(fcx)
        check(info.kdf_name == "argon2id",
              f"a new file uses Argon2id by default (got {info.kdf_name})")
        out = engine.decrypt_file(fcx, Path(tmp) / "back.bin", secret)
        check(out.read_bytes() == data, "a new file round-trips with the default settings")


# --- from outside, against the built folder ------------------------------------

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("timeout", 300)
    return subprocess.run(cmd, capture_output=True, **kwargs)


def describe(result: subprocess.CompletedProcess) -> str:
    out = (result.stdout or b"").decode("utf-8", "replace").strip()
    err = (result.stderr or b"").decode("utf-8", "replace").strip()
    return f"exit {result.returncode}\n--- stdout\n{out}\n--- stderr\n{err}"


def dist(folder: Path, vectors: Path) -> None:
    folder = folder.resolve()
    vectors = vectors.resolve()
    selftest = folder / f"filecrypt-selftest{EXE}"
    cli = folder / f"filecrypt{EXE}"
    gui = folder / f"filecrypt-gui{EXE}"
    for exe in (selftest, cli, gui):
        check(exe.is_file(), f"{exe.name} is in {folder}")

    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    # Keep a stray site-packages or PYTHONPATH from leaking into the bundle.
    for name in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)

    result = run([str(selftest), "inside", "--vectors", str(vectors)], env=env)
    sys.stdout.write((result.stdout or b"").decode("utf-8", "replace"))
    if result.returncode != 0:
        err = (result.stderr or b"").decode("utf-8", "replace").strip()
        raise CheckFailed(f"the frozen self-test failed (exit {result.returncode}):\n{err}")
    ok("the frozen self-test passed")

    result = run([str(cli), "--version"], env=env)
    check(result.returncode == 0 and b"filecrypt" in result.stdout,
          f"filecrypt --version runs ({result.stdout.decode('utf-8', 'replace').strip()})")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        valid = load_manifest(vectors)
        for v in valid:
            expected = (vectors / v["plaintext"]).read_bytes()
            for i, entry in enumerate(v["secrets"]):
                out = tmp / f"{v['name']}-{i}.out"
                key, stdin = cli_key(entry, tmp / f"{v['name']}-{i}.key")
                result = run([str(cli), "decrypt", str(vectors / v["file"]), "-o", str(out),
                              "--key", key], input=stdin, env=env)
                if result.returncode != 0:
                    raise CheckFailed(f"filecrypt decrypt {v['name']} failed: {describe(result)}")
                check(out.read_bytes() == expected,
                      f"{cli.name}: {v['name']} (secret {i}, {v['kdf']}) decrypts")

        wrong = next(v for v in valid if v["secrets"][0]["kind"] == "passphrase")
        out = tmp / "wrong.out"
        result = run([str(cli), "decrypt", str(vectors / wrong["file"]), "-o", str(out),
                      "--key", "stdin:"], input=b"not the passphrase\n", env=env)
        check(result.returncode != 0 and not out.exists(),
              f"{cli.name} refuses a wrong passphrase (exit {result.returncode})")

    check_gui_starts(gui, env)


def cli_key(entry: dict, keyfile: Path):
    """The --key value and stdin bytes that hand this vector secret to the CLI."""
    if entry["kind"] == "passphrase":
        # stdin passes the exact bytes, so the NFD vectors stay decomposed.
        return "stdin:", entry["utf8"].encode("utf-8") + b"\n"
    keyfile.write_text(base64.b64encode(bytes.fromhex(entry["hex"])).decode("ascii"),
                       encoding="ascii")
    return f"file:{keyfile}", None


def check_gui_starts(gui: Path, env: dict, seconds: float = 8.0) -> None:
    proc = subprocess.Popen([str(gui)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise CheckFailed(f"filecrypt-gui exited early with {proc.returncode}: "
                                  f"{(out + err).decode('utf-8', 'replace').strip()}")
            time.sleep(0.25)
        ok(f"filecrypt-gui starts offscreen and is still running after {seconds:.0f}s")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("inside", help="checks that run inside the frozen bundle")
    p.add_argument("--vectors", type=Path, required=True)
    p.add_argument("--allow-unfrozen", action="store_true",
                   help="run from a normal Python (for working on this script)")
    p = sub.add_parser("dist", help="drive the built executables from outside")
    p.add_argument("--dist", type=Path, required=True, help="the built dist/filecrypt folder")
    p.add_argument("--vectors", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "inside":
            inside(args.vectors, args.allow_unfrozen)
        else:
            dist(args.dist, args.vectors)
    except CheckFailed as e:
        print(f"FAIL  {e}", flush=True)
        return 1
    print("all checks passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
