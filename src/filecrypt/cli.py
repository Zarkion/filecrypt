"""Command-line interface: keygen, encrypt, decrypt, rekey."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import __version__, container, kdf, keygen, sources
from .container import AuthenticationError, FormatError
from .kdf import Argon2Params, KDFError
from .sources import KeySourceError

FCX_SUFFIX = ".fcx"


class CLIError(Exception):
    pass


# --- atomic output -----------------------------------------------------------

class AtomicOutput:
    """Write to a temp file next to ``dest``; rename into place on commit.

    If ``commit`` is never reached the temp file is deleted, so a failed or
    interrupted run leaves no partial output. Without ``force`` an existing
    ``dest`` is never replaced, even if it appears while we are writing.
    """

    def __init__(self, dest: Path, force: bool):
        self.dest = Path(dest)
        self.force = force
        self.file = None
        self._tmp: Optional[str] = None
        self._committed = False

    def __enter__(self) -> "AtomicOutput":
        parent = self.dest.absolute().parent
        fd, self._tmp = tempfile.mkstemp(prefix=f".{self.dest.name}.", suffix=".part", dir=parent)
        self.file = os.fdopen(fd, "wb")
        return self

    def commit(self) -> None:
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()
        if self.force:
            os.replace(self._tmp, self.dest)
        elif os.name == "nt":
            os.rename(self._tmp, self.dest)  # fails if dest exists
        else:
            try:
                os.link(self._tmp, self.dest)  # atomic, fails if dest exists
                os.unlink(self._tmp)
            except FileExistsError:
                raise
            except OSError:  # filesystem without hard links
                if self.dest.exists():
                    raise FileExistsError(17, "File exists", str(self.dest)) from None
                os.rename(self._tmp, self.dest)
        self._committed = True

    def __exit__(self, *exc) -> None:
        if not self._committed:
            try:
                self.file.close()
            except Exception:
                pass
            try:
                os.unlink(self._tmp)
            except OSError:
                pass


# --- helpers -----------------------------------------------------------------

def _warn(msg: str) -> None:
    print(f"filecrypt: {msg}", file=sys.stderr)


def _open_input(path: str):
    try:
        return open(path, "rb")
    except OSError as e:
        raise CLIError(f"cannot open {path}: {e.strerror or e}") from None


def _check_output(src: str, dest: Path, force: bool) -> None:
    if dest.exists():
        try:
            same = os.path.samefile(src, dest)
        except OSError:
            same = False
        if same:
            raise CLIError("output would overwrite the input file")
        if not force:
            raise CLIError(f"{dest} already exists (use --force to overwrite)")


def _argon_flags_given(args) -> bool:
    return any(v is not None for v in (args.argon_memory, args.argon_iterations, args.argon_parallelism))


def _argon_params(args) -> Optional[Argon2Params]:
    """Validate Argon2id flags up front, before anyone is asked for a passphrase."""
    if not _argon_flags_given(args):
        return None
    if args.kdf == "scrypt":
        raise CLIError("--argon-* options only apply with --kdf argon2id")
    p = Argon2Params.from_cli(args.argon_memory, args.argon_iterations, args.argon_parallelism)
    p.check_for_encrypt()
    return p


def _new_key_block(args, secret: kdf.Secret, argon: Optional[Argon2Params]):
    """Pick the KDF for ``secret``. Returns (derive_kek, kdf_id, settings).

    The container calls ``derive_kek`` with the fresh salt it generates.
    """
    warning = kdf.passphrase_warning(secret)
    if warning:
        _warn(warning)
    kdf_id, settings = kdf.select_kdf(secret, kdf=args.kdf, argon=argon,
                                      keyfile_is_passphrase=args.keyfile_is_passphrase)
    if kdf_id == kdf.HKDF and (argon is not None or args.kdf):
        _warn("warning: KDF options are ignored for keys (HKDF is used)")

    def derive(salt: bytes) -> bytes:
        return kdf.derive_kek(kdf_id, settings, salt, secret.value)

    return derive, kdf_id, settings


def _unlock(header: container.Header, spec: str) -> bytes:
    secret = sources.resolve_secret(spec)
    kek = kdf.derive_kek(header.kdf_id, header.settings, header.salt, secret.value)
    return container.unwrap_file_key(header, kek)


# --- commands ----------------------------------------------------------------

def cmd_keygen(args) -> None:
    if not args.output and not args.store:
        raise CLIError("give an output path, --store, or both")
    if args.output and Path(args.output).exists() and not args.force:
        raise CLIError(f"{args.output} already exists (use --force to overwrite)")
    store = None
    if args.store:
        scheme, location = sources.parse_key_spec(args.store)
        store = (sources.get_source(scheme), location)
    key = keygen.generate_key(args.bytes)
    if args.output:
        keygen.write_keyfile(args.output, keygen.encode_key(key, args.format), force=args.force)
        _warn(f"wrote {len(key)}-byte key to {args.output}")
    if store:
        src, location = store
        try:
            src.store(location, key)
        except FileExistsError as e:
            raise CLIError(f"{e.filename or location} already exists") from None
        _warn(f"stored {len(key)}-byte key in {args.store}")


def cmd_encrypt(args) -> None:
    dest = Path(args.output) if args.output else Path(args.input + FCX_SUFFIX)
    argon = _argon_params(args)
    with _open_input(args.input) as src:
        _check_output(args.input, dest, args.force)
        secret = sources.resolve_secret(args.key, confirm=True)
        derive, kdf_id, settings = _new_key_block(args, secret, argon)
        with AtomicOutput(dest, args.force) as out:
            container.encrypt_stream(src, out.file, derive_kek=derive, kdf_id=kdf_id,
                                     settings=settings)
            src.close()
            out.commit()


def _default_plain_name(path: str) -> Path:
    if path.lower().endswith(FCX_SUFFIX) and len(path) > len(FCX_SUFFIX):
        return Path(path[:-len(FCX_SUFFIX)])
    raise CLIError(f"{path} does not end in {FCX_SUFFIX}; choose an output name with -o")


def cmd_decrypt(args) -> None:
    with _open_input(args.input) as src:
        header = container.read_header(src)
        dest = Path(args.output) if args.output else _default_plain_name(args.input)
        _check_output(args.input, dest, args.force)
        file_key = _unlock(header, args.key)
        with AtomicOutput(dest, args.force) as out:
            container.decrypt_body(header, file_key, src, out.file)
            src.close()
            out.commit()


def cmd_rekey(args) -> None:
    argon = _argon_params(args)
    with _open_input(args.input) as src:
        header = container.read_header(src)
        in_place = not args.output
        if args.output:
            dest = Path(args.output)
            try:
                in_place = os.path.samefile(args.input, dest)
            except OSError:
                pass
            if not in_place and dest.exists() and not args.force:
                raise CLIError(f"{dest} already exists (use --force to overwrite)")
        else:
            dest = Path(args.input)
        both_prompt = sources.parse_key_spec(args.key)[0] == "prompt" == sources.parse_key_spec(args.new_key)[0]
        if both_prompt:
            _warn("current key:")
        file_key = _unlock(header, args.key)
        if both_prompt:
            _warn("new key:")
        secret = sources.resolve_secret(args.new_key, confirm=True)
        derive, kdf_id, settings = _new_key_block(args, secret, argon)
        new_header = container.rewrap_header(header, file_key, derive_kek=derive,
                                             kdf_id=kdf_id, settings=settings)
        with AtomicOutput(dest, force=in_place or args.force) as out:
            out.file.write(new_header)
            shutil.copyfileobj(src, out.file, 1024 * 1024)
            src.close()  # Windows cannot replace a file that is still open
            out.commit()


# --- argument parsing --------------------------------------------------------

def _positive_int(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text}") from None
    if v < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return v


KEY_HELP = ("key source as scheme:location: prompt (default), file:PATH, env:VAR, "
            "stdin, keyring:SERVICE/NAME, or a plugin such as azkv:VAULT/SECRET")


def _add_kdf_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kdf", choices=["argon2id", "scrypt"],
                   help="passphrase KDF (default argon2id; scrypt if Argon2id is unavailable)")
    p.add_argument("--argon-memory", type=_positive_int, metavar="MIB",
                   help="Argon2id memory in MiB (default 64, minimum 19, maximum 4096)")
    p.add_argument("--argon-iterations", type=_positive_int, metavar="N",
                   help="Argon2id iterations (default 3, range 2-16)")
    p.add_argument("--argon-parallelism", type=_positive_int, metavar="N",
                   help="Argon2id lanes (default 4, range 1-16)")
    p.add_argument("--keyfile-is-passphrase", action="store_true",
                   help="treat key material as a passphrase (allows keys under 32 bytes)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filecrypt", description="Encrypt files to .fcx.")
    parser.add_argument("--version", action="version", version=f"filecrypt {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p = sub.add_parser("keygen", help="generate a random key")
    p.add_argument("output", nargs="?", help="keyfile to create")
    p.add_argument("--bytes", type=_positive_int, default=32, help="key length (default 32, minimum 32)")
    p.add_argument("--format", choices=keygen.FORMATS, default="raw", help="keyfile format (default raw)")
    p.add_argument("--store", metavar="SPEC", help="also store the key in a key source, e.g. keyring:filecrypt/main")
    p.add_argument("--force", action="store_true", help="overwrite an existing keyfile")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="encrypt a file")
    p.add_argument("input")
    p.add_argument("-o", "--output", help="output path (default INPUT.fcx)")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help=KEY_HELP)
    _add_kdf_options(p)
    p.add_argument("--force", action="store_true", help="overwrite an existing output file")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt an .fcx file")
    p.add_argument("input")
    p.add_argument("-o", "--output", help="output path (default INPUT without .fcx)")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help=KEY_HELP)
    p.add_argument("--force", action="store_true", help="overwrite an existing output file")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("rekey", help="change the key of an .fcx file without re-encrypting it")
    p.add_argument("input")
    p.add_argument("-o", "--output", help="write to a new file instead of replacing INPUT")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help="current key; " + KEY_HELP)
    p.add_argument("--new-key", default=sources.DEFAULT_SPEC, help="new key; same forms as --key")
    _add_kdf_options(p)
    p.add_argument("--force", action="store_true", help="overwrite an existing -o file")
    p.set_defaults(func=cmd_rekey)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 2)
    try:
        args.func(args)
        return 0
    except (CLIError, FormatError, AuthenticationError, KDFError, KeySourceError, ValueError) as e:
        _warn(f"error: {e}")
    except FileExistsError as e:
        _warn(f"error: {e.filename} already exists (use --force to overwrite)")
    except OSError as e:
        where = f"{e.filename}: " if e.filename else ""
        _warn(f"error: {where}{e.strerror or e}")
    except KeyboardInterrupt:
        _warn("interrupted")
        return 130
    return 1
