"""Command-line interface: keygen, encrypt, decrypt, rekey.

A thin layer over :mod:`filecrypt.engine`: it parses arguments, reads keys
from key sources and talks to the terminal. All file handling lives in the
engine so other front-ends share it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, engine, keygen, sources
from .container import AuthenticationError, FormatError
from .kdf import Argon2Params, KDFError
from .sources import KeySourceError



class CLIError(Exception):
    pass


# --- terminal helpers ----------------------------------------------------------

def _warn(msg: str) -> None:
    print(f"filecrypt: {msg}", file=sys.stderr)


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def _confirm(prompt: str) -> bool:
    print(prompt, end="", file=sys.stderr, flush=True)
    try:
        return input().strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _handle_stale_parts(stale: List[Path]) -> None:
    """Offer to delete partial files left by an earlier interrupted run."""
    names = ", ".join(p.name for p in stale)
    _warn(f"found {len(stale)} partial file(s) left by an interrupted run: {names}. "
          f"They may contain decrypted data.")
    if _interactive():
        if _confirm("filecrypt: delete them? [y/N] "):
            for p in stale:
                try:
                    p.unlink()
                except OSError as e:
                    _warn(f"could not delete {p.name}: {e.strerror or e}")
    else:
        _warn("delete them yourself if you don't need them")


def _argon_params(args) -> Optional[Argon2Params]:
    """Validate Argon2id flags up front, before anyone is asked for a passphrase."""
    given = (args.argon_memory, args.argon_iterations, args.argon_parallelism)
    if all(v is None for v in given):
        return None
    if args.kdf == "scrypt":
        raise CLIError("--argon-* options only apply with --kdf argon2id")
    p = Argon2Params.from_cli(*given)
    p.check_for_encrypt()
    return p


def _encrypt_options(args) -> engine.EncryptOptions:
    return engine.EncryptOptions(kdf=args.kdf, argon=_argon_params(args),
                                 keyfile_is_passphrase=args.keyfile_is_passphrase)


def _kdf_policy(args) -> dict:
    """Costly KDF settings: --max-kdf-memory decides for scripts, otherwise ask on a terminal."""
    if args.max_kdf_memory is not None:
        return {"kdf_memory_limit": args.max_kdf_memory * 1024**2, "confirm_expensive": None}
    if not _interactive():
        return {"kdf_memory_limit": None, "confirm_expensive": None}
    return {"kdf_memory_limit": None, "confirm_expensive": lambda reason: _confirm(
        f"filecrypt: {reason}. Files made with the defaults need 64 MiB. Continue? [y/N] ")}


PROMPT_ATTEMPTS = 3


def _retry_policy(spec: str) -> dict:
    """Typed passphrases get three tries on a terminal; other key sources one."""
    if sources.parse_key_spec(spec)[0] == "prompt" and _interactive():
        return {"max_attempts": PROMPT_ATTEMPTS,
                "on_wrong_key": lambda attempt: _warn("wrong key or passphrase, try again")}
    return {"max_attempts": 1, "on_wrong_key": None}


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
    options = _encrypt_options(args)
    dest = Path(args.output) if args.output else engine.default_encrypt_output(args.input)
    engine.encrypt_file(args.input, dest, lambda: sources.resolve_secret(args.key, confirm=True),
                        options=options, force=args.force, notify=_warn,
                        on_stale_parts=_handle_stale_parts)


def cmd_decrypt(args) -> None:
    dest = Path(args.output) if args.output else engine.default_decrypt_output(args.input)
    if dest is None:
        engine.inspect_file(args.input)  # a non-.fcx input is the clearer error
        raise CLIError(f"{args.input} does not end in {engine.FCX_SUFFIX}; "
                       f"choose an output name with -o")
    engine.decrypt_file(args.input, dest, lambda: sources.resolve_secret(args.key),
                        force=args.force, on_stale_parts=_handle_stale_parts,
                        **_kdf_policy(args), **_retry_policy(args.key))


def cmd_rekey(args) -> None:
    options = _encrypt_options(args)
    both_prompt = (sources.parse_key_spec(args.key)[0] == "prompt"
                   == sources.parse_key_spec(args.new_key)[0])

    def old_secret():
        if both_prompt:
            _warn("current key:")
        return sources.resolve_secret(args.key)

    def new_secret():
        if both_prompt:
            _warn("new key:")
        return sources.resolve_secret(args.new_key, confirm=True)

    engine.rekey_file(args.input, old_secret, new_secret, dest=args.output, options=options,
                      force=args.force, notify=_warn, on_stale_parts=_handle_stale_parts,
                      **_kdf_policy(args), **_retry_policy(args.key))


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


def _add_max_kdf_memory(p: argparse.ArgumentParser) -> None:
    p.add_argument("--max-kdf-memory", type=_positive_int, metavar="MIB",
                   help="allow key derivation up to this much memory without asking "
                        "(default: ask above 1024 MiB or half your RAM)")


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
    _add_max_kdf_memory(p)
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("rekey", help="change the key of an .fcx file without re-encrypting it")
    p.add_argument("input")
    p.add_argument("-o", "--output", help="write to a new file instead of replacing INPUT")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help="current key; " + KEY_HELP)
    p.add_argument("--new-key", default=sources.DEFAULT_SPEC, help="new key; same forms as --key")
    _add_kdf_options(p)
    p.add_argument("--force", action="store_true", help="overwrite an existing -o file")
    _add_max_kdf_memory(p)
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
    except engine.ExpensiveKDFError as e:
        _warn(f"error: {e}; if you trust this file, rerun with --max-kdf-memory MIB")
    except engine.OutputExistsError as e:
        _warn(f"error: {e} (use --force to overwrite)")
    except (CLIError, engine.EngineError, FormatError, AuthenticationError, KDFError,
            KeySourceError, ValueError) as e:
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
