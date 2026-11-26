"""Command-line interface: keygen, encrypt, decrypt, rekey, verify, info.

A thin layer over :mod:`filecrypt.engine`: it parses arguments, reads keys
from key sources and talks to the terminal. All file handling lives in the
engine so other front-ends share it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, engine, keygen, sources
from . import container, kdf
from .container import AuthenticationError, CorruptedFileError, FormatError, WrongKeyError
from .kdf import Argon2Params, KDFError
from .sources import KeySourceError

# Exit codes. Documented in README.md; scripts depend on them, so never renumber.
EXIT_OK = 0
EXIT_ERROR = 1          # anything not listed below, e.g. output exists without --force
EXIT_USAGE = 2
EXIT_FORMAT = 3         # not an .fcx file, or its header is malformed or unsupported
EXIT_WRONG_KEY = 4      # wrong key or passphrase, or a modified header: indistinguishable
EXIT_CORRUPTED = 5      # the key was right but the body is damaged, truncated or extended
EXIT_KDF_REFUSED = 6    # the file's key derivation costs more than allowed
EXIT_KEY_SOURCE = 7
EXIT_IO = 8
EXIT_INTERRUPTED = 130

# Stable names for --json error objects, one per exit code.
ERROR_KINDS = {
    EXIT_ERROR: "error",
    EXIT_USAGE: "usage",
    EXIT_FORMAT: "format",
    EXIT_WRONG_KEY: "wrong_key_or_modified_header",
    EXIT_CORRUPTED: "corrupted",
    EXIT_KDF_REFUSED: "kdf_cost_refused",
    EXIT_KEY_SOURCE: "key_source",
    EXIT_IO: "io",
    EXIT_INTERRUPTED: "interrupted",
}


class CLIError(Exception):
    def __init__(self, message: str, code: int = EXIT_USAGE):
        super().__init__(message)
        self.code = code


# --- terminal helpers ----------------------------------------------------------

_quiet = False


def _warn(msg: str) -> None:
    """Errors, prompts' context and anything the user must see, even with --quiet."""
    print(f"filecrypt: {msg}", file=sys.stderr)


def _notice(msg: str) -> None:
    """Warnings and progress notes that --quiet hides."""
    if not _quiet:
        _warn(msg)


def _emit_json(obj: dict) -> None:
    # ensure_ascii escapes every non-ASCII character, so any file name (even
    # undecodable bytes, which Python keeps as lone surrogates) prints safely
    # on any console encoding and parses as JSON.
    print(json.dumps(obj, ensure_ascii=True, sort_keys=True))


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
    # Shown even with --quiet: these files may hold plaintext.
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

def cmd_keygen(args) -> dict:
    if not args.output and not args.store:
        raise CLIError("give an output path, --store, or both")
    if args.bytes < keygen.MIN_KEY_BYTES:
        raise CLIError(f"keys must be at least {keygen.MIN_KEY_BYTES} bytes")
    if args.output and Path(args.output).exists() and not args.force:
        raise CLIError(f"{args.output} already exists (use --force to overwrite)", EXIT_ERROR)
    store = None
    if args.store:
        scheme, location = sources.parse_key_spec(args.store)
        store = (sources.get_source(scheme), location)
    key = keygen.generate_key(args.bytes)
    if args.output:
        keygen.write_keyfile(args.output, keygen.encode_key(key, args.format), force=args.force)
        _notice(f"wrote {len(key)}-byte key to {args.output}")
    if store:
        src, location = store
        try:
            src.store(location, key)
        except FileExistsError as e:
            raise CLIError(f"{e.filename or location} already exists", EXIT_ERROR) from None
        _notice(f"stored {len(key)}-byte key in {args.store}")
    return {"output": args.output, "store": args.store, "bytes": len(key)}


def cmd_encrypt(args) -> dict:
    options = _encrypt_options(args)
    dest = Path(args.output) if args.output else engine.default_encrypt_output(args.input)
    engine.encrypt_file(args.input, dest, lambda: sources.resolve_secret(args.key, confirm=True),
                        options=options, force=args.force, notify=_notice,
                        on_stale_parts=_handle_stale_parts)
    return {"input": args.input, "output": str(dest)}


def cmd_decrypt(args) -> dict:
    dest = Path(args.output) if args.output else engine.default_decrypt_output(args.input)
    if dest is None:
        engine.inspect_file(args.input)  # a non-.fcx input is the clearer error
        raise CLIError(f"{args.input} does not end in {engine.FCX_SUFFIX}; "
                       f"choose an output name with -o")
    engine.decrypt_file(args.input, dest, lambda: sources.resolve_secret(args.key),
                        force=args.force, on_stale_parts=_handle_stale_parts,
                        **_kdf_policy(args), **_retry_policy(args.key))
    return {"input": args.input, "output": str(dest)}


def cmd_rekey(args) -> dict:
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

    dest = engine.rekey_file(args.input, old_secret, new_secret, dest=args.output,
                             options=options, force=args.force, notify=_notice,
                             on_stale_parts=_handle_stale_parts,
                             rotate_file_key=args.rotate_file_key,
                             **_kdf_policy(args), **_retry_policy(args.key))
    return {"input": args.input, "output": str(dest),
            "file_key_rotated": args.rotate_file_key}


def cmd_verify(args) -> dict:
    result = engine.verify_file(args.input, lambda: sources.resolve_secret(args.key),
                                **_kdf_policy(args), **_retry_policy(args.key))
    if not args.json and not _quiet:
        print(f"{args.input}: OK, {result.chunk_count} chunk"
              f"{'s' if result.chunk_count != 1 else ''} authenticated, "
              f"{result.plaintext_size} bytes of plaintext")
    return {"input": args.input, "authenticated": True,
            "chunk_count": result.chunk_count, "plaintext_size": result.plaintext_size}


def _kdf_description(info: engine.FileInfo, settings: Optional[bytes]) -> str:
    if info.kdf_id == kdf.HKDF:
        return "HKDF-SHA256"
    mib = info.kdf_memory / 1024**2
    mem = f"{mib:g} MiB"
    if info.kdf_id == kdf.ARGON2ID and settings is not None:
        p = kdf.Argon2Params.decode(settings)
        lanes = f"{p.parallelism} lane{'s' if p.parallelism != 1 else ''}"
        return f"Argon2id, {mem}, {p.iterations} iterations, {lanes}"
    if info.kdf_id == kdf.SCRYPT and settings is not None:
        sp = kdf.ScryptParams.decode(settings)
        return f"scrypt, {mem} (N=2^{sp.log2n}, r={sp.r}, p={sp.p})"
    return info.kdf_name


def cmd_info(args) -> dict:
    info = engine.inspect_file(args.input)
    with open(args.input, "rb") as f:
        settings = container.read_header(f).settings
    result = {
        "input": args.input,
        "version": info.version,
        "kdf": info.kdf_name,
        "kdf_id": info.kdf_id,
        "needs": info.needs,
        "kdf_memory": info.kdf_memory,
        "kdf_passes": info.kdf_passes,
        "chunk_size": info.chunk_size,
        "header_size": info.header_len,
        "file_size": info.file_size,
        "chunk_count": info.chunk_count,
        "plaintext_size": info.plaintext_size,
        "authenticated": False,
    }
    if not args.json:
        if info.plaintext_size is None:
            size = "unknown: the file's length is impossible for .fcx, so it is truncated or damaged"
        else:
            size = (f"{info.plaintext_size} bytes in {info.chunk_count} "
                    f"chunk{'s' if info.chunk_count != 1 else ''}")
        print(f"{args.input}: .fcx version {info.version}")
        print(f"  needs:          a {info.needs}")
        print(f"  key derivation: {_kdf_description(info, settings)}")
        print(f"  chunk size:     {info.chunk_size} bytes")
        print(f"  plaintext size: {size}")
        print("  None of this is authenticated until the file is decrypted; "
              "run 'filecrypt verify' to check it.")
    return result


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


def _common() -> argparse.ArgumentParser:
    """Options every command takes."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-q", "--quiet", action="store_true",
                   help="hide notices and success messages (errors are always shown)")
    p.add_argument("--json", action="store_true",
                   help="print one JSON result object on standard output")
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filecrypt", description="Encrypt files to .fcx.",
                                     epilog=EXIT_HELP,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"filecrypt {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    common = [_common()]

    p = sub.add_parser("keygen", help="generate a random key", parents=common)
    p.add_argument("output", nargs="?", help="keyfile to create")
    p.add_argument("--bytes", type=_positive_int, default=32, help="key length (default 32, minimum 32)")
    p.add_argument("--format", choices=keygen.FORMATS, default="raw", help="keyfile format (default raw)")
    p.add_argument("--store", metavar="SPEC", help="also store the key in a key source, e.g. keyring:filecrypt/main")
    p.add_argument("--force", action="store_true", help="overwrite an existing keyfile")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="encrypt a file", parents=common)
    p.add_argument("input")
    p.add_argument("-o", "--output", help="output path (default INPUT.fcx)")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help=KEY_HELP)
    _add_kdf_options(p)
    p.add_argument("--force", action="store_true", help="overwrite an existing output file")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt an .fcx file", parents=common)
    p.add_argument("input")
    p.add_argument("-o", "--output", help="output path (default INPUT without .fcx)")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help=KEY_HELP)
    p.add_argument("--force", action="store_true", help="overwrite an existing output file")
    _add_max_kdf_memory(p)
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("rekey", parents=common,
                       help="change the key of an .fcx file (add --rotate-file-key "
                            "if the old key may have leaked)")
    p.add_argument("input")
    p.add_argument("-o", "--output", help="write to a new file instead of replacing INPUT")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help="current key; " + KEY_HELP)
    p.add_argument("--new-key", default=sources.DEFAULT_SPEC, help="new key; same forms as --key")
    p.add_argument("--rotate-file-key", action="store_true",
                   help="also replace the file key and re-encrypt the whole body, checking "
                        "every chunk; use this if the old key or passphrase may have leaked "
                        "(slower: reads and rewrites the whole file)")
    _add_kdf_options(p)
    p.add_argument("--force", action="store_true", help="overwrite an existing -o file")
    _add_max_kdf_memory(p)
    p.set_defaults(func=cmd_rekey)

    p = sub.add_parser("verify", parents=common,
                       help="check that an .fcx file opens with KEY and is intact, writing nothing")
    p.add_argument("input")
    p.add_argument("--key", default=sources.DEFAULT_SPEC, help=KEY_HELP)
    _add_max_kdf_memory(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("info", parents=common,
                       help="show an .fcx file's header without a key (unauthenticated)")
    p.add_argument("input")
    p.set_defaults(func=cmd_info)
    return parser


EXIT_HELP = """exit codes:
  0    success
  1    other error (for example, the output exists and --force wasn't given)
  2    usage error
  3    not an .fcx file, or a malformed or unsupported header
  4    wrong key or passphrase, or the header was modified (these can't be told apart)
  5    the file is damaged, truncated or was tampered with
  6    the file's key derivation needs more memory than allowed (see --max-kdf-memory)
  7    the key source failed
  8    a file couldn't be read or written
  130  interrupted"""


def _exit_code(exc: BaseException, command: str) -> int:
    """Map an exception to the documented exit code. Order matters: subclasses first."""
    if isinstance(exc, KeyboardInterrupt):
        return EXIT_INTERRUPTED
    if isinstance(exc, CLIError):
        return exc.code
    if isinstance(exc, (engine.ExpensiveKDFError, engine.Cancelled)):
        return EXIT_KDF_REFUSED    # in the CLI, Cancelled means "no" to the KDF cost question
    if isinstance(exc, WrongKeyError):
        return EXIT_WRONG_KEY
    if isinstance(exc, CorruptedFileError):   # includes TrailingDataError
        return EXIT_CORRUPTED
    if isinstance(exc, AuthenticationError):
        return EXIT_WRONG_KEY
    if isinstance(exc, FormatError):
        return EXIT_FORMAT
    if isinstance(exc, KeySourceError):
        return EXIT_KEY_SOURCE
    if isinstance(exc, KDFError):
        # Reading a file, the settings came from its header; otherwise from our options.
        return EXIT_FORMAT if command in ("decrypt", "rekey", "verify", "info") else EXIT_USAGE
    if isinstance(exc, engine.SameFileError):
        return EXIT_USAGE
    if isinstance(exc, (engine.OutputExistsError, FileExistsError)):
        return EXIT_ERROR
    if isinstance(exc, (engine.InputError, OSError)):
        return EXIT_IO
    return EXIT_ERROR


def _message(exc: BaseException) -> str:
    if isinstance(exc, KeyboardInterrupt):
        return "interrupted"
    if isinstance(exc, engine.ExpensiveKDFError):
        return f"error: {exc}; if you trust this file, rerun with --max-kdf-memory MIB"
    if isinstance(exc, engine.OutputExistsError):
        return f"error: {exc} (use --force to overwrite)"
    if isinstance(exc, (CLIError, engine.EngineError, FormatError, AuthenticationError,
                        KDFError, KeySourceError, ValueError)):
        return f"error: {exc}"
    if isinstance(exc, FileExistsError):
        return f"error: {exc.filename} already exists (use --force to overwrite)"
    if isinstance(exc, OSError):
        where = f"{exc.filename}: " if exc.filename else ""
        return f"error: {where}{exc.strerror or exc}"
    raise exc


def main(argv: Optional[List[str]] = None) -> int:
    global _quiet
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else EXIT_USAGE)
    _quiet = args.quiet
    try:
        result = args.func(args)
    except (Exception, KeyboardInterrupt) as e:
        message = _message(e)        # re-raises anything unexpected (a bug): keep the traceback
        code = _exit_code(e, args.command)
        _warn(message)
        if args.json:
            _emit_json({"ok": False, "command": args.command, "exit_code": code,
                        "error": {"kind": ERROR_KINDS[code], "message": str(e) or message}})
        return code
    finally:
        _quiet = False
    if args.json:
        _emit_json({"ok": True, "command": args.command, **result})
    return EXIT_OK
