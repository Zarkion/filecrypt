"""The filecrypt engine: encrypt, decrypt, rekey, verify and inspect .fcx files.

This is the layer every front-end shares (the CLI today, a GUI later). It
never prints, prompts or reads the keyboard; everything a user might need
to see or decide goes through callbacks:

* ``secret`` may be a :class:`~filecrypt.kdf.Secret` or a zero-argument
  callable returning one. A callable is invoked only after every cheap check
  has passed (input readable and well formed, output free, KDF cost
  acceptable), so a UI never asks for a password it can't use.
* ``progress(done, total)`` reports bytes processed.
* ``notify(message)`` receives one-line warnings and notices.
* ``confirm_expensive(reason) -> bool`` is asked before running unusually
  costly KDF settings read from an unauthenticated file header. Without it,
  such files raise :class:`ExpensiveKDFError`.
* ``on_stale_parts(paths)`` is told about partial files an earlier
  interrupted run left next to the output.
* ``cancel`` is a :class:`CancelToken`. Calling ``token.cancel()`` from any
  thread stops the operation at the next check (before each KDF run and
  between chunks) with :class:`Cancelled`, leaving no partial output.
* ``max_attempts`` lets a callable ``secret`` be asked again after a wrong
  passphrase or key, without reopening the file or redoing the checks;
  ``on_wrong_key(attempt)`` is called before each new attempt.

A wrong passphrase or key raises :class:`~filecrypt.container.WrongKeyError`;
a damaged or tampered file raises
:class:`~filecrypt.container.CorruptedFileError`.

Output is always written atomically and never replaces an existing file
unless ``force`` is set.
"""

from __future__ import annotations

import errno
import glob
import os
import secrets
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, List, Optional, Tuple, Union

from . import container, kdf
from .kdf import Argon2Params, Secret

FCX_SUFFIX = ".fcx"

PathLike = Union[str, "os.PathLike[str]"]
SecretArg = Union[Secret, Callable[[], Secret]]
Progress = Callable[[int, int], None]
Notify = Callable[[str], None]
ConfirmExpensive = Callable[[str], bool]
StaleHandler = Callable[[List[Path]], None]
WrongKeyHandler = Callable[[int], None]


# --- errors ------------------------------------------------------------------

class EngineError(Exception):
    """Base class for problems a front-end should show to the user."""


class InputError(EngineError):
    """The input file can't be opened."""


class OutputExistsError(EngineError, FileExistsError):
    """The output file exists and ``force`` wasn't given."""

    def __init__(self, path: PathLike):
        FileExistsError.__init__(self, errno.EEXIST, "already exists", os.fspath(path))
        self.path = Path(path)

    def __str__(self) -> str:
        return f"{self.path} already exists"


class SameFileError(EngineError):
    def __str__(self) -> str:
        return "output would overwrite the input file"


class ExpensiveKDFError(EngineError):
    """The file's KDF settings exceed the memory/work limit and weren't confirmed."""

    def __init__(self, reason: str, limit: int):
        super().__init__(reason, limit)
        self.reason = reason
        self.limit = limit

    def __str__(self) -> str:
        return f"{self.reason}, more than the {self.limit // 1024**2} MiB allowed"


class Cancelled(EngineError):
    def __str__(self) -> str:
        return "cancelled"


class CancelToken:
    """Thread-safe cancel flag. A GUI keeps one per running operation."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise Cancelled()


def _check_cancel(token: Optional[CancelToken]) -> None:
    if token is not None:
        token.raise_if_cancelled()


# --- options and file info ---------------------------------------------------

@dataclass(frozen=True)
class EncryptOptions:
    """How to protect a file. The defaults suit almost everyone."""
    kdf: Optional[str] = None                 # "argon2id", "scrypt" or None (best available)
    argon: Optional[Argon2Params] = None      # None = Argon2Params.default()
    keyfile_is_passphrase: bool = False

    def validate(self) -> None:
        if self.argon is not None:
            if self.kdf == "scrypt":
                raise ValueError("Argon2id settings only apply with the argon2id KDF")
            self.argon.check_for_encrypt()


@dataclass(frozen=True)
class FileInfo:
    """What an .fcx header says, read without a key.

    Nothing here is authenticated. The header is only checked when the file
    key is unwrapped, and the body only when it is decrypted or verified, so
    ``chunk_count`` and ``plaintext_size`` are what the file's length implies
    if nobody truncated or extended it. Use :func:`verify_file` to know.
    """
    version: int
    kdf_id: int
    kdf_name: str
    needs: str           # "key" (HKDF) or "passphrase" (Argon2id / scrypt)
    kdf_memory: int      # bytes the KDF needs
    kdf_passes: int
    chunk_size: int
    header_len: int
    file_size: Optional[int] = None       # bytes on disk, header included
    chunk_count: Optional[int] = None     # unauthenticated; None if the length can't be valid
    plaintext_size: Optional[int] = None  # unauthenticated; None if the length can't be valid


@dataclass(frozen=True)
class VerifyResult:
    """What :func:`verify_file` authenticated: every chunk, in order, up to the final one."""
    chunk_count: int
    plaintext_size: int


def body_layout(body_len: int, chunk_size: int) -> Optional[Tuple[int, int]]:
    """``(chunks, plaintext bytes)`` a body of ``body_len`` bytes holds, or None
    if no valid file has that length (for example a cut-off tag)."""
    full = chunk_size + container.TAG_LEN
    whole, rest = divmod(body_len, full)
    if rest == 0:
        if whole == 0:
            return None          # even an empty file has one 16-byte final chunk
        chunks, size = whole, whole * chunk_size
    elif rest >= container.TAG_LEN:
        chunks, size = whole + 1, whole * chunk_size + rest - container.TAG_LEN
    else:
        return None
    if chunks > container.MAX_CHUNKS:
        return None
    return chunks, size


def inspect_file(path: PathLike) -> FileInfo:
    """Read an .fcx header without needing a key. Raises FormatError for other files.

    The sizes it reports are unauthenticated (see :class:`FileInfo`).
    """
    with _open_input(path) as f:
        h = container.read_header(f)
        file_size = os.fstat(f.fileno()).st_size
    memory, passes = kdf.kdf_cost(h.kdf_id, h.settings)
    layout = body_layout(file_size - h.header_len, h.chunk_size)
    chunks, size = layout if layout is not None else (None, None)
    return FileInfo(h.version, h.kdf_id, kdf.KDF_NAMES.get(h.kdf_id, f"unknown ({h.kdf_id})"),
                    "key" if h.kdf_id == kdf.HKDF else "passphrase",
                    memory, passes, h.chunk_size, h.header_len,
                    file_size=file_size, chunk_count=chunks, plaintext_size=size)


def default_encrypt_output(path: PathLike) -> Path:
    return Path(os.fspath(path) + FCX_SUFFIX)


def default_decrypt_output(path: PathLike) -> Optional[Path]:
    """``report.pdf.fcx`` -> ``report.pdf``; None if the name doesn't end in .fcx."""
    s = os.fspath(path)
    if s.lower().endswith(FCX_SUFFIX) and len(Path(s).name) > len(FCX_SUFFIX):
        return Path(s[:-len(FCX_SUFFIX)])
    return None


def stale_parts(dest: PathLike) -> List[Path]:
    """Partial files an interrupted run left next to ``dest``."""
    dest = Path(dest)
    pattern = f".{glob.escape(dest.name)}.*.part"
    return sorted(Path(p) for p in glob.glob(str(dest.absolute().parent / pattern)))


# --- operations --------------------------------------------------------------

def encrypt_file(src: PathLike, dest: PathLike, secret: SecretArg, *,
                 options: Optional[EncryptOptions] = None, force: bool = False,
                 progress: Optional[Progress] = None, notify: Optional[Notify] = None,
                 on_stale_parts: Optional[StaleHandler] = None,
                 cancel: Optional[CancelToken] = None) -> Path:
    """Encrypt ``src`` to ``dest``. Returns ``dest``."""
    options = options or EncryptOptions()
    options.validate()
    dest = Path(dest)
    _check_cancel(cancel)
    with _open_input(src) as f:
        _check_output(src, dest, force)
        _report_stale(dest, on_stale_parts)
        derive, kdf_id, settings = _new_key_block(_resolve(secret), options, notify, cancel)
        total = os.fstat(f.fileno()).st_size
        reader = _ProgressReader(f, total, progress, cancel)
        with AtomicOutput(dest, force) as out:
            container.encrypt_stream(reader, out.file, derive_kek=derive, kdf_id=kdf_id,
                                     settings=settings)
            reader.finish()
            f.close()
            _check_cancel(cancel)
            out.commit()
    return dest


def decrypt_file(src: PathLike, dest: PathLike, secret: SecretArg, *, force: bool = False,
                 progress: Optional[Progress] = None,
                 kdf_memory_limit: Optional[int] = None,
                 confirm_expensive: Optional[ConfirmExpensive] = None,
                 on_stale_parts: Optional[StaleHandler] = None,
                 cancel: Optional[CancelToken] = None, max_attempts: int = 1,
                 on_wrong_key: Optional[WrongKeyHandler] = None) -> Path:
    """Decrypt ``src`` to ``dest``. Returns ``dest``.

    ``kdf_memory_limit`` (bytes) defaults to 1 GiB or half of RAM.
    """
    dest = Path(dest)
    _check_cancel(cancel)
    with _open_input(src) as f:
        header = container.read_header(f)
        _check_output(src, dest, force)
        _report_stale(dest, on_stale_parts)
        file_key = _unlock(header, secret, kdf_memory_limit, confirm_expensive,
                           cancel, max_attempts, on_wrong_key)
        total = os.fstat(f.fileno()).st_size - header.header_len
        reader = _ProgressReader(f, total, progress, cancel)
        with AtomicOutput(dest, force) as out:
            container.decrypt_body(header, file_key, reader, out.file)
            reader.finish()
            f.close()
            _check_cancel(cancel)
            out.commit()
    return dest


def rekey_file(src: PathLike, old_secret: SecretArg, new_secret: SecretArg, *,
               dest: Optional[PathLike] = None, options: Optional[EncryptOptions] = None,
               force: bool = False, progress: Optional[Progress] = None,
               notify: Optional[Notify] = None, kdf_memory_limit: Optional[int] = None,
               confirm_expensive: Optional[ConfirmExpensive] = None,
               on_stale_parts: Optional[StaleHandler] = None,
               cancel: Optional[CancelToken] = None, max_attempts: int = 1,
               on_wrong_key: Optional[WrongKeyHandler] = None) -> Path:
    """Wrap the file key under a new key without re-encrypting the body.

    Replaces ``src`` in place unless ``dest`` is given. ``new_secret`` is only
    requested after ``old_secret`` has unlocked the file. Note that rekeying
    doesn't help once the old key has leaked: decrypt and re-encrypt instead.
    """
    options = options or EncryptOptions()
    options.validate()
    _check_cancel(cancel)
    with _open_input(src) as f:
        header = container.read_header(f)
        in_place = dest is None
        if dest is None:
            dest = Path(src)
        else:
            dest = Path(dest)
            try:
                in_place = os.path.samefile(src, dest)
            except OSError:
                pass
            if not in_place and dest.exists() and not force:
                raise OutputExistsError(dest)
        _report_stale(dest, on_stale_parts)
        file_key = _unlock(header, old_secret, kdf_memory_limit, confirm_expensive,
                           cancel, max_attempts, on_wrong_key)
        derive, kdf_id, settings = _new_key_block(_resolve(new_secret), options, notify, cancel)
        new_header = container.rewrap_header(header, file_key, derive_kek=derive,
                                             kdf_id=kdf_id, settings=settings)
        total = os.fstat(f.fileno()).st_size - header.header_len
        reader = _ProgressReader(f, total, progress, cancel)
        with AtomicOutput(dest, force=in_place or force) as out:
            out.file.write(new_header)
            while True:
                block = reader.read(container.DEFAULT_CHUNK_SIZE)  # fine-grained progress and cancel
                if not block:
                    break
                out.file.write(block)
            reader.finish()
            f.close()  # Windows cannot replace a file that is still open
            _check_cancel(cancel)
            out.commit()
    return dest


def verify_file(src: PathLike, secret: SecretArg, *, progress: Optional[Progress] = None,
                kdf_memory_limit: Optional[int] = None,
                confirm_expensive: Optional[ConfirmExpensive] = None,
                cancel: Optional[CancelToken] = None, max_attempts: int = 1,
                on_wrong_key: Optional[WrongKeyHandler] = None) -> VerifyResult:
    """Check that ``src`` decrypts and is intact, without writing anything.

    Unlocks the file exactly as :func:`decrypt_file` does (KDF cost check,
    passphrase forms, retries), then authenticates every chunk and discards
    the plaintext. No output or temporary file is created. Raises the same
    errors as decrypt: :class:`~filecrypt.container.WrongKeyError` for a wrong
    key or a modified header, :class:`~filecrypt.container.CorruptedFileError`
    for a damaged, truncated or extended body.
    """
    _check_cancel(cancel)
    with _open_input(src) as f:
        header = container.read_header(f)
        file_key = _unlock(header, secret, kdf_memory_limit, confirm_expensive,
                           cancel, max_attempts, on_wrong_key)
        total = os.fstat(f.fileno()).st_size - header.header_len
        reader = _ProgressReader(f, total, progress, cancel)
        sink = _NullSink()
        container.decrypt_body(header, file_key, reader, sink)
        reader.finish()
    return VerifyResult(sink.writes, sink.size)


# --- internals ---------------------------------------------------------------

def _resolve(secret: SecretArg) -> Secret:
    value = secret() if callable(secret) else secret
    if not isinstance(value, Secret):
        raise TypeError("secret must be a Secret or a callable returning one")
    return value


def _open_input(path: PathLike) -> BinaryIO:
    try:
        return open(path, "rb")
    except OSError as e:
        raise InputError(f"cannot open {os.fspath(path)}: {e.strerror or e}") from None


def _check_output(src: PathLike, dest: Path, force: bool) -> None:
    if dest.exists():
        try:
            same = os.path.samefile(src, dest)
        except OSError:
            same = False
        if same:
            raise SameFileError()
        if not force:
            raise OutputExistsError(dest)


def _report_stale(dest: Path, handler: Optional[StaleHandler]) -> None:
    if handler is not None:
        found = stale_parts(dest)
        if found:
            handler(found)


def _new_key_block(secret: Secret, options: EncryptOptions, notify: Optional[Notify],
                   cancel: Optional[CancelToken] = None
                   ) -> Tuple[Callable[[bytes], bytes], int, bytes]:
    say = notify or (lambda msg: None)
    warning = kdf.passphrase_warning(secret)
    if warning:
        say(warning)
    kdf_id, settings = kdf.select_kdf(secret, kdf=options.kdf, argon=options.argon,
                                      keyfile_is_passphrase=options.keyfile_is_passphrase,
                                      notify=say)
    if kdf_id == kdf.HKDF and (options.argon is not None or options.kdf):
        say("warning: KDF options are ignored for keys (HKDF is used)")

    def derive(salt: bytes) -> bytes:
        _check_cancel(cancel)
        kek = kdf.derive_kek(kdf_id, settings, salt, secret.value)
        _check_cancel(cancel)
        return kek

    return derive, kdf_id, settings


def _unlock(header: container.Header, secret: SecretArg, limit: Optional[int],
            confirm: Optional[ConfirmExpensive], cancel: Optional[CancelToken] = None,
            max_attempts: int = 1, on_wrong_key: Optional[WrongKeyHandler] = None) -> bytes:
    if limit is None:
        limit = kdf.default_kdf_memory_limit()
    reason = kdf.expensive_kdf_reason(header.kdf_id, header.settings, limit)
    if reason is not None:
        if confirm is None:
            raise ExpensiveKDFError(reason, limit)
        if not confirm(reason):
            raise Cancelled()
    attempt = 0
    while True:
        attempt += 1
        _check_cancel(cancel)
        value = _resolve(secret)
        _check_cancel(cancel)
        try:
            return _unwrap(header, value)
        except container.WrongKeyError:
            # Asking again only helps if the caller can supply a different secret.
            if not callable(secret) or attempt >= max_attempts:
                raise
            if on_wrong_key is not None:
                on_wrong_key(attempt)


def _unwrap(header: container.Header, secret: Secret) -> bytes:
    """Unwrap the file key. A passphrase is tried in NFC form first, then as
    the exact bytes given, which files made before normalization used."""
    *earlier, last = secret.unlock_candidates()
    for candidate in earlier:
        try:
            return container.unwrap_file_key(header, _kek(header, candidate))
        except container.AuthenticationError:
            pass
    return container.unwrap_file_key(header, _kek(header, last))


def _kek(header: container.Header, secret: bytes) -> bytes:
    if header.kdf_id == kdf.HKDF and len(secret) < kdf.MIN_KEY_BYTES:
        # Too short to be the key, so it's a wrong key: the caller may ask again.
        raise container.WrongKeyError(
            f"wrong key: this file was encrypted with a key of at least {kdf.MIN_KEY_BYTES} "
            f"bytes (such as a keyfile), not a passphrase")
    return kdf.derive_kek(header.kdf_id, header.settings, header.salt, secret)


class _NullSink:
    """Counts what decrypt_body would have written (one write per chunk)."""

    def __init__(self) -> None:
        self.writes = 0
        self.size = 0

    def write(self, data: bytes) -> int:
        self.writes += 1
        self.size += len(data)
        return len(data)


class _ProgressReader:
    """Wrap a binary file, report bytes read and honour cancellation."""

    def __init__(self, f: BinaryIO, total: int, progress: Optional[Progress],
                 cancel: Optional[CancelToken] = None):
        self._f, self._total, self._progress = f, max(total, 0), progress
        self._cancel = cancel
        self._done = 0
        self._last = -1

    def read(self, n: int = -1) -> bytes:
        _check_cancel(self._cancel)      # between chunks
        data = self._f.read(n)
        if data:
            self._done += len(data)
            self._report()
        return data

    def finish(self) -> None:
        if self._last != self._done:
            self._report()

    def _report(self) -> None:
        if self._progress is not None:
            self._progress(min(self._done, self._total), self._total)
        self._last = self._done


class AtomicOutput:
    """Write to a temp file next to ``dest``; rename into place on commit.

    If ``commit`` is never reached the temp file is deleted, so a failed or
    interrupted run leaves no partial output. On Windows the temp file is
    opened delete-on-close, so it disappears even if the process is killed;
    a power cut can still leave one behind (see :func:`stale_parts`). Without
    ``force`` an existing ``dest`` is never replaced, even if it appears while
    we are writing.
    """

    def __init__(self, dest: PathLike, force: bool):
        self.dest = Path(dest)
        self.force = force
        self.file = None
        self._tmp: Optional[str] = None
        self._delete_on_close = False
        self._committed = False

    def __enter__(self) -> "AtomicOutput":
        parent = self.dest.absolute().parent
        fd = self._open_windows_temp(parent) if os.name == "nt" else None
        if fd is None:
            fd, self._tmp = tempfile.mkstemp(prefix=f".{self.dest.name}.", suffix=".part", dir=parent)
            if os.name == "nt":
                # Only reached when the owner-only DACL couldn't be applied at
                # creation; restrict the file before any plaintext is written.
                from . import _winacl
                _winacl.restrict_to_owner(self._tmp)
        self.file = os.fdopen(fd, "wb")
        return self

    def _open_windows_temp(self, parent: Path) -> Optional[int]:
        """Create the owner-only temp file on Windows.

        The file is created with the owner-only DACL already applied, so the
        plaintext is never readable by other accounts, not even for a moment.
        It is also opened delete-on-close, so Windows removes it even if we
        are killed. When delete-on-close can't be cleared on this Windows
        version (needed to keep the file on commit), an ordinary owner-only
        file is created instead. Returns None, so the caller falls back to
        create-then-restrict, only when the DACL can't be applied at creation.
        """
        from . import _winacl, _windelete
        delete_on_close = True
        for _ in range(100):
            path = str(parent / f".{self.dest.name}.{secrets.token_hex(4)}.part")
            try:
                fd = _winacl.create_owner_only(path, delete_on_close=delete_on_close)
            except FileExistsError:
                continue
            if fd is None:
                return None
            if not delete_on_close:
                self._tmp = path
                return fd
            # Probe once that the flag can be toggled, so commit can clear it.
            if _windelete.set_delete_on_close(fd, True):
                self._tmp, self._delete_on_close = path, True
                return fd
            os.close(fd)  # deleted by Windows on close
            delete_on_close = False
        raise FileExistsError(errno.EEXIST, "could not create a temporary file", str(parent))

    def commit(self) -> None:
        self.file.flush()
        os.fsync(self.file.fileno())
        if self._delete_on_close:
            from . import _windelete
            if not _windelete.set_delete_on_close(self.file.fileno(), False):
                raise OSError("could not keep the finished output file")
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
                    raise FileExistsError(errno.EEXIST, "File exists", str(self.dest)) from None
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
