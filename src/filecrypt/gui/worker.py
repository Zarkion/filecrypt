"""Run one encrypt or decrypt operation on a background thread.

The engine calls back into the GUI for things only the person can answer (a
new password after a wrong one, "delete these leftovers?", "this file needs a
lot of memory, continue?"). Those callbacks run on the worker thread, so they
send a :attr:`Job.question` signal to the window and wait for
:meth:`Job.answer`. Cancelling also wakes a waiting worker, so the thread
never hangs on a closed dialog.
"""

from __future__ import annotations

import os
import queue
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from PySide6.QtCore import QThread, Signal

from .. import engine, kdf
from ..container import CorruptedFileError, FormatError, WrongKeyError
from ..engine import CancelToken, EncryptOptions
from ..kdf import KDFError, Secret
from ..sources import FileSource, KeySourceError

ENCRYPT = "encrypt"
DECRYPT = "decrypt"

# Questions the worker can ask the window.
ASK_PASSWORD = "password"          # payload: attempt number that failed; answer: str or None
ASK_STALE = "stale"                # payload: list of Paths; answer: bool (delete them)
ASK_EXPENSIVE = "expensive"        # payload: reason text; answer: bool (continue)

# How many passwords a person may try on one file before we give up.
MAX_PASSWORD_ATTEMPTS = 10

_CANCELLED = object()


def passphrase_secret(text: str) -> Secret:
    """Turn typed text into a passphrase Secret, the same way the CLI does."""
    convert = getattr(kdf, "passphrase_from_text", None)  # newer engines normalise text
    if convert is not None:
        return convert(text)
    return Secret(text.encode("utf-8"), "passphrase")


@dataclass(frozen=True)
class JobSpec:
    """Everything a :class:`Job` needs; built by the window from its fields."""
    mode: str                                  # ENCRYPT or DECRYPT
    src: Path
    dest: Path
    password: Optional[str] = None             # used when keyfile is None
    keyfile: Optional[Path] = None
    keyfile_is_passphrase: bool = False
    argon: Optional[kdf.Argon2Params] = None   # encrypt only; None = defaults
    force: bool = False


@dataclass(frozen=True)
class Failure:
    """Why a job failed, sorted into the cases the window explains differently."""
    kind: str            # "wrong_key", "corrupted", "not_fcx", "cancelled", "exists", "error"
    message: str


def classify(exc: BaseException, spec: JobSpec) -> Failure:
    """Map an engine exception to a plain-language :class:`Failure`."""
    if isinstance(exc, engine.Cancelled):
        return Failure("cancelled", "Cancelled. No file was written.")
    if isinstance(exc, WrongKeyError):
        if spec.keyfile is not None:
            return Failure("wrong_key", "This keyfile doesn't unlock the file. "
                                        "Check that you chose the keyfile it was locked with.")
        return Failure("wrong_key", "That password doesn't unlock this file.")
    if isinstance(exc, CorruptedFileError):
        return Failure("corrupted", "This file is damaged or has been changed since it was "
                                    "encrypted, so it can't be decrypted safely. Your password "
                                    "was right. No file was written. If you have another copy "
                                    "of the encrypted file, try that one.")
    if isinstance(exc, FormatError):
        return Failure("not_fcx", "This isn't a file filecrypt can decrypt, or its beginning "
                                  "is damaged.")
    if isinstance(exc, engine.OutputExistsError):
        return Failure("exists", f"{exc.path.name} already exists.")
    if isinstance(exc, engine.ExpensiveKDFError):
        return Failure("error", f"This file needs too much memory to open safely: {exc}.")
    if isinstance(exc, (engine.EngineError, KDFError, KeySourceError, ValueError)):
        return Failure("error", _sentence(str(exc)))
    if isinstance(exc, OSError):
        where = f" ({exc.filename})" if getattr(exc, "filename", None) else ""
        return Failure("error", f"Couldn't read or write a file{where}: "
                                f"{exc.strerror or exc}.")
    return Failure("error", f"Something went wrong: {exc!r}")


def _sentence(text: str) -> str:
    text = text.strip()
    for prefix in ("warning: ", "notice: "):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if not text:
        return "Something went wrong."
    text = text[0].upper() + text[1:]
    return text if text.endswith((".", "!", "?")) else text + "."


class Job(QThread):
    """One encrypt or decrypt run. Create, connect the signals, then ``start()``."""

    progress = Signal(int, int)          # percent (0..1000), total bytes
    notice = Signal(str)                 # one-line notices from the engine
    question = Signal(str, object)       # ASK_* kind, payload; reply with answer()
    wrong_password = Signal(int)         # a password attempt failed (attempt number)
    succeeded = Signal(object)           # output Path
    failed = Signal(object)              # Failure

    def __init__(self, spec: JobSpec, parent=None):
        super().__init__(parent)
        self.spec = spec
        self.token = CancelToken()
        self._answers: "queue.Queue[Any]" = queue.Queue()
        self.result: Optional[Path] = None
        self.failure: Optional[Failure] = None
        self._attempt = 0
        self._last_permille = -1

    # --- called from the GUI thread ---------------------------------------------

    def cancel(self) -> None:
        self.token.cancel()
        self._answers.put(_CANCELLED)

    def answer(self, value: Any) -> None:
        self._answers.put(value)

    # --- worker thread -------------------------------------------------------------

    def _ask(self, kind: str, payload: Any) -> Any:
        self.token.raise_if_cancelled()
        self.question.emit(kind, payload)
        value = self._answers.get()
        if value is _CANCELLED:
            raise engine.Cancelled()
        self.token.raise_if_cancelled()
        return value

    def _report(self, done: int, total: int) -> None:
        permille = 1000 if total <= 0 else int(done * 1000 / total)
        if permille != self._last_permille:   # don't flood the GUI with tiny updates
            self._last_permille = permille
            self.progress.emit(permille, total)

    def _secret_source(self) -> Callable[[], Secret]:
        spec = self.spec
        if spec.keyfile is not None:
            def from_keyfile() -> Secret:
                s = FileSource().get(os.fspath(spec.keyfile))
                if spec.keyfile_is_passphrase:
                    s = Secret(s.value, "passphrase")
                return s
            return from_keyfile

        first = [True]

        def from_password() -> Secret:
            if first[0]:
                first[0] = False
                text = spec.password or ""
            else:
                text = self._ask(ASK_PASSWORD, self._attempt)
                if not text:
                    raise engine.Cancelled()
            return passphrase_secret(text)
        return from_password

    def run(self) -> None:  # noqa: D401 - QThread entry point
        spec = self.spec

        def on_wrong(attempt: int) -> None:
            self._attempt = attempt
            self.wrong_password.emit(attempt)

        def on_stale(paths):
            if self._ask(ASK_STALE, list(paths)):
                for p in paths:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

        try:
            if spec.mode == ENCRYPT:
                options = EncryptOptions(argon=spec.argon,
                                         keyfile_is_passphrase=spec.keyfile_is_passphrase)
                self.result = engine.encrypt_file(
                    spec.src, spec.dest, self._secret_source(), options=options,
                    force=spec.force, progress=self._report,
                    notify=lambda m: self.notice.emit(_sentence(m)),
                    on_stale_parts=on_stale, cancel=self.token)
            else:
                self.result = engine.decrypt_file(
                    spec.src, spec.dest, self._secret_source(), force=spec.force,
                    progress=self._report,
                    confirm_expensive=lambda reason: bool(self._ask(ASK_EXPENSIVE, reason)),
                    on_stale_parts=on_stale, cancel=self.token,
                    max_attempts=1 if spec.keyfile is not None else MAX_PASSWORD_ATTEMPTS,
                    on_wrong_key=on_wrong)
        except Exception as e:  # report everything; the thread must not die silently
            self.failure = classify(e, spec)
            self.failed.emit(self.failure)
            return
        self.succeeded.emit(self.result)
