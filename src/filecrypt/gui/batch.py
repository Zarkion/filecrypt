"""Jobs for Explorer launches: several files with one password, and "Test".

:class:`BatchJob` is a :class:`~filecrypt.gui.worker.Job` that remembers the
password that finally worked, so when the person retypes it for the first
file of a batch, the rest of the batch uses the corrected one.

The ``TEST`` mode unlocks a file and authenticates every chunk without
writing anything, for the "Test with filecrypt" entry on .fcx files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .. import engine
from ..engine import CancelToken
from ..kdf import Secret
from .worker import ASK_EXPENSIVE, MAX_PASSWORD_ATTEMPTS, Job, JobSpec, classify

TEST = "test"


def verify_file(src: Path, secret: Callable[[], Secret], *, progress=None,
                confirm_expensive=None, cancel: Optional[CancelToken] = None,
                max_attempts: int = 1, on_wrong_key=None) -> None:
    """Unlock ``src`` and authenticate every chunk without writing anything
    (``engine.verify_file``: same KDF-cost check, passphrase forms and retries
    as decrypt, and the same errors)."""
    engine.verify_file(src, secret, progress=progress, confirm_expensive=confirm_expensive,
                       cancel=cancel, max_attempts=max_attempts, on_wrong_key=on_wrong_key)


class BatchJob(Job):
    """A Job that also does TEST and records the password that was used."""

    def __init__(self, spec: JobSpec, parent=None):
        super().__init__(spec, parent)
        self.password: Optional[str] = spec.password

    def _ask(self, kind, payload):
        value = super()._ask(kind, payload)
        if kind == "password" and value:
            self.password = value      # the latest attempt; the right one on success
        return value

    def run(self) -> None:
        if self.spec.mode != TEST:
            super().run()
            return
        spec = self.spec

        def on_wrong(attempt: int) -> None:
            self._attempt = attempt
            self.wrong_password.emit(attempt)

        try:
            verify_file(
                spec.src, self._secret_source(), progress=self._report,
                confirm_expensive=lambda reason: bool(self._ask(ASK_EXPENSIVE, reason)),
                cancel=self.token,
                max_attempts=1 if spec.keyfile is not None else MAX_PASSWORD_ATTEMPTS,
                on_wrong_key=on_wrong)
        except Exception as e:  # report everything; the thread must not die silently
            self.failure = classify(e, spec)
            self.failed.emit(self.failure)
            return
        self.result = spec.src
        self.succeeded.emit(self.result)
