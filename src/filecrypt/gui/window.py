"""The filecrypt main window: pick a file, type a password, encrypt or decrypt."""

from __future__ import annotations

from dataclasses import replace
import html
import os
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QDragEnterEvent, QDropEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFormLayout, QFrame, QGridLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
                               QMainWindow, QMessageBox, QProgressBar, QPushButton,
                               QSizePolicy, QSpinBox, QStackedWidget, QToolButton,
                               QVBoxLayout, QWidget)

from .. import _motw, engine, kdf
from ..container import FormatError
from ..kdf import Argon2Params, KDFError
from . import strength
from .batch import TEST, BatchJob
from .worker import (ASK_EXPENSIVE, ASK_PASSWORD, ASK_STALE, DECRYPT, ENCRYPT, Failure,
                     Job, JobSpec)

_VERBS = {ENCRYPT: ("Encrypt", "Encrypting", "encrypted"),
          DECRYPT: ("Decrypt", "Decrypting", "decrypted"),
          TEST: ("Verify", "Verifying", "verified")}

_METER_COLORS = ("#d93025", "#e8710a", "#f9ab00", "#1e8e3e", "#137333")

LOSS_WARNING = ("<b>Keep this password safe.</b> If you forget or lose it, this file "
                "can't be opened again. Nobody can reset it or get the file back for you, "
                "not even the people who made filecrypt.")


class DropZone(QFrame):
    """The big area at the top: drop a file here or click to choose one."""

    file_dropped = Signal(list)
    choose_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumHeight(120)
        self.setStyleSheet(
            "#dropZone { border: 2px dashed palette(mid); border-radius: 10px; }"
            "#dropZone[hover=\"true\"] { border-color: palette(highlight); }")
        layout = QVBoxLayout(self)
        self.title = QLabel("Drop a file here")
        self.title.setAlignment(Qt.AlignCenter)
        f = self.title.font()
        f.setPointSizeF(f.pointSizeF() * 1.3)
        f.setBold(True)
        self.title.setFont(f)
        self.title.setWordWrap(True)
        self.detail = QLabel("or")
        self.detail.setAlignment(Qt.AlignCenter)
        self.detail.setWordWrap(True)
        self.detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.choose = QPushButton("Choose a file…")
        self.choose.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.choose.clicked.connect(self.choose_clicked)
        layout.addStretch(1)
        layout.addWidget(self.title)
        layout.addWidget(self.detail)
        layout.addWidget(self.choose, alignment=Qt.AlignCenter)
        layout.addStretch(1)

    def _set_hover(self, on: bool) -> None:
        self.setProperty("hover", on)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() and any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()
            self._set_hover(True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self._set_hover(False)

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_hover(False)
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.file_dropped.emit(paths)


class MainWindow(QMainWindow):
    """One window, one file or one batch of files with one password.

    Every dialog goes through a small method (``confirm``, ``ask_password_again``,
    ``choose_open_path``, ``choose_save_path``) so tests can replace them.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("filecrypt")
        self.setAcceptDrops(True)
        self.src: Optional[Path] = None
        self.batch: List[Path] = []        # every file the next run works on (src first)
        self.mode: Optional[str] = None
        self.needs_keyfile = False
        self.job: Optional[Job] = None
        self.last_output: Optional[Path] = None
        self._queue: List[JobSpec] = []    # specs still to run in this batch
        self._done: List[Path] = []        # outputs (or tested files) of this batch
        self._problems: List[str] = []     # "name: why" for files that failed
        self._motw_failed: List[str] = []
        self._pending: Optional[tuple] = None   # a request that arrived while busy
        self._total = 0                    # files in the running batch
        self._not_run: List[str] = []
        self._verify_from: Optional[str] = None  # mode to go back to after "Verify"
        self._build()
        self._refresh()

    # --- layout --------------------------------------------------------------------

    def _build(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        self.drop = DropZone()
        self.drop.file_dropped.connect(self.files_dropped)
        self.drop.choose_clicked.connect(self._choose_file)
        root.addWidget(self.drop)

        # The files of a batch, listed in full for the person to check.
        self.batch_list = QListWidget()
        self.batch_list.setVisible(False)
        self.batch_list.setMaximumHeight(140)
        self.batch_list.setSelectionMode(QListWidget.NoSelection)
        root.addWidget(self.batch_list)

        # Password pages: encrypt (with confirm, meter, warning) and decrypt.
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_encrypt_page())
        self.pages.addWidget(self._build_decrypt_page())
        self.pages.currentChanged.connect(self._fit_page)
        self._fit_page(0)
        root.addWidget(self.pages)

        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(self._toggle_echo)
        root.addWidget(self.show_password)

        # Advanced section, collapsed by default.
        self.advanced_toggle = QToolButton()
        self.advanced_toggle.setText("Advanced")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.advanced_toggle.setArrowType(Qt.RightArrow)
        self.advanced_toggle.setAutoRaise(True)
        self.advanced_toggle.toggled.connect(self._toggle_advanced)
        root.addWidget(self.advanced_toggle)
        self.advanced = self._build_advanced()
        self.advanced.setVisible(False)
        root.addWidget(self.advanced)

        # Status message, progress and buttons.
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.status.setVisible(False)
        root.addWidget(self.status)

        self.open_folder = QPushButton("Open folder")
        self.open_folder.setVisible(False)
        self.open_folder.clicked.connect(self._open_output_folder)

        prow = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(True)
        self.progress.setVisible(False)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel)
        prow.addWidget(self.progress, 1)
        prow.addWidget(self.cancel_button)
        root.addLayout(prow)

        brow = QHBoxLayout()
        brow.addWidget(self.open_folder)
        brow.addStretch(1)
        self.reason_label = QLabel()
        self.reason_label.setEnabled(False)  # greyed-out hint next to the button
        brow.addWidget(self.reason_label)
        self.verify_button = QPushButton("Verify")
        self.verify_button.setToolTip("Check the password and that the file is undamaged, "
                                      "without decrypting it. Nothing is written.")
        self.verify_button.setVisible(False)
        self.verify_button.clicked.connect(self.verify)
        brow.addWidget(self.verify_button)
        self.action = QPushButton("Encrypt")
        self.action.setDefault(True)
        self.action.setMinimumWidth(140)
        self.action.clicked.connect(self.start)
        brow.addWidget(self.action)
        root.addLayout(brow)
        root.addStretch(1)

        QShortcut(QKeySequence.Open, self, activated=self._choose_file)
        self.resize(520, 560)

    def _build_encrypt_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        self.enc_password = QLineEdit()
        self.enc_password.setEchoMode(QLineEdit.Password)
        self.enc_password.setPlaceholderText("Choose a password")
        self.enc_password.textChanged.connect(self._password_changed)
        self.enc_confirm = QLineEdit()
        self.enc_confirm.setEchoMode(QLineEdit.Password)
        self.enc_confirm.setPlaceholderText("Type it again")
        self.enc_confirm.textChanged.connect(self._refresh)
        self.enc_password.returnPressed.connect(self.enc_confirm.setFocus)
        self.enc_confirm.returnPressed.connect(self.start)
        form.addRow("Password:", self.enc_password)
        form.addRow("Confirm:", self.enc_confirm)

        meter_row = QHBoxLayout()
        self.meter = QProgressBar()
        self.meter.setRange(0, 4)
        self.meter.setTextVisible(False)
        self.meter.setFixedHeight(8)
        self.meter_label = QLabel()
        self.meter_label.setMinimumWidth(80)
        meter_row.addWidget(self.meter, 1)
        meter_row.addWidget(self.meter_label)
        form.addRow("Strength:", meter_row)
        self.meter_hint = QLabel()
        self.meter_hint.setWordWrap(True)
        self.meter_hint.setVisible(False)
        form.addRow("", self.meter_hint)
        self.match_label = QLabel()
        self.match_label.setVisible(False)
        form.addRow("", self.match_label)

        warn = QFrame()
        warn.setObjectName("lossWarning")
        warn.setStyleSheet("#lossWarning { background: rgba(249, 171, 0, 0.18); "
                           "border: 1px solid rgba(249, 171, 0, 0.7); border-radius: 6px; }")
        wl = QVBoxLayout(warn)
        self.warning_label = QLabel(LOSS_WARNING)
        self.warning_label.setWordWrap(True)
        self.understand = QCheckBox("I understand that a lost password means a lost file")
        self.understand.toggled.connect(self._refresh)
        wl.addWidget(self.warning_label)
        wl.addWidget(self.understand)
        form.addRow(warn)
        return page

    def _build_decrypt_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        self.dec_password = QLineEdit()
        self.dec_password.setEchoMode(QLineEdit.Password)
        self.dec_password.setPlaceholderText("The password this file was locked with")
        self.dec_password.textChanged.connect(self._refresh)
        self.dec_password.returnPressed.connect(self.start)
        form.addRow("Password:", self.dec_password)
        return page

    def _build_advanced(self) -> QWidget:
        box = QFrame()
        grid = QGridLayout(box)
        grid.setContentsMargins(16, 0, 0, 0)

        self.use_keyfile = QCheckBox("Use a keyfile instead of a password")
        self.use_keyfile.toggled.connect(self._refresh)
        grid.addWidget(self.use_keyfile, 0, 0, 1, 3)
        self.keyfile_path = QLineEdit()
        self.keyfile_path.setPlaceholderText("Keyfile")
        self.keyfile_path.textChanged.connect(self._refresh)
        self.keyfile_browse = QPushButton("Browse…")
        self.keyfile_browse.clicked.connect(self._choose_keyfile)
        grid.addWidget(self.keyfile_path, 1, 0, 1, 2)
        grid.addWidget(self.keyfile_browse, 1, 2)
        self.keyfile_is_passphrase = QCheckBox("Treat the keyfile as a password (for short "
                                               "or hand-written keyfiles)")
        grid.addWidget(self.keyfile_is_passphrase, 2, 0, 1, 3)

        self.argon_box = QFrame()
        ag = QFormLayout(self.argon_box)
        ag.setContentsMargins(0, 8, 0, 0)
        d = Argon2Params.default()
        self.argon_memory = QSpinBox()
        self.argon_memory.setRange(kdf.ARGON2_MIN_MEMORY_KIB // 1024, 4096)
        self.argon_memory.setValue(d.memory_kib // 1024)
        self.argon_memory.setSuffix(" MiB")
        self.argon_iterations = QSpinBox()
        self.argon_iterations.setRange(kdf.ARGON2_MIN_ITERATIONS, kdf.ARGON2_MAX_ITERATIONS)
        self.argon_iterations.setValue(d.iterations)
        self.argon_parallelism = QSpinBox()
        self.argon_parallelism.setRange(kdf.ARGON2_MIN_LANES, kdf.ARGON2_MAX_LANES)
        self.argon_parallelism.setValue(d.parallelism)
        self.argon_note = QLabel("Password hashing (Argon2id). Higher memory and passes make "
                                 "password guessing slower, and also make opening the file "
                                 "slower and need more memory on every computer that opens it.")
        self.argon_note.setWordWrap(True)
        ag.addRow(self.argon_note)
        ag.addRow("Memory:", self.argon_memory)
        ag.addRow("Passes:", self.argon_iterations)
        ag.addRow("Parallel lanes:", self.argon_parallelism)
        self.reset_argon = QPushButton("Reset to defaults")
        self.reset_argon.clicked.connect(self._reset_argon)
        ag.addRow("", self.reset_argon)
        grid.addWidget(self.argon_box, 3, 0, 1, 3)
        if not kdf.argon2_available():
            for w in (self.argon_memory, self.argon_iterations, self.argon_parallelism,
                      self.reset_argon):
                w.setEnabled(False)
            self.argon_note.setText("Argon2id isn't available on this computer, so scrypt is "
                                    "used with its standard settings.")
        return box

    # --- choosing a file -------------------------------------------------------------

    def choose_open_path(self) -> Optional[Path]:
        name, _ = QFileDialog.getOpenFileName(self, "Choose a file to encrypt or decrypt")
        return Path(name) if name else None

    def choose_save_path(self, suggested: Path) -> Optional[Path]:
        name, _ = QFileDialog.getSaveFileName(self, "Save the decrypted file as",
                                              os.fspath(suggested))
        return Path(name) if name else None

    def _choose_file(self) -> None:
        if self._busy():
            return
        path = self.choose_open_path()
        if path is not None:
            self.set_file(path)

    def _choose_keyfile(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Choose a keyfile")
        if name:
            self.keyfile_path.setText(name)
            self.use_keyfile.setChecked(True)

    def files_dropped(self, paths: List[Path]) -> None:
        if self._busy():
            return
        if len(paths) == 1:
            self.set_file(paths[0])
        else:
            self._listed_action = None      # a drop starts a new list
            self.open_request("open", paths)

    # --- several files (Explorer, drag and drop) --------------------------------------

    _listed_action: Optional[str] = None    # the request that built the current list

    def open_request(self, action: str, paths) -> None:
        """Show files from the command line or another filecrypt process.

        ``action`` is "encrypt", "decrypt", "test" or "open" (pick by file type).
        Requests for the same action that arrive before the person starts are
        added to the list, because Explorer starts one process per selected file.
        """
        new = [Path(p) for p in paths]
        if not new:
            return
        if self._busy():
            if self._pending is not None and self._pending[0] == action:
                new = self._pending[1] + new
            self._pending = (action, new)
            return
        self._bring_to_front()
        if action == self._listed_action and self.batch:
            new = self.batch + new
        seen, files = set(), []
        for p in new:
            key = os.path.normcase(os.path.abspath(p))
            if key not in seen:
                seen.add(key)
                files.append(p)
        if action == "open" and len(files) == 1:
            self.set_file(files[0])
            self._listed_action = action
            return
        self._load(action, files)
        self._listed_action = action

    def _bring_to_front(self) -> None:
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()

    def _load(self, action: str, files: List[Path]) -> None:
        """Check every file for ``action`` and list the ones that can be done."""
        self._clear_status()
        self.src, self.batch, self.mode, self.needs_keyfile = None, [], None, False
        ok: List[Path] = []
        modes, needs, problems = set(), set(), []
        for p in files:
            if p.is_dir():
                problems.append((p, "it's a folder; put it in a .zip file first"))
                continue
            try:
                info = engine.inspect_file(p)
            except engine.InputError as e:
                problems.append((p, f"couldn't open it ({e})"))
                continue
            except (FormatError, KDFError):
                info = None
            if action == ENCRYPT:
                mode = ENCRYPT
            elif info is not None:
                mode = DECRYPT if action == "open" else action
            elif action == "open" and not p.name.lower().endswith(engine.FCX_SUFFIX):
                mode = ENCRYPT
            else:
                problems.append((p, "it isn't a file filecrypt can decrypt, or its "
                                    "beginning is damaged"))
                continue
            modes.add(mode)
            if mode != ENCRYPT:
                needs.add(info.needs)
            ok.append(p)
        if len(modes) > 1:
            self._show("Some of these files are encrypted and some aren't. Encrypt and "
                       "decrypt them separately.", "error")
            ok = []
        elif needs == {"key", "passphrase"}:
            self._show("Some of these files were locked with a keyfile and some with a "
                       "password. Open them separately.", "error")
            ok = []
        if ok:
            self._apply(modes.pop(), ok, needs == {"key"})
        else:
            self.batch_list.setVisible(False)
        if problems:
            lines = "".join(f"<br>&bull; {html.escape(p.name)}: {html.escape(why)}"
                            for p, why in problems)
            skipped = "This file was" if len(problems) == 1 else "These files were"
            self._show(f"{skipped} left out:{lines}", "error" if not ok else "info")
        self._refresh()

    def _apply(self, mode: str, files: List[Path], needs_key: bool) -> None:
        self.src, self.batch, self.mode, self.needs_keyfile = files[0], files, mode, needs_key
        n = len(files)
        self.drop.title.setText(files[0].name if n == 1 else f"{n} files")
        if mode == ENCRYPT:
            detail = (f"Will be encrypted to {files[0].name}{engine.FCX_SUFFIX}. The original "
                      f"file is kept." if n == 1 else
                      "Each file will be encrypted to a .fcx file next to it, with the same "
                      "password. The originals are kept.")
        elif mode == DECRYPT:
            detail = ("Encrypted file. Will be decrypted next to it." if n == 1 else
                      "Encrypted files. Each will be decrypted next to it.")
        else:
            detail = ("Will check that the password opens " + ("this file" if n == 1 else
                      "every file") + " and that nothing in it was damaged or changed. "
                      "Nothing is written.")
        self.drop.detail.setText(detail)
        self.batch_list.clear()
        for p in files:
            self.batch_list.addItem(os.fspath(p))
        self.batch_list.setVisible(n > 1)
        self.pages.setCurrentIndex(0 if mode == ENCRYPT else 1)
        if needs_key:
            self.use_keyfile.setChecked(True)
            self.advanced_toggle.setChecked(True)
            self._show("These files were locked with a keyfile, not a password. Choose the "
                       "keyfile under Advanced." if n > 1 else
                       "This file was locked with a keyfile, not a password. Choose the "
                       "keyfile under Advanced.", "info")
        elif mode == ENCRYPT:
            self.enc_password.setFocus()
        else:
            self.dec_password.setFocus()
        self.drop.choose.setText("Choose another file…")

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        self.drop.dragEnterEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self.drop.dropEvent(event)

    def set_file(self, path: Path) -> None:
        """Pick ``path`` and decide whether it is to be encrypted or decrypted."""
        path = Path(path)
        self._clear_status()
        self.src, self.mode, self.needs_keyfile = None, None, False
        self.batch = []
        self._listed_action = None
        self.batch_list.setVisible(False)
        if path.is_dir():
            self._show("That's a folder. filecrypt encrypts one file at a time; to protect a "
                       "folder, put it in a .zip file first.", "error")
            self._refresh()
            return
        try:
            info = engine.inspect_file(path)
        except engine.InputError as e:
            self._show(f"Couldn't open that file: {e}", "error")
            self._refresh()
            return
        except (FormatError, KDFError):
            if path.name.lower().endswith(engine.FCX_SUFFIX):
                self._show("This file ends in .fcx but isn't a file filecrypt can decrypt, "
                           "or its beginning is damaged.", "error")
                self._refresh()
                return
            info = None
        self.src = path
        self.batch = [path]
        if info is None:
            self.mode = ENCRYPT
            self.drop.title.setText(path.name)
            self.drop.detail.setText(f"Will be encrypted to {path.name}{engine.FCX_SUFFIX}. "
                                     f"The original file is kept.")
            self.pages.setCurrentIndex(0)
            self.enc_password.setFocus()
        else:
            self.mode = DECRYPT
            out = engine.default_decrypt_output(path)
            self.drop.title.setText(path.name)
            self.drop.detail.setText(f"Encrypted file. Will be decrypted to "
                                     f"{out.name if out else 'a name you choose'}.")
            self.pages.setCurrentIndex(1)
            self.needs_keyfile = info.needs == "key"
            if self.needs_keyfile:
                self.use_keyfile.setChecked(True)
                self.advanced_toggle.setChecked(True)
                self._show("This file was locked with a keyfile, not a password. Choose the "
                           "keyfile under Advanced.", "info")
            else:
                self.dec_password.setFocus()
        self.drop.choose.setText("Choose another file…")
        self._refresh()

    # --- form state -------------------------------------------------------------------

    def _fit_page(self, index: int) -> None:
        """Size the stack to the visible page, not the tallest one."""
        for i in range(self.pages.count()):
            policy = QSizePolicy.Preferred if i == index else QSizePolicy.Ignored
            self.pages.widget(i).setSizePolicy(QSizePolicy.Preferred, policy)
        self.pages.adjustSize()

    def _password_changed(self) -> None:
        s = strength.estimate(self.enc_password.text())
        self.meter.setValue(s.score if self.enc_password.text() else 0)
        self.meter.setStyleSheet(f"QProgressBar::chunk {{ background: {_METER_COLORS[s.score]}; }}")
        self.meter_label.setText(s.label if self.enc_password.text() else "")
        self.meter_hint.setText(" ".join(s.hints) if self.enc_password.text() else "")
        self.meter_hint.setVisible(bool(self.meter_hint.text()))
        self._refresh()

    def _toggle_echo(self, show: bool) -> None:
        mode = QLineEdit.Normal if show else QLineEdit.Password
        for field in (self.enc_password, self.enc_confirm, self.dec_password):
            field.setEchoMode(mode)

    def _toggle_advanced(self, on: bool) -> None:
        self.advanced.setVisible(on)
        self.advanced_toggle.setArrowType(Qt.DownArrow if on else Qt.RightArrow)

    def _reset_argon(self) -> None:
        d = Argon2Params.default()
        self.argon_memory.setValue(d.memory_kib // 1024)
        self.argon_iterations.setValue(d.iterations)
        self.argon_parallelism.setValue(d.parallelism)

    def _keyfile(self) -> Optional[Path]:
        if self.use_keyfile.isChecked() and self.keyfile_path.text().strip():
            return Path(self.keyfile_path.text().strip())
        return None

    def _argon(self) -> Optional[Argon2Params]:
        if not kdf.argon2_available():
            return None
        p = Argon2Params.from_cli(self.argon_memory.value(), self.argon_iterations.value(),
                                  self.argon_parallelism.value())
        return None if p == Argon2Params.default() else p

    def _busy(self) -> bool:
        return self.job is not None

    def ready_reason(self) -> Optional[str]:
        """Why the action button is disabled, or None if it can run."""
        if self.src is None or self.mode is None:
            return "Choose a file first."
        keyfile_mode = self.use_keyfile.isChecked()
        if keyfile_mode and self._keyfile() is None:
            return "Choose a keyfile."
        if self.mode in (DECRYPT, TEST):
            if self.needs_keyfile and not keyfile_mode:
                return "This file needs its keyfile."
            if not keyfile_mode and not self.dec_password.text():
                return "Type the password."
            return None
        if not keyfile_mode:
            if not self.enc_password.text():
                return "Choose a password."
            if self.enc_password.text() != self.enc_confirm.text():
                return "The passwords don't match."
        if not self.understand.isChecked():
            return "Tick the box to confirm you understand the warning."
        return None

    def _refresh(self) -> None:
        busy = self._busy()
        keyfile_mode = self.use_keyfile.isChecked()
        self.action.setText(_VERBS.get(self.mode, _VERBS[ENCRYPT])[0])
        reason = self.ready_reason()
        self.action.setEnabled(not busy and reason is None)
        self.action.setToolTip(reason or "")
        self.verify_button.setVisible(self.mode == DECRYPT and self.src is not None)
        self.verify_button.setEnabled(not busy and reason is None)
        for w in (self.drop, self.pages, self.show_password, self.advanced):
            w.setEnabled(not busy)
        self.pages.setVisible(self.src is not None)
        self.show_password.setVisible(self.src is not None)
        for w in (self.enc_password, self.enc_confirm, self.dec_password):
            w.setEnabled(not keyfile_mode)
        self.keyfile_path.setEnabled(keyfile_mode)
        self.keyfile_browse.setEnabled(keyfile_mode)
        self.keyfile_is_passphrase.setEnabled(keyfile_mode)
        self.argon_box.setVisible(self.mode not in (DECRYPT, TEST))
        both = self.enc_password.text() and self.enc_confirm.text()
        if not keyfile_mode and both and self.enc_password.text() != self.enc_confirm.text():
            self.match_label.setText("\u2717 The passwords don't match.")
            self.match_label.setStyleSheet("color: #d93025;")
        elif not keyfile_mode and both:
            self.match_label.setText("\u2713 The passwords match.")
            self.match_label.setStyleSheet("color: #1e8e3e;")
        else:
            self.match_label.setText("")
        self.match_label.setVisible(bool(self.match_label.text()))
        self.reason_label.setText("" if busy or reason is None or self.src is None else reason)
        self.progress.setVisible(busy)
        self.cancel_button.setVisible(busy)

    # --- messages and dialogs -----------------------------------------------------------

    def _show(self, text: str, kind: str = "info") -> None:
        colors = {"error": "rgba(217, 48, 37, 0.15)", "ok": "rgba(30, 142, 62, 0.15)",
                  "info": "rgba(128, 128, 128, 0.12)"}
        self.status.setStyleSheet(f"QLabel {{ background: {colors[kind]}; padding: 8px; "
                                  f"border-radius: 6px; }}")
        self.status.setProperty("kind", kind)
        self.status.setText(text)
        self.status.setVisible(True)

    def _clear_status(self) -> None:
        self.status.setVisible(False)
        self.status.setText("")
        self.status.setProperty("kind", None)
        self.open_folder.setVisible(False)

    def confirm(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text, QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No) == QMessageBox.Yes

    def ask_password_again(self, attempt: int) -> Optional[str]:
        text, ok = QInputDialog.getText(
            self, "Wrong password",
            "That password doesn't unlock this file. Check Caps Lock and try again:",
            QLineEdit.Password)
        return text if ok and text else None

    # --- running ----------------------------------------------------------------------------

    def start(self) -> None:
        if self._busy() or self.ready_reason() is not None:
            return
        self._clear_status()
        keyfile = self._keyfile()
        if self.mode == ENCRYPT and keyfile is None:
            s = strength.estimate(self.enc_password.text())
            if s.score < 2 and not self.confirm(
                    "Weak password",
                    f"This password is {s.label.lower()}. Someone who gets the encrypted "
                    f"file could guess it. Use it anyway?"):
                return
        files = self.batch or [self.src]
        targets = []
        for src in files:
            if self.mode == ENCRYPT:
                dest = engine.default_encrypt_output(src)
            elif self.mode == TEST:
                dest = src            # nothing is written
            else:
                dest = engine.default_decrypt_output(src)
                if dest is None:
                    dest = self.choose_save_path(src.with_name(src.name + ".decrypted"))
                    if dest is None:
                        return
            targets.append((src, dest))
        existing = [d for _, d in targets if self.mode != TEST and d.exists()]
        if len(existing) == 1:
            if not self.confirm("Replace file?",
                                f"{existing[0].name} already exists. Replace it?"):
                return
        elif existing:
            names = "\n".join(d.name for d in existing[:10])
            if len(existing) > 10:
                names += f"\n…and {len(existing) - 10} more"
            if not self.confirm("Replace files?",
                                f"These files already exist:\n\n{names}\n\nReplace them?"):
                return
        password = None if keyfile else (self.enc_password.text() if self.mode == ENCRYPT
                                         else self.dec_password.text())
        specs = [JobSpec(
            mode=self.mode, src=src, dest=dest, password=password, keyfile=keyfile,
            keyfile_is_passphrase=self.keyfile_is_passphrase.isChecked(),
            argon=self._argon() if self.mode == ENCRYPT else None,
            force=dest in existing) for src, dest in targets]
        self.run_batch(specs)

    def verify(self) -> None:
        """Run the decrypt form as a check only: unlock and authenticate, write nothing."""
        if self.mode != DECRYPT or self._busy() or self.ready_reason() is not None:
            return
        self._verify_from, self.mode = self.mode, TEST
        self.start()
        if self.job is None:           # nothing started; go back to decrypting
            self._end_verify()

    def _end_verify(self) -> None:
        if self._verify_from is not None:
            self.mode, self._verify_from = self._verify_from, None
            self._refresh()

    def run_batch(self, specs: List[JobSpec]) -> None:
        self._total, self._done, self._problems = len(specs), [], []
        self._not_run, self._motw_failed = [], []
        self._queue = list(specs[1:])
        self.run_job(specs[0], _continuing=True)

    def run_job(self, spec: JobSpec, _continuing: bool = False) -> Job:
        if not _continuing:      # one job on its own
            self._total, self._done, self._problems = 1, [], []
            self._not_run, self._motw_failed, self._queue = [], [], []
        job = BatchJob(spec, self)
        job.progress.connect(self._on_progress)
        job.notice.connect(lambda m: self._show(m, "info"))
        job.question.connect(self._on_question)
        job.wrong_password.connect(self._on_wrong_password)
        job.succeeded.connect(self._on_succeeded)
        job.failed.connect(self._on_failed)
        job.finished.connect(self._on_finished)
        self.job = job
        self.progress.setValue(0)
        self.progress.setFormat(self._file_prefix() +
                                ("Preparing…" if spec.mode == ENCRYPT else "Unlocking…"))
        self._refresh()
        job.start()
        return job

    def cancel(self) -> None:
        if self.job is not None:
            self.cancel_button.setEnabled(False)
            self.progress.setFormat("Cancelling…")
            self.job.cancel()

    def _on_progress(self, permille: int, total: int) -> None:
        self.progress.setValue(permille)
        verb = _VERBS.get(self.mode, _VERBS[ENCRYPT])[1]
        self.progress.setFormat(f"{self._file_prefix()}{verb}… {permille // 10}%")

    def _file_prefix(self) -> str:
        if self._total <= 1:
            return ""
        return f"File {self._total - len(self._queue)} of {self._total}: "

    def _on_question(self, kind: str, payload) -> None:
        job = self.sender()
        if not isinstance(job, Job):
            job = self.job
        if job is None:
            return
        if kind == ASK_PASSWORD:
            job.answer(self.ask_password_again(int(payload)))
        elif kind == ASK_STALE:
            names = "\n".join(p.name for p in payload)
            job.answer(self.confirm(
                "Leftover files",
                "An earlier run was interrupted and left these unfinished files next to "
                f"the output:\n\n{names}\n\nThey may contain part of a decrypted file. "
                "Delete them?"))
        elif kind == ASK_EXPENSIVE:
            job.answer(self.confirm(
                "This file needs a lot of memory",
                f"Opening this file needs unusually heavy password hashing ({payload}). "
                "That can make this computer slow for a while. Only continue if you "
                "expect this file to need it. Continue?"))
        else:
            job.answer(None)

    def _on_wrong_password(self, attempt: int) -> None:
        self.progress.setFormat("Wrong password, asking again…")

    def _on_succeeded(self, dest: Path) -> None:
        job = self.job
        dest = Path(dest)
        if self.mode in (ENCRYPT, DECRYPT) and job is not None:
            # Carry "downloaded from the internet" over, so encrypting and
            # decrypting can't be used to strip it.
            if _motw.copy_zone_identifier(job.spec.src, dest) is False:
                self._motw_failed.append(dest.name)
        self._done.append(dest)
        if self.mode != TEST:
            self.last_output = dest
        if self._queue:
            if job is not None and job.spec.keyfile is None and isinstance(job, BatchJob):
                # If the person had to retype the password, use the one that worked.
                self._queue = [replace(s, password=job.password) for s in self._queue]
            return
        if self._total > 1:
            self._show_summary()
            return
        name = html.escape(dest.name)
        if self.mode == ENCRYPT:
            text = (f"Done. Encrypted to <b>{name}</b>. The original file "
                    f"is unchanged. Before deleting it, use Verify to check the new file opens, "
                    f"and keep the password somewhere safe.")
        elif self.mode == TEST:
            text = (f"<b>{name}</b> is intact: the password is right and the file hasn't "
                    f"been damaged or changed since it was encrypted.")
        else:
            text = f"Done. Decrypted to <b>{name}</b>."
        text += self._motw_note()
        self._show(text, "ok")
        self._after_success()

    def _after_success(self) -> None:
        self.open_folder.setVisible(self.last_output is not None and self.mode != TEST)
        if self._verify_from is not None:
            return                     # keep the password: decrypting is likely next
        self.enc_password.clear()
        self.enc_confirm.clear()
        self.dec_password.clear()
        self.understand.setChecked(False)

    def _motw_note(self) -> str:
        if not self._motw_failed:
            return ""
        names = ", ".join(html.escape(n) for n in self._motw_failed)
        return (f"<br>Windows' \"downloaded from the internet\" mark couldn't be copied to "
                f"{names} (the drive may not support it). Be careful opening it.")

    def _failure_text(self, failure: Failure) -> str:
        if self.mode == TEST and failure.kind == "corrupted":
            return ("This file is damaged or has been changed since it was encrypted. Your "
                    "password was right. If you have another copy of the encrypted file, "
                    "verify that one.")
        return failure.message

    def _on_failed(self, failure: Failure) -> None:
        job = self.job
        if self._total <= 1:
            self._show(self._failure_text(failure),
                       "info" if failure.kind == "cancelled" else "error")
        else:
            name = job.spec.src.name if job is not None else "?"
            self._problems.append(f"{name}: {self._failure_text(failure)}")
            if failure.kind in ("cancelled", "wrong_key"):
                # Stop here: a cancel means stop, and a password that failed on one
                # file after every retry won't open the rest either.
                self._not_run = [s.src.name for s in self._queue]
                self._queue = []
            if not self._queue:
                self._show_summary()
        if failure.kind == "wrong_key" and self.mode in (DECRYPT, TEST):
            self.dec_password.selectAll()
            self.dec_password.setFocus()

    def _show_summary(self) -> None:
        verb = _VERBS[self.mode][2]
        n, ok = self._total, len(self._done)
        if self.mode == TEST and ok == n:
            text = (f"All {n} files are intact: the password is right and none of them was "
                    f"damaged or changed since it was encrypted.")
        elif ok == n:
            text = f"Done. All {n} files {verb}."
            if self.mode == ENCRYPT:
                text += " The originals are unchanged."
        else:
            text = f"{ok} of {n} files {verb}."
        for line in self._problems:
            text += f"<br>&bull; {html.escape(line)}"
        if self._not_run:
            text += (f"<br>Not started: {html.escape(', '.join(self._not_run))}.")
        text += self._motw_note()
        self._show(text, "ok" if ok == n else "error")
        if ok == n:
            self._after_success()
        elif ok:
            self.open_folder.setVisible(self.mode != TEST and self.last_output is not None)

    def _on_finished(self) -> None:
        job = self.job
        self.job = None
        self.cancel_button.setEnabled(True)
        if job is not None:
            job.deleteLater()
        if self._queue:
            self.run_job(self._queue.pop(0), _continuing=True)
            return
        self._end_verify()
        self._refresh()
        if self._pending is not None:
            action, paths = self._pending
            self._pending = None
            self._listed_action = None
            summary = (self.status.text(), self.status.property("kind"))
            self.open_request(action, paths)
            if summary[0] and not self.status.text():
                self._show(summary[0], summary[1] or "info")

    def _open_output_folder(self) -> None:
        if self.last_output is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.fspath(self.last_output.parent)))

    def closeEvent(self, event) -> None:
        if self.job is not None:
            if not self.confirm("Stop?", "filecrypt is still working. Stop and close? "
                                         "No partial file will be left behind."):
                event.ignore()
                return
            job = self.job
            job.cancel()
            job.wait()
        event.accept()
