"""The desktop window, driven offscreen with pytest-qt."""

import os
from pathlib import Path

import pytest

pytest.importorskip("pytestqt", reason="GUI tests need pytest-qt (pip install filecrypt[test-gui])")
pytest.importorskip("PySide6.QtWidgets", reason="GUI tests need PySide6")

from filecrypt import engine, kdf, keygen  # noqa: E402
from filecrypt.engine import EncryptOptions  # noqa: E402
from filecrypt.gui import worker  # noqa: E402
from filecrypt.gui.window import MainWindow  # noqa: E402
from filecrypt.gui.worker import DECRYPT, ENCRYPT, Job, JobSpec  # noqa: E402
from filecrypt.kdf import Argon2Params, Secret  # noqa: E402

pytestmark = pytest.mark.skipif(not kdf.argon2_available(),
                                reason="the window tests use fast Argon2id settings")

PW = "copper lantern violet harbor"
FAST = Argon2Params(19 * 1024, 2, 1)
DATA = os.urandom(300_000)
WAIT = 60_000


@pytest.fixture
def win(qtbot, tmp_path, monkeypatch):
    w = MainWindow()
    qtbot.addWidget(w)
    # No real dialogs in tests: fail loudly if one is reached unexpectedly.
    w.confirm = lambda title, text: pytest.fail(f"unexpected confirm: {title}")
    w.ask_password_again = lambda attempt: pytest.fail("unexpected password re-ask")
    w.choose_save_path = lambda suggested: pytest.fail("unexpected save dialog")
    # Fast Argon2id so tests don't spend 64 MiB x 3 passes each time.
    w.argon_memory.setValue(19)
    w.argon_iterations.setValue(2)
    w.argon_parallelism.setValue(1)
    yield w
    if w.job is not None:
        w.job.cancel()
        w.job.wait()


@pytest.fixture
def doc(tmp_path):
    p = tmp_path / "report.pdf"
    p.write_bytes(DATA)
    return p


def encrypted(tmp_path, data=DATA, password=PW, name="secret.txt"):
    src = tmp_path / "plain.tmp"
    src.write_bytes(data)
    # Encrypt under a safe name, then rename: the engine itself refuses to
    # write hostile names, but an attacker can still hand us one.
    out = engine.encrypt_file(src, tmp_path / "enc.tmp.fcx",
                              Secret(password.encode(), "passphrase"),
                              options=EncryptOptions(argon=FAST))
    src.unlink()
    return out.rename(tmp_path / (name + ".fcx"))


def run(qtbot, w):
    assert w.action.isEnabled(), w.ready_reason()
    w.action.click()
    assert w.job is not None
    qtbot.waitUntil(lambda: w.job is None, timeout=WAIT)


def status(w):
    return w.status.property("kind"), w.status.text()


def leftovers(d):
    return [p.name for p in Path(d).iterdir() if p.name.endswith(".part")]


# --- encrypting ---------------------------------------------------------------------

def test_encrypt_mode_and_button_state(win, doc):
    win.set_file(doc)
    assert win.mode == ENCRYPT and win.action.text() == "Encrypt"
    assert not win.action.isEnabled()
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW + "x")
    win.understand.setChecked(True)
    assert not win.action.isEnabled()
    assert "match" in win.ready_reason()
    win.enc_confirm.setText(PW)
    assert win.action.isEnabled()
    win.understand.setChecked(False)
    assert not win.action.isEnabled()
    assert "warning" in win.ready_reason()


def test_loss_warning_is_shown(win, doc):
    win.set_file(doc)
    assert "can't be opened again" in win.warning_label.text()
    assert win.warning_label.isVisibleTo(win)


def test_strength_meter_follows_password(win, doc):
    win.set_file(doc)
    win.enc_password.setText("password")
    assert win.meter.value() == 0 and win.meter_label.text() == "Very weak"
    win.enc_password.setText(PW)
    assert win.meter.value() >= 3


def test_encrypt_then_decrypt_round_trip(win, qtbot, doc, tmp_path):
    win.set_file(doc)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)
    out = tmp_path / "report.pdf.fcx"
    assert status(win)[0] == "ok", status(win)
    assert out.exists() and doc.read_bytes() == DATA
    assert win.enc_password.text() == ""          # passwords aren't kept around
    info = engine.inspect_file(out)
    assert info.kdf_memory == 19 * 1024 * 1024 and info.kdf_passes == 2

    doc.unlink()
    win.set_file(out)
    assert win.mode == DECRYPT and win.action.text() == "Decrypt"
    win.dec_password.setText(PW)
    run(qtbot, win)
    assert status(win)[0] == "ok", status(win)
    assert doc.read_bytes() == DATA
    assert leftovers(tmp_path) == []


def test_default_argon_settings_are_not_passed(win):
    win._reset_argon()
    assert win._argon() is None
    win.argon_memory.setValue(128)
    assert win._argon() == Argon2Params(128 * 1024, 3, 4)


def test_weak_password_needs_confirmation(win, qtbot, doc, tmp_path):
    asked = []
    win.confirm = lambda title, text: asked.append(title) or False
    win.set_file(doc)
    win.enc_password.setText("abc")
    win.enc_confirm.setText("abc")
    win.understand.setChecked(True)
    win.action.click()
    assert asked == ["Weak password"]
    assert win.job is None and not (tmp_path / "report.pdf.fcx").exists()


def test_existing_output_asks_before_replacing(win, qtbot, doc, tmp_path):
    out = tmp_path / "report.pdf.fcx"
    out.write_bytes(b"old")
    answers = [False, True]
    win.confirm = lambda title, text: answers.pop(0)
    win.set_file(doc)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    win.action.click()
    assert win.job is None and out.read_bytes() == b"old"     # said no
    run(qtbot, win)                                           # said yes
    assert status(win)[0] == "ok"
    assert engine.inspect_file(out).needs == "passphrase"


def test_cancel_during_encrypt_leaves_nothing(win, qtbot, tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(8 * 1024 * 1024))
    win.set_file(big)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    win.action.click()
    win.job.progress.connect(lambda *a: win.cancel())
    qtbot.waitUntil(lambda: win.job is None, timeout=WAIT)
    kind, text = status(win)
    assert "Cancelled" in text, text
    assert not (tmp_path / "big.bin.fcx").exists()
    assert leftovers(tmp_path) == []
    assert win.action.isEnabled()                 # ready to try again


def test_multiple_files_dropped_become_a_batch(win, tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("a")
    b.write_text("b")
    win.files_dropped([a, b])
    assert win.src == a and win.batch == [a, b]
    assert win.mode == ENCRYPT
    assert win.batch_list.count() == 2


def test_folder_is_refused(win, tmp_path):
    win.set_file(tmp_path)
    assert win.src is None and status(win)[0] == "error"


# --- decrypting ---------------------------------------------------------------------

def test_wrong_password_asks_again_then_succeeds(win, qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    tries = []
    win.ask_password_again = lambda attempt: tries.append(attempt) or (
        "still wrong" if len(tries) == 1 else PW)
    win.set_file(fcx)
    win.dec_password.setText("wrong password")
    run(qtbot, win)
    assert tries == [1, 2]
    assert status(win)[0] == "ok", status(win)
    assert (tmp_path / "secret.txt").read_bytes() == DATA


def test_wrong_password_then_give_up(win, qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    win.ask_password_again = lambda attempt: None      # pressed Cancel on the re-ask
    win.set_file(fcx)
    win.dec_password.setText("wrong password")
    run(qtbot, win)
    kind, text = status(win)
    assert "Cancelled" in text
    assert not (tmp_path / "secret.txt").exists()


def test_damaged_file_is_not_called_a_wrong_password(win, qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    b = bytearray(fcx.read_bytes())
    b[-100] ^= 1                                        # damage the encrypted body
    fcx.write_bytes(bytes(b))
    win.set_file(fcx)
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "damaged" in text and "password was right" in text
    assert not (tmp_path / "secret.txt").exists()
    assert leftovers(tmp_path) == []


def test_damaged_header_named_fcx(win, tmp_path):
    bad = tmp_path / "junk.fcx"
    bad.write_bytes(b"not an fcx file at all")
    win.set_file(bad)
    assert win.src is None and status(win)[0] == "error"
    assert "isn't a file filecrypt can decrypt" in win.status.text()


def test_decrypt_name_without_fcx_asks_where_to_save(win, qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    odd = fcx.rename(tmp_path / "renamed.bin")
    target = tmp_path / "chosen.txt"
    win.choose_save_path = lambda suggested: target
    win.set_file(odd)
    assert win.mode == DECRYPT
    win.dec_password.setText(PW)
    run(qtbot, win)
    assert target.read_bytes() == DATA


def test_leftover_part_files_offered_for_deletion(win, qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    stale = tmp_path / ".secret.txt.abcd1234.part"
    stale.write_bytes(b"half a file")
    asked = []
    win.confirm = lambda title, text: asked.append(title) or True
    win.set_file(fcx)
    win.dec_password.setText(PW)
    run(qtbot, win)
    assert asked == ["Leftover files"]
    assert not stale.exists()
    assert status(win)[0] == "ok"


# --- keyfiles -----------------------------------------------------------------------

def test_keyfile_round_trip_and_wrong_keyfile(win, qtbot, doc, tmp_path):
    key = tmp_path / "my.key"
    keygen.write_keyfile(key, keygen.generate_key())
    win.set_file(doc)
    win.use_keyfile.setChecked(True)
    assert not win.enc_password.isEnabled()
    win.keyfile_path.setText(str(key))
    win.understand.setChecked(True)
    run(qtbot, win)
    out = tmp_path / "report.pdf.fcx"
    assert engine.inspect_file(out).needs == "key"

    # A fresh window sees the file needs a keyfile and opens Advanced for it.
    doc.unlink()
    win.use_keyfile.setChecked(False)
    win.keyfile_path.clear()
    win.set_file(out)
    assert win.needs_keyfile and win.use_keyfile.isChecked()
    assert win.advanced.isVisibleTo(win)
    assert not win.action.isEnabled()

    other = tmp_path / "other.key"
    keygen.write_keyfile(other, keygen.generate_key())
    win.keyfile_path.setText(str(other))
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "keyfile doesn't unlock" in text

    win.keyfile_path.setText(str(key))
    run(qtbot, win)
    assert doc.read_bytes() == DATA


# --- the worker on its own -----------------------------------------------------------

def test_cancel_while_waiting_for_password(qtbot, tmp_path):
    fcx = encrypted(tmp_path)
    job = Job(JobSpec(DECRYPT, fcx, tmp_path / "out.txt", password="wrong"))
    job.question.connect(lambda kind, payload: job.cancel())
    with qtbot.waitSignal(job.failed, timeout=WAIT) as blocker:
        job.start()
    assert blocker.args[0].kind == "cancelled"
    job.wait()
    assert not (tmp_path / "out.txt").exists()


def test_worker_reports_success(qtbot, doc, tmp_path):
    job = Job(JobSpec(ENCRYPT, doc, tmp_path / "x.fcx", password=PW, argon=FAST))
    seen = []
    job.progress.connect(lambda p, total: seen.append(p))
    with qtbot.waitSignal(job.succeeded, timeout=WAIT) as blocker:
        job.start()
    job.wait()
    assert blocker.args[0] == tmp_path / "x.fcx"
    assert seen and seen[-1] == 1000 and seen == sorted(seen)


RLO = "\u202e"


def test_window_refuses_a_disguised_decrypt_name(win, qtbot, tmp_path):
    # "invoice<RLO>fdp.exe" displays as "invoiceexe.pdf": the CLI refuses it, so must we.
    fcx = encrypted(tmp_path, name=f"invoice{RLO}fdp.exe")
    win.set_file(fcx)
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "unsafe name" in text and RLO not in text
    assert sorted(p.name for p in tmp_path.iterdir()) == [fcx.name]


def test_window_refuses_a_disguised_encrypt_name(win, qtbot, tmp_path):
    src = tmp_path / f"photo{RLO}gpj.exe"
    src.write_bytes(DATA)
    win.set_file(src)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)
    assert status(win)[0] == "error" and "unsafe name" in win.status.text()
    assert sorted(p.name for p in tmp_path.iterdir()) == [src.name]


@pytest.mark.parametrize("name", ["CON", "nul.txt", "notes.txt:hidden", "trailing."])
def test_worker_refuses_windows_unsafe_names(qtbot, tmp_path, monkeypatch, name):
    monkeypatch.setattr(engine, "_WINDOWS_NAMES", True)
    fcx = encrypted(tmp_path)
    job = Job(JobSpec(DECRYPT, fcx, tmp_path / name, password=PW))
    with qtbot.waitSignal(job.failed, timeout=WAIT) as blocker:
        job.start()
    job.wait()
    assert blocker.args[0].kind == "error" and "unsafe name" in blocker.args[0].message
    assert sorted(p.name for p in tmp_path.iterdir()) == [fcx.name]


@pytest.mark.parametrize("exc, kind", [
    (engine.Cancelled(), "cancelled"),
    (worker.WrongKeyError("x"), "wrong_key"),
    (worker.CorruptedFileError("x"), "corrupted"),
    (worker.FormatError("x"), "not_fcx"),
    (engine.OutputExistsError("a.txt"), "exists"),
    (engine.UnsafeOutputNameError("CON", "CON is a reserved Windows device name"), "error"),
    (kdf.KDFError("key is 3 bytes"), "error"),
    (PermissionError(13, "Permission denied", "a.txt"), "error"),
])
def test_classify(exc, kind, tmp_path):
    f = worker.classify(exc, JobSpec(DECRYPT, tmp_path / "a", tmp_path / "b"))
    assert f.kind == kind and f.message


def test_passphrase_secret_matches_cli_encoding():
    s = worker.passphrase_secret("café au lait")
    assert s.kind == "passphrase"
    assert s.value in ("café au lait".encode(), "café au lait".encode())


# --- Verify (check without writing) ----------------------------------------------------

def verify(qtbot, w):
    assert w.verify_button.isVisible() and w.verify_button.isEnabled(), w.ready_reason()
    w.verify_button.click()
    qtbot.waitUntil(lambda: w.job is None, timeout=WAIT)


def test_verify_button_only_for_encrypted_files(win, doc, tmp_path):
    win.show()
    win.set_file(doc)
    assert not win.verify_button.isVisible()
    win.set_file(encrypted(tmp_path))
    assert win.verify_button.isVisible() and not win.verify_button.isEnabled()
    win.dec_password.setText(PW)
    assert win.verify_button.isEnabled()


def test_verify_writes_nothing_and_keeps_decrypt_ready(win, qtbot, tmp_path):
    win.show()
    fcx = encrypted(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    win.set_file(fcx)
    win.dec_password.setText(PW)
    verify(qtbot, win)
    kind, text = status(win)
    assert kind == "ok" and "intact" in text, text
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    # Back to decrypting, password kept, so Decrypt works straight after.
    assert win.mode == DECRYPT and win.action.text() == "Decrypt"
    assert win.dec_password.text() == PW
    run(qtbot, win)
    assert (tmp_path / "secret.txt").read_bytes() == DATA


def test_verify_finds_damage(win, qtbot, tmp_path):
    win.show()
    fcx = encrypted(tmp_path)
    b = bytearray(fcx.read_bytes())
    b[-100] ^= 1
    fcx.write_bytes(bytes(b))
    win.set_file(fcx)
    win.dec_password.setText(PW)
    verify(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "damaged" in text and "password was right" in text
    assert win.mode == DECRYPT
    assert leftovers(tmp_path) == []


def test_verify_wrong_password(win, qtbot, tmp_path):
    win.show()
    asked = []
    win.ask_password_again = lambda attempt: asked.append(attempt)   # then Cancel
    win.set_file(encrypted(tmp_path))
    win.dec_password.setText("not it")
    verify(qtbot, win)
    assert asked and "Cancelled" in status(win)[1]
    assert win.mode == DECRYPT and not (tmp_path / "secret.txt").exists()


# --- "Check it opens" after encrypting ----------------------------------------------

def _encrypt_in_window(win, qtbot, doc):
    win.show()
    win.set_file(doc)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)


def test_check_it_opens_after_encrypting(win, qtbot, doc, tmp_path):
    _encrypt_in_window(win, qtbot, doc)
    kind, text = status(win)
    assert kind == "ok" and "Check it opens" in text, text
    assert win.check_button.isVisible()
    before = sorted(p.name for p in tmp_path.iterdir())
    win.check_button.click()
    qtbot.waitUntil(lambda: win.job is None, timeout=WAIT)
    kind, text = status(win)
    assert kind == "ok" and "safe to delete the original" in text, text
    assert sorted(p.name for p in tmp_path.iterdir()) == before   # nothing written
    assert win.mode == ENCRYPT and not win.check_button.isVisible()


def test_check_it_opens_warns_when_damaged(win, qtbot, doc, tmp_path):
    _encrypt_in_window(win, qtbot, doc)
    out = tmp_path / "report.pdf.fcx"
    b = bytearray(out.read_bytes())
    b[-100] ^= 1
    out.write_bytes(bytes(b))
    win.check_button.click()
    qtbot.waitUntil(lambda: win.job is None, timeout=WAIT)
    kind, text = status(win)
    assert kind == "error" and text.startswith("Don't delete the original"), text


def test_check_it_opens_goes_away_with_a_new_file(win, qtbot, doc, tmp_path):
    _encrypt_in_window(win, qtbot, doc)
    assert win.check_button.isVisible()
    win.set_file(encrypted(tmp_path))
    assert not win.check_button.isVisible() and win._check_specs == []


def test_check_it_opens_with_a_keyfile_as_password(win, qtbot, doc, tmp_path):
    key = tmp_path / "words.txt"
    key.write_bytes("café short".encode())   # text, not NFC
    win.show()
    win.set_file(doc)
    win.use_keyfile.setChecked(True)
    win.keyfile_path.setText(str(key))
    win.keyfile_is_passphrase.setChecked(True)
    win.understand.setChecked(True)
    run(qtbot, win)
    assert status(win)[0] == "ok", status(win)
    win.check_button.click()
    qtbot.waitUntil(lambda: win.job is None, timeout=WAIT)
    kind, text = status(win)
    assert kind == "ok" and "keep the keyfile" in text, text
    # The window now builds the same secret as the CLI's --keyfile-is-passphrase:
    # the keyfile's exact bytes, so the CLI's way of reading the keyfile opens it.
    from filecrypt import sources
    raw = sources.FileSource().get(str(key))
    assert raw.kind == "key" and raw.value == key.read_bytes()
    engine.verify_file(tmp_path / "report.pdf.fcx", raw)


# --- forgetting the password -------------------------------------------------------

def test_closing_forgets_the_password(win, qtbot, doc):
    _encrypt_in_window(win, qtbot, doc)
    assert win._check_specs and win._check_specs[0].password == PW
    win.show_password.setChecked(True)       # undo is only possible in plain-text mode
    win.dec_password.insert(PW)              # typed, so it is in the undo history
    win.close()
    assert win._check_specs == [] and win._queue == []
    for field in (win.enc_password, win.enc_confirm, win.dec_password):
        assert field.text() == ""
        field.undo()                         # Ctrl+Z must not bring it back
        assert field.text() == ""
