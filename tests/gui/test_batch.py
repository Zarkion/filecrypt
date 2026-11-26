"""Several files in one window (Explorer launches, drag and drop) and the Test verb."""

import os

import pytest

pytest.importorskip("pytestqt", reason="GUI tests need pytest-qt (pip install filecrypt[test-gui])")
pytest.importorskip("PySide6.QtWidgets", reason="GUI tests need PySide6")

from filecrypt import _motw, engine, kdf  # noqa: E402
from filecrypt.engine import EncryptOptions  # noqa: E402
from filecrypt.gui import window as window_mod  # noqa: E402
from filecrypt.gui.batch import TEST  # noqa: E402
from filecrypt.gui.window import MainWindow  # noqa: E402
from filecrypt.gui.worker import DECRYPT, ENCRYPT  # noqa: E402
from filecrypt.kdf import Argon2Params, Secret  # noqa: E402

pytestmark = pytest.mark.skipif(not kdf.argon2_available(),
                                reason="the window tests use fast Argon2id settings")

PW = "copper lantern violet harbor"
FAST = Argon2Params(19 * 1024, 2, 1)
WAIT = 60_000


@pytest.fixture
def win(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    w.confirm = lambda title, text: pytest.fail(f"unexpected confirm: {title}")
    w.ask_password_again = lambda attempt: pytest.fail("unexpected password re-ask")
    w.choose_save_path = lambda suggested: pytest.fail("unexpected save dialog")
    w.argon_memory.setValue(19)
    w.argon_iterations.setValue(2)
    w.argon_parallelism.setValue(1)
    yield w
    if w.job is not None:
        w.job.cancel()
        w.job.wait()


def plain(tmp_path, *names):
    out = []
    for n in names:
        p = tmp_path / n
        p.write_bytes(os.urandom(5000) + n.encode())
        out.append(p)
    return out


def encrypted(tmp_path, name, password=PW, data=None):
    src = tmp_path / name
    src.write_bytes(data if data is not None else name.encode() * 1000)
    dest = engine.encrypt_file(src, tmp_path / (name + ".fcx"),
                               Secret(password.encode(), "passphrase"),
                               options=EncryptOptions(argon=FAST))
    src.unlink()
    return dest


def run(qtbot, w):
    assert w.action.isEnabled(), w.ready_reason()
    w.action.click()
    qtbot.waitUntil(lambda: w.job is None and not w._queue, timeout=WAIT)


def status(w):
    return w.status.property("kind"), w.status.text()


def test_encrypt_request_lists_every_file(win, tmp_path):
    files = plain(tmp_path, "a.txt", "b.txt", "c.txt")
    win.open_request("encrypt", [str(p) for p in files])
    assert win.mode == ENCRYPT and win.batch == files
    assert win.drop.title.text() == "3 files"
    assert [win.batch_list.item(i).text() for i in range(3)] == [os.fspath(p) for p in files]
    assert win.batch_list.isVisibleTo(win)


def test_requests_for_the_same_action_are_merged(win, tmp_path):
    a, b = plain(tmp_path, "a.txt", "b.txt")
    win.open_request("encrypt", [str(a)])
    assert win.batch == [a]
    win.open_request("encrypt", [str(b)])
    win.open_request("encrypt", [str(a)])       # duplicates are dropped
    assert win.batch == [a, b]


def test_a_different_action_replaces_the_list(win, tmp_path):
    a, = plain(tmp_path, "a.txt")
    f = encrypted(tmp_path, "b.txt")
    win.open_request("encrypt", [str(a)])
    win.open_request("decrypt", [str(f)])
    assert win.mode == DECRYPT and win.batch == [f]


def test_encrypt_verb_on_an_fcx_file_encrypts_it(win, tmp_path):
    f = encrypted(tmp_path, "a.txt")
    win.open_request("encrypt", [str(f)])
    assert win.mode == ENCRYPT and win.batch == [f]


def test_batch_encrypt_with_one_password(win, qtbot, tmp_path):
    files = plain(tmp_path, "a.txt", "b.txt", "c.txt")
    win.open_request("encrypt", files)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)
    assert status(win)[0] == "ok", status(win)
    assert "All 3 files encrypted" in status(win)[1]
    for p in files:
        out = engine.default_encrypt_output(p)
        back = tmp_path / ("back-" + p.name)
        engine.decrypt_file(out, back, Secret(PW.encode(), "passphrase"))
        assert back.read_bytes() == p.read_bytes()
    assert win.enc_password.text() == ""


def test_batch_decrypt_keeps_going_after_a_damaged_file(win, qtbot, tmp_path):
    good1 = encrypted(tmp_path, "one.txt")
    bad = encrypted(tmp_path, "two.txt")
    good2 = encrypted(tmp_path, "three.txt")
    raw = bytearray(bad.read_bytes())
    raw[-5] ^= 1
    bad.write_bytes(bytes(raw))
    win.open_request("decrypt", [good1, bad, good2])
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "2 of 3 files decrypted" in text and "two.txt.fcx" in text
    assert (tmp_path / "one.txt").read_bytes() == b"one.txt" * 1000
    assert (tmp_path / "three.txt").read_bytes() == b"three.txt" * 1000
    assert not (tmp_path / "two.txt").exists()


def test_retyped_password_is_used_for_the_rest(win, qtbot, tmp_path):
    files = [encrypted(tmp_path, n) for n in ("a.txt", "b.txt")]
    asked = []
    win.ask_password_again = lambda attempt: asked.append(attempt) or PW
    win.open_request("decrypt", files)
    win.dec_password.setText("not it")
    run(qtbot, win)
    assert status(win)[0] == "ok", status(win)
    assert asked == [1]          # only the first file had to ask
    assert (tmp_path / "b.txt").exists()


def test_wrong_password_stops_the_batch(win, qtbot, tmp_path):
    files = [encrypted(tmp_path, n) for n in ("a.txt", "b.txt")]
    win.ask_password_again = lambda attempt: None      # the person gives up
    win.open_request("decrypt", files)
    win.dec_password.setText("not it")
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "0 of 2" in text and "Not started: b.txt.fcx" in text


def test_existing_outputs_are_confirmed_once(win, qtbot, tmp_path):
    files = plain(tmp_path, "a.txt", "b.txt")
    for p in files:
        engine.default_encrypt_output(p).write_bytes(b"old")
    asked = []
    win.confirm = lambda title, text: asked.append((title, text)) or True
    win.open_request("encrypt", files)
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)
    assert [t for t, _ in asked] == ["Replace files?"]
    assert "a.txt.fcx" in asked[0][1] and "b.txt.fcx" in asked[0][1]
    assert status(win)[0] == "ok", status(win)


def test_mixed_files_are_refused(win, tmp_path):
    a, = plain(tmp_path, "a.txt")
    f = encrypted(tmp_path, "b.txt")
    win.open_request("open", [a, f])
    assert win.src is None and status(win)[0] == "error"


def test_non_fcx_files_are_left_out_of_a_decrypt(win, tmp_path):
    a, = plain(tmp_path, "a.txt")
    f = encrypted(tmp_path, "b.txt")
    win.open_request("decrypt", [a, f])
    assert win.batch == [f]
    assert status(win)[0] == "info" and "a.txt" in status(win)[1]


def test_keyfile_and_password_files_are_not_mixed(win, tmp_path):
    src = tmp_path / "x.txt"
    src.write_bytes(b"x")
    by_key = engine.encrypt_file(src, tmp_path / "x.txt.fcx", Secret(os.urandom(32), "key"))
    by_pw = encrypted(tmp_path, "y.txt")
    win.open_request("decrypt", [by_key, by_pw])
    assert win.src is None and "keyfile" in status(win)[1]


def test_requests_while_busy_wait_for_the_end(win, qtbot, tmp_path):
    a, b = plain(tmp_path, "a.txt", "b.txt")
    win.open_request("encrypt", [a])
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    win.action.click()
    assert win.job is not None
    win.open_request("encrypt", [b])            # arrives while a.txt is encrypting
    assert win.batch == [a]
    qtbot.waitUntil(lambda: win.job is None, timeout=WAIT)
    assert win.batch == [b] and win.mode == ENCRYPT


# --- Test (verify without writing) -------------------------------------------------

def test_test_verb_reports_an_intact_file(win, qtbot, tmp_path):
    f = encrypted(tmp_path, "a.txt")
    before = sorted(p.name for p in tmp_path.iterdir())
    win.open_request("test", [f])
    assert win.mode == TEST and win.action.text() == "Test"
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "ok" and "intact" in text, text
    assert sorted(p.name for p in tmp_path.iterdir()) == before     # nothing written


def test_test_verb_finds_damage(win, qtbot, tmp_path):
    f = encrypted(tmp_path, "a.txt", data=os.urandom(200_000))
    raw = bytearray(f.read_bytes())
    raw[len(raw) // 2] ^= 0x40
    f.write_bytes(bytes(raw))
    win.open_request("test", [f])
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "error" and "damaged" in text and "password was right" in text


def test_test_verb_wrong_password(win, qtbot, tmp_path):
    f = encrypted(tmp_path, "a.txt")
    asked = []
    win.ask_password_again = lambda attempt: asked.append(attempt) or None   # gives up
    win.open_request("test", [f])
    win.dec_password.setText("nope")
    run(qtbot, win)
    assert asked == [1]
    assert status(win) == ("info", "Cancelled. No file was written.")


def test_test_several_files(win, qtbot, tmp_path):
    files = [encrypted(tmp_path, n) for n in ("a.txt", "b.txt")]
    win.open_request("test", files)
    win.dec_password.setText(PW)
    run(qtbot, win)
    assert status(win)[0] == "ok" and "All 2 files are intact" in status(win)[1]


# --- Mark of the Web ---------------------------------------------------------------

def test_mark_of_the_web_is_copied_on_encrypt_and_decrypt(win, qtbot, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(window_mod._motw, "copy_zone_identifier",
                        lambda src, dest: calls.append((src.name, dest.name)) or True)
    a, = plain(tmp_path, "a.txt")
    win.open_request("encrypt", [a])
    win.enc_password.setText(PW)
    win.enc_confirm.setText(PW)
    win.understand.setChecked(True)
    run(qtbot, win)
    a.unlink()
    win.open_request("decrypt", [engine.default_encrypt_output(a)])
    win.dec_password.setText(PW)
    run(qtbot, win)
    assert calls == [("a.txt", "a.txt.fcx"), ("a.txt.fcx", "a.txt")]


def test_mark_of_the_web_failure_is_reported(win, qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(window_mod._motw, "copy_zone_identifier", lambda src, dest: False)
    f = encrypted(tmp_path, "a.txt")
    win.open_request("decrypt", [f])
    win.dec_password.setText(PW)
    run(qtbot, win)
    kind, text = status(win)
    assert kind == "ok" and "downloaded from the internet" in text


def test_motw_module_is_the_one_the_window_uses():
    assert window_mod._motw is _motw
