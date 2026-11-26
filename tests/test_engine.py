"""The UI-neutral engine shared by the CLI and future front-ends."""

import os
import subprocess
import sys

import pytest

from filecrypt import container, engine, sources
from filecrypt.container import AuthenticationError, FormatError
from filecrypt.engine import (Cancelled, EncryptOptions, ExpensiveKDFError, OutputExistsError,
                              SameFileError)
from filecrypt.kdf import ARGON2ID, HKDF, SCRYPT, Argon2Params, Secret

PW = Secret(b"a perfectly fine passphrase", "passphrase")
KEY = Secret(bytes(range(32)), "key")
FAST = EncryptOptions(argon=Argon2Params(19 * 1024, 2, 1))
DATA = os.urandom(300_000)


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "doc.bin").write_bytes(DATA)

    def boom(prompt=""):
        raise AssertionError("the engine must never prompt")
    monkeypatch.setattr(sources.getpass, "getpass", boom)
    return tmp_path


def names(d):
    return sorted(p.name for p in d.iterdir())


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, done, total):
        self.calls.append((done, total))


# --- round trips --------------------------------------------------------------

def test_encrypt_decrypt_round_trip(work, capsys):
    out = engine.encrypt_file(work / "doc.bin", work / "doc.bin.fcx", PW, options=FAST)
    assert out == work / "doc.bin.fcx"
    back = engine.decrypt_file(out, work / "back.bin", PW)
    assert back.read_bytes() == DATA
    assert capsys.readouterr() == ("", "")       # the engine never prints


def test_keys_use_hkdf(work):
    engine.encrypt_file(work / "doc.bin", work / "k.fcx", KEY)
    assert engine.inspect_file(work / "k.fcx").kdf_id == HKDF
    assert engine.decrypt_file(work / "k.fcx", work / "b.bin", KEY).read_bytes() == DATA


def test_default_output_names():
    assert engine.default_encrypt_output("a/report.pdf") == engine.Path("a/report.pdf.fcx")
    assert engine.default_decrypt_output("a/report.pdf.fcx") == engine.Path("a/report.pdf")
    assert engine.default_decrypt_output("a/report.PDF.FCX") == engine.Path("a/report.PDF")
    assert engine.default_decrypt_output("a/blob.bin") is None


@pytest.mark.requires_argon2
def test_inspect_file(work):
    engine.encrypt_file(work / "doc.bin", work / "p.fcx", PW, options=FAST)
    info = engine.inspect_file(work / "p.fcx")
    assert info.kdf_id == ARGON2ID and info.kdf_name == "argon2id"
    assert info.needs == "passphrase"
    assert info.kdf_memory == 19 * 1024**2 and info.kdf_passes == 2
    assert info.chunk_size == container.DEFAULT_CHUNK_SIZE
    engine.encrypt_file(work / "doc.bin", work / "k.fcx", KEY)
    assert engine.inspect_file(work / "k.fcx").needs == "key"
    with pytest.raises(FormatError):
        engine.inspect_file(work / "doc.bin")


# --- lazy secrets: nothing is asked for until checks pass -----------------------

def test_secret_provider_called_once(work):
    calls = []
    engine.encrypt_file(work / "doc.bin", work / "x.fcx", lambda: calls.append(1) or PW, options=FAST)
    engine.decrypt_file(work / "x.fcx", work / "x.bin", lambda: calls.append(2) or PW)
    assert calls == [1, 2]


def test_secret_not_requested_when_output_exists(work):
    (work / "taken.fcx").write_bytes(b"keep")
    with pytest.raises(OutputExistsError):
        engine.encrypt_file(work / "doc.bin", work / "taken.fcx", lambda: pytest.fail("asked"))
    assert (work / "taken.fcx").read_bytes() == b"keep"


def test_secret_not_requested_for_non_fcx_input(work):
    with pytest.raises(FormatError):
        engine.decrypt_file(work / "doc.bin", work / "x", lambda: pytest.fail("asked"))


def test_output_exists_error_is_a_file_exists_error():
    assert issubclass(OutputExistsError, FileExistsError)


def test_force_overwrites(work):
    (work / "o.fcx").write_bytes(b"old")
    engine.encrypt_file(work / "doc.bin", work / "o.fcx", KEY, force=True)
    assert (work / "o.fcx").read_bytes()[:4] == b"FCX1"


def test_same_file_rejected(work):
    with pytest.raises(SameFileError):
        engine.encrypt_file(work / "doc.bin", work / "doc.bin", KEY, force=True)
    assert (work / "doc.bin").read_bytes() == DATA


def test_missing_input(work):
    with pytest.raises(engine.InputError, match="nope"):
        engine.encrypt_file(work / "nope", work / "nope.fcx", KEY)


def test_wrong_key_leaves_nothing(work):
    engine.encrypt_file(work / "doc.bin", work / "d.fcx", KEY)
    before = names(work)
    with pytest.raises(AuthenticationError):
        engine.decrypt_file(work / "d.fcx", work / "out.bin", Secret(b"\x01" * 32, "key"))
    assert names(work) == before


# --- progress -----------------------------------------------------------------

def check_progress(rec, total):
    assert rec.calls, "no progress reported"
    dones = [d for d, _ in rec.calls]
    assert dones == sorted(dones)
    assert all(t == total for _, t in rec.calls)
    assert dones[-1] == total


def test_encrypt_progress(work):
    rec = Recorder()
    engine.encrypt_file(work / "doc.bin", work / "p.fcx", KEY, progress=rec)
    check_progress(rec, len(DATA))
    assert len(rec.calls) >= 4               # several chunks, not one jump


def test_decrypt_progress(work):
    engine.encrypt_file(work / "doc.bin", work / "p.fcx", KEY)
    body = os.path.getsize(work / "p.fcx") - engine.inspect_file(work / "p.fcx").header_len
    rec = Recorder()
    engine.decrypt_file(work / "p.fcx", work / "b.bin", KEY, progress=rec)
    check_progress(rec, body)


def test_empty_file_progress(work):
    (work / "empty").write_bytes(b"")
    rec = Recorder()
    engine.encrypt_file(work / "empty", work / "e.fcx", KEY, progress=rec)
    assert rec.calls[-1] == (0, 0)


# --- notices --------------------------------------------------------------------

def test_short_passphrase_notice(work):
    notes = []
    engine.encrypt_file(work / "doc.bin", work / "s.fcx", Secret(b"short", "passphrase"),
                        options=FAST, notify=notes.append)
    assert any("12" in n for n in notes)


def test_scrypt_fallback_notice(work, monkeypatch):
    from filecrypt import kdf
    monkeypatch.setattr(kdf, "argon2_available", lambda: False)
    notes = []
    engine.encrypt_file(work / "doc.bin", work / "s.fcx", PW, notify=notes.append)
    assert engine.inspect_file(work / "s.fcx").kdf_id == SCRYPT
    assert any("argon2-cffi" in n for n in notes)


@pytest.mark.requires_argon2
def test_short_key_rejected_unless_passphrase_mode(work):
    from filecrypt.kdf import KDFError
    weak = Secret(b"x" * 20, "key")
    with pytest.raises(KDFError):
        engine.encrypt_file(work / "doc.bin", work / "w.fcx", weak)
    opts = EncryptOptions(argon=FAST.argon, keyfile_is_passphrase=True)
    engine.encrypt_file(work / "doc.bin", work / "w.fcx", weak, options=opts)
    assert engine.inspect_file(work / "w.fcx").kdf_id == ARGON2ID


# --- costly KDF settings from an unauthenticated header -------------------------

@pytest.fixture
def heavy(work):
    engine.encrypt_file(work / "doc.bin", work / "h.fcx", PW, options=FAST)
    blob = bytearray((work / "h.fcx").read_bytes())
    blob[8:17] = Argon2Params(2048 * 1024, 2, 1).encode()
    (work / "h.fcx").write_bytes(bytes(blob))
    return work / "h.fcx"


@pytest.fixture
def fake_derive(monkeypatch):
    from filecrypt import kdf
    calls = []
    monkeypatch.setattr(kdf, "derive_kek", lambda *a: calls.append(a[0]) or b"\x00" * 32)
    return calls


@pytest.mark.requires_argon2
def test_expensive_refused_without_confirm(heavy, fake_derive):
    with pytest.raises(ExpensiveKDFError) as e:
        engine.decrypt_file(heavy, heavy.with_name("o"), lambda: pytest.fail("asked"))
    assert "2048 MiB" in e.value.reason and e.value.limit > 0
    assert fake_derive == []


def test_expensive_declined(heavy, fake_derive):
    with pytest.raises(Cancelled):
        engine.decrypt_file(heavy, heavy.with_name("o"), lambda: pytest.fail("asked"),
                            confirm_expensive=lambda reason: False)
    assert fake_derive == []


@pytest.mark.requires_argon2
def test_expensive_accepted(heavy, fake_derive):
    asked = []
    with pytest.raises(AuthenticationError):          # fake KEK
        engine.decrypt_file(heavy, heavy.with_name("o"), PW,
                            confirm_expensive=lambda reason: asked.append(reason) or True)
    assert len(asked) == 1 and fake_derive == [ARGON2ID]


@pytest.mark.requires_argon2
def test_expensive_within_explicit_limit(heavy, fake_derive):
    with pytest.raises(AuthenticationError):
        engine.decrypt_file(heavy, heavy.with_name("o"), PW, kdf_memory_limit=4096 * 1024**2)
    assert fake_derive == [ARGON2ID]


# --- rekey ----------------------------------------------------------------------

def test_rekey_in_place_keeps_body(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", PW, options=FAST)
    old = (work / "r.fcx").read_bytes()
    old_len = engine.inspect_file(work / "r.fcx").header_len
    rec = Recorder()
    out = engine.rekey_file(work / "r.fcx", PW, KEY, progress=rec)
    assert out == work / "r.fcx"
    info = engine.inspect_file(out)
    assert info.kdf_id == HKDF
    assert out.read_bytes()[info.header_len:] == old[old_len:]
    check_progress(rec, len(old) - old_len)
    assert engine.decrypt_file(out, work / "b.bin", KEY).read_bytes() == DATA
    assert names(work) == ["b.bin", "doc.bin", "r.fcx"]


def test_rekey_to_other_file_respects_force(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", KEY)
    (work / "other.fcx").write_bytes(b"keep")
    with pytest.raises(OutputExistsError):
        engine.rekey_file(work / "r.fcx", KEY, PW, dest=work / "other.fcx", options=FAST)
    engine.rekey_file(work / "r.fcx", KEY, PW, dest=work / "other.fcx", options=FAST, force=True)
    assert engine.decrypt_file(work / "other.fcx", work / "b.bin", PW).read_bytes() == DATA


def test_rekey_wrong_old_key_untouched(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", KEY)
    before = (work / "r.fcx").read_bytes()
    with pytest.raises(AuthenticationError):
        engine.rekey_file(work / "r.fcx", Secret(b"\x02" * 32, "key"),
                          lambda: pytest.fail("new key asked before old key worked"))
    assert (work / "r.fcx").read_bytes() == before


def test_rotate_file_key_in_place(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", PW, options=FAST)
    old = (work / "r.fcx").read_bytes()
    old_h = container.read_header(open(work / "r.fcx", "rb"))
    rec = Recorder()
    out = engine.rekey_file(work / "r.fcx", PW, KEY, progress=rec, rotate_file_key=True)
    assert out == work / "r.fcx"
    new = out.read_bytes()
    with open(out, "rb") as f:
        new_h = container.read_header(f)
    assert new_h.kdf_id == HKDF
    assert new_h.nonce_prefix != old_h.nonce_prefix
    assert new[new_h.header_len:] != old[old_h.header_len:]
    check_progress(rec, len(old) - old_h.header_len)
    assert engine.decrypt_file(out, work / "b.bin", KEY).read_bytes() == DATA
    with pytest.raises(AuthenticationError):
        engine.decrypt_file(out, work / "c.bin", PW)
    assert names(work) == ["b.bin", "doc.bin", "r.fcx"]


def test_rotate_file_key_defeats_old_header(work):
    # The leak scenario: an attacker has the old passphrase and the old header.
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", PW, options=FAST)
    old = (work / "r.fcx").read_bytes()
    old_h = container.read_header(open(work / "r.fcx", "rb"))
    old_key = engine._unwrap(old_h, PW)
    engine.rekey_file(work / "r.fcx", PW, KEY, rotate_file_key=True)
    new = (work / "r.fcx").read_bytes()
    with open(work / "r.fcx", "rb") as f:
        new_h = container.read_header(f)
    import io
    src = io.BytesIO(new)
    src.seek(new_h.header_len)
    with pytest.raises(container.CorruptedFileError):
        container.decrypt_body(new_h, old_key, src, io.BytesIO())
    # and splicing the old header onto the new body fails too
    spliced = old[:old_h.header_len] + new[new_h.header_len:]
    (work / "s.fcx").write_bytes(spliced)
    with pytest.raises(container.CorruptedFileError):
        engine.decrypt_file(work / "s.fcx", work / "s.bin", PW)
    assert not (work / "s.bin").exists()


def test_rotate_file_key_tampered_body_writes_nothing(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", KEY)
    blob = bytearray((work / "r.fcx").read_bytes())
    blob[len(blob) // 2] ^= 1
    (work / "r.fcx").write_bytes(bytes(blob))
    with pytest.raises(container.CorruptedFileError):
        engine.rekey_file(work / "r.fcx", KEY, PW, options=FAST, rotate_file_key=True)
    assert (work / "r.fcx").read_bytes() == bytes(blob)       # original untouched
    with pytest.raises(container.CorruptedFileError):
        engine.rekey_file(work / "r.fcx", KEY, PW, dest=work / "new.fcx", options=FAST,
                          rotate_file_key=True)
    assert names(work) == ["doc.bin", "r.fcx"]                # no output, no .part


def test_rotate_file_key_to_other_file(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", KEY)
    before = (work / "r.fcx").read_bytes()
    engine.rekey_file(work / "r.fcx", KEY, KEY, dest=work / "new.fcx", rotate_file_key=True)
    assert (work / "r.fcx").read_bytes() == before
    assert engine.decrypt_file(work / "new.fcx", work / "b.bin", KEY).read_bytes() == DATA


def test_rotate_file_key_cancel_leaves_original(work):
    engine.encrypt_file(work / "doc.bin", work / "r.fcx", KEY)
    before = (work / "r.fcx").read_bytes()
    token = engine.CancelToken()

    def progress(done, total):
        if done > total // 2:
            token.cancel()
    with pytest.raises(Cancelled):
        engine.rekey_file(work / "r.fcx", KEY, PW, options=FAST, progress=progress,
                          cancel=token, rotate_file_key=True)
    assert (work / "r.fcx").read_bytes() == before
    assert names(work) == ["doc.bin", "r.fcx"]


# --- stale partial files ----------------------------------------------------------

def test_stale_parts(work):
    (work / ".doc.bin.k3j9.part").write_bytes(b"x")
    (work / ".other.k3j9.part").write_bytes(b"x")
    assert [p.name for p in engine.stale_parts(work / "doc.bin")] == [".doc.bin.k3j9.part"]


# --- layering -----------------------------------------------------------------------

def test_engine_does_not_import_cli():
    code = "import sys, filecrypt.engine; print('filecrypt.cli' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"
