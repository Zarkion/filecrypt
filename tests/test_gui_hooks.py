"""Engine behaviour a GUI needs: clear failure kinds, password retry, cancel."""

import io
import os
import threading

import pytest

from filecrypt import cli, container, engine, kdf, sources
from filecrypt.container import (AuthenticationError, CorruptedFileError, FormatError,
                                 TrailingDataError, WrongKeyError)
from filecrypt.engine import CancelToken, Cancelled, EncryptOptions
from filecrypt.kdf import Argon2Params, Secret

PW = Secret(b"a perfectly fine passphrase", "passphrase")
BAD = Secret(b"not the right passphrase!", "passphrase")
KEY = Secret(bytes(range(32)), "key")
FAST = EncryptOptions(argon=Argon2Params(19 * 1024, 2, 1))
DATA = os.urandom(400_000)


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "doc.bin").write_bytes(DATA)
    return tmp_path


def names(d):
    return sorted(p.name for p in d.iterdir())


def flip(path, index):
    b = bytearray(path.read_bytes())
    b[index] ^= 1
    path.write_bytes(bytes(b))


# --- (a) wrong key vs damaged file: container level ---------------------------------

def _blob(data=DATA, kek=bytes(32)):
    out = io.BytesIO()
    container.encrypt_stream(io.BytesIO(data), out, derive_kek=lambda s: kek, kdf_id=3,
                             settings=b"", chunk_size=4096)
    return out.getvalue()


def _decrypt(blob, kek=bytes(32)):
    src = io.BytesIO(blob)
    h = container.read_header(src)
    fk = container.unwrap_file_key(h, kek)
    container.decrypt_body(h, fk, src, io.BytesIO())


def test_wrong_kek_is_wrong_key():
    with pytest.raises(WrongKeyError) as e:
        _decrypt(_blob(), kek=b"\x01" * 32)
    assert isinstance(e.value, AuthenticationError)      # still caught by old handlers


@pytest.mark.parametrize("damage", ["ciphertext", "truncate", "reorder", "nonce_prefix"])
def test_damage_after_unwrap_is_corruption(damage):
    blob = bytearray(_blob(os.urandom(3 * 4096 + 50)))
    h = container.read_header(io.BytesIO(bytes(blob)))
    n = 4096 + 16
    if damage == "ciphertext":
        blob[-20] ^= 1
    elif damage == "truncate":
        blob = blob[:h.header_len + 2 * n]
    elif damage == "reorder":
        body = blob[h.header_len:]
        blob = blob[:h.header_len] + body[n:2 * n] + body[:n] + body[2 * n:]
    else:
        blob[h.header_len - 4 - 7] ^= 1
    with pytest.raises(CorruptedFileError) as e:
        _decrypt(bytes(blob))
    assert isinstance(e.value, AuthenticationError)
    assert not isinstance(e.value, WrongKeyError)


def test_trailing_data_is_corruption_and_format_error():
    blob = _blob(b"y" * 4096)
    with pytest.raises(TrailingDataError) as e:
        _decrypt(blob + os.urandom(4096 + 16))
    assert isinstance(e.value, CorruptedFileError) and isinstance(e.value, FormatError)


# --- (a) engine level ---------------------------------------------------------------

def test_engine_wrong_passphrase(work):
    engine.encrypt_file("doc.bin", "d.fcx", PW, options=FAST)
    with pytest.raises(WrongKeyError):
        engine.decrypt_file("d.fcx", "o.bin", BAD)
    assert "o.bin" not in names(work)


def test_engine_damaged_file(work):
    engine.encrypt_file("doc.bin", "d.fcx", KEY)
    flip(work / "d.fcx", -100)
    with pytest.raises(CorruptedFileError):
        engine.decrypt_file("d.fcx", "o.bin", KEY)
    assert [n for n in names(work) if n.startswith(("o.bin", ".o.bin"))] == []


# --- (b) password retry -------------------------------------------------------------

@pytest.fixture
def counters(monkeypatch):
    c = {"open": 0, "header": 0, "derive": 0}
    real_open, real_header, real_derive = engine._open_input, container.read_header, kdf.derive_kek

    def o(p):
        c["open"] += 1
        return real_open(p)

    def h(f):
        c["header"] += 1
        return real_header(f)

    def d(*a):
        c["derive"] += 1
        return real_derive(*a)

    monkeypatch.setattr(engine, "_open_input", o)
    monkeypatch.setattr(container, "read_header", h)
    monkeypatch.setattr(kdf, "derive_kek", d)
    return c


def test_retry_until_right(work, counters):
    engine.encrypt_file("doc.bin", "d.fcx", PW, options=FAST)
    for k in counters:
        counters[k] = 0
    answers = iter([BAD, BAD, PW])
    wrong = []
    out = engine.decrypt_file("d.fcx", "o.bin", lambda: next(answers), max_attempts=3,
                              on_wrong_key=wrong.append)
    assert out.read_bytes() == DATA
    assert wrong == [1, 2]
    assert counters == {"open": 1, "header": 1, "derive": 3}   # checks once, KDF per attempt


def test_retry_gives_up(work):
    engine.encrypt_file("doc.bin", "d.fcx", PW, options=FAST)
    calls = []
    with pytest.raises(WrongKeyError):
        engine.decrypt_file("d.fcx", "o.bin", lambda: calls.append(1) or BAD, max_attempts=2)
    assert len(calls) == 2


def test_default_is_a_single_attempt(work):
    engine.encrypt_file("doc.bin", "d.fcx", PW, options=FAST)
    calls = []
    with pytest.raises(WrongKeyError):
        engine.decrypt_file("d.fcx", "o.bin", lambda: calls.append(1) or BAD)
    assert len(calls) == 1


def test_fixed_secret_is_not_retried(work, counters):
    engine.encrypt_file("doc.bin", "d.fcx", PW, options=FAST)
    counters["derive"] = 0
    with pytest.raises(WrongKeyError):
        engine.decrypt_file("d.fcx", "o.bin", BAD, max_attempts=5)
    assert counters["derive"] == 1


def test_damaged_file_is_not_retried(work):
    engine.encrypt_file("doc.bin", "d.fcx", KEY)
    flip(work / "d.fcx", -100)
    calls = []
    with pytest.raises(CorruptedFileError):
        engine.decrypt_file("d.fcx", "o.bin", lambda: calls.append(1) or KEY, max_attempts=3)
    assert len(calls) == 1


def test_rekey_retries_old_key(work):
    engine.encrypt_file("doc.bin", "r.fcx", PW, options=FAST)
    answers = iter([BAD, PW])
    engine.rekey_file("r.fcx", lambda: next(answers), KEY, max_attempts=2)
    assert engine.decrypt_file("r.fcx", "o.bin", KEY).read_bytes() == DATA


# --- (c) cooperative cancel ---------------------------------------------------------

def test_cancel_token_basics():
    t = CancelToken()
    assert not t.cancelled
    t.cancel()
    assert t.cancelled
    with pytest.raises(Cancelled):
        t.raise_if_cancelled()


def test_cancelled_before_start(work):
    t = CancelToken()
    t.cancel()
    with pytest.raises(Cancelled):
        engine.encrypt_file("doc.bin", "c.fcx", lambda: pytest.fail("asked"), cancel=t)
    assert names(work) == ["doc.bin"]


def test_cancel_before_kdf(work, counters):
    t = CancelToken()

    def provider():
        t.cancel()            # e.g. the user hits Cancel right after typing
        return PW

    counters["derive"] = 0
    with pytest.raises(Cancelled):
        engine.encrypt_file("doc.bin", "c.fcx", provider, options=FAST, cancel=t)
    assert counters["derive"] == 0
    assert names(work) == ["doc.bin"]


@pytest.mark.parametrize("op", ["encrypt", "decrypt", "rekey"])
def test_cancel_mid_stream_cleans_up(work, op):
    engine.encrypt_file("doc.bin", "src.fcx", KEY)
    before = names(work)
    original = (work / "src.fcx").read_bytes()
    t = CancelToken()
    seen = []

    def progress(done, total):
        seen.append(done)
        if len(seen) == 2:
            t.cancel()

    with pytest.raises(Cancelled):
        if op == "encrypt":
            engine.encrypt_file("doc.bin", "c.fcx", KEY, progress=progress, cancel=t)
        elif op == "decrypt":
            engine.decrypt_file("src.fcx", "c.bin", KEY, progress=progress, cancel=t)
        else:
            engine.rekey_file("src.fcx", KEY, PW, options=FAST, progress=progress, cancel=t)
    assert names(work) == before                      # no output, no .part
    assert (work / "src.fcx").read_bytes() == original
    assert seen[-1] < len(DATA)                       # stopped early


def test_cancel_from_another_thread(work):
    engine.encrypt_file("doc.bin", "src.fcx", KEY)
    t = CancelToken()
    started = threading.Event()
    result = {}

    def progress(done, total):
        started.set()
        threading.Event().wait(0.02)   # slow each chunk so the other thread can cancel

    def worker():
        try:
            engine.decrypt_file("src.fcx", "c.bin", KEY, progress=progress, cancel=t)
            result["ok"] = True
        except Cancelled:
            result["cancelled"] = True

    th = threading.Thread(target=worker)
    th.start()
    assert started.wait(10)
    t.cancel()
    th.join(30)
    assert result == {"cancelled": True}
    assert "c.bin" not in names(work)


# --- CLI ----------------------------------------------------------------------------

@pytest.fixture
def cli_work(work, monkeypatch):
    monkeypatch.setenv("FC_PASS", PW.value.decode())
    assert cli.main(["encrypt", "doc.bin", "--key", "env:FC_PASS", "--argon-memory", "19",
                     "--argon-iterations", "2", "--argon-parallelism", "1"]) == 0
    return work


def test_cli_wrong_key_message(cli_work, monkeypatch, capsys):
    monkeypatch.setenv("FC_PASS", "the wrong passphrase")
    assert cli.main(["decrypt", "doc.bin.fcx", "-o", "o.bin", "--key", "env:FC_PASS"]) == 1
    err = capsys.readouterr().err
    assert "wrong key or passphrase" in err and "damaged" not in err


def test_cli_damaged_message(cli_work, capsys):
    flip(cli_work / "doc.bin.fcx", -100)
    assert cli.main(["decrypt", "doc.bin.fcx", "-o", "o.bin", "--key", "env:FC_PASS"]) == 1
    err = capsys.readouterr().err
    assert "damaged" in err and "wrong key" not in err


def test_cli_prompt_retries_on_a_terminal(cli_work, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    answers = iter(["nope nope nope", PW.value.decode()])
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": next(answers))
    assert cli.main(["decrypt", "doc.bin.fcx", "-o", "o.bin"]) == 0
    assert (cli_work / "o.bin").read_bytes() == DATA
    assert "try again" in capsys.readouterr().err


def test_cli_prompt_gives_up_after_three(cli_work, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    calls = []
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": calls.append(p) or "nope nope nope")
    assert cli.main(["decrypt", "doc.bin.fcx", "-o", "o.bin"]) == 1
    assert len(calls) == 3


def test_cli_non_prompt_sources_get_one_attempt(cli_work, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setenv("FC_PASS", "the wrong passphrase")
    calls = []
    real = sources.resolve_secret
    monkeypatch.setattr(sources, "resolve_secret", lambda *a, **k: calls.append(1) or real(*a, **k))
    assert cli.main(["decrypt", "doc.bin.fcx", "-o", "o.bin", "--key", "env:FC_PASS"]) == 1
    assert len(calls) == 1
