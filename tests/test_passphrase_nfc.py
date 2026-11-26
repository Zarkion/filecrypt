"""Passphrases are encoded as NFC UTF-8, with the exact bytes as a fallback."""

import io
import unicodedata

import pytest

from filecrypt import container, engine, kdf, sources
from filecrypt.container import AuthenticationError
from filecrypt.engine import EncryptOptions
from filecrypt.kdf import Argon2Params, Secret

COMPOSED = "café crème brûlée"            # é as one code point
DECOMPOSED = unicodedata.normalize("NFD", COMPOSED)            # e + combining acute
assert COMPOSED != DECOMPOSED

if kdf.argon2_available():
    OPTIONS = EncryptOptions(argon=Argon2Params(19 * 1024, 2, 1))
else:  # the scrypt-only CI job
    OPTIONS = EncryptOptions(kdf="scrypt")
DATA = b"secret recipe " * 500


def pw(text):
    return Secret(text.encode("utf-8"), "passphrase")


def legacy_encrypt(path, raw: bytes):
    """Encrypt the way releases before normalization did: with the exact bytes."""
    kdf_id, settings = kdf.select_kdf(Secret(b"x" * 12, "passphrase"), kdf=OPTIONS.kdf,
                                      argon=OPTIONS.argon)
    with open(path, "wb") as out:
        container.encrypt_stream(io.BytesIO(DATA), out, kdf_id=kdf_id, settings=settings,
                                 derive_kek=lambda salt: kdf.derive_kek(kdf_id, settings, salt, raw))


# --- the Secret itself --------------------------------------------------------

def test_decomposed_passphrase_is_stored_as_nfc():
    s = pw(DECOMPOSED)
    assert s.value == COMPOSED.encode("utf-8")
    assert s.unnormalized == DECOMPOSED.encode("utf-8")
    assert s.unlock_candidates() == [COMPOSED.encode("utf-8"), DECOMPOSED.encode("utf-8")]


def test_single_e_acute_both_ways():
    assert pw("é").value == "é".encode("utf-8") == b"\xc3\xa9"
    assert pw("é").value == b"\xc3\xa9"


def test_nfc_passphrase_unchanged():
    s = pw(COMPOSED)
    assert s.value == COMPOSED.encode("utf-8")
    assert s.unnormalized is None
    assert s.unlock_candidates() == [s.value]


def test_keys_are_never_normalized():
    raw = DECOMPOSED.encode("utf-8")
    s = Secret(raw, "key")
    assert s.value == raw and s.unnormalized is None


def test_non_utf8_passphrase_kept_as_is():
    raw = b"\xff\xfe not utf-8 at all"
    s = Secret(raw, "passphrase")
    assert s.value == raw and s.unnormalized is None


def test_normalization_is_nfc_not_nfkc():
    # Compatibility characters (here a ligature) must keep their identity.
    assert pw("ﬁle").value == "ﬁle".encode("utf-8")


def test_repr_does_not_leak():
    assert "caf" not in repr(pw(DECOMPOSED))


def test_sources_produce_nfc(monkeypatch):
    monkeypatch.setattr(sources.getpass, "getpass", lambda prompt="": DECOMPOSED)
    assert sources.PromptSource().get("").value == COMPOSED.encode("utf-8")
    assert sources.secret_from_stored_text(DECOMPOSED).value == COMPOSED.encode("utf-8")
    monkeypatch.setenv("FCX_TEST_PW", DECOMPOSED)
    assert sources.EnvSource().get("FCX_TEST_PW").value == COMPOSED.encode("utf-8")


# --- encrypt, decrypt and rekey -----------------------------------------------

@pytest.fixture
def plain(tmp_path):
    p = tmp_path / "recipe.txt"
    p.write_bytes(DATA)
    return p


@pytest.mark.parametrize("enc,dec", [(DECOMPOSED, COMPOSED), (COMPOSED, DECOMPOSED)])
def test_new_files_open_however_the_passphrase_is_typed(plain, tmp_path, enc, dec):
    out = engine.encrypt_file(plain, tmp_path / "r.fcx", pw(enc), options=OPTIONS)
    back = engine.decrypt_file(out, tmp_path / "back.txt", pw(dec))
    assert back.read_bytes() == DATA


def test_new_files_are_keyed_with_nfc_bytes(plain, tmp_path):
    out = engine.encrypt_file(plain, tmp_path / "r.fcx", pw(DECOMPOSED), options=OPTIONS)
    with open(out, "rb") as f:
        header = container.read_header(f)
    kek = kdf.derive_kek(header.kdf_id, header.settings, header.salt, COMPOSED.encode("utf-8"))
    container.unwrap_file_key(header, kek)     # raises if NFC bytes weren't used


def test_legacy_decomposed_file_still_opens(tmp_path):
    legacy = tmp_path / "old.fcx"
    legacy_encrypt(legacy, DECOMPOSED.encode("utf-8"))
    back = engine.decrypt_file(legacy, tmp_path / "back.txt", pw(DECOMPOSED))
    assert back.read_bytes() == DATA


def test_legacy_decomposed_file_needs_the_decomposed_input(tmp_path):
    # Known limit: typing the composed form can't recover decomposed bytes.
    legacy = tmp_path / "old.fcx"
    legacy_encrypt(legacy, DECOMPOSED.encode("utf-8"))
    with pytest.raises(AuthenticationError):
        engine.decrypt_file(legacy, tmp_path / "back.txt", pw(COMPOSED))


def test_legacy_composed_file_opens_either_way(tmp_path):
    legacy = tmp_path / "old.fcx"
    legacy_encrypt(legacy, COMPOSED.encode("utf-8"))
    for i, text in enumerate([COMPOSED, DECOMPOSED]):
        back = engine.decrypt_file(legacy, tmp_path / f"back{i}.txt", pw(text))
        assert back.read_bytes() == DATA


def test_wrong_passphrase_still_rejected_after_both_tries(plain, tmp_path, monkeypatch):
    out = engine.encrypt_file(plain, tmp_path / "r.fcx", pw(COMPOSED), options=OPTIONS)
    tried = []
    real = kdf.derive_kek
    monkeypatch.setattr(kdf, "derive_kek", lambda *a: tried.append(a[3]) or real(*a))
    wrong = pw(unicodedata.normalize("NFD", "cr\u00e8me caramel"))
    with pytest.raises(AuthenticationError):
        engine.decrypt_file(out, tmp_path / "back.txt", wrong)
    assert tried == wrong.unlock_candidates()
    assert not (tmp_path / "back.txt").exists()


def test_rekey_legacy_file_moves_it_to_nfc(tmp_path):
    legacy = tmp_path / "old.fcx"
    legacy_encrypt(legacy, DECOMPOSED.encode("utf-8"))
    engine.rekey_file(legacy, pw(DECOMPOSED), pw(DECOMPOSED), options=OPTIONS)
    # After rekeying, the composed form opens it too.
    back = engine.decrypt_file(legacy, tmp_path / "back.txt", pw(COMPOSED))
    assert back.read_bytes() == DATA


def test_keyfile_as_passphrase_is_not_normalized(plain, tmp_path):
    raw = DECOMPOSED.encode("utf-8") * 3
    opts = EncryptOptions(kdf=OPTIONS.kdf, argon=OPTIONS.argon, keyfile_is_passphrase=True)
    out = engine.encrypt_file(plain, tmp_path / "r.fcx", Secret(raw, "key"), options=opts)
    with open(out, "rb") as f:
        header = container.read_header(f)
    kek = kdf.derive_kek(header.kdf_id, header.settings, header.salt, raw)
    container.unwrap_file_key(header, kek)     # keyed with the exact bytes


def test_keyfile_as_passphrase_old_gui_and_cli_encodings_both_open(tmp_path):
    """Older desktop windows NFC-normalized a keyfile used as a password; the CLI
    always used its exact bytes. Both kinds of file open with the keyfile today."""
    keyfile = tmp_path / "words.txt"
    keyfile.write_bytes(DECOMPOSED.encode("utf-8"))      # text that NFC changes
    raw = keyfile.read_bytes()
    nfc = COMPOSED.encode("utf-8")
    src = tmp_path / "plain"
    src.write_bytes(DATA)
    opts = EncryptOptions(kdf=OPTIONS.kdf, argon=OPTIONS.argon, keyfile_is_passphrase=True)
    # Old window: Secret(kind="passphrase") over the keyfile, so its NFC form.
    old_gui = engine.encrypt_file(src, tmp_path / "gui.fcx", pw(DECOMPOSED), options=opts)
    # CLI (and the window now): the keyfile's exact bytes, stretched like a passphrase.
    cli = engine.encrypt_file(src, tmp_path / "cli.fcx", Secret(raw, "key"), options=opts)
    secret = sources.FileSource().get(str(keyfile))
    assert secret.kind == "key" and secret.unlock_candidates() == [raw, nfc]
    for f in (old_gui, cli):
        engine.verify_file(f, secret)


def test_random_key_has_one_candidate():
    k = bytes(range(32))
    assert Secret(k, "key").unlock_candidates() == [k]
