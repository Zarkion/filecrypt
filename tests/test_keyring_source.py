import base64
import os
import sys
import types

import pytest

from filecrypt import cli, sources
from filecrypt.kdf import Secret
from filecrypt.sources import KeySourceError


class FakeKeyring(types.ModuleType):
    def __init__(self):
        super().__init__("keyring")
        self.store = {}

    def get_password(self, service, name):
        return self.store.get((service, name))

    def set_password(self, service, name, value):
        self.store[(service, name)] = value


@pytest.fixture
def fake_keyring(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return kr


def test_keyring_is_builtin():
    assert "keyring" in sources.available_sources()


def test_store_then_get_round_trip(fake_keyring):
    k = os.urandom(32)
    sources.get_source("keyring").store("filecrypt/main", k)
    assert fake_keyring.store[("filecrypt", "main")] == base64.b64encode(k).decode()
    assert sources.resolve_secret("keyring:filecrypt/main") == Secret(k, "key")


def test_default_service_name(fake_keyring):
    sources.get_source("keyring").store("backup", b"k" * 32)
    assert ("filecrypt", "backup") in fake_keyring.store


def test_manually_stored_passphrase_is_a_passphrase(fake_keyring):
    fake_keyring.set_password("svc", "pw", "typed by a human")
    assert sources.resolve_secret("keyring:svc/pw") == Secret(b"typed by a human", "passphrase")


def test_missing_entry(fake_keyring):
    with pytest.raises(KeySourceError, match="svc/none"):
        sources.resolve_secret("keyring:svc/none")


def test_store_refuses_to_overwrite(fake_keyring):
    src = sources.get_source("keyring")
    src.store("svc/k", b"a" * 32)
    with pytest.raises(KeySourceError, match="already"):
        src.store("svc/k", b"b" * 32)


@pytest.mark.parametrize("loc", ["", "svc/", "/name"])
def test_bad_location(fake_keyring, loc):
    with pytest.raises(KeySourceError):
        sources.resolve_secret(f"keyring:{loc}")


def test_keyring_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # makes import fail
    with pytest.raises(KeySourceError, match=r"filecrypt\[keyring\]"):
        sources.resolve_secret("keyring:svc/k")


def test_cli_keygen_store_and_encrypt(fake_keyring, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "f.txt").write_bytes(b"data")
    assert cli.main(["keygen", "--store", "keyring:filecrypt/test"]) == 0
    assert cli.main(["encrypt", "f.txt", "--key", "keyring:filecrypt/test"]) == 0
    assert cli.main(["decrypt", "f.txt.fcx", "-o", "g.txt", "--key", "keyring:filecrypt/test"]) == 0
    assert (tmp_path / "g.txt").read_bytes() == b"data"
    assert cli.main(["keygen", "--store", "keyring:filecrypt/test"]) == 1


@pytest.mark.parametrize("text,expected", [
    (base64.b64encode(b"k" * 32).decode(), Secret(b"k" * 32, "key")),
    ("  " + base64.b64encode(b"k" * 48).decode() + "\n", Secret(b"k" * 48, "key")),
    ("not a key", Secret(b"not a key", "passphrase")),
    (base64.b64encode(b"short").decode(), Secret(base64.b64encode(b"short"), "passphrase")),
])
def test_secret_from_stored_text(text, expected):
    assert sources.secret_from_stored_text(text) == expected
