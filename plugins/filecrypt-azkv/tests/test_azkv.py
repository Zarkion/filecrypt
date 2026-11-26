import base64
import os

import pytest

from filecrypt import cli, sources
from filecrypt.kdf import Secret
from filecrypt.sources import KeySourceError

import filecrypt_azkv
from filecrypt_azkv import AzureKeyVaultSource, parse_location


class NotFound(Exception):
    pass


class FakeProps:
    def __init__(self, version):
        self.version = version


class FakeSecret:
    def __init__(self, value, version=None):
        self.value = value
        self.properties = FakeProps(version)


class FakeClient:
    def __init__(self, vault_url, vaults):
        self.vault_url = vault_url
        self.data = vaults.setdefault(vault_url, {})

    def get_secret(self, name, version=None):
        try:
            return FakeSecret(self.data[(name, version)] if version else self.data[(name, "latest")])
        except KeyError:
            raise NotFound(name) from None

    def set_secret(self, name, value):
        version = os.urandom(16).hex()
        self.data[(name, "latest")] = value
        self.data[(name, version)] = value
        return FakeSecret(value, version)

    def list_properties_of_secret_versions(self, name):
        return [FakeProps(v) for (n, v) in self.data if n == name and v != "latest"]


V = "0123456789abcdef0123456789abcdef"  # Key Vault versions are 32 hex characters


@pytest.fixture
def vaults(monkeypatch):
    store = {}
    monkeypatch.setattr(filecrypt_azkv, "_make_client", lambda url: FakeClient(url, store))
    monkeypatch.setattr(filecrypt_azkv, "_is_not_found", lambda e: isinstance(e, NotFound))
    return store


@pytest.mark.parametrize("loc,expected", [
    ("myvault/mykey", ("https://myvault.vault.azure.net", "mykey", None)),
    ("myvault/mykey/" + V, ("https://myvault.vault.azure.net", "mykey", V)),
    ("myvault/mykey/" + V.upper(), ("https://myvault.vault.azure.net", "mykey", V.upper())),
    ("https://v2.vault.azure.net/secrets/k", ("https://v2.vault.azure.net", "k", None)),
    ("https://v2.vault.azure.net/secrets/k/" + V, ("https://v2.vault.azure.net", "k", V)),
    ("https://v.vault.usgovcloudapi.net/secrets/k", ("https://v.vault.usgovcloudapi.net", "k", None)),
])
def test_parse_location(loc, expected):
    assert parse_location(loc) == expected


@pytest.mark.parametrize("loc", ["", "vaultonly", "/k", "v/", "bad vault/k",
                                 "http://v.vault.azure.net/secrets/k", "https://evil.example.com/secrets/k"])
def test_parse_location_rejects(loc):
    with pytest.raises(KeySourceError):
        parse_location(loc)


@pytest.mark.parametrize("loc", ["myv/k/abc123", "myv/k/" + V[:-1], "myv/k/" + V + "0",
                                 "myv/k/" + "g" * 32, "myv/k/" + V[:-2] + "..", "https://v.vault.azure.net/secrets/k/ver",
                                 "https://v.vault.azure.net/secrets/k/" + V + "%2F"])
def test_parse_location_rejects_bad_version(loc):
    with pytest.raises(KeySourceError, match="version"):
        parse_location(loc)


def test_get_specific_version(vaults):
    vaults["https://myv.vault.azure.net"] = {("pw", V): "older passphrase", ("pw", "latest"): "newer"}
    assert AzureKeyVaultSource().get("myv/pw/" + V) == Secret(b"older passphrase", "passphrase")


def test_store_detects_concurrent_writer(vaults, monkeypatch):
    # Simulate another keygen whose set_secret lands between our existence
    # check and our own set_secret.
    real_set = FakeClient.set_secret
    raced = []

    def racing_set(self, name, value):
        if not raced:
            raced.append(real_set(self, name, "fcxkey:v1:someone-else"))
        return real_set(self, name, value)

    monkeypatch.setattr(FakeClient, "set_secret", racing_set)
    with pytest.raises(KeySourceError, match="same time") as exc:
        AzureKeyVaultSource().store("myv/k", b"a" * 32)
    assert raced[0].properties.version in str(exc.value)


def test_store_and_get(vaults):
    k = os.urandom(32)
    src = AzureKeyVaultSource()
    src.store("myvault/filekey", k)
    stored = vaults["https://myvault.vault.azure.net"][("filekey", "latest")]
    assert stored.startswith("fcxkey:v1:")
    assert base64.b64decode(stored[len("fcxkey:v1:"):]) == k
    assert src.get("myvault/filekey") == Secret(k, "key")


def test_store_refuses_existing(vaults):
    src = AzureKeyVaultSource()
    src.store("myv/k", b"a" * 32)
    with pytest.raises(KeySourceError, match="already exists"):
        src.store("myv/k", b"b" * 32)


def test_missing_secret(vaults):
    with pytest.raises(KeySourceError, match="not found"):
        AzureKeyVaultSource().get("myv/missing")


def test_base64_looking_passphrase_stays_a_passphrase(vaults):
    pw = "MyDogSpotLovesTheParkEverySundayMorning2024x"
    vaults["https://myv.vault.azure.net"] = {("pw", "latest"): pw}
    assert AzureKeyVaultSource().get("myv/pw") == Secret(pw.encode(), "passphrase")


def test_passphrase_secret(vaults):
    vaults["https://myv.vault.azure.net"] = {("pw", "latest"): "a human passphrase"}
    assert AzureKeyVaultSource().get("myv/pw") == Secret(b"a human passphrase", "passphrase")


def test_azure_errors_become_key_source_errors(monkeypatch):
    class Boom:
        def get_secret(self, name, version=None):
            raise RuntimeError("auth failed")
    monkeypatch.setattr(filecrypt_azkv, "_make_client", lambda url: Boom())
    monkeypatch.setattr(filecrypt_azkv, "_is_not_found", lambda e: False)
    with pytest.raises(KeySourceError, match="auth failed"):
        AzureKeyVaultSource().get("myv/k")


def test_discovered_through_entry_point():
    # Requires the plugin to be installed (pip install -e plugins/filecrypt-azkv).
    assert "azkv" in sources.available_sources()
    assert isinstance(sources.get_source("azkv"), AzureKeyVaultSource)


def test_cli_end_to_end(vaults, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "doc.txt").write_bytes(b"cloud-protected")
    assert cli.main(["keygen", "--store", "azkv:corpvault/filecrypt-main"]) == 0
    assert cli.main(["encrypt", "doc.txt", "--key", "azkv:corpvault/filecrypt-main"]) == 0
    assert cli.main(["decrypt", "doc.txt.fcx", "-o", "out.txt", "--key", "azkv:corpvault/filecrypt-main"]) == 0
    assert (tmp_path / "out.txt").read_bytes() == b"cloud-protected"
