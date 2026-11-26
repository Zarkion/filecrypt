import base64
import io
import os
from importlib.metadata import EntryPoint

import pytest

from filecrypt import sources
from filecrypt.kdf import Secret
from filecrypt.sources import KeySource, KeySourceError, parse_key_spec, resolve_secret


# --- spec parsing ------------------------------------------------------------

@pytest.mark.parametrize("spec,expected", [
    ("prompt", ("prompt", "")),
    ("stdin", ("stdin", "")),
    ("file:/home/me/k.key", ("file", "/home/me/k.key")),
    ("file:C:\\keys\\k.key", ("file", "C:\\keys\\k.key")),
    ("env:FILECRYPT_PASS", ("env", "FILECRYPT_PASS")),
    ("azkv:myvault/mysecret", ("azkv", "myvault/mysecret")),
    ("aws-sm:prod/key", ("aws-sm", "prod/key")),
    ("Keyring:svc/user", ("keyring", "svc/user")),
])
def test_parse_key_spec(spec, expected):
    assert parse_key_spec(spec) == expected


@pytest.mark.parametrize("spec", ["", "C:\\keys\\k.key", "/abs/path", "9x:loc", ":loc"])
def test_parse_key_spec_rejects(spec):
    with pytest.raises(KeySourceError):
        parse_key_spec(spec)


def test_drive_letter_hint():
    with pytest.raises(KeySourceError, match="file:"):
        parse_key_spec("C:\\keys\\k.key")


# --- built-in sources --------------------------------------------------------

def test_prompt_once(monkeypatch):
    calls = []
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": calls.append(p) or "hunter2 hunter2")
    s = resolve_secret("prompt")
    assert s == Secret(b"hunter2 hunter2", "passphrase") and len(calls) == 1


def test_prompt_confirm_twice(monkeypatch):
    answers = iter(["pässword long", "pässword long"])
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": next(answers))
    assert resolve_secret("prompt", confirm=True).value == "pässword long".encode()


def test_prompt_confirm_mismatch(monkeypatch):
    answers = iter(["one", "two"])
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": next(answers))
    with pytest.raises(KeySourceError, match="match"):
        resolve_secret("prompt", confirm=True)


def test_prompt_empty_rejected(monkeypatch):
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": "")
    with pytest.raises(KeySourceError):
        resolve_secret("prompt")


def test_file_source_raw_and_base64(tmp_path):
    k = os.urandom(32)
    (tmp_path / "raw").write_bytes(k)
    (tmp_path / "b64").write_bytes(base64.b64encode(k) + b"\n")
    assert resolve_secret(f"file:{tmp_path / 'raw'}") == Secret(k, "key")
    assert resolve_secret(f"file:{tmp_path / 'b64'}") == Secret(k, "key")


def test_file_source_missing(tmp_path):
    with pytest.raises(KeySourceError, match="cannot read"):
        resolve_secret(f"file:{tmp_path / 'nope'}")
    with pytest.raises(KeySourceError):
        resolve_secret("file:")


def test_file_source_store(tmp_path):
    p = tmp_path / "stored.key"
    sources.get_source("file").store(str(p), b"k" * 32)
    assert p.read_bytes() == b"k" * 32
    with pytest.raises(FileExistsError):
        sources.get_source("file").store(str(p), b"j" * 32)


def test_env_source(monkeypatch):
    monkeypatch.setenv("FC_TEST_PASS", "from the environment")
    assert resolve_secret("env:FC_TEST_PASS") == Secret(b"from the environment", "passphrase")
    monkeypatch.delenv("FC_TEST_PASS")
    with pytest.raises(KeySourceError, match="FC_TEST_PASS"):
        resolve_secret("env:FC_TEST_PASS")
    with pytest.raises(KeySourceError):
        resolve_secret("env:")


def test_stdin_source_reads_first_line(monkeypatch):
    monkeypatch.setattr(sources.sys, "stdin", io.TextIOWrapper(io.BytesIO(b"piped secret\r\nignored\n")))
    assert resolve_secret("stdin") == Secret(b"piped secret", "passphrase")


def test_stdin_source_empty(monkeypatch):
    monkeypatch.setattr(sources.sys, "stdin", io.TextIOWrapper(io.BytesIO(b"")))
    with pytest.raises(KeySourceError):
        resolve_secret("stdin")


def test_stdin_confirm_not_repeated(monkeypatch):
    monkeypatch.setattr(sources.sys, "stdin", io.TextIOWrapper(io.BytesIO(b"once\n")))
    assert resolve_secret("stdin", confirm=True).value == b"once"


def test_store_unsupported_for_prompt():
    with pytest.raises(KeySourceError, match="cannot store"):
        sources.get_source("prompt").store("", b"k" * 32)


# --- plugin registry ---------------------------------------------------------

class FakeVault(KeySource):
    name = "fakevault"
    stored = {}

    def get(self, location, *, confirm=False):
        return Secret(self.stored[location], "key")

    def store(self, location, key):
        self.stored[location] = key


def _fake_eps(*eps):
    return lambda: list(eps)


def test_entry_point_plugin_loaded(monkeypatch):
    ep = EntryPoint(name="fakevault", value=f"{__name__}:FakeVault", group=sources.ENTRY_POINT_GROUP)
    monkeypatch.setattr(sources, "_entry_points", _fake_eps(ep))
    src = sources.get_source("fakevault")
    src.store("v/s", b"z" * 32)
    assert resolve_secret("fakevault:v/s") == Secret(b"z" * 32, "key")
    assert "fakevault" in sources.available_sources()


def test_plugin_cannot_shadow_builtin(monkeypatch):
    ep = EntryPoint(name="file", value=f"{__name__}:FakeVault", group=sources.ENTRY_POINT_GROUP)
    monkeypatch.setattr(sources, "_entry_points", _fake_eps(ep))
    assert isinstance(sources.get_source("file"), sources.FileSource)


def test_unknown_scheme_lists_available(monkeypatch):
    monkeypatch.setattr(sources, "_entry_points", _fake_eps())
    with pytest.raises(KeySourceError, match="prompt"):
        sources.get_source("nosuch")


def test_broken_plugin_reports_cleanly(monkeypatch):
    ep = EntryPoint(name="broken", value="no_such_module_xyz:Thing", group=sources.ENTRY_POINT_GROUP)
    monkeypatch.setattr(sources, "_entry_points", _fake_eps(ep))
    with pytest.raises(KeySourceError, match="broken"):
        sources.get_source("broken")


def test_plugin_must_be_key_source(monkeypatch):
    ep = EntryPoint(name="notsource", value="os:getcwd", group=sources.ENTRY_POINT_GROUP)
    monkeypatch.setattr(sources, "_entry_points", _fake_eps(ep))
    with pytest.raises(KeySourceError, match="notsource"):
        sources.get_source("notsource")


# --- L4: plugin loading hygiene ---------------------------------------------------

class _FakeDist:
    def __init__(self, name):
        self.name = name
        self.metadata = {"Name": name}


class _FakeEP:
    def __init__(self, name, dist, obj=FakeVault, exc=None):
        self.name, self.dist, self.value = name, _FakeDist(dist), f"{dist}:Thing"
        self._obj, self._exc = obj, exc

    def load(self):
        if self._exc:
            raise self._exc
        return self._obj


def test_duplicate_scheme_names_both_distributions(monkeypatch):
    monkeypatch.setattr(sources, "_entry_points",
                        _fake_eps(_FakeEP("vault", "good-vault"), _FakeEP("vault", "sneaky-vault")))
    with pytest.raises(KeySourceError) as e:
        sources.get_source("vault")
    assert "good-vault" in str(e.value) and "sneaky-vault" in str(e.value)


def test_same_distribution_listed_twice_is_not_a_conflict(monkeypatch):
    monkeypatch.setattr(sources, "_entry_points",
                        _fake_eps(_FakeEP("vault", "good-vault"), _FakeEP("vault", "good-vault")))
    assert isinstance(sources.get_source("vault"), FakeVault)


def test_plugin_load_error_is_sanitized(monkeypatch):
    nasty = RuntimeError("\x1b[2J\x1b[31mfake prompt\nPassphrase: " + "x" * 500)
    monkeypatch.setattr(sources, "_entry_points", _fake_eps(_FakeEP("vault", "bad-vault", exc=nasty)))
    with pytest.raises(KeySourceError) as e:
        sources.get_source("vault")
    msg = str(e.value)
    assert "\x1b" not in msg and "\n" not in msg
    assert "RuntimeError" in msg and "bad-vault" in msg
    assert len(msg) < 400
