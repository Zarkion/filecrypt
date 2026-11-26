import io
import os
import subprocess
import sys

import pytest

from filecrypt import cli, container, sources
from filecrypt.kdf import ARGON2ID, SCRYPT, HKDF, Argon2Params

FAST = ["--argon-memory", "19", "--argon-iterations", "2", "--argon-parallelism", "1"]
PASS = "a perfectly fine passphrase"


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FC_PASS", PASS)
    (tmp_path / "plain.txt").write_bytes(b"hello world\n" * 1000)
    return tmp_path


@pytest.fixture
def keyfile(work):
    assert cli.main(["keygen", "k.key"]) == 0
    return work / "k.key"


@pytest.fixture
def no_prompt(monkeypatch):
    def boom(prompt=""):
        raise AssertionError("unexpected prompt")
    monkeypatch.setattr(sources.getpass, "getpass", boom)


def header_of(path):
    with open(path, "rb") as f:
        return container.read_header(f)


def files_in(d):
    return sorted(p.name for p in d.iterdir())


# --- encrypt / decrypt -------------------------------------------------------

def test_round_trip_env_passphrase(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    assert (work / "plain.txt.fcx").exists()
    h = header_of(work / "plain.txt.fcx")
    assert h.kdf_id == ARGON2ID
    assert Argon2Params.decode(h.settings) == Argon2Params(19 * 1024, 2, 1)
    os.remove(work / "plain.txt")
    assert cli.main(["decrypt", "plain.txt.fcx", "--key", "env:FC_PASS"]) == 0
    assert (work / "plain.txt").read_bytes() == b"hello world\n" * 1000


def test_round_trip_keyfile(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "-o", "out.fcx", "--key", f"file:{keyfile}"]) == 0
    assert header_of(work / "out.fcx").kdf_id == HKDF
    assert cli.main(["decrypt", "out.fcx", "-o", "back.txt", "--key", f"file:{keyfile}"]) == 0
    assert (work / "back.txt").read_bytes() == (work / "plain.txt").read_bytes()


def test_default_argon_settings(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS"]) == 0
    assert Argon2Params.decode(header_of(work / "plain.txt.fcx").settings) == Argon2Params.default()


def test_prompt_asks_twice_on_encrypt_once_on_decrypt(work, monkeypatch):
    prompts = []
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": prompts.append(p) or PASS)
    assert cli.main(["encrypt", "plain.txt", *FAST]) == 0
    assert len(prompts) == 2
    prompts.clear()
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt"]) == 0
    assert len(prompts) == 1


def test_scrypt_option(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", "--kdf", "scrypt"]) == 0
    assert header_of(work / "plain.txt.fcx").kdf_id == SCRYPT
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt", "--key", "env:FC_PASS"]) == 0


def test_argon_flags_with_scrypt_rejected(work, capsys):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", "--kdf", "scrypt", *FAST]) == 1
    assert "argon" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("flags", [
    ["--argon-memory", "18"], ["--argon-iterations", "1"], ["--argon-parallelism", "0"],
    ["--argon-memory", "4097"], ["--argon-iterations", "17"], ["--argon-parallelism", "17"],
])
def test_argon_limits_enforced(work, flags, no_prompt):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *flags]) == 1
    assert not (work / "plain.txt.fcx").exists()


def test_short_passphrase_warns(work, monkeypatch, capsys):
    monkeypatch.setenv("FC_SHORT", "short")
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_SHORT", *FAST]) == 0
    assert "12" in capsys.readouterr().err


def test_short_keyfile_rejected_unless_flag(work):
    (work / "weak.key").write_bytes(b"x" * 20)
    assert cli.main(["encrypt", "plain.txt", "--key", "file:weak.key"]) == 1
    assert not (work / "plain.txt.fcx").exists()
    assert cli.main(["encrypt", "plain.txt", "--key", "file:weak.key",
                     "--keyfile-is-passphrase", *FAST]) == 0
    assert header_of(work / "plain.txt.fcx").kdf_id == ARGON2ID
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt", "--key", "file:weak.key"]) == 0


def test_no_overwrite_without_force_and_before_prompting(work, no_prompt):
    (work / "plain.txt.fcx").write_bytes(b"precious")
    assert cli.main(["encrypt", "plain.txt"]) == 1
    assert (work / "plain.txt.fcx").read_bytes() == b"precious"


def test_force_overwrites(work):
    (work / "plain.txt.fcx").write_bytes(b"old")
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", "--force", *FAST]) == 0
    assert (work / "plain.txt.fcx").read_bytes()[:4] == b"FCX1"


def test_decrypt_refuses_overwrite(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    assert cli.main(["decrypt", "plain.txt.fcx", "--key", "env:FC_PASS"]) == 1
    assert cli.main(["decrypt", "plain.txt.fcx", "--key", "env:FC_PASS", "--force"]) == 0


def test_decrypt_needs_output_name_without_fcx_suffix(work):
    assert cli.main(["encrypt", "plain.txt", "-o", "blob.bin", "--key", "env:FC_PASS", *FAST]) == 0
    assert cli.main(["decrypt", "blob.bin", "--key", "env:FC_PASS"]) == 1
    assert cli.main(["decrypt", "blob.bin", "-o", "x.txt", "--key", "env:FC_PASS"]) == 0


def test_same_input_and_output_rejected(work):
    assert cli.main(["encrypt", "plain.txt", "-o", "plain.txt", "--force", "--key", "env:FC_PASS"]) == 1
    assert (work / "plain.txt").read_bytes() == b"hello world\n" * 1000


def test_wrong_key_leaves_nothing_behind(work, monkeypatch, capsys):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    before = files_in(work)
    monkeypatch.setenv("FC_PASS", "the wrong passphrase")
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "out.txt", "--key", "env:FC_PASS"]) == 1
    assert files_in(work) == before
    assert "wrong key" in capsys.readouterr().err


def test_tampered_body_partial_output_deleted(work, keyfile):
    big = os.urandom(300_000)
    (work / "big.bin").write_bytes(big)
    assert cli.main(["encrypt", "big.bin", "--key", f"file:{keyfile}"]) == 0
    blob = bytearray((work / "big.bin.fcx").read_bytes())
    blob[-100] ^= 1  # last chunk: earlier chunks decrypt fine first
    (work / "big.bin.fcx").write_bytes(bytes(blob))
    before = files_in(work)
    assert cli.main(["decrypt", "big.bin.fcx", "-o", "out.bin", "--key", f"file:{keyfile}"]) == 1
    assert files_in(work) == before


def test_not_an_fcx_file_fails_before_prompting(work, no_prompt, capsys):
    assert cli.main(["decrypt", "plain.txt", "-o", "x"]) == 1
    assert "not an .fcx" in capsys.readouterr().err


def test_missing_input(work, capsys):
    assert cli.main(["encrypt", "nope.txt", "--key", "env:FC_PASS"]) == 1
    assert "nope.txt" in capsys.readouterr().err


def test_empty_file_round_trip(work, keyfile):
    (work / "empty").write_bytes(b"")
    assert cli.main(["encrypt", "empty", "--key", f"file:{keyfile}"]) == 0
    os.remove(work / "empty")
    assert cli.main(["decrypt", "empty.fcx", "--key", f"file:{keyfile}"]) == 0
    assert (work / "empty").read_bytes() == b""


def test_stdin_key(work, monkeypatch):
    monkeypatch.setattr(sources.sys, "stdin", io.TextIOWrapper(io.BytesIO(PASS.encode() + b"\n")))
    assert cli.main(["encrypt", "plain.txt", "--key", "stdin", *FAST]) == 0
    monkeypatch.setattr(sources.sys, "stdin", io.TextIOWrapper(io.BytesIO(PASS.encode() + b"\n")))
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt", "--key", "stdin"]) == 0


# --- keygen ------------------------------------------------------------------

def test_keygen(work):
    assert cli.main(["keygen", "a.key"]) == 0
    assert len((work / "a.key").read_bytes()) == 32
    assert cli.main(["keygen", "a.key"]) == 1
    assert cli.main(["keygen", "a.key", "--force", "--bytes", "64"]) == 0
    assert len((work / "a.key").read_bytes()) == 64


def test_keygen_rules(work):
    assert cli.main(["keygen", "b.key", "--bytes", "16"]) == 1
    assert not (work / "b.key").exists()
    assert cli.main(["keygen", "b.key", "--format", "base64"]) == 0
    assert (work / "b.key").read_bytes().endswith(b"\n")
    assert cli.main(["keygen"]) == 1  # neither a path nor --store


def test_keygen_store(work):
    assert cli.main(["keygen", "--store", "file:stored.key"]) == 0
    assert len((work / "stored.key").read_bytes()) == 32
    assert cli.main(["keygen", "--store", "prompt"]) == 1


def test_keygen_file_and_store_hold_same_key(work):
    assert cli.main(["keygen", "a.key", "--format", "base64", "--store", "file:b.key"]) == 0
    assert sources.resolve_secret("file:a.key") == sources.resolve_secret("file:b.key")


# --- rekey -------------------------------------------------------------------

def test_rekey_in_place_passphrase_to_keyfile(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    old = (work / "plain.txt.fcx").read_bytes()
    old_h = header_of(work / "plain.txt.fcx")
    assert cli.main(["rekey", "plain.txt.fcx", "--key", "env:FC_PASS",
                     "--new-key", f"file:{keyfile}"]) == 0
    new = (work / "plain.txt.fcx").read_bytes()
    new_h = header_of(work / "plain.txt.fcx")
    assert new_h.kdf_id == HKDF
    assert new[new_h.header_len:] == old[old_h.header_len:]  # body byte-identical
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "a.txt", "--key", "env:FC_PASS"]) == 1
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "a.txt", "--key", f"file:{keyfile}"]) == 0
    assert (work / "a.txt").read_bytes() == (work / "plain.txt").read_bytes()
    assert files_in(work) == sorted(["a.txt", "k.key", "plain.txt", "plain.txt.fcx"])


def test_rekey_argon_settings(work, monkeypatch):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    monkeypatch.setenv("FC_NEW", "another good passphrase")
    assert cli.main(["rekey", "plain.txt.fcx", "--key", "env:FC_PASS", "--new-key", "env:FC_NEW",
                     "--argon-memory", "32", "--argon-iterations", "2", "--argon-parallelism", "2"]) == 0
    assert Argon2Params.decode(header_of(work / "plain.txt.fcx").settings) == Argon2Params(32 * 1024, 2, 2)


def test_rekey_wrong_old_key_leaves_file_untouched(work, keyfile, monkeypatch):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    before = (work / "plain.txt.fcx").read_bytes()
    monkeypatch.setenv("FC_BAD", "not the passphrase")
    assert cli.main(["rekey", "plain.txt.fcx", "--key", "env:FC_BAD",
                     "--new-key", f"file:{keyfile}"]) == 1
    assert (work / "plain.txt.fcx").read_bytes() == before
    assert files_in(work) == sorted(["k.key", "plain.txt", "plain.txt.fcx"])


def test_rekey_to_other_file_respects_force(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    (work / "other.fcx").write_bytes(b"keep")
    args = ["rekey", "plain.txt.fcx", "-o", "other.fcx", "--key", "env:FC_PASS", "--new-key", f"file:{keyfile}"]
    assert cli.main(args) == 1
    assert (work / "other.fcx").read_bytes() == b"keep"
    assert cli.main(args + ["--force"]) == 0
    assert cli.main(["decrypt", "other.fcx", "-o", "o.txt", "--key", f"file:{keyfile}"]) == 0


# --- misc --------------------------------------------------------------------

def test_usage_errors_exit_2(capsys):
    assert cli.main([]) == 2
    assert cli.main(["frobnicate"]) == 2


def test_python_dash_m_version():
    out = subprocess.run([sys.executable, "-m", "filecrypt", "--version"],
                         capture_output=True, text=True, check=True)
    assert "filecrypt" in out.stdout
