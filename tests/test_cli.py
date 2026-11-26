import io
import os
import subprocess
import sys

import pytest

from filecrypt import cli, container, engine, sources
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

@pytest.mark.requires_argon2
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


@pytest.mark.requires_argon2
def test_default_argon_settings(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS"]) == 0
    assert Argon2Params.decode(header_of(work / "plain.txt.fcx").settings) == Argon2Params.default()


def test_prompt_asks_twice_on_encrypt_once_on_decrypt(work, monkeypatch):
    monkeypatch.setattr(cli, "_can_prompt", lambda: True)
    prompts = []
    monkeypatch.setattr(sources.getpass, "getpass", lambda p="": prompts.append(p) or PASS)
    assert cli.main(["encrypt", "plain.txt", *FAST]) == 0
    assert len(prompts) == 2
    prompts.clear()
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt"]) == 0
    assert len(prompts) == 1


@pytest.mark.parametrize("command", [
    ["encrypt", "plain.txt", *FAST],
    ["decrypt", "plain.txt.fcx", "-o", "b.txt"],
    ["verify", "plain.txt.fcx"],
    ["rekey", "plain.txt.fcx", "--new-key", "env:FC_PASS"],
])
def test_no_terminal_refuses_to_prompt(work, monkeypatch, capsys, no_prompt, command):
    if command[0] != "encrypt":
        assert cli.main(["encrypt", "plain.txt", *FAST, "--key", "env:FC_PASS"]) == 0
    monkeypatch.setattr(cli, "_can_prompt", lambda: False)
    capsys.readouterr()
    assert cli.main([*command, "--quiet"]) == cli.EXIT_KEY_SOURCE
    err = capsys.readouterr().err
    assert "no terminal" in err and "--key env:VAR" in err and "Traceback" not in err


def test_prompt_eof_is_a_clean_key_source_error(work, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_can_prompt", lambda: True)

    def eof(prompt=""):
        raise EOFError
    monkeypatch.setattr(sources.getpass, "getpass", eof)
    assert cli.main(["encrypt", "plain.txt", *FAST]) == cli.EXIT_KEY_SOURCE
    assert "no terminal" in capsys.readouterr().err
    assert not (work / "plain.txt.fcx").exists()


def test_scrypt_option(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", "--kdf", "scrypt"]) == 0
    assert header_of(work / "plain.txt.fcx").kdf_id == SCRYPT
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt", "--key", "env:FC_PASS"]) == 0


def test_argon_flags_with_scrypt_rejected(work, capsys):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", "--kdf", "scrypt", *FAST]) == 2
    assert "argon" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("flags", [
    ["--argon-memory", "18"], ["--argon-iterations", "1"], ["--argon-parallelism", "0"],
    ["--argon-memory", "4097"], ["--argon-iterations", "17"], ["--argon-parallelism", "17"],
])
def test_argon_limits_enforced(work, flags, no_prompt):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *flags]) == 2
    assert not (work / "plain.txt.fcx").exists()


def test_short_passphrase_warns(work, monkeypatch, capsys):
    monkeypatch.setenv("FC_SHORT", "short")
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_SHORT", *FAST]) == 0
    assert "12" in capsys.readouterr().err


@pytest.mark.requires_argon2
def test_short_keyfile_rejected_unless_flag(work):
    (work / "weak.key").write_bytes(b"x" * 20)
    assert cli.main(["encrypt", "plain.txt", "--key", "file:weak.key"]) == 2
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
    assert cli.main(["decrypt", "blob.bin", "--key", "env:FC_PASS"]) == 2
    assert cli.main(["decrypt", "blob.bin", "-o", "x.txt", "--key", "env:FC_PASS"]) == 0


def test_same_input_and_output_rejected(work):
    assert cli.main(["encrypt", "plain.txt", "-o", "plain.txt", "--force", "--key", "env:FC_PASS"]) == 2
    assert (work / "plain.txt").read_bytes() == b"hello world\n" * 1000


def test_wrong_key_leaves_nothing_behind(work, monkeypatch, capsys):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    before = files_in(work)
    monkeypatch.setenv("FC_PASS", "the wrong passphrase")
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "out.txt", "--key", "env:FC_PASS"]) == 4
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
    assert cli.main(["decrypt", "big.bin.fcx", "-o", "out.bin", "--key", f"file:{keyfile}"]) == 5
    assert files_in(work) == before


def test_not_an_fcx_file_fails_before_prompting(work, no_prompt, capsys):
    assert cli.main(["decrypt", "plain.txt", "-o", "x"]) == 3
    assert "not an .fcx" in capsys.readouterr().err


def test_missing_input(work, capsys):
    assert cli.main(["encrypt", "nope.txt", "--key", "env:FC_PASS"]) == 8
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
    assert cli.main(["keygen", "b.key", "--bytes", "16"]) == 2
    assert not (work / "b.key").exists()
    assert cli.main(["keygen", "b.key", "--format", "base64"]) == 0
    assert (work / "b.key").read_bytes().endswith(b"\n")
    assert cli.main(["keygen"]) == 2  # neither a path nor --store


def test_keygen_store(work):
    assert cli.main(["keygen", "--store", "file:stored.key"]) == 0
    assert len((work / "stored.key").read_bytes()) == 32
    assert cli.main(["keygen", "--store", "prompt"]) == 7


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
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "a.txt", "--key", "env:FC_PASS"]) == 4
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "a.txt", "--key", f"file:{keyfile}"]) == 0
    assert (work / "a.txt").read_bytes() == (work / "plain.txt").read_bytes()
    assert files_in(work) == sorted(["a.txt", "k.key", "plain.txt", "plain.txt.fcx"])


@pytest.mark.requires_argon2
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
                     "--new-key", f"file:{keyfile}"]) == 4
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


def test_rekey_rotate_file_key(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    old = (work / "plain.txt.fcx").read_bytes()
    old_h = header_of(work / "plain.txt.fcx")
    assert cli.main(["rekey", "plain.txt.fcx", "--key", "env:FC_PASS",
                     "--new-key", f"file:{keyfile}", "--rotate-file-key"]) == 0
    new = (work / "plain.txt.fcx").read_bytes()
    new_h = header_of(work / "plain.txt.fcx")
    assert new_h.nonce_prefix != old_h.nonce_prefix
    assert new[new_h.header_len:] != old[old_h.header_len:]
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "a.txt", "--key", f"file:{keyfile}"]) == 0
    assert (work / "a.txt").read_bytes() == (work / "plain.txt").read_bytes()


def test_rekey_rotate_file_key_corrupted_exit_5(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "--key", f"file:{keyfile}"]) == 0
    blob = bytearray((work / "plain.txt.fcx").read_bytes())
    blob[-1] ^= 1
    (work / "plain.txt.fcx").write_bytes(bytes(blob))
    assert cli.main(["rekey", "plain.txt.fcx", "--key", f"file:{keyfile}",
                     "--new-key", "env:FC_PASS", "--rotate-file-key", *FAST]) == 5
    assert (work / "plain.txt.fcx").read_bytes() == bytes(blob)
    assert files_in(work) == sorted(["k.key", "plain.txt", "plain.txt.fcx"])


# --- output name safety ------------------------------------------------------

def test_decrypt_refuses_bidi_default_name(work, keyfile):
    evil = "invoice\u202efdp.exe"
    (work / evil).write_bytes(b"MZ not really")
    assert cli.main(["encrypt", evil, "--key", f"file:{keyfile}"]) == 2
    assert cli.main(["encrypt", evil, "-o", "x.fcx", "--key", f"file:{keyfile}"]) == 0
    (work / evil).unlink()
    (work / "x.fcx").rename(work / (evil + ".fcx"))
    assert cli.main(["decrypt", evil + ".fcx", "--key", f"file:{keyfile}"]) == 2
    assert not (work / evil).exists()
    assert cli.main(["decrypt", evil + ".fcx", "-o", "safe.bin", "--key", f"file:{keyfile}"]) == 0
    assert (work / "safe.bin").read_bytes() == b"MZ not really"


def test_unsafe_output_name_json(work, keyfile, capsys):
    import json
    assert cli.main(["encrypt", "plain.txt", "-o", "a\u202eb.fcx", "--key", f"file:{keyfile}",
                     "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["error"]["kind"] == "usage"
    assert "-o" in out["error"]["message"]


def test_rekey_refuses_unsafe_dash_o(work, keyfile):
    assert cli.main(["encrypt", "plain.txt", "--key", f"file:{keyfile}"]) == 0
    assert cli.main(["rekey", "plain.txt.fcx", "-o", "x\x1b.fcx", "--key", f"file:{keyfile}",
                     "--new-key", f"file:{keyfile}"]) == 2
    assert files_in(work) == sorted(["k.key", "plain.txt", "plain.txt.fcx"])


def test_windows_reserved_names_refused_on_windows(work, keyfile, monkeypatch):
    monkeypatch.setattr(engine, "_WINDOWS_NAMES", True)
    for name in ("NUL.txt", "out.txt:stream", "trailing. "):
        assert cli.main(["decrypt", "whatever.fcx", "-o", name, "--key", f"file:{keyfile}"]) == 2


# --- misc --------------------------------------------------------------------

def test_usage_errors_exit_2(capsys):
    assert cli.main([]) == 2
    assert cli.main(["frobnicate"]) == 2


def test_python_dash_m_version():
    out = subprocess.run([sys.executable, "-m", "filecrypt", "--version"],
                         capture_output=True, text=True, check=True)
    assert "filecrypt" in out.stdout


def test_scrypt_fallback_notice_on_stderr(work, monkeypatch, capsys):
    from filecrypt import kdf as kdf_mod
    monkeypatch.setattr(kdf_mod, "argon2_available", lambda: False)
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS"]) == 0
    assert header_of(work / "plain.txt.fcx").kdf_id == SCRYPT
    assert "argon2-cffi" in capsys.readouterr().err


# --- L2: confirm before costly KDF settings from an unauthenticated header ------

def make_heavy(path, memory_mib=2048, iterations=2):
    """Rewrite a file's Argon2id settings in place (the header isn't authenticated)."""
    blob = bytearray(path.read_bytes())
    blob[8:17] = Argon2Params(memory_mib * 1024, iterations, 1).encode()
    path.write_bytes(bytes(blob))


@pytest.fixture
def heavy_file(work):
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS", *FAST]) == 0
    make_heavy(work / "plain.txt.fcx")
    return work / "plain.txt.fcx"


@pytest.fixture
def no_derive(monkeypatch):
    calls = []

    def fake(kdf_id, settings, salt, secret):
        calls.append(kdf_id)
        return b"\x00" * 32  # wrong KEK: decrypt then fails authentication

    from filecrypt import kdf as kdf_mod
    monkeypatch.setattr(kdf_mod, "derive_kek", fake)
    return calls


@pytest.mark.requires_argon2
def test_heavy_file_refused_when_not_interactive(heavy_file, no_prompt, no_derive, capsys):
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt"]) == 6
    err = capsys.readouterr().err
    assert "2048 MiB" in err and "--max-kdf-memory" in err
    assert no_derive == []


def test_heavy_file_refused_above_explicit_limit(heavy_file, no_prompt, no_derive):
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt", "--max-kdf-memory", "1024"]) == 6
    assert no_derive == []


@pytest.mark.requires_argon2
def test_heavy_file_allowed_with_explicit_limit(heavy_file, no_derive):
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt", "--key", "env:FC_PASS",
                     "--max-kdf-memory", "4096"]) == 4   # fails later: fake KEK
    assert no_derive == [ARGON2ID]


@pytest.mark.requires_argon2
def test_heavy_file_interactive_confirm(heavy_file, no_derive, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    answers = []
    monkeypatch.setattr(cli, "_confirm", lambda prompt: answers.append(prompt) or False)
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt", "--key", "env:FC_PASS"]) == 6
    assert len(answers) == 1 and no_derive == []
    monkeypatch.setattr(cli, "_confirm", lambda prompt: True)
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt", "--key", "env:FC_PASS"]) == 4
    assert no_derive == [ARGON2ID]


def test_heavy_file_rekey_refused(heavy_file, keyfile, no_derive):
    assert cli.main(["rekey", str(heavy_file), "--key", "env:FC_PASS",
                     "--new-key", f"file:{keyfile}"]) == 6
    assert no_derive == []


def test_normal_file_not_questioned(work, monkeypatch):
    monkeypatch.setattr(cli, "_confirm", lambda prompt: pytest.fail("should not ask"))
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    assert cli.main(["encrypt", "plain.txt", "--key", "env:FC_PASS"]) == 0
    assert cli.main(["decrypt", "plain.txt.fcx", "-o", "b.txt", "--key", "env:FC_PASS"]) == 0


# --- L4: python -m filecrypt ignores code planted in the current folder -----------

def test_python_dash_m_ignores_current_folder(tmp_path):
    planted = tmp_path / "cryptography"
    planted.mkdir()
    marker = tmp_path / "PWNED"
    (planted / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').write('planted module ran')\n")
    out = subprocess.run([sys.executable, "-m", "filecrypt", "--version"], cwd=tmp_path,
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert not marker.exists()


# --- Mark of the Web ---------------------------------------------------------

@pytest.fixture
def motw_calls(monkeypatch):
    calls = []
    result = {"value": None}

    def fake(src, dest):
        calls.append((str(src), str(dest)))
        return result["value"]
    monkeypatch.setattr(cli._motw, "copy_zone_identifier", fake)
    return calls, result


def test_decrypt_copies_mark_of_the_web(work, keyfile, motw_calls, capsys):
    calls, _ = motw_calls
    assert cli.main(["encrypt", "plain.txt", "-o", "out.fcx", "--key", f"file:{keyfile}"]) == 0
    assert cli.main(["decrypt", "out.fcx", "-o", "back.txt", "--key", f"file:{keyfile}"]) == 0
    assert calls == [("out.fcx", "back.txt")]
    assert "mark" not in capsys.readouterr().err


def test_decrypt_warns_when_mark_cannot_be_copied(work, keyfile, motw_calls, capsys):
    _, result = motw_calls
    result["value"] = False
    assert cli.main(["encrypt", "plain.txt", "-o", "out.fcx", "--key", f"file:{keyfile}"]) == 0
    assert cli.main(["decrypt", "out.fcx", "-o", "back.txt", "-q",
                     "--key", f"file:{keyfile}"]) == 0
    err = capsys.readouterr().err
    assert "downloaded from the internet" in err and "back.txt" in err


def test_failed_decrypt_does_not_touch_mark(work, keyfile, motw_calls):
    calls, _ = motw_calls
    assert cli.main(["encrypt", "plain.txt", "-o", "out.fcx", "--key", f"file:{keyfile}"]) == 0
    assert cli.main(["keygen", "other.key"]) == 0
    assert cli.main(["decrypt", "out.fcx", "-o", "back.txt", "--key", "file:other.key"]) == 4
    assert calls == []


def test_cli_uses_the_shared_motw_helper():
    from filecrypt import _motw
    assert cli._motw is _motw


# --- yes/no questions fail cleanly with no terminal -----------------------------

class _BrokenStdin:
    def readline(self, *a):
        raise OSError("console detached")

    def isatty(self):
        return False


@pytest.mark.parametrize("stdin", [io.StringIO(""), _BrokenStdin(), None])
def test_confirm_without_input_is_no(stdin, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", stdin)
    assert cli._confirm("filecrypt: continue? [y/N] ") is False
    assert "taking it as no" in capsys.readouterr().err


@pytest.mark.parametrize("stdin", [io.StringIO("y\n"), None])
def test_piped_or_missing_stdin_is_not_interactive(stdin, monkeypatch):
    monkeypatch.setattr(sys, "stdin", stdin)
    assert cli._interactive() is False


@pytest.mark.requires_argon2
def test_heavy_file_no_answer_names_the_flag(heavy_file, no_derive, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["decrypt", str(heavy_file), "-o", "out.txt", "--key", "env:FC_PASS"]) == 6
    err = capsys.readouterr().err
    assert "--max-kdf-memory" in err and "Traceback" not in err
    assert no_derive == []
