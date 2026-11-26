"""engine.verify_file, FileInfo sizes, and the CLI's verify and info commands,
exit codes, --quiet and --json."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

from filecrypt import cli, container, engine, kdf, sources
from filecrypt.container import CorruptedFileError, FormatError, WrongKeyError
from filecrypt.engine import Cancelled, CancelToken, EncryptOptions, ExpensiveKDFError
from filecrypt.kdf import Argon2Params, Secret

PW = Secret(b"a perfectly fine passphrase", "passphrase")
KEY = Secret(bytes(range(32)), "key")
FAST = EncryptOptions(argon=Argon2Params(19 * 1024, 2, 1))
CHUNK = container.DEFAULT_CHUNK_SIZE

VECTORS = Path(__file__).resolve().parent / "vectors"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text(encoding="ascii"))


def _load_generator():
    spec = importlib.util.spec_from_file_location("fcx_vector_generator_v", VECTORS / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def boom(prompt=""):
        raise AssertionError("unexpected prompt")
    monkeypatch.setattr(sources.getpass, "getpass", boom)
    return tmp_path


def make(work, name, size, secret=KEY):
    data = os.urandom(size)
    (work / name).write_bytes(data)
    out = engine.encrypt_file(work / name, work / (name + ".fcx"), secret, options=FAST)
    return out, data


def flip(path, offset):
    b = bytearray(path.read_bytes())
    b[offset] ^= 1
    path.write_bytes(bytes(b))


# --- body_layout and FileInfo -------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7])
def test_inspect_reports_exact_sizes(work, size):
    out, _ = make(work, "f.bin", size)
    info = engine.inspect_file(out)
    assert info.plaintext_size == size
    assert info.chunk_count == max(1, -(-size // CHUNK))
    assert info.file_size == out.stat().st_size


def test_body_layout_rejects_impossible_lengths():
    assert engine.body_layout(0, 1024) is None              # no final chunk at all
    assert engine.body_layout(15, 1024) is None             # cut-off tag
    assert engine.body_layout(1040 + 5, 1024) is None       # cut-off second tag
    assert engine.body_layout(16, 1024) == (1, 0)
    assert engine.body_layout(1040, 1024) == (1, 1024)
    assert engine.body_layout(1040 + 17, 1024) == (2, 1025)


def test_inspect_truncated_body_has_unknown_size(work):
    out, _ = make(work, "f.bin", 1000)
    data = out.read_bytes()
    header_len = engine.inspect_file(out).header_len
    out.write_bytes(data[:header_len + 10])
    info = engine.inspect_file(out)
    assert info.plaintext_size is None and info.chunk_count is None


def test_file_info_docstring_says_unauthenticated():
    assert "authenticated" in engine.FileInfo.__doc__


# --- verify_file ----------------------------------------------------------------

def test_verify_ok_and_writes_nothing(work):
    out, data = make(work, "f.bin", 3 * CHUNK + 5)
    before = sorted(p.name for p in work.iterdir())
    result = engine.verify_file(out, KEY)
    assert result == engine.VerifyResult(4, len(data))
    assert sorted(p.name for p in work.iterdir()) == before


@pytest.mark.requires_argon2
def test_verify_passphrase_and_callable_secret(work):
    out, data = make(work, "f.bin", 1000, PW)
    asked = []
    assert engine.verify_file(out, lambda: asked.append(1) or PW).plaintext_size == 1000
    assert asked == [1]


def test_verify_wrong_key(work):
    out, _ = make(work, "f.bin", 1000)
    with pytest.raises(WrongKeyError):
        engine.verify_file(out, Secret(bytes(32), "key"))


def test_verify_short_secret_on_key_file_is_wrong_key(work):
    out, _ = make(work, "f.bin", 1000)
    with pytest.raises(WrongKeyError, match="key of at least 32 bytes"):
        engine.verify_file(out, Secret(b"a passphrase", "passphrase"))


def test_verify_retries_like_decrypt(work):
    out, _ = make(work, "f.bin", 1000)
    answers = iter([Secret(bytes(32), "key"), KEY])
    wrong = []
    engine.verify_file(out, lambda: next(answers), max_attempts=3, on_wrong_key=wrong.append)
    assert wrong == [1]


@pytest.mark.parametrize("where", ["body", "tail"])
def test_verify_detects_damage(work, where):
    out, _ = make(work, "f.bin", 3 * CHUNK)
    flip(out, -1 if where == "tail" else engine.inspect_file(out).header_len + 100)
    with pytest.raises(CorruptedFileError):
        engine.verify_file(out, KEY)


def test_verify_detects_truncation_and_trailing_data(work):
    out, _ = make(work, "f.bin", 3 * CHUNK)
    data = out.read_bytes()
    out.write_bytes(data[:-(CHUNK + 16)])         # drop the whole final chunk
    with pytest.raises(CorruptedFileError):
        engine.verify_file(out, KEY)
    out.write_bytes(data + b"x" * 40)
    with pytest.raises(CorruptedFileError):
        engine.verify_file(out, KEY)


def test_verify_checks_kdf_cost_before_asking(work):
    heavy = Argon2Params(4096 * 1024, 2, 1).encode()
    header = container._key_aad(kdf.ARGON2ID, heavy, bytes(16)) + bytes(48) + bytes(7) \
        + CHUNK.to_bytes(4, "little")
    (work / "h.fcx").write_bytes(header + bytes(16))
    with pytest.raises(ExpensiveKDFError):
        engine.verify_file(work / "h.fcx", lambda: pytest.fail("asked for a secret"),
                           kdf_memory_limit=1024**3)
    with pytest.raises(Cancelled):
        engine.verify_file(work / "h.fcx", lambda: pytest.fail("asked for a secret"),
                           kdf_memory_limit=1024**3, confirm_expensive=lambda reason: False)


def test_verify_cancel_and_progress(work):
    out, _ = make(work, "f.bin", 3 * CHUNK)
    seen = []
    engine.verify_file(out, KEY, progress=lambda d, t: seen.append((d, t)))
    assert seen[-1][0] == seen[-1][1] == out.stat().st_size - engine.inspect_file(out).header_len
    token = CancelToken()
    token.cancel()
    with pytest.raises(Cancelled):
        engine.verify_file(out, KEY, cancel=token)


def test_verify_rejects_non_fcx(work):
    (work / "x.txt").write_bytes(b"hello")
    with pytest.raises(FormatError):
        engine.verify_file(work / "x.txt", KEY)


VALID = [(v, i) for v in MANIFEST["vectors"] if v["valid"] for i in range(len(v["secrets"]))]
BODY_BAD = [v for v in MANIFEST["vectors"] if not v["valid"] and v["reject_at"] == "body"]


@pytest.mark.parametrize("v,which", VALID, ids=[f"{v['name']}-{i}" for v, i in VALID])
def test_vectors_verify_and_sizes_match(v, which):
    if v["kdf"] == "argon2id" and not kdf.argon2_available():
        pytest.skip("Argon2id unavailable in this install")
    src = VECTORS / v["file"]
    info = engine.inspect_file(src)
    assert info.plaintext_size == v["plaintext_len"]
    result = engine.verify_file(src, gen.secret_from_json(v["secrets"][which]))
    assert result.plaintext_size == v["plaintext_len"]
    assert result.chunk_count == info.chunk_count


@pytest.mark.parametrize("v", BODY_BAD, ids=[v["name"] for v in BODY_BAD])
def test_damaged_vectors_fail_verify(v):
    if v["kdf"] == "argon2id" and not kdf.argon2_available():
        pytest.skip("Argon2id unavailable in this install")
    with pytest.raises(CorruptedFileError):
        engine.verify_file(VECTORS / v["file"], gen.secret_from_json(v["secret"]))


# --- CLI: verify and info -----------------------------------------------------

@pytest.fixture
def keyed(work):
    assert cli.main(["keygen", "k.key", "-q"]) == 0
    (work / "doc.txt").write_bytes(b"x" * 100_000)
    assert cli.main(["encrypt", "doc.txt", "--key", "file:k.key", "-q"]) == 0
    return work


def test_cli_verify_ok(keyed, capsys):
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:k.key"]) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "100000 bytes" in out
    assert sorted(p.name for p in keyed.iterdir()) == ["doc.txt", "doc.txt.fcx", "k.key"]


def test_cli_verify_quiet_prints_nothing(keyed, capsys):
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:k.key", "--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_cli_verify_json(keyed, capsys):
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:k.key", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"ok": True, "command": "verify", "input": "doc.txt.fcx",
                      "authenticated": True, "chunk_count": 2, "plaintext_size": 100_000}


def test_cli_verify_damaged_exit_5_and_json_error(keyed, capsys):
    flip(keyed / "doc.txt.fcx", -50)
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:k.key", "--json"]) == 5
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["ok"] is False and result["exit_code"] == 5
    assert result["error"]["kind"] == "corrupted"
    assert "damaged" in captured.err


def test_cli_wrong_key_exit_4_never_claims_which(keyed, capsys):
    assert cli.main(["keygen", "other.key", "-q"]) == 0
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:other.key", "--json"]) == 4
    result = json.loads(capsys.readouterr().out)
    assert result["error"]["kind"] == "wrong_key_or_modified_header"
    assert "modified" in result["error"]["message"]


def test_cli_info(keyed, capsys):
    assert cli.main(["info", "doc.txt.fcx"]) == 0
    out = capsys.readouterr().out
    assert "a key" in out and "HKDF-SHA256" in out
    assert "100000 bytes in 2 chunks" in out and "authenticated" in out


@pytest.mark.requires_argon2
def test_cli_info_passphrase_json(work, monkeypatch, capsys):
    monkeypatch.setenv("FC_PASS", PW.value.decode())
    (work / "p.txt").write_bytes(b"")
    assert cli.main(["encrypt", "p.txt", "--key", "env:FC_PASS", "--argon-memory", "19",
                     "--argon-iterations", "2", "--argon-parallelism", "1", "-q"]) == 0
    capsys.readouterr()
    assert cli.main(["info", "p.txt.fcx", "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["kdf"] == "argon2id" and r["needs"] == "passphrase"
    assert r["kdf_memory"] == 19 * 1024**2 and r["kdf_passes"] == 2
    assert r["plaintext_size"] == 0 and r["chunk_count"] == 1
    assert r["authenticated"] is False
    assert cli.main(["info", "p.txt.fcx"]) == 0
    assert "19 MiB, 2 iterations, 1 lane" in capsys.readouterr().out


def test_cli_info_needs_no_key(keyed):
    os.remove(keyed / "k.key")
    assert cli.main(["info", "doc.txt.fcx", "-q"]) == 0


def test_cli_info_truncated(keyed, capsys):
    p = keyed / "doc.txt.fcx"
    p.write_bytes(p.read_bytes()[:-(34_464 + 16 - 5)])   # 5 bytes of the last chunk remain
    assert cli.main(["info", str(p), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["plaintext_size"] is None


# --- CLI: exit codes ------------------------------------------------------------

def test_exit_format_error(work, capsys):
    (work / "x.txt").write_bytes(b"not fcx at all")
    assert cli.main(["info", "x.txt"]) == 3
    assert cli.main(["verify", "x.txt", "--key", "env:NOPE"]) == 3


def test_exit_io_error(work):
    assert cli.main(["info", "missing.fcx"]) == 8
    assert cli.main(["encrypt", "missing.txt", "--key", "env:NOPE"]) == 8


def test_exit_key_source_error(keyed, monkeypatch):
    monkeypatch.delenv("FC_UNSET_VAR", raising=False)
    assert cli.main(["verify", "doc.txt.fcx", "--key", "env:FC_UNSET_VAR"]) == 7
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:nope.key"]) == 7


def test_exit_usage(work):
    assert cli.main(["verify"]) == 2
    assert cli.main(["info", "a", "--bogus"]) == 2


def test_exit_output_exists(keyed):
    assert cli.main(["encrypt", "doc.txt", "--key", "file:k.key"]) == 1


def test_exit_interrupted(keyed, monkeypatch, capsys):
    def interrupt(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(engine, "verify_file", interrupt)
    assert cli.main(["verify", "doc.txt.fcx", "--key", "file:k.key", "--json"]) == 130
    assert json.loads(capsys.readouterr().out)["error"]["kind"] == "interrupted"


def test_every_exit_code_has_a_json_kind():
    codes = {getattr(cli, n) for n in dir(cli) if n.startswith("EXIT_") and n != "EXIT_HELP"}
    assert codes - {cli.EXIT_OK} == set(cli.ERROR_KINDS)


def test_readme_documents_every_exit_code():
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    for code in cli.ERROR_KINDS:
        assert f"| {code} |" in readme, code


# --- CLI: --json and --quiet on the other commands ----------------------------

def test_json_escapes_odd_file_names(work, capsys):
    name = 'we"ird\\näme\t.txt'
    try:
        (work / name).write_bytes(b"data")
    except OSError:
        pytest.skip("this filesystem doesn't allow such names")
    assert cli.main(["keygen", "k.key", "-q"]) == 0
    assert cli.main(["encrypt", name, "--key", "file:k.key", "--json"]) == 0
    line = capsys.readouterr().out
    assert line.count("\n") == 1 and line.isascii()
    r = json.loads(line)
    assert r["input"] == name and r["output"] == name + ".fcx"


def test_json_decrypt_and_rekey(keyed, capsys):
    assert cli.main(["keygen", "new.key", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["bytes"] == 32
    assert cli.main(["rekey", "doc.txt.fcx", "--key", "file:k.key", "--new-key", "file:new.key",
                     "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["output"] == "doc.txt.fcx"
    assert cli.main(["decrypt", "doc.txt.fcx", "-o", "back.txt", "--key", "file:new.key",
                     "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "command": "decrypt",
                                                   "input": "doc.txt.fcx", "output": "back.txt"}


def test_quiet_hides_notices_not_errors(work, capsys):
    assert cli.main(["keygen", "a.key", "--quiet"]) == 0
    assert capsys.readouterr().err == ""
    assert cli.main(["keygen", "a.key", "--quiet"]) == 1
    assert "already exists" in capsys.readouterr().err


@pytest.mark.requires_argon2
def test_quiet_hides_short_passphrase_warning(work, monkeypatch, capsys):
    monkeypatch.setenv("FC_PASS", "short")
    (work / "s.txt").write_bytes(b"x")
    fast = ["--argon-memory", "19", "--argon-iterations", "2", "--argon-parallelism", "1"]
    assert cli.main(["encrypt", "s.txt", "--key", "env:FC_PASS", *fast]) == 0
    assert "warning" in capsys.readouterr().err
    assert cli.main(["encrypt", "s.txt", "--key", "env:FC_PASS", "--force", "-q", *fast]) == 0
    assert capsys.readouterr().err == ""
