"""Partial output after crashes (review L3)."""

import subprocess
import sys
import textwrap
import time

import pytest

from filecrypt import cli, engine

PASS = "a perfectly fine passphrase"
FAST = ["--argon-memory", "19", "--argon-iterations", "2", "--argon-parallelism", "1"]


def parts(d):
    return sorted(p.name for p in d.iterdir() if p.name.endswith(".part"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows delete-on-close")
def test_killed_process_leaves_no_part_file(tmp_path):
    script = textwrap.dedent(f"""
        import sys, time
        from pathlib import Path
        from filecrypt.engine import AtomicOutput
        with AtomicOutput(Path(r"{tmp_path}") / "out.txt", force=False) as out:
            out.file.write(b"plaintext that must not survive")
            out.file.flush()
            print("ready", flush=True)
            time.sleep(60)
    """)
    proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        assert len(parts(tmp_path)) == 1      # the temp file exists while writing
        proc.kill()                           # like closing the console window
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
    for _ in range(50):
        if not parts(tmp_path):
            break
        time.sleep(0.1)
    assert parts(tmp_path) == []
    assert not (tmp_path / "out.txt").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows delete-on-close")
def test_falls_back_when_delete_on_close_unsupported(tmp_path, monkeypatch):
    from filecrypt import _windelete
    monkeypatch.setattr(_windelete, "set_delete_on_close", lambda fd, enabled: False)
    with engine.AtomicOutput(tmp_path / "out.txt", force=False) as out:
        out.file.write(b"data")
        out.commit()
    assert (tmp_path / "out.txt").read_bytes() == b"data"
    assert parts(tmp_path) == []


def test_commit_and_abort_leave_no_part(tmp_path):
    with engine.AtomicOutput(tmp_path / "ok.txt", force=False) as out:
        out.file.write(b"data")
        out.commit()
    with pytest.raises(RuntimeError):
        with engine.AtomicOutput(tmp_path / "bad.txt", force=False) as out:
            out.file.write(b"data")
            raise RuntimeError("boom")
    assert (tmp_path / "ok.txt").read_bytes() == b"data"
    assert not (tmp_path / "bad.txt").exists()
    assert parts(tmp_path) == []


@pytest.fixture
def encrypted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FC_PASS", PASS)
    (tmp_path / "doc.txt").write_bytes(b"hello")
    assert cli.main(["encrypt", "doc.txt", "--key", "env:FC_PASS", *FAST]) == 0
    (tmp_path / "doc.txt").unlink()
    stale = tmp_path / ".doc.txt.k3j9x2.part"
    stale.write_bytes(b"leftover plaintext")
    return tmp_path, stale


def test_stale_part_reported_when_not_interactive(encrypted, capsys):
    d, stale = encrypted
    assert cli.main(["decrypt", "doc.txt.fcx", "--key", "env:FC_PASS"]) == 0
    err = capsys.readouterr().err
    assert stale.name in err and "interrupted" in err
    assert stale.exists()                       # never deleted without asking


def test_stale_part_deleted_when_confirmed(encrypted, monkeypatch):
    d, stale = encrypted
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    prompts = []
    monkeypatch.setattr(cli, "_confirm", lambda p: prompts.append(p) or True)
    assert cli.main(["decrypt", "doc.txt.fcx", "--key", "env:FC_PASS"]) == 0
    assert not stale.exists() and len(prompts) == 1
    assert (d / "doc.txt").read_bytes() == b"hello"


def test_stale_part_kept_when_declined(encrypted, monkeypatch):
    d, stale = encrypted
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(cli, "_confirm", lambda p: False)
    assert cli.main(["decrypt", "doc.txt.fcx", "--key", "env:FC_PASS"]) == 0
    assert stale.exists()


def test_unrelated_files_not_treated_as_stale(encrypted, monkeypatch):
    d, stale = encrypted
    stale.unlink()
    other = d / ".other.txt.abc.part"
    other.write_bytes(b"not ours")
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(cli, "_confirm", lambda p: pytest.fail("should not ask"))
    assert cli.main(["decrypt", "doc.txt.fcx", "--key", "env:FC_PASS"]) == 0
    assert other.exists()
