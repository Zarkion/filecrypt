"""Owner-only file permissions on Windows (review M2)."""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")

from filecrypt import cli, engine, keygen  # noqa: E402

if sys.platform == "win32":
    from filecrypt import _winacl


@pytest.fixture
def open_dir(tmp_path):
    """A folder whose inherited ACL lets Everyone read new files."""
    d = tmp_path / "shared"
    d.mkdir()
    subprocess.run(["icacls", str(d), "/grant", "*S-1-1-0:(OI)(CI)R"], check=True,
                   capture_output=True)
    return d


def assert_owner_only(path):
    sddl = _winacl.dacl_sddl(str(path))
    assert sddl.startswith("D:P"), sddl          # protected: nothing inherited
    sid = _winacl.current_user_sid()
    # SDDL writes the built-in Administrator account (RID 500) as "LA", not by
    # its SID. CI runners on GitHub run as that account.
    owner = ";;;LA)" if sid.endswith("-500") else f";;;{sid})"
    assert owner in sddl, sddl
    for broad in ("WD", "AU", "BU", "S-1-1-0"):   # Everyone, Authenticated Users, Users
        assert f";;;{broad})" not in sddl, sddl


def test_baseline_dir_really_is_open(open_dir):
    p = open_dir / "plain.txt"
    p.write_bytes(b"x")
    assert ";;;WD)" in _winacl.dacl_sddl(str(p))


def test_keyfile_is_owner_only(open_dir):
    p = open_dir / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert_owner_only(p)
    assert p.read_bytes() == b"a" * 32


def test_forced_keyfile_is_owner_only(open_dir):
    p = open_dir / "k.key"
    p.write_bytes(b"old")
    keygen.write_keyfile(p, b"b" * 32, force=True)
    assert_owner_only(p)
    assert p.read_bytes() == b"b" * 32


def _no_security_descriptor():
    raise OSError("no security descriptor")


def test_create_owner_only_acl_in_place_before_any_write(open_dir):
    p = open_dir / "new.bin"
    fd = _winacl.create_owner_only(p)
    try:
        assert p.stat().st_size == 0
        assert_owner_only(p)                 # already restricted while still empty
        assert not os.get_inheritable(fd)
        os.write(fd, b"a\nb\r\n")
    finally:
        os.close(fd)
    assert p.read_bytes() == b"a\nb\r\n"    # binary: no newline translation
    assert_owner_only(p)


def test_create_owner_only_is_exclusive(open_dir):
    p = open_dir / "taken.bin"
    p.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        _winacl.create_owner_only(p)
    assert p.read_bytes() == b"keep"


def test_create_owner_only_delete_on_close(open_dir):
    p = open_dir / "tmp.part"
    fd = _winacl.create_owner_only(p, delete_on_close=True)
    try:
        assert_owner_only(p)
        os.write(fd, b"secret")
        assert p.exists()
    finally:
        os.close(fd)
    assert not p.exists()


def test_create_owner_only_returns_none_without_descriptor(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "_owner_only_sd", _no_security_descriptor)
    p = open_dir / "new.bin"
    assert _winacl.create_owner_only(p) is None
    assert not p.exists()


@pytest.mark.parametrize("force", [False, True])
def test_keyfile_is_created_owner_only_not_restricted_later(open_dir, monkeypatch, force):
    """The DACL is set by CreateFileW, so nothing has to fix it up afterwards."""
    def fail(path):
        raise AssertionError("restrict_to_owner should not be needed")
    monkeypatch.setattr(_winacl, "restrict_to_owner", fail)
    p = open_dir / "k.key"
    if force:
        p.write_bytes(b"old")
    keygen.write_keyfile(p, b"c" * 32, force=force)
    assert_owner_only(p)
    assert p.read_bytes() == b"c" * 32


def test_restrict_fallback_when_create_unavailable(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "create_owner_only", lambda path, **kw: None)
    p = open_dir / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert_owner_only(p)
    assert p.read_bytes() == b"a" * 32


def test_icacls_fallback(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "_owner_only_sd", _no_security_descriptor)
    monkeypatch.setattr(_winacl, "_set_dacl_ctypes", lambda path: False)
    p = open_dir / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert_owner_only(p)


def test_warns_when_every_method_fails(open_dir, monkeypatch, capsys):
    monkeypatch.setattr(_winacl, "_owner_only_sd", _no_security_descriptor)
    monkeypatch.setattr(_winacl, "_set_dacl_ctypes", lambda path: False)
    monkeypatch.setattr(_winacl, "_set_dacl_icacls", lambda path: False)
    p = open_dir / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert p.read_bytes() == b"a" * 32
    assert "warning" in capsys.readouterr().err.lower()


def test_cli_keygen_owner_only(open_dir, monkeypatch):
    monkeypatch.chdir(open_dir)
    assert cli.main(["keygen", "cli.key"]) == 0
    assert_owner_only(open_dir / "cli.key")


# Output temp files (.part), which hold plaintext while decrypting.

def _no_restrict(path):
    raise AssertionError("restrict_to_owner should not be needed")


def test_part_file_owner_only_before_any_write(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "restrict_to_owner", _no_restrict)
    dest = open_dir / "out.txt"
    with engine.AtomicOutput(dest, force=False) as out:
        assert out._delete_on_close
        assert os.path.getsize(out._tmp) == 0
        assert_owner_only(out._tmp)
        out.file.write(b"plaintext")
        out.commit()
    assert dest.read_bytes() == b"plaintext"
    assert_owner_only(dest)


def test_part_file_owner_only_without_delete_on_close(open_dir, monkeypatch):
    from filecrypt import _windelete
    monkeypatch.setattr(_windelete, "set_delete_on_close", lambda fd, enabled: False)
    monkeypatch.setattr(_winacl, "restrict_to_owner", _no_restrict)
    dest = open_dir / "out.txt"
    with engine.AtomicOutput(dest, force=False) as out:
        assert not out._delete_on_close
        assert_owner_only(out._tmp)
        out.file.write(b"plaintext")
        out.commit()
    assert dest.read_bytes() == b"plaintext"
    assert_owner_only(dest)
    assert [p.name for p in open_dir.iterdir()] == ["out.txt"]


def test_part_file_abort_removes_it(open_dir):
    dest = open_dir / "out.txt"
    with pytest.raises(RuntimeError):
        with engine.AtomicOutput(dest, force=False) as out:
            out.file.write(b"plaintext")
            raise RuntimeError("boom")
    assert list(open_dir.iterdir()) == []


def test_part_file_restricted_when_descriptor_unavailable(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "_owner_only_sd", _no_security_descriptor)
    monkeypatch.setattr(_winacl, "_set_dacl_ctypes", lambda path: False)  # icacls only
    dest = open_dir / "out.txt"
    with engine.AtomicOutput(dest, force=False) as out:
        assert_owner_only(out._tmp)
        out.file.write(b"plaintext")
        out.commit()
    assert_owner_only(dest)


def test_cli_decrypt_output_owner_only(open_dir, monkeypatch):
    monkeypatch.chdir(open_dir)
    monkeypatch.setenv("FC_PASS", "a perfectly fine passphrase")
    fast = ["--argon-memory", "19", "--argon-iterations", "2", "--argon-parallelism", "1"]
    (open_dir / "doc.txt").write_bytes(b"secret")
    assert cli.main(["encrypt", "doc.txt", "--key", "env:FC_PASS", *fast]) == 0
    (open_dir / "doc.txt").unlink()
    assert cli.main(["decrypt", "doc.txt.fcx", "--key", "env:FC_PASS"]) == 0
    assert (open_dir / "doc.txt").read_bytes() == b"secret"
    assert_owner_only(open_dir / "doc.txt")
