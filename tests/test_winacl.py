"""Owner-only keyfile permissions on Windows (review M2)."""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")

from filecrypt import cli, keygen  # noqa: E402

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


def test_icacls_fallback(open_dir, monkeypatch):
    monkeypatch.setattr(_winacl, "_set_dacl_ctypes", lambda path: False)
    p = open_dir / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert_owner_only(p)


def test_warns_when_both_methods_fail(open_dir, monkeypatch, capsys):
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
