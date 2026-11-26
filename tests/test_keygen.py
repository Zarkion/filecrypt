import base64
import os
import stat
import sys

import pytest

from filecrypt import keygen


def test_generate_default_32_bytes_and_random():
    a, b = keygen.generate_key(), keygen.generate_key()
    assert len(a) == 32 and a != b


def test_generate_custom_length_and_minimum():
    assert len(keygen.generate_key(64)) == 64
    with pytest.raises(ValueError, match="32"):
        keygen.generate_key(31)


def test_encode_formats():
    k = os.urandom(32)
    assert keygen.encode_key(k, "raw") == k
    enc = keygen.encode_key(k, "base64")
    assert enc.endswith(b"\n") and base64.b64decode(enc.strip()) == k
    with pytest.raises(ValueError):
        keygen.encode_key(k, "hex")


def test_write_keyfile_exclusive(tmp_path):
    p = tmp_path / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    assert p.read_bytes() == b"a" * 32
    with pytest.raises(FileExistsError):
        keygen.write_keyfile(p, b"b" * 32)
    assert p.read_bytes() == b"a" * 32


def test_write_keyfile_force_overwrites(tmp_path):
    p = tmp_path / "k.key"
    keygen.write_keyfile(p, b"a" * 32)
    keygen.write_keyfile(p, b"b" * 32, force=True)
    assert p.read_bytes() == b"b" * 32
    assert [x.name for x in tmp_path.iterdir()] == ["k.key"]  # no temp left behind


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize("force", [False, True])
def test_write_keyfile_mode_0600(tmp_path, force):
    p = tmp_path / "k.key"
    if force:
        p.write_bytes(b"old")
        os.chmod(p, 0o644)
    keygen.write_keyfile(p, b"a" * 32, force=force)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_load_key_material_accepts_raw_and_base64():
    k = os.urandom(32)
    assert keygen.load_key_material(k) == k
    assert keygen.load_key_material(keygen.encode_key(k, "base64")) == k
    assert keygen.load_key_material(base64.b64encode(k) + b"\r\n") == k


def test_load_key_material_leaves_non_base64_alone():
    text = b"this is not base64 at all!!!!!!!!!!!!"
    assert keygen.load_key_material(text) == text
    short = base64.b64encode(b"x" * 16)  # valid base64 but decodes to < 32 bytes
    assert keygen.load_key_material(short) == short
