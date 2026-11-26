"""Cross-check filecrypt against tools/fcx_ref_decrypt.py.

The reference decryptor was written from docs/FORMAT.md alone, without
filecrypt's container code. If a test here fails, the spec and the code
disagree: find out which is wrong and fix that (FORMAT.md or filecrypt). Don't
change the reference to match filecrypt.
"""

import importlib.util
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from filecrypt import engine
from filecrypt.container import AuthenticationError, FormatError
from filecrypt.kdf import KDFError, Secret

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"
ALL = json.loads((VECTORS / "vectors.json").read_text(encoding="ascii"))["vectors"]
VALID = [v for v in ALL if v["valid"]]
INVALID = [v for v in ALL if not v["valid"]]
KEY = bytes(range(32))  # the key of every hkdf-* vector


def _load_reference():
    path = ROOT / "tools" / "fcx_ref_decrypt.py"
    spec = importlib.util.spec_from_file_location("fcx_ref_decrypt", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = _load_reference()
FILECRYPT_ERRORS = (FormatError, AuthenticationError, KDFError)


def ref_secret(entry):
    if entry["kind"] == "passphrase":
        return entry["utf8"].encode("utf-8"), True
    return bytes.fromhex(entry["hex"]), False


def fc_secret(entry):
    if entry["kind"] == "passphrase":
        return Secret(entry["utf8"].encode("utf-8"), "passphrase")
    return Secret(bytes.fromhex(entry["hex"]), "key")


def needs_argon2(v, stage):
    # Rejected before any KDF work: no Argon2id backend is needed.
    if v["kdf"] == "argon2id" and stage in ("ok", "key", "body") and not ref.argon2id_available():
        pytest.skip("no Argon2id implementation for the reference decryptor")


def ref_outcome(data, secret, is_passphrase):
    try:
        return "ok", ref.decrypt(data, secret, is_passphrase)
    except ref.RefError as e:
        return e.stage, None


def fc_outcome(data, secret, tmp_path):
    src, out = tmp_path / "in.fcx", tmp_path / "out"
    src.write_bytes(data)
    try:
        engine.decrypt_file(src, out, secret, force=True, kdf_memory_limit=64 * 1024**3,
                            confirm_expensive=lambda r: True)
    except FILECRYPT_ERRORS:
        assert not out.exists()
        return "rejected", None
    return "ok", out.read_bytes()


def assert_agree(data, ref_secret_, fc_secret_, tmp_path):
    r_stage, r_plain = ref_outcome(data, *ref_secret_)
    f_stage, f_plain = fc_outcome(data, fc_secret_, tmp_path)
    assert (r_stage == "ok") == (f_stage == "ok"), (r_stage, f_stage)
    assert r_plain == f_plain
    return r_stage, r_plain


# --- every frozen vector -------------------------------------------------------

CASES = [(v, i) for v in VALID for i in range(len(v["secrets"]))]


@pytest.mark.parametrize("v,which", CASES, ids=[f"{v['name']}-secret{i}" for v, i in CASES])
def test_valid_vector_matches(v, which, tmp_path):
    needs_argon2(v, "ok")
    entry = v["secrets"][which]
    data = (VECTORS / v["file"]).read_bytes()
    stage, plain = assert_agree(data, ref_secret(entry), fc_secret(entry), tmp_path)
    assert stage == "ok"
    assert plain == (VECTORS / v["plaintext"]).read_bytes()


@pytest.mark.parametrize("v", INVALID, ids=[v["name"] for v in INVALID])
def test_invalid_vector_matches(v, tmp_path):
    needs_argon2(v, v["reject_at"])
    data = (VECTORS / v["file"]).read_bytes()
    stage, _ = assert_agree(data, ref_secret(v["secret"]), fc_secret(v["secret"]), tmp_path)
    assert stage == v["reject_at"]


def test_reference_covers_every_vector():
    assert len(VALID) + len(INVALID) == len(ALL)
    assert {v["reject_at"] for v in INVALID} == {"header", "kdf", "key", "body"}


# --- the worked example in FORMAT.md -----------------------------------------

def test_worked_example():
    data = (VECTORS / "hkdf-key.fcx").read_bytes()
    h = ref.parse_header(data)
    assert h["header_len"] == 83 and len(data) == 2631
    assert h["salt"].hex() == "4351860295a35effe8bd95a9d07aa5ae"
    assert h["nonce_prefix"].hex() == "dc5b099810bf9f"
    assert h["chunk_size"] == 1024
    kek = ref.derive_kek(3, (), KEY, h["salt"])
    assert kek.hex() == "19b20a0b35291dde22e326bcdf02398b56463538cd6ef553159390d09f75c1e4"
    file_key = ref.unwrap(h, (), KEY, False)
    assert file_key.hex() == "e50d6d745cda0ab68116ad8e2921dae5adad52f16483acc12909a9224d6c936a"


# --- files filecrypt writes now -------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 2 * 65536, 2 * 65536 + 5])
def test_filecrypt_output_decrypts_with_reference(size, tmp_path):
    plain = bytes((i * 31 + 7) & 0xFF for i in range(size))
    src = tmp_path / "plain"
    src.write_bytes(plain)
    engine.encrypt_file(src, tmp_path / "c.fcx", Secret(KEY, "key"))
    data = (tmp_path / "c.fcx").read_bytes()
    assert ref.decrypt(data, KEY, False) == plain
    # FORMAT.md: an exact multiple of chunk_size ends with a full last chunk,
    # never an extra empty one.
    h = ref.parse_header(data)
    full_chunks, rest = divmod(size, h["chunk_size"])
    n_chunks = max(1, full_chunks + (1 if rest else 0))
    assert len(data) == h["header_len"] + size + 16 * n_chunks


# --- mutations: both must reject every changed or cut file -----------------------

def test_every_bit_flip_rejected_by_both(tmp_path):
    data = (VECTORS / "hkdf-key.fcx").read_bytes()
    secret = ({"kind": "key", "hex": KEY.hex()})
    for pos in range(len(data)):
        mutated = bytearray(data)
        mutated[pos] ^= 0x01
        stage, _ = assert_agree(bytes(mutated), ref_secret(secret), fc_secret(secret), tmp_path)
        assert stage != "ok", pos


def test_every_truncation_rejected_by_both(tmp_path):
    data = (VECTORS / "hkdf-key.fcx").read_bytes()
    secret = ({"kind": "key", "hex": KEY.hex()})
    for n in range(len(data)):
        stage, _ = assert_agree(data[:n], ref_secret(secret), fc_secret(secret), tmp_path)
        assert stage != "ok", n


def test_extra_empty_last_chunk_accepted_by_both(tmp_path):
    # FORMAT.md: an encryptor MUST NOT write an empty last chunk after a full
    # chunk, but filecrypt's decryptor accepts one (it authenticates) and other
    # decryptors MAY. Build such a file from hkdf-full-final and check both agree.
    data = (VECTORS / "hkdf-full-final.fcx").read_bytes()
    plain = (VECTORS / "hkdf-full-final.plain").read_bytes()
    h = ref.parse_header(data)
    file_key = ref.unwrap(h, (), KEY, False)
    aead = AESGCM(file_key)
    cs, prefix = h["chunk_size"], h["nonce_prefix"]
    aad = b"FCX1\x01" + prefix + struct.pack("<I", cs)
    n = len(plain) // cs
    assert n >= 1 and len(plain) == n * cs
    body = b"".join(aead.encrypt(prefix + struct.pack(">I", i) + b"\x00",
                                 plain[i * cs:(i + 1) * cs], aad) for i in range(n))
    body += aead.encrypt(prefix + struct.pack(">I", n) + b"\x01", b"", aad)
    crafted = data[:h["header_len"]] + body
    secret = {"kind": "key", "hex": KEY.hex()}
    stage, out = assert_agree(crafted, ref_secret(secret), fc_secret(secret), tmp_path)
    assert stage == "ok" and out == plain


# --- the command line ---------------------------------------------------------

def test_cli(tmp_path, capsys):
    out = tmp_path / "out"
    assert ref.main([str(VECTORS / "hkdf-key.fcx"), "--key-hex", KEY.hex(), "-o", str(out)]) == 0
    assert out.read_bytes() == (VECTORS / "hkdf-key.plain").read_bytes()
    assert ref.main([str(VECTORS / "bad-tag-bit.fcx"), "--key-hex", KEY.hex()]) == 1
    assert "rejected at body" in capsys.readouterr().err
