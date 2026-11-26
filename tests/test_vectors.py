"""The frozen .fcx version 1 test vectors in tests/vectors (see docs/FORMAT.md).

Every release must decrypt every valid vector and reject every invalid one at
the stage the manifest names. If a test here fails, the format changed: fix the
code, never the vectors.
"""

import importlib.util
import io
import json
from pathlib import Path

import pytest

from filecrypt import container, engine, kdf
from filecrypt.container import AuthenticationError, FormatError
from filecrypt.kdf import KDFError

VECTORS = Path(__file__).resolve().parent / "vectors"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text(encoding="ascii"))
ALL = MANIFEST["vectors"]
ARGON2 = kdf.argon2_available()


def _load_generator():
    spec = importlib.util.spec_from_file_location("fcx_vector_generator", VECTORS / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def needs_argon2(v, stage_reached=True):
    # Files rejected before any KDF work don't need an Argon2id backend.
    if v["kdf"] == "argon2id" and stage_reached and not ARGON2:
        pytest.skip("Argon2id unavailable in this install")


def ids(vs):
    return [v["name"] for v in vs]


VALID = [v for v in ALL if v["valid"]]
INVALID = [v for v in ALL if not v["valid"]]


def test_manifest_covers_every_file():
    named = {v["file"] for v in ALL} | {v["plaintext"] for v in VALID} | {"vectors.json"}
    on_disk = {p.name for p in VECTORS.iterdir() if p.suffix in (".fcx", ".plain", ".json")}
    assert on_disk == named
    assert len({v["name"] for v in ALL}) == len(ALL)
    assert {v["kdf"] for v in VALID} == {"argon2id", "scrypt", "hkdf-sha256"}
    assert {v["reject_at"] for v in INVALID} == {"header", "kdf", "key", "body"}


CASES = [(v, i) for v in VALID for i in range(len(v["secrets"]))]


@pytest.mark.parametrize("v,which", CASES,
                         ids=[f"{v['name']}-secret{i}" for v, i in CASES])
def test_valid_vector_decrypts(v, which, tmp_path):
    needs_argon2(v)
    src = VECTORS / v["file"]
    info = engine.inspect_file(src)
    assert info.kdf_name == v["kdf"]
    assert info.chunk_size == v["chunk_size"]
    secret = gen.secret_from_json(v["secrets"][which])
    out = engine.decrypt_file(src, tmp_path / "out", secret)
    expected = (VECTORS / v["plaintext"]).read_bytes()
    assert len(expected) == v["plaintext_len"]
    assert out.read_bytes() == expected


def _stage_reached(data, secret):
    """Run decryption step by step; return the stage that rejected the file, or None."""
    f = io.BytesIO(data)
    try:
        header = container.read_header(f)
    except FormatError:
        return "header"
    try:
        candidates = secret.unlock_candidates()
        keks = [kdf.derive_kek(header.kdf_id, header.settings, header.salt, c) for c in candidates]
    except KDFError:
        return "kdf"
    file_key = None
    for kek in keks:
        try:
            file_key = container.unwrap_file_key(header, kek)
            break
        except AuthenticationError:
            pass
    if file_key is None:
        return "key"
    try:
        container.decrypt_body(header, file_key, f, io.BytesIO())
    except (AuthenticationError, FormatError):
        return "body"
    return None


@pytest.mark.parametrize("v", INVALID, ids=ids(INVALID))
def test_invalid_vector_rejected_at_expected_stage(v):
    needs_argon2(v, stage_reached=v["reject_at"] in ("key", "body"))
    data = (VECTORS / v["file"]).read_bytes()
    assert _stage_reached(data, gen.secret_from_json(v["secret"])) == v["reject_at"]


@pytest.mark.parametrize("v", INVALID, ids=ids(INVALID))
def test_invalid_vector_rejected_by_engine(v, tmp_path):
    needs_argon2(v, stage_reached=v["reject_at"] in ("key", "body"))
    out = tmp_path / "out"
    with pytest.raises((FormatError, AuthenticationError, KDFError)):
        engine.decrypt_file(VECTORS / v["file"], out, gen.secret_from_json(v["secret"]),
                            kdf_memory_limit=64 * 1024**3, confirm_expensive=lambda r: True)
    assert not out.exists()
    assert list(tmp_path.iterdir()) == []


def test_over_cap_settings_never_run_the_kdf(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("KDF ran on over-cap settings")
    monkeypatch.setattr(kdf, "_argon2", boom)
    monkeypatch.setattr(kdf, "Scrypt", boom)
    for v in INVALID:
        if v["reject_at"] == "kdf":
            data = (VECTORS / v["file"]).read_bytes()
            assert _stage_reached(data, gen.secret_from_json(v["secret"])) == "kdf", v["name"]


def test_generator_reproduces_the_frozen_files():
    built = gen.build(include_argon2=ARGON2)
    for name, data in built.items():
        assert (VECTORS / name).read_bytes() == data, f"{name} no longer matches the generator"
