import struct

import pytest

from filecrypt import kdf
from filecrypt.kdf import (
    ARGON2ID, SCRYPT, HKDF, Argon2Params, ScryptParams, Secret, KDFError,
)

SALT = b"s" * 16
FAST_ARGON = Argon2Params(memory_kib=19 * 1024, iterations=2, parallelism=1)
FAST_SCRYPT = ScryptParams(log2n=14, r=8, p=1)


# --- settings encoding -------------------------------------------------------

def test_argon2_settings_little_endian():
    p = Argon2Params(memory_kib=65536, iterations=3, parallelism=4)
    assert p.encode() == struct.pack("<IIB", 65536, 3, 4)
    assert Argon2Params.decode(p.encode()) == p


def test_scrypt_settings_little_endian():
    p = ScryptParams(log2n=16, r=8, p=1)
    assert p.encode() == struct.pack("<BII", 16, 8, 1)
    assert ScryptParams.decode(p.encode()) == p


@pytest.mark.parametrize("raw", [b"", b"\x00" * 8, b"\x00" * 10])
def test_argon2_decode_wrong_length(raw):
    with pytest.raises(KDFError):
        Argon2Params.decode(raw)


def test_argon2_default():
    d = Argon2Params.default()
    assert (d.memory_kib, d.iterations, d.parallelism) == (64 * 1024, 3, 4)


def test_argon2_from_cli_mib():
    assert Argon2Params.from_cli(memory_mib=128).memory_kib == 128 * 1024
    assert Argon2Params.from_cli().memory_kib == 64 * 1024


# --- floors and caps ---------------------------------------------------------

@pytest.mark.parametrize("p", [
    Argon2Params(19 * 1024 - 1, 3, 4),
    Argon2Params(64 * 1024, 1, 4),
    Argon2Params(64 * 1024, 3, 0),
])
def test_argon2_floor_rejected_on_encrypt(p):
    with pytest.raises(KDFError):
        p.check_for_encrypt()


@pytest.mark.parametrize("p", [
    Argon2Params(4 * 1024 * 1024 + 1, 3, 4),
    Argon2Params(64 * 1024, 17, 4),
    Argon2Params(64 * 1024, 3, 17),
])
def test_argon2_cap_rejected_on_encrypt_and_decrypt(p):
    with pytest.raises(KDFError):
        p.check_for_encrypt()
    with pytest.raises(KDFError):
        kdf.derive_kek(ARGON2ID, p.encode(), SALT, b"pw")


def test_argon2_caps_are_inclusive():
    # Each value may reach its cap, as long as total work stays within 16 GiB-passes.
    Argon2Params(4 * 1024 * 1024, 4, 16).check_for_encrypt()
    Argon2Params(1024 * 1024, 16, 16).check_for_encrypt()
    FAST_ARGON.check_for_encrypt()


def test_scrypt_limits():
    ScryptParams.default().check_for_encrypt()
    with pytest.raises(KDFError):
        ScryptParams(13, 8, 1).check_for_encrypt()
    with pytest.raises(KDFError):
        kdf.derive_kek(SCRYPT, ScryptParams(23, 8, 1).encode(), SALT, b"pw")
    with pytest.raises(KDFError):  # 2^22 * 128 * 16 = 8 GiB
        kdf.derive_kek(SCRYPT, ScryptParams(22, 16, 1).encode(), SALT, b"pw")


# --- derivation --------------------------------------------------------------

def test_argon2_derive_deterministic_and_salted():
    s = FAST_ARGON.encode()
    a = kdf.derive_kek(ARGON2ID, s, SALT, b"correct horse")
    assert len(a) == 32
    assert a == kdf.derive_kek(ARGON2ID, s, SALT, b"correct horse")
    assert a != kdf.derive_kek(ARGON2ID, s, b"t" * 16, b"correct horse")
    assert a != kdf.derive_kek(ARGON2ID, s, SALT, b"correct horsf")


def test_argon2_backends_agree():
    pytest.importorskip("argon2")
    if not kdf._native_argon2_available():
        pytest.skip("no native Argon2id in this cryptography build")
    s = FAST_ARGON
    native = kdf._argon2_native(b"pw", SALT, s)
    cffi = kdf._argon2_cffi(b"pw", SALT, s)
    assert native == cffi


def test_argon2_falls_back_to_cffi(monkeypatch):
    pytest.importorskip("argon2")
    monkeypatch.setattr(kdf, "_native_argon2_available", lambda: False)
    out = kdf.derive_kek(ARGON2ID, FAST_ARGON.encode(), SALT, b"pw")
    assert out == kdf._argon2_cffi(b"pw", SALT, FAST_ARGON)


def test_scrypt_derive():
    a = kdf.derive_kek(SCRYPT, FAST_SCRYPT.encode(), SALT, b"pw")
    assert len(a) == 32 and a != kdf.derive_kek(SCRYPT, FAST_SCRYPT.encode(), SALT, b"px")


def test_hkdf_derive_matches_reference():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as RefHKDF
    key = bytes(range(32))
    expected = RefHKDF(algorithm=hashes.SHA256(), length=32, salt=SALT,
                       info=kdf.HKDF_INFO).derive(key)
    assert kdf.derive_kek(HKDF, b"", SALT, key) == expected


def test_hkdf_rejects_short_key_and_settings():
    with pytest.raises(KDFError):
        kdf.derive_kek(HKDF, b"", SALT, b"x" * 31)
    with pytest.raises(KDFError):
        kdf.derive_kek(HKDF, b"\x01", SALT, b"x" * 32)


def test_unknown_kdf():
    with pytest.raises(KDFError):
        kdf.derive_kek(9, b"", SALT, b"pw")


# --- selection ---------------------------------------------------------------

def test_select_passphrase_defaults_to_argon2id():
    kdf_id, settings = kdf.select_kdf(Secret(b"pw", "passphrase"))
    assert kdf_id == ARGON2ID
    assert Argon2Params.decode(settings) == Argon2Params.default()


def test_select_custom_argon():
    kdf_id, settings = kdf.select_kdf(Secret(b"pw", "passphrase"), argon=FAST_ARGON)
    assert Argon2Params.decode(settings) == FAST_ARGON


def test_select_rejects_argon_below_floor():
    with pytest.raises(KDFError):
        kdf.select_kdf(Secret(b"pw", "passphrase"), argon=Argon2Params(1024, 3, 4))


def test_select_scrypt_on_request():
    kdf_id, settings = kdf.select_kdf(Secret(b"pw", "passphrase"), kdf="scrypt")
    assert kdf_id == SCRYPT
    assert ScryptParams.decode(settings) == ScryptParams.default()


def test_select_falls_back_to_scrypt_without_argon2(monkeypatch):
    monkeypatch.setattr(kdf, "argon2_available", lambda: False)
    assert kdf.select_kdf(Secret(b"pw", "passphrase"))[0] == SCRYPT
    with pytest.raises(KDFError):
        kdf.select_kdf(Secret(b"pw", "passphrase"), kdf="argon2id")


def test_select_key_uses_hkdf():
    assert kdf.select_kdf(Secret(b"k" * 32, "key")) == (HKDF, b"")


def test_select_short_key_rejected_unless_passphrase_mode():
    with pytest.raises(KDFError, match="32"):
        kdf.select_kdf(Secret(b"k" * 31, "key"))
    kdf_id, _ = kdf.select_kdf(Secret(b"k" * 31, "key"), keyfile_is_passphrase=True)
    assert kdf_id == ARGON2ID


def test_keyfile_is_passphrase_forces_passphrase_kdf_even_for_long_keys():
    kdf_id, _ = kdf.select_kdf(Secret(b"k" * 64, "key"), keyfile_is_passphrase=True)
    assert kdf_id == ARGON2ID


def test_short_passphrase_warning():
    assert kdf.passphrase_warning(Secret("short".encode(), "passphrase"))
    assert kdf.passphrase_warning(Secret("twelve chars".encode(), "passphrase")) is None
    # counted in characters, not bytes
    assert kdf.passphrase_warning(Secret("ééééééééééé".encode(), "passphrase"))
    assert kdf.passphrase_warning(Secret(b"x" * 5, "key")) is None


# --- M3: scrypt strength and fallback ------------------------------------------

def test_scrypt_default_is_owasp_strength():
    assert ScryptParams.default() == ScryptParams(17, 8, 1)


@pytest.mark.parametrize("p,ok", [
    (ScryptParams(17, 8, 1), True),
    (ScryptParams(16, 8, 1), True),   # N*p = 2^16
    (ScryptParams(15, 8, 2), True),
    (ScryptParams(14, 8, 4), True),
    (ScryptParams(15, 8, 1), False),  # N*p = 2^15
    (ScryptParams(14, 8, 3), False),
    (ScryptParams(17, 4, 1), False),  # r below 8
])
def test_scrypt_encrypt_floor_is_cost_based(p, ok):
    if ok:
        p.check_for_encrypt()
    else:
        with pytest.raises(KDFError):
            p.check_for_encrypt()


def test_select_reports_silent_fallback(monkeypatch):
    monkeypatch.setattr(kdf, "argon2_available", lambda: False)
    notes = []
    kdf_id, _ = kdf.select_kdf(Secret(b"pw", "passphrase"), notify=notes.append)
    assert kdf_id == SCRYPT
    assert len(notes) == 1 and "argon2-cffi" in notes[0] and "44" in notes[0]


def test_no_notice_when_scrypt_requested(monkeypatch):
    monkeypatch.setattr(kdf, "argon2_available", lambda: False)
    notes = []
    kdf.select_kdf(Secret(b"pw", "passphrase"), kdf="scrypt", notify=notes.append)
    assert notes == []


# --- L2: total work cap and cost reporting --------------------------------------

GIB = 1024**3


def test_kdf_cost():
    assert kdf.kdf_cost(ARGON2ID, Argon2Params(65536, 3, 4).encode()) == (64 * 1024**2, 3)
    assert kdf.kdf_cost(SCRYPT, ScryptParams(17, 8, 2).encode()) == (128 * 1024**2, 2)
    assert kdf.kdf_cost(HKDF, b"") == (0, 0)


@pytest.mark.parametrize("p", [
    Argon2Params(4 * 1024 * 1024, 5, 1),   # 4 GiB x 5 passes
    Argon2Params(2 * 1024 * 1024, 16, 1),  # 2 GiB x 16 passes
])
def test_argon2_total_work_capped(p):
    with pytest.raises(KDFError, match="total"):
        p.check_for_encrypt()
    with pytest.raises(KDFError, match="total"):
        kdf.derive_kek(ARGON2ID, p.encode(), SALT, b"pw")


def test_scrypt_total_work_capped():
    ScryptParams(22, 8, 4).check_caps()                # 4 GiB x 4 = the cap
    with pytest.raises(KDFError, match="total"):
        kdf.derive_kek(SCRYPT, ScryptParams(22, 8, 5).encode(), SALT, b"pw")


def test_default_memory_limit_uses_half_of_ram(monkeypatch):
    monkeypatch.setattr(kdf, "physical_memory", lambda: 1 * GIB)
    assert kdf.default_kdf_memory_limit() == GIB // 2
    monkeypatch.setattr(kdf, "physical_memory", lambda: 64 * GIB)
    assert kdf.default_kdf_memory_limit() == GIB
    monkeypatch.setattr(kdf, "physical_memory", lambda: None)
    assert kdf.default_kdf_memory_limit() == GIB


def test_physical_memory_detected():
    mem = kdf.physical_memory()
    assert mem is None or mem > 256 * 1024**2


@pytest.mark.parametrize("settings,limit,heavy", [
    (Argon2Params.default().encode(), GIB, False),
    (Argon2Params(2 * 1024 * 1024, 2, 1).encode(), GIB, True),     # 2 GiB > 1 GiB
    (Argon2Params(512 * 1024, 16, 1).encode(), GIB, False),        # 8 GiB-passes = 8 x limit
    (Argon2Params(768 * 1024, 16, 1).encode(), GIB, True),         # 12 GiB-passes > 8 x limit
    (Argon2Params(2 * 1024 * 1024, 2, 1).encode(), 4 * GIB, False),
])
def test_is_expensive(settings, limit, heavy):
    assert (kdf.expensive_kdf_reason(ARGON2ID, settings, limit) is not None) == heavy
