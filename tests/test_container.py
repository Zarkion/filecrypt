import io
import os
import struct

import pytest

from filecrypt import container as c
from filecrypt.container import FormatError, AuthenticationError

KEK = bytes(range(32))
SALT = b"S" * 16
SETTINGS = struct.pack("<IIB", 19456, 2, 1)


def encrypt(data, chunk_size=c.DEFAULT_CHUNK_SIZE, kek=KEK, kdf_id=1, settings=SETTINGS, salts=None):
    out = io.BytesIO()

    def derive(salt):
        if salts is not None:
            salts.append(salt)
        return kek

    c.encrypt_stream(io.BytesIO(data), out, derive_kek=derive, kdf_id=kdf_id,
                     settings=settings, chunk_size=chunk_size)
    return out.getvalue()


def decrypt(blob, kek=KEK):
    src = io.BytesIO(blob)
    header = c.read_header(src)
    file_key = c.unwrap_file_key(header, kek)
    out = io.BytesIO()
    c.decrypt_body(header, file_key, src, out)
    return out.getvalue()


@pytest.mark.parametrize("size", [0, 1, 15, 16, 4095, 4096, 4097, 3 * 4096, 3 * 4096 + 7])
def test_round_trip_sizes(size):
    data = os.urandom(size)
    assert decrypt(encrypt(data, chunk_size=4096)) == data


def test_round_trip_default_chunk():
    data = os.urandom(200_000)
    assert decrypt(encrypt(data)) == data


def test_header_layout():
    salts = []
    blob = encrypt(b"hello", chunk_size=4096, salts=salts)
    assert len(salts) == 1 and len(salts[0]) == 16
    assert blob[:4] == b"FCX1"
    assert blob[4] == c.VERSION
    assert blob[5] == 1
    (slen,) = struct.unpack("<H", blob[6:8])
    assert slen == len(SETTINGS)
    off = 8
    assert blob[off:off + slen] == SETTINGS
    off += slen
    assert blob[off:off + 16] == salts[0]
    off += 16 + 48 + 7
    (chunk_size,) = struct.unpack("<I", blob[off:off + 4])
    assert chunk_size == 4096
    off += 4
    # single final chunk: 5 bytes plaintext + 16 tag
    assert len(blob) - off == 5 + 16


def test_empty_file_is_one_empty_final_chunk():
    blob = encrypt(b"")
    h = c.read_header(io.BytesIO(blob))
    assert len(blob) - h.header_len == 16


def test_exact_multiple_has_no_extra_empty_chunk():
    blob = encrypt(b"x" * 8192, chunk_size=4096)
    h = c.read_header(io.BytesIO(blob))
    assert len(blob) - h.header_len == 2 * (4096 + 16)


def test_fresh_file_key_and_nonce_each_time():
    a, b = encrypt(b"same"), encrypt(b"same")
    assert a != b


def test_wrong_kek_rejected():
    with pytest.raises(AuthenticationError):
        decrypt(encrypt(b"secret"), kek=b"\x00" * 32)


def test_bad_magic_and_version():
    blob = bytearray(encrypt(b"x"))
    with pytest.raises(FormatError):
        c.read_header(io.BytesIO(b"NOPE" + bytes(blob[4:])))
    blob[4] = 99
    with pytest.raises(FormatError):
        c.read_header(io.BytesIO(bytes(blob)))


def test_truncated_header():
    blob = encrypt(b"x")
    for n in (0, 3, 7, 20, 60):
        with pytest.raises(FormatError):
            c.read_header(io.BytesIO(blob[:n]))


def flip(blob, index):
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


def test_tampered_header_fields_break_key_unwrap():
    blob = encrypt(b"data")
    h = c.read_header(io.BytesIO(blob))
    # kdf_id, a settings byte, a salt byte, a wrapped-key byte
    for idx in (5, 8, 8 + len(SETTINGS), 8 + len(SETTINGS) + 16):
        bad = flip(blob, idx)
        with pytest.raises((AuthenticationError, FormatError)):
            hb = c.read_header(io.BytesIO(bad))
            c.unwrap_file_key(hb, KEK)


def test_tampered_nonce_prefix_breaks_chunks():
    blob = encrypt(b"data")
    h = c.read_header(io.BytesIO(blob))
    idx = h.header_len - 4 - 7  # first nonce-prefix byte
    with pytest.raises(AuthenticationError):
        decrypt(flip(blob, idx))


def test_tampered_ciphertext():
    blob = encrypt(os.urandom(10_000), chunk_size=4096)
    with pytest.raises(AuthenticationError):
        decrypt(flip(blob, len(blob) - 30))


def test_truncation_at_chunk_boundary_detected():
    blob = encrypt(os.urandom(3 * 4096 + 100), chunk_size=4096)
    h = c.read_header(io.BytesIO(blob))
    cut = h.header_len + 2 * (4096 + 16)
    with pytest.raises(AuthenticationError):
        decrypt(blob[:cut])


def test_chunk_reorder_detected():
    blob = encrypt(os.urandom(3 * 4096), chunk_size=4096)
    h = c.read_header(io.BytesIO(blob))
    n = 4096 + 16
    body = blob[h.header_len:]
    swapped = body[n:2 * n] + body[:n] + body[2 * n:]
    with pytest.raises(AuthenticationError):
        decrypt(blob[:h.header_len] + swapped)


def test_trailing_data_rejected():
    blob = encrypt(os.urandom(100), chunk_size=4096)
    with pytest.raises((FormatError, AuthenticationError)):
        decrypt(blob + b"extra")


def test_trailing_data_after_full_final_chunk_reports_trailing():
    blob = encrypt(b"y" * 4096, chunk_size=4096)
    with pytest.raises(FormatError, match="trailing"):
        decrypt(blob + os.urandom(4096 + 16))


def test_chunk_size_limits():
    with pytest.raises(ValueError):
        encrypt(b"x", chunk_size=10)
    with pytest.raises(ValueError):
        encrypt(b"x", chunk_size=c.MAX_CHUNK_SIZE + 1)
    blob = bytearray(encrypt(b"x"))
    h = c.read_header(io.BytesIO(bytes(blob)))
    struct.pack_into("<I", blob, h.header_len - 4, 0)
    with pytest.raises(FormatError):
        c.read_header(io.BytesIO(bytes(blob)))
    struct.pack_into("<I", blob, h.header_len - 4, c.MAX_CHUNK_SIZE + 1)
    with pytest.raises(FormatError):
        c.read_header(io.BytesIO(bytes(blob)))


def test_settings_length_cap():
    with pytest.raises(ValueError):
        encrypt(b"x", settings=b"\x00" * (c.MAX_SETTINGS_LEN + 1))


def test_rewrap_keeps_body_byte_identical():
    blob = encrypt(os.urandom(9000), chunk_size=4096)
    src = io.BytesIO(blob)
    h = c.read_header(src)
    fk = c.unwrap_file_key(h, KEK)
    new_kek = os.urandom(32)
    seen = []
    new_header = c.rewrap_header(h, fk, derive_kek=lambda s: seen.append(s) or new_kek,
                                 kdf_id=3, settings=b"")
    assert len(seen) == 1 and seen[0] != h.salt
    new_blob = new_header + blob[h.header_len:]
    assert new_blob[len(new_header):] == blob[h.header_len:]
    assert decrypt(new_blob, kek=new_kek) == decrypt(blob)
    with pytest.raises(AuthenticationError):
        decrypt(new_blob, kek=KEK)


def test_kek_must_be_32_bytes():
    with pytest.raises(ValueError):
        encrypt(b"x", kek=b"short")


# --- L1: the container owns the wrap salt -------------------------------------

def test_container_generates_fresh_salt_every_time():
    salts = []
    for _ in range(3):
        encrypt(b"x", salts=salts)
    assert len(set(salts)) == 3


def test_rewrap_salt_is_fresh_each_time():
    blob = encrypt(b"x")
    h = c.read_header(io.BytesIO(blob))
    fk = c.unwrap_file_key(h, KEK)
    seen = []
    for _ in range(3):
        c.rewrap_header(h, fk, derive_kek=lambda s: seen.append(s) or KEK, kdf_id=1, settings=SETTINGS)
    assert len(set(seen)) == 3 and h.salt not in seen


def test_callers_cannot_supply_a_salt():
    with pytest.raises(TypeError):
        c.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), derive_kek=lambda s: KEK,
                         kdf_id=1, settings=SETTINGS, salt=SALT)
    blob = encrypt(b"x")
    h = c.read_header(io.BytesIO(blob))
    with pytest.raises(TypeError):
        c.rewrap_header(h, c.unwrap_file_key(h, KEK), derive_kek=lambda s: KEK,
                        kdf_id=1, settings=SETTINGS, salt=SALT)
