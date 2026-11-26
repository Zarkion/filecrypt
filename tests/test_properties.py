"""Property-based and fuzz tests (Hypothesis).

Most tests drive the container directly with a stub key-encryption key so they
stay fast; a few go through the engine with HKDF keys. Failures are asserted
against the base classes ``AuthenticationError`` and ``FormatError`` (plus
``KDFError`` and ``EngineError`` where the KDF settings or engine are
involved), never a narrower subclass.

In CI (the ``CI`` environment variable is set, as GitHub Actions does) the
examples are derandomized so a run is reproducible; locally they are random.
"""

from __future__ import annotations

import hashlib
import io
import os
import random
import struct
import tempfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from filecrypt import container, engine, kdf  # noqa: E402
from filecrypt.container import AuthenticationError, FormatError  # noqa: E402
from filecrypt.kdf import KDFError  # noqa: E402

settings.register_profile(
    "filecrypt-dev", deadline=None, max_examples=60,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "filecrypt-ci", deadline=None, max_examples=60, derandomize=True, database=None,
    print_blob=True, suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("filecrypt-ci" if os.environ.get("CI") else "filecrypt-dev")

TAMPER_ERRORS = (AuthenticationError, FormatError)
MAX_HEADER_LEN = (8 + container.MAX_SETTINGS_LEN + container.SALT_LEN
                  + container.WRAPPED_KEY_LEN + container.NONCE_PREFIX_LEN + 4)


# --- helpers -----------------------------------------------------------------

def stub_kek(secret: bytes):
    """A cheap, deterministic KEK derivation: different secret, different KEK."""
    return lambda salt: hashlib.sha256(b"filecrypt-test" + secret + salt).digest()


KEK = stub_kek(b"right")
WRONG_KEK = stub_kek(b"wrong")


def encrypt(plain: bytes, chunk_size: int, derive=KEK) -> bytes:
    out = io.BytesIO()
    container.encrypt_stream(io.BytesIO(plain), out, derive_kek=derive, kdf_id=kdf.HKDF,
                             settings=b"", chunk_size=chunk_size)
    return out.getvalue()


def decrypt(blob: bytes, derive=KEK) -> bytes:
    src = io.BytesIO(blob)
    header = container.read_header(src)
    file_key = container.unwrap_file_key(header, derive(header.salt))
    out = io.BytesIO()
    container.decrypt_body(header, file_key, src, out)
    return out.getvalue()


def chunks_of(blob: bytes):
    """Split a container into (header bytes, [chunk bytes, ...])."""
    header = container.read_header(io.BytesIO(blob))
    body = blob[header.header_len:]
    full = header.chunk_size + container.TAG_LEN
    return blob[:header.header_len], [body[i:i + full] for i in range(0, len(body), full)]


def payload(seed: int, n: int) -> bytes:
    return random.Random(seed).getrandbits(8 * n).to_bytes(n, "little") if n else b""


chunk_sizes = st.sampled_from([container.MIN_CHUNK_SIZE, container.MIN_CHUNK_SIZE + 1, 1536, 4096])


@st.composite
def sized_plaintexts(draw, max_chunks: int = 4):
    """(chunk_size, plaintext) with lengths clustered on and around chunk boundaries."""
    chunk_size = draw(chunk_sizes)
    if draw(st.booleans()):
        n = draw(st.integers(0, max_chunks)) * chunk_size + draw(st.integers(-2, 2))
    else:
        n = draw(st.integers(0, max_chunks * chunk_size))
    n = max(0, n)
    return chunk_size, payload(draw(st.integers(0, 2**32)), n)


@st.composite
def multi_chunk(draw):
    """A plaintext that encrypts to at least two chunks."""
    chunk_size = draw(chunk_sizes)
    n = draw(st.integers(chunk_size + 1, 4 * chunk_size))
    return chunk_size, payload(draw(st.integers(0, 2**32)), n)


# --- round trips -------------------------------------------------------------

@given(sized_plaintexts())
def test_round_trip(case):
    chunk_size, plain = case
    blob = encrypt(plain, chunk_size)
    assert decrypt(blob) == plain


@given(sized_plaintexts())
def test_ciphertext_length_is_exact(case):
    chunk_size, plain = case
    blob = encrypt(plain, chunk_size)
    header_len = container.read_header(io.BytesIO(blob)).header_len
    # A full final chunk carries the last flag itself; only empty input gets an empty chunk.
    n_chunks = max(1, -(-len(plain) // chunk_size))
    assert len(blob) == header_len + len(plain) + n_chunks * container.TAG_LEN


@given(sized_plaintexts(max_chunks=2))
def test_encryptions_are_randomized(case):
    chunk_size, plain = case
    a, b = encrypt(plain, chunk_size), encrypt(plain, chunk_size)
    ha, hb = (container.read_header(io.BytesIO(x)) for x in (a, b))
    assert ha.salt != hb.salt and ha.nonce_prefix != hb.nonce_prefix
    assert a[ha.header_len:] != b[hb.header_len:]


@given(sized_plaintexts(max_chunks=2))
def test_rekey_keeps_body_and_switches_key(case):
    chunk_size, plain = case
    blob = encrypt(plain, chunk_size)
    header = container.read_header(io.BytesIO(blob))
    file_key = container.unwrap_file_key(header, KEK(header.salt))
    new_kek = stub_kek(b"new")
    rekeyed = container.rewrap_header(header, file_key, derive_kek=new_kek, kdf_id=kdf.HKDF,
                                      settings=b"") + blob[header.header_len:]
    assert rekeyed[-(len(blob) - header.header_len):] == blob[header.header_len:]
    assert decrypt(rekeyed, new_kek) == plain
    with pytest.raises(AuthenticationError):
        decrypt(rekeyed, KEK)


@settings(max_examples=15)
@given(sized_plaintexts(max_chunks=2))
def test_engine_round_trip_with_hkdf_key(case):
    _, plain = case  # the engine always uses the default chunk size
    key = kdf.Secret(os.urandom(32), "key")
    with tempfile.TemporaryDirectory() as d:
        src, enc, dec = Path(d, "in"), Path(d, "in.fcx"), Path(d, "out")
        src.write_bytes(plain)
        engine.encrypt_file(src, enc, key)
        engine.decrypt_file(enc, dec, key)
        assert dec.read_bytes() == plain
        with pytest.raises(AuthenticationError):
            engine.decrypt_file(enc, Path(d, "wrong"), kdf.Secret(os.urandom(32), "key"))
        assert not Path(d, "wrong").exists()


# --- tamper detection --------------------------------------------------------

@given(sized_plaintexts(max_chunks=2))
def test_wrong_key_fails(case):
    chunk_size, plain = case
    with pytest.raises(AuthenticationError):
        decrypt(encrypt(plain, chunk_size), WRONG_KEK)


@given(sized_plaintexts(max_chunks=3), st.data())
def test_any_byte_change_fails(case, data):
    chunk_size, plain = case
    blob = bytearray(encrypt(plain, chunk_size))
    i = data.draw(st.integers(0, len(blob) - 1), label="index")
    blob[i] ^= data.draw(st.integers(1, 255), label="xor")
    with pytest.raises(TAMPER_ERRORS):
        decrypt(bytes(blob))


@given(sized_plaintexts(max_chunks=3), st.data())
def test_any_truncation_fails(case, data):
    chunk_size, plain = case
    blob = encrypt(plain, chunk_size)
    cut = data.draw(st.integers(0, len(blob) - 1), label="cut")
    with pytest.raises(TAMPER_ERRORS):
        decrypt(blob[:cut])


@given(sized_plaintexts(max_chunks=2), st.binary(min_size=1, max_size=5000))
def test_any_appended_data_fails(case, extra):
    chunk_size, plain = case
    with pytest.raises(TAMPER_ERRORS):
        decrypt(encrypt(plain, chunk_size) + extra)


@given(sized_plaintexts(max_chunks=2), st.integers(1, 3))
def test_appended_copy_of_last_chunk_fails(case, copies):
    chunk_size, plain = case
    blob = encrypt(plain, chunk_size)
    _, chunks = chunks_of(blob)
    with pytest.raises(TAMPER_ERRORS):
        decrypt(blob + chunks[-1] * copies)


@given(multi_chunk(), st.data())
def test_reordered_chunks_fail(case, data):
    chunk_size, plain = case
    head, chunks = chunks_of(encrypt(plain, chunk_size))
    order = data.draw(st.permutations(range(len(chunks))), label="order")
    assume(list(order) != list(range(len(chunks))))
    with pytest.raises(TAMPER_ERRORS):
        decrypt(head + b"".join(chunks[i] for i in order))


@given(multi_chunk(), st.data())
def test_dropped_or_duplicated_chunk_fails(case, data):
    chunk_size, plain = case
    head, chunks = chunks_of(encrypt(plain, chunk_size))
    i = data.draw(st.integers(0, len(chunks) - 1), label="chunk")
    if data.draw(st.booleans(), label="drop"):
        changed = chunks[:i] + chunks[i + 1:]
    else:
        changed = chunks[:i + 1] + [chunks[i]] + chunks[i + 1:]
    with pytest.raises(TAMPER_ERRORS):
        decrypt(head + b"".join(changed))


@given(multi_chunk(), st.integers(0, 2**32))
def test_chunks_from_another_file_fail(case, seed):
    """Splicing in a chunk from a different file (different key and prefix) fails."""
    chunk_size, plain = case
    head_a, chunks_a = chunks_of(encrypt(plain, chunk_size))
    _, chunks_b = chunks_of(encrypt(payload(seed, 2 * chunk_size), chunk_size))
    with pytest.raises(TAMPER_ERRORS):
        decrypt(head_a + chunks_b[0] + b"".join(chunks_a[1:]))


# --- read_header fuzzing -----------------------------------------------------

class CountingReader(io.BytesIO):
    """Records the largest single read, to check caps are enforced before allocating."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.largest = 0

    def read(self, n=-1):
        assert n is not None and n >= 0, "read_header must never read to EOF"
        self.largest = max(self.largest, n)
        return super().read(n)


def _check_header_or_format_error(raw: bytes):
    reader = CountingReader(raw)
    try:
        header = container.read_header(reader)
    except FormatError:
        pass
    else:
        assert container.MIN_CHUNK_SIZE <= header.chunk_size <= container.MAX_CHUNK_SIZE
        assert len(header.settings) <= container.MAX_SETTINGS_LEN
        assert len(header.salt) == container.SALT_LEN
        assert len(header.wrapped_key) == container.WRAPPED_KEY_LEN
        assert len(header.nonce_prefix) == container.NONCE_PREFIX_LEN
        assert header.header_len == reader.tell() <= MAX_HEADER_LEN
    assert reader.largest <= MAX_HEADER_LEN


@given(st.binary(max_size=2048))
def test_read_header_on_random_bytes(raw):
    _check_header_or_format_error(raw)


@given(st.binary(max_size=1200))
def test_read_header_on_random_bytes_after_magic(raw):
    _check_header_or_format_error(container.MAGIC + raw)


@st.composite
def plausible_headers(draw):
    """Headers with valid magic and version but arbitrary field values and lengths."""
    settings_len = draw(st.one_of(st.integers(0, 64), st.integers(0, 0xFFFF),
                                  st.sampled_from([container.MAX_SETTINGS_LEN,
                                                   container.MAX_SETTINGS_LEN + 1, 0xFFFF])))
    chunk_size = draw(st.one_of(
        st.integers(0, 2**32 - 1),
        st.sampled_from([0, container.MIN_CHUNK_SIZE - 1, container.MIN_CHUNK_SIZE,
                         container.MAX_CHUNK_SIZE, container.MAX_CHUNK_SIZE + 1, 2**32 - 1])))
    body_len = min(settings_len, 64)
    raw = (container.MAGIC + bytes([draw(st.sampled_from([container.VERSION, 0, 2, 255])),
                                    draw(st.integers(0, 255))])
           + struct.pack("<H", settings_len)
           + draw(st.binary(min_size=body_len, max_size=body_len))
           + b"\x00" * (settings_len - body_len)
           + draw(st.binary(min_size=16 + 48 + 7, max_size=16 + 48 + 7))
           + struct.pack("<I", chunk_size))
    cut = draw(st.one_of(st.just(len(raw)), st.integers(0, len(raw))))
    return raw[:cut] + draw(st.binary(max_size=32))


@given(plausible_headers())
def test_read_header_on_plausible_headers(raw):
    _check_header_or_format_error(raw)


@given(st.integers(0, 0xFFFF))
def test_settings_length_cap_is_checked_before_reading(settings_len):
    # A huge declared length with nothing behind it must be rejected (or found
    # truncated) without asking the stream for more than the cap allows.
    raw = container.MAGIC + bytes([container.VERSION, kdf.HKDF]) + struct.pack("<H", settings_len)
    reader = CountingReader(raw)
    with pytest.raises(FormatError):
        container.read_header(reader)
    assert reader.largest <= MAX_HEADER_LEN


# --- KDF settings fuzzing ----------------------------------------------------

class _Recorded(Exception):
    pass


def _fake_backends(monkeypatch_calls):
    """Replace the real KDFs with recorders, so fuzzing never allocates."""
    def fake_argon2(secret, salt, p):
        monkeypatch_calls.append(("argon2id", p))
        raise _Recorded

    class FakeScrypt:
        def __init__(self, *, salt, length, n, r, p):
            monkeypatch_calls.append(("scrypt", (n, r, p)))
            raise _Recorded

    return fake_argon2, FakeScrypt


@given(st.integers(0, 255), st.binary(max_size=24), st.binary(max_size=64))
def test_derive_kek_enforces_caps_before_running_a_kdf(kdf_id, raw, secret):
    calls = []
    fake_argon2, fake_scrypt = _fake_backends(calls)
    real_argon2, real_scrypt = kdf._argon2, kdf.Scrypt
    kdf._argon2, kdf.Scrypt = fake_argon2, fake_scrypt
    try:
        try:
            kek = kdf.derive_kek(kdf_id, raw, b"\x00" * 16, secret)
        except (KDFError, _Recorded):
            pass
        else:
            assert kdf_id == kdf.HKDF and raw == b"" and len(secret) >= kdf.MIN_KEY_BYTES
            assert len(kek) == kdf.KEK_LEN
    finally:
        kdf._argon2, kdf.Scrypt = real_argon2, real_scrypt
    for name, p in calls:
        if name == "argon2id":
            assert 8 * p.parallelism <= p.memory_kib <= kdf.ARGON2_MAX_MEMORY_KIB
            assert 1 <= p.iterations <= kdf.ARGON2_MAX_ITERATIONS
            assert 1 <= p.parallelism <= kdf.ARGON2_MAX_LANES
            assert p.memory_kib * 1024 * p.iterations <= kdf.MAX_TOTAL_WORK
        else:
            n, r, p = p
            assert 2 <= n <= 1 << kdf.SCRYPT_MAX_LOG2N
            assert 1 <= r <= kdf.SCRYPT_MAX_R and 1 <= p <= kdf.SCRYPT_MAX_P
            assert 128 * r * n <= kdf.SCRYPT_MAX_MEMORY
            assert 128 * r * n * p <= kdf.MAX_TOTAL_WORK


@given(st.integers(0, 255), st.binary(max_size=24), st.integers(0, 2**34))
def test_kdf_cost_and_expensive_check_only_raise_kdf_error(kdf_id, raw, limit):
    try:
        memory, passes = kdf.kdf_cost(kdf_id, raw)
    except KDFError:
        return
    assert memory >= 0 and passes >= 0
    reason = kdf.expensive_kdf_reason(kdf_id, raw, limit)
    assert reason is None or isinstance(reason, str)


@given(st.integers(0, 2**32 - 1), st.integers(0, 2**32 - 1), st.integers(0, 255))
def test_argon2_settings_round_trip(memory, iterations, lanes):
    p = kdf.Argon2Params(memory, iterations, lanes)
    assert kdf.Argon2Params.decode(p.encode()) == p
    try:
        p.check_caps()
    except KDFError:
        return
    assert memory <= kdf.ARGON2_MAX_MEMORY_KIB and iterations <= kdf.ARGON2_MAX_ITERATIONS


@given(st.integers(0, 255), st.integers(0, 2**32 - 1), st.integers(0, 2**32 - 1))
def test_scrypt_settings_round_trip(log2n, r, p):
    sp = kdf.ScryptParams(log2n, r, p)
    assert kdf.ScryptParams.decode(sp.encode()) == sp
    try:
        sp.check_caps()
    except KDFError:
        return
    assert sp.memory_bytes <= kdf.SCRYPT_MAX_MEMORY


@st.composite
def headers_with_random_kdf(draw):
    """A real HKDF-encrypted file whose KDF id and settings were replaced."""
    kdf_id = draw(st.sampled_from([kdf.ARGON2ID, kdf.SCRYPT, kdf.HKDF, 0, 4, 255]))
    if kdf_id == kdf.ARGON2ID and draw(st.booleans()):
        raw = kdf.Argon2Params(draw(st.integers(0, 2048)), draw(st.integers(0, 20)),
                               draw(st.integers(0, 20))).encode()
    elif kdf_id == kdf.SCRYPT and draw(st.booleans()):
        raw = kdf.ScryptParams(draw(st.integers(0, 12)), draw(st.integers(0, 40)),
                               draw(st.integers(0, 20))).encode()
    else:
        raw = draw(st.binary(max_size=16))
    return kdf_id, raw


@settings(max_examples=40)
@given(headers_with_random_kdf(), st.binary(max_size=200))
def test_engine_decrypt_with_crafted_kdf_settings(kdf_case, plain):
    """Through the engine, crafted KDF settings give only documented errors."""
    kdf_id, raw = kdf_case
    key = kdf.Secret(os.urandom(32), "key")
    with tempfile.TemporaryDirectory() as d:
        src, enc, out = Path(d, "in"), Path(d, "in.fcx"), Path(d, "out")
        src.write_bytes(plain)
        engine.encrypt_file(src, enc, key)
        blob = enc.read_bytes()
        header = container.read_header(io.BytesIO(blob))
        crafted = (container.MAGIC + bytes([container.VERSION, kdf_id])
                   + struct.pack("<H", len(raw)) + raw + blob[8 + len(header.settings):])
        enc.write_bytes(crafted)
        if (kdf_id, raw) == (kdf.HKDF, b""):  # unchanged: must still decrypt
            engine.decrypt_file(enc, out, key)
            assert out.read_bytes() == plain
            return
        with pytest.raises((AuthenticationError, FormatError, KDFError, engine.EngineError)):
            # A 1 MiB limit with a refusing confirm keeps any real KDF run tiny.
            engine.decrypt_file(enc, out, key, kdf_memory_limit=1024**2,
                                confirm_expensive=lambda reason: False)
        assert not out.exists()


# --- nonce counter boundary --------------------------------------------------

@given(st.binary(min_size=7, max_size=7), st.integers(0, container.MAX_CHUNKS - 1),
       st.integers(0, container.MAX_CHUNKS - 1), st.booleans(), st.booleans())
def test_nonces_are_unique_per_counter_and_flag(prefix, c1, c2, last1, last2):
    n1 = container._nonce(prefix, c1, last1)
    n2 = container._nonce(prefix, c2, last2)
    assert len(n1) == len(n2) == 12
    assert (n1 == n2) == ((c1, last1) == (c2, last2))


def test_nonce_counter_boundary():
    prefix = b"\xAA" * 7
    top = container._nonce(prefix, container.MAX_CHUNKS - 1, True)
    assert top == prefix + b"\xff\xff\xff\xff\x01"
    assert container._nonce(prefix, 0, False) == prefix + b"\x00\x00\x00\x00\x00"
    for last in (False, True):
        with pytest.raises(ValueError):
            container._nonce(prefix, container.MAX_CHUNKS, last)


@pytest.mark.parametrize("n_chunks", [1, 2, 3])
def test_encrypt_stops_at_the_counter_limit(monkeypatch, n_chunks):
    # Shrink the counter space so the boundary is reachable in a test.
    monkeypatch.setattr(container, "MAX_CHUNKS", 3)
    size = container.MIN_CHUNK_SIZE
    plain = payload(n_chunks, (n_chunks - 1) * size + 1)
    assert decrypt(encrypt(plain, size)) == plain


def test_encrypt_refuses_to_wrap_the_counter(monkeypatch):
    monkeypatch.setattr(container, "MAX_CHUNKS", 3)
    size = container.MIN_CHUNK_SIZE
    with pytest.raises(ValueError):
        encrypt(payload(0, 3 * size + 1), size)  # needs 4 chunks


def test_decrypt_refuses_to_wrap_the_counter(monkeypatch):
    size = container.MIN_CHUNK_SIZE
    blob = encrypt(payload(1, 3 * size + 1), size)  # 4 chunks
    monkeypatch.setattr(container, "MAX_CHUNKS", 3)
    with pytest.raises((ValueError, AuthenticationError, FormatError)):
        decrypt(blob)
