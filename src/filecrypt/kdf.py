"""Key derivation: turn a user secret into the 32-byte key-encryption key.

kdf_id 1  Argon2id   passphrases (default). settings: memory KiB u32, iterations u32, lanes u8
kdf_id 2  scrypt     passphrase fallback.   settings: log2(N) u8, r u32, p u32
kdf_id 3  HKDF-SHA256 high-entropy keys (keyfiles, key stores). settings: empty

All settings are little-endian. Settings in a file are read before anything is
authenticated, so decryption enforces hard caps to stop a crafted file from
demanding unbounded memory or time.
"""

from __future__ import annotations

import os
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, List, Literal, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ARGON2ID = 1
SCRYPT = 2
HKDF = 3

KDF_NAMES = {ARGON2ID: "argon2id", SCRYPT: "scrypt", HKDF: "hkdf-sha256"}

KEK_LEN = 32
MIN_KEY_BYTES = 32
MIN_PASSPHRASE_CHARS = 12
HKDF_INFO = b"filecrypt v1 key-encryption key"

KIB_PER_MIB = 1024
ARGON2_MIN_MEMORY_KIB = 19 * KIB_PER_MIB
ARGON2_MAX_MEMORY_KIB = 4 * 1024 * KIB_PER_MIB
ARGON2_MIN_ITERATIONS = 2
ARGON2_MAX_ITERATIONS = 16
ARGON2_MIN_LANES = 1
ARGON2_MAX_LANES = 16

# Encrypt floor: cost N*p of at least 2^16 with r >= 8 (default is OWASP's
# N=2^17, r=8, p=1).
SCRYPT_MIN_COST = 1 << 16
SCRYPT_MAX_LOG2N = 22
SCRYPT_MIN_R = 8
SCRYPT_MAX_R = 32
SCRYPT_MAX_P = 16
SCRYPT_MAX_MEMORY = 4 * 1024**3

# Total work cap: memory x passes (Argon2id iterations, scrypt p).
MAX_TOTAL_WORK = 16 * 1024**3
# Decrypt/rekey ask before running a KDF whose memory exceeds this (or half of
# physical RAM, whichever is lower), or whose total work exceeds 8x it.
DEFAULT_KDF_MEMORY_LIMIT = 1024**3
EXPENSIVE_WORK_FACTOR = 8


class KDFError(Exception):
    """Bad KDF parameters, unsupported KDF, or unsuitable key material."""


@dataclass(frozen=True)
class Secret:
    """Secret material from a key source.

    ``kind`` is "passphrase" for human-chosen text (prompt, env, stdin) and
    "key" for random key material (keyfiles, key stores).

    A passphrase that is valid UTF-8 is stored in Unicode NFC form, so the
    same accented passphrase gives the same bytes whether the keyboard or
    operating system produced composed or decomposed characters. If that
    changed the bytes, ``unnormalized`` keeps the bytes exactly as given:
    files made before passphrases were normalized used those, so decryption
    tries them second (see :meth:`unlock_candidates`). Keys are never
    normalized, and neither are passphrases that aren't valid UTF-8.
    """
    value: bytes
    kind: Literal["passphrase", "key"]
    unnormalized: Optional[bytes] = field(default=None, init=False, compare=False)

    def __post_init__(self) -> None:
        if self.kind == "passphrase":
            nfc = normalize_passphrase(self.value)
            if nfc != self.value:
                object.__setattr__(self, "unnormalized", self.value)
                object.__setattr__(self, "value", nfc)

    def unlock_candidates(self) -> List[bytes]:
        """Byte strings to try when opening a file: the NFC form, then the original."""
        return [self.value] if self.unnormalized is None else [self.value, self.unnormalized]

    def __repr__(self) -> str:  # never leak the value into logs/tracebacks
        return f"Secret(kind={self.kind!r}, len={len(self.value)})"


def normalize_passphrase(raw: bytes) -> bytes:
    """Return the NFC UTF-8 form of a passphrase, or ``raw`` unchanged if it isn't UTF-8."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    return unicodedata.normalize("NFC", text).encode("utf-8")


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int
    iterations: int
    parallelism: int

    _FMT = "<IIB"

    @classmethod
    def default(cls) -> "Argon2Params":
        return cls(64 * KIB_PER_MIB, 3, 4)

    @classmethod
    def from_cli(cls, memory_mib: Optional[int] = None, iterations: Optional[int] = None,
                 parallelism: Optional[int] = None) -> "Argon2Params":
        d = cls.default()
        return cls(
            d.memory_kib if memory_mib is None else memory_mib * KIB_PER_MIB,
            d.iterations if iterations is None else iterations,
            d.parallelism if parallelism is None else parallelism,
        )

    def encode(self) -> bytes:
        return struct.pack(self._FMT, self.memory_kib, self.iterations, self.parallelism)

    @classmethod
    def decode(cls, raw: bytes) -> "Argon2Params":
        if len(raw) != struct.calcsize(cls._FMT):
            raise KDFError("malformed Argon2id settings")
        return cls(*struct.unpack(cls._FMT, raw))

    def check_caps(self) -> None:
        if self.memory_kib > ARGON2_MAX_MEMORY_KIB:
            raise KDFError("Argon2id memory above the 4 GiB limit")
        if self.iterations > ARGON2_MAX_ITERATIONS:
            raise KDFError(f"Argon2id iterations above the limit of {ARGON2_MAX_ITERATIONS}")
        if self.parallelism > ARGON2_MAX_LANES:
            raise KDFError(f"Argon2id parallelism above the limit of {ARGON2_MAX_LANES}")
        # Argon2 itself requires memory >= 8 KiB per lane and at least one lane.
        if self.parallelism < 1 or self.iterations < 1 or self.memory_kib < 8 * self.parallelism:
            raise KDFError("invalid Argon2id settings")
        if self.memory_kib * 1024 * self.iterations > MAX_TOTAL_WORK:
            raise KDFError("Argon2id total work (memory x iterations) above the 16 GiB limit")

    def check_for_encrypt(self) -> None:
        if self.memory_kib < ARGON2_MIN_MEMORY_KIB:
            raise KDFError("Argon2id memory must be at least 19 MiB")
        if self.iterations < ARGON2_MIN_ITERATIONS:
            raise KDFError(f"Argon2id iterations must be at least {ARGON2_MIN_ITERATIONS}")
        if self.parallelism < ARGON2_MIN_LANES:
            raise KDFError("Argon2id parallelism must be at least 1")
        self.check_caps()


@dataclass(frozen=True)
class ScryptParams:
    log2n: int
    r: int
    p: int

    _FMT = "<BII"

    @classmethod
    def default(cls) -> "ScryptParams":
        return cls(17, 8, 1)  # 128 MiB, OWASP's first recommended setting

    def encode(self) -> bytes:
        return struct.pack(self._FMT, self.log2n, self.r, self.p)

    @classmethod
    def decode(cls, raw: bytes) -> "ScryptParams":
        if len(raw) != struct.calcsize(cls._FMT):
            raise KDFError("malformed scrypt settings")
        return cls(*struct.unpack(cls._FMT, raw))

    @property
    def memory_bytes(self) -> int:
        return 128 * self.r * (1 << self.log2n)

    def check_caps(self) -> None:
        if not 1 <= self.log2n <= SCRYPT_MAX_LOG2N:
            raise KDFError("scrypt N out of range")
        if not 1 <= self.r <= SCRYPT_MAX_R or not 1 <= self.p <= SCRYPT_MAX_P:
            raise KDFError("scrypt r or p out of range")
        if self.memory_bytes > SCRYPT_MAX_MEMORY:
            raise KDFError("scrypt memory above the 4 GiB limit")
        if self.memory_bytes * self.p > MAX_TOTAL_WORK:
            raise KDFError("scrypt total work (memory x p) above the 16 GiB limit")

    def check_for_encrypt(self) -> None:
        if self.r < SCRYPT_MIN_R or (1 << self.log2n) * self.p < SCRYPT_MIN_COST:
            raise KDFError("scrypt settings below the minimum (N*p >= 2^16 with r >= 8)")
        self.check_caps()


# --- Argon2id backends -------------------------------------------------------

def _native_argon2_available() -> bool:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        Argon2id(salt=b"\x00" * 16, length=32, iterations=1, lanes=1, memory_cost=8).derive(b"x")
        return True
    except Exception:
        return False


def _cffi_argon2_available() -> bool:
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ImportError:
        return False


def argon2_available() -> bool:
    return _native_argon2_available() or _cffi_argon2_available()


def _argon2_native(secret: bytes, salt: bytes, p: Argon2Params) -> bytes:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    return Argon2id(salt=salt, length=KEK_LEN, iterations=p.iterations,
                    lanes=p.parallelism, memory_cost=p.memory_kib).derive(secret)


def _argon2_cffi(secret: bytes, salt: bytes, p: Argon2Params) -> bytes:
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(secret, salt, time_cost=p.iterations, memory_cost=p.memory_kib,
                           parallelism=p.parallelism, hash_len=KEK_LEN, type=Type.ID)


def _argon2(secret: bytes, salt: bytes, p: Argon2Params) -> bytes:
    if _native_argon2_available():
        return _argon2_native(secret, salt, p)
    if _cffi_argon2_available():
        return _argon2_cffi(secret, salt, p)
    raise KDFError("Argon2id is unavailable: upgrade cryptography (>= 44) "
                   "or install argon2-cffi (pip install filecrypt[argon2])")


# --- public API --------------------------------------------------------------

def derive_kek(kdf_id: int, settings: bytes, salt: bytes, secret: bytes) -> bytes:
    """Derive the KEK. Settings are validated against decrypt-time caps."""
    if kdf_id == ARGON2ID:
        p = Argon2Params.decode(settings)
        p.check_caps()
        return _argon2(secret, salt, p)
    if kdf_id == SCRYPT:
        p = ScryptParams.decode(settings)
        p.check_caps()
        return Scrypt(salt=salt, length=KEK_LEN, n=1 << p.log2n, r=p.r, p=p.p).derive(secret)
    if kdf_id == HKDF:
        if settings:
            raise KDFError("malformed HKDF settings")
        if len(secret) < MIN_KEY_BYTES:
            raise KDFError(f"this file was encrypted with a key; keys must be at least "
                           f"{MIN_KEY_BYTES} bytes")
        return _HKDF(algorithm=hashes.SHA256(), length=KEK_LEN, salt=salt,
                     info=HKDF_INFO).derive(secret)
    raise KDFError(f"unknown KDF id {kdf_id}")


def select_kdf(secret: Secret, *, kdf: Optional[str] = None,
               argon: Optional[Argon2Params] = None,
               scrypt: Optional[ScryptParams] = None,
               keyfile_is_passphrase: bool = False,
               notify: Optional[Callable[[str], None]] = None) -> Tuple[int, bytes]:
    """Choose the KDF and its settings for encrypting with ``secret``.

    ``notify`` receives a one-line notice when Argon2id is unavailable and
    scrypt is used instead without being asked for.
    """
    treat_as_key = secret.kind == "key" and not keyfile_is_passphrase
    if treat_as_key:
        if len(secret.value) < MIN_KEY_BYTES:
            raise KDFError(f"key is {len(secret.value)} bytes; keys must be at least "
                           f"{MIN_KEY_BYTES} bytes (use --keyfile-is-passphrase to "
                           f"treat it as a passphrase)")
        if not key_looks_human_made(secret.value):
            return HKDF, b""
        # Text or a repeating pattern: HKDF alone would let an attacker guess
        # it billions of times a second, so stretch it like a passphrase.
        # The header records the KDF, so decryption needs no flag.
        if notify is not None:
            notify("notice: this key looks like text or a pattern rather than random "
                   "bytes, so it is stretched like a passphrase; for a random key use "
                   "'filecrypt keygen'")

    if kdf not in (None, "argon2id", "scrypt"):
        raise KDFError(f"unknown KDF {kdf!r} (choose argon2id or scrypt)")
    if kdf is None:
        kdf = "argon2id" if argon2_available() else "scrypt"
        if kdf == "scrypt" and notify is not None:
            notify("notice: Argon2id is unavailable, so scrypt is used; for Argon2id install "
                   "cryptography >= 44 or argon2-cffi (pip install filecrypt[argon2])")
    if kdf == "argon2id":
        if not argon2_available():
            raise KDFError("Argon2id is unavailable: upgrade cryptography (>= 44) "
                           "or install argon2-cffi (pip install filecrypt[argon2])")
        p = argon or Argon2Params.default()
        p.check_for_encrypt()
        return ARGON2ID, p.encode()
    sp = scrypt or ScryptParams.default()
    sp.check_for_encrypt()
    return SCRYPT, sp.encode()


#: A random key of 32 or more bytes almost surely holds this many distinct
#: byte values (32 random bytes average about 30); fewer means a pattern.
MIN_DISTINCT_KEY_BYTES = 16


def key_looks_human_made(value: bytes) -> bool:
    """True when key material is printable text or has too few distinct bytes.

    Random keys (``keygen`` output, decoded base64 keyfiles, ``fcxkey:v1:``
    entries) are almost never valid printable UTF-8 and use many distinct
    byte values, so they keep plain HKDF. A sentence in a .txt file, or a
    repeated byte, gets the passphrase KDF instead when encrypting.
    """
    if len(set(value)) < MIN_DISTINCT_KEY_BYTES:
        return True
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    text = text.lstrip("\ufeff")
    return bool(text) and all(ch.isprintable() or ch in "\t\r\n" for ch in text)


def passphrase_warning(secret: Secret) -> Optional[str]:
    if secret.kind != "passphrase":
        return None
    try:
        n = len(secret.value.decode("utf-8"))
    except UnicodeDecodeError:
        n = len(secret.value)
    if n < MIN_PASSPHRASE_CHARS:
        return (f"warning: passphrase is only {n} characters; "
                f"{MIN_PASSPHRASE_CHARS} or more is recommended")
    return None


# --- resource policy for unauthenticated settings (decrypt, rekey) -----------

def kdf_cost(kdf_id: int, settings: bytes) -> Tuple[int, int]:
    """Return (memory in bytes, passes) that deriving with these settings needs."""
    if kdf_id == ARGON2ID:
        p = Argon2Params.decode(settings)
        return p.memory_kib * 1024, p.iterations
    if kdf_id == SCRYPT:
        sp = ScryptParams.decode(settings)
        return sp.memory_bytes, sp.p
    return 0, 0


def physical_memory() -> Optional[int]:
    """Installed RAM in bytes, or None if it can't be determined."""
    try:
        if os.name == "nt":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            st = _MemStatus()
            st.dwLength = ctypes.sizeof(st)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullTotalPhys)
            return None
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        return None


def default_kdf_memory_limit() -> int:
    ram = physical_memory()
    if ram:
        return min(DEFAULT_KDF_MEMORY_LIMIT, ram // 2)
    return DEFAULT_KDF_MEMORY_LIMIT


def expensive_kdf_reason(kdf_id: int, settings: bytes, limit: int) -> Optional[str]:
    """Describe why these settings exceed ``limit``, or None if they don't."""
    memory, passes = kdf_cost(kdf_id, settings)
    if memory > limit or memory * passes > EXPENSIVE_WORK_FACTOR * limit:
        name = KDF_NAMES.get(kdf_id, str(kdf_id))
        return (f"this file's key derivation ({name}) needs {memory // 1024**2} MiB of memory "
                f"for {passes} pass{'es' if passes != 1 else ''}")
    return None
