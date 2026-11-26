"""Generate the frozen .fcx version 1 test vectors in this directory.

    python tests/vectors/generate.py            # (re)write the vectors
    python tests/vectors/generate.py --check    # verify the files on disk match

The vectors are frozen: once committed they must never change, because they
stand for files that real users already have. ``tests/test_vectors.py``
decrypts every valid vector, checks that every invalid one is rejected at the
expected stage, and runs this generator in memory to confirm it still produces
the committed bytes (which also pins the encryption side of the format).

Randomness (salt, file key, nonce prefix, plaintexts) comes from a
deterministic generator seeded by each vector's name, so the output is
reproducible. Real files always use ``os.urandom``.

KDF settings are the cheapest ones filecrypt lets you encrypt with (its
encryption floors), so every vector is a file a released filecrypt could
have written: Argon2id 19 MiB, 2 iterations, 1 lane; scrypt N=2^16, r=8, p=1.
See docs/FORMAT.md for the format and vectors.json for what each file is.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import types
import unicodedata
from pathlib import Path
from typing import Callable, Dict, List, Optional

from filecrypt import container, kdf
from filecrypt.kdf import Argon2Params, ScryptParams, Secret

HERE = Path(__file__).resolve().parent
MANIFEST = "vectors.json"

ARGON = Argon2Params(19 * 1024, 2, 1)
SCRYPT = ScryptParams(16, 8, 1)
PASSPHRASE = "correct horse battery staple"
NFC_PASSPHRASE = "crème brûlée for the café"
NFD_PASSPHRASE = unicodedata.normalize("NFD", NFC_PASSPHRASE)
KEY = bytes(range(32))                                   # 000102...1f
WRONG_KEY = bytes(range(1, 33))


# --- deterministic randomness -------------------------------------------------

def drbg(label: str) -> Callable[[int], bytes]:
    """SHA-256 in counter mode, seeded by ``label``. Not for real keys."""
    state = {"counter": 0}

    def read(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(f"filecrypt test vector:{label}:{state['counter']}".encode()).digest()
            state["counter"] += 1
        return out[:n]

    return read


def plaintext(label: str, size: int) -> bytes:
    return drbg("plaintext:" + label)(size)


def encrypt(label: str, data: bytes, kdf_id: int, settings: bytes, secret: bytes,
            chunk_size: int) -> bytes:
    """Encrypt with the real container code, with seeded randomness."""
    real_os = container.os
    container.os = types.SimpleNamespace(urandom=drbg("random:" + label))
    try:
        out = io.BytesIO()
        container.encrypt_stream(io.BytesIO(data), out, kdf_id=kdf_id, settings=settings,
                                 chunk_size=chunk_size,
                                 derive_kek=lambda salt: kdf.derive_kek(kdf_id, settings, salt, secret))
        return out.getvalue()
    finally:
        container.os = real_os


# --- secrets as they appear in the manifest ------------------------------------

def passphrase(text: str) -> dict:
    return {"kind": "passphrase", "utf8": text}


def key(raw: bytes) -> dict:
    return {"kind": "key", "hex": raw.hex()}


def secret_from_json(entry: dict) -> Secret:
    if entry["kind"] == "passphrase":
        return Secret(entry["utf8"].encode("utf-8"), "passphrase")
    return Secret(bytes.fromhex(entry["hex"]), "key")


# --- byte surgery for the invalid vectors --------------------------------------

def split(fcx: bytes) -> tuple:
    """(header, [chunk, ...]) of a well-formed file."""
    h = container.read_header(io.BytesIO(fcx))
    body = fcx[h.header_len:]
    full = h.chunk_size + container.TAG_LEN
    return fcx[:h.header_len], [body[i:i + full] for i in range(0, len(body), full)]


def flip(data: bytes, offset: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[offset] ^= 1 << bit
    return bytes(b)


def with_kdf(fcx: bytes, kdf_id: int, settings: bytes) -> bytes:
    """Replace the KDF id and settings, keeping the rest of the file."""
    h = container.read_header(io.BytesIO(fcx))
    old = 8 + len(h.settings)
    return (fcx[:5] + bytes([kdf_id]) + struct.pack("<H", len(settings)) + settings
            + fcx[old:])


# Offsets into a header with empty settings (HKDF): see docs/FORMAT.md.
OFF_SALT = 8
OFF_WRAPPED = OFF_SALT + 16
OFF_PREFIX = OFF_WRAPPED + 48
OFF_CHUNK_SIZE = OFF_PREFIX + 7


# --- the vectors ---------------------------------------------------------------

def build(include_argon2: bool = True) -> Dict[str, bytes]:
    """Return {file name: contents} for every vector file, manifest included.

    With ``include_argon2=False`` the Argon2id files are left out (for
    machines with no Argon2id backend); the manifest is still complete.
    """
    files: Dict[str, bytes] = {}
    vectors: List[dict] = []

    def valid(name: str, kdf_name: str, data: bytes, ciphertext: Optional[bytes],
              secrets: List[dict], description: str, chunk_size: int) -> None:
        if ciphertext is not None:
            files[name + ".fcx"] = ciphertext
        files[name + ".plain"] = data
        vectors.append({"name": name, "valid": True, "file": name + ".fcx",
                        "plaintext": name + ".plain", "kdf": kdf_name,
                        "chunk_size": chunk_size, "plaintext_len": len(data),
                        "secrets": secrets, "description": description})

    def invalid(name: str, kdf_name: str, ciphertext: Optional[bytes], secret: dict,
                reject_at: str, description: str) -> None:
        if ciphertext is not None:
            files[name + ".fcx"] = ciphertext
        vectors.append({"name": name, "valid": False, "file": name + ".fcx", "kdf": kdf_name,
                        "secret": secret, "reject_at": reject_at, "description": description})

    argon_settings = ARGON.encode()
    scrypt_settings = SCRYPT.encode()

    def argon(label: str, data: bytes, secret: bytes, chunk: int = 1024) -> Optional[bytes]:
        if not include_argon2:
            return None
        return encrypt(label, data, kdf.ARGON2ID, argon_settings, secret, chunk)

    nfc = NFC_PASSPHRASE.encode("utf-8")
    nfd = NFD_PASSPHRASE.encode("utf-8")
    pw = PASSPHRASE.encode("utf-8")

    # Valid files ---------------------------------------------------------------
    data = plaintext("argon2id-passphrase", 2500)
    argon_base = argon("argon2id-passphrase", data, pw)
    valid("argon2id-passphrase", "argon2id", data, argon_base, [passphrase(PASSPHRASE)],
          "Argon2id passphrase, 1 KiB chunks, three chunks (the last one partial).", 1024)

    valid("argon2id-empty", "argon2id", b"", argon("argon2id-empty", b"", pw),
          [passphrase(PASSPHRASE)],
          "Empty plaintext: a single empty final chunk (just a 16-byte tag).", 1024)

    data = plaintext("argon2id-nfc", 1500)
    valid("argon2id-nfc", "argon2id", data, argon("argon2id-nfc", data, nfc),
          [passphrase(NFC_PASSPHRASE), passphrase(NFD_PASSPHRASE)],
          "Accented passphrase, keyed with its NFC UTF-8 bytes as filecrypt does now. "
          "Opens whether the passphrase is entered composed (NFC) or decomposed (NFD).", 1024)

    data = plaintext("argon2id-legacy-nfd", 1500)
    valid("argon2id-legacy-nfd", "argon2id", data, argon("argon2id-legacy-nfd", data, nfd),
          [passphrase(NFD_PASSPHRASE)],
          "Accented passphrase keyed with its exact decomposed (NFD) bytes, as releases before "
          "passphrase normalization wrote. A decryptor must retry with the exact bytes when "
          "the NFC form fails.", 1024)

    data = plaintext("scrypt-passphrase", 3072)
    valid("scrypt-passphrase", "scrypt", data,
          encrypt("scrypt-passphrase", data, kdf.SCRYPT, scrypt_settings, pw, 1024),
          [passphrase(PASSPHRASE)],
          "scrypt passphrase, 1 KiB chunks, plaintext an exact multiple of the chunk size: "
          "three full chunks, the third flagged last, and no empty chunk after it.", 1024)

    data = plaintext("hkdf-key", 2500)
    hkdf_base = encrypt("hkdf-key", data, kdf.HKDF, b"", KEY, 1024)
    valid("hkdf-key", "hkdf-sha256", data, hkdf_base, [key(KEY)],
          "HKDF-SHA256 with a 32-byte key, 1 KiB chunks, three chunks.", 1024)

    data = plaintext("hkdf-full-final", 2048)
    hkdf_full = encrypt("hkdf-full-final", data, kdf.HKDF, b"", KEY, 1024)
    valid("hkdf-full-final", "hkdf-sha256", data, hkdf_full, [key(KEY)],
          "HKDF, two full 1 KiB chunks; the second is the final one.", 1024)

    valid("hkdf-empty", "hkdf-sha256", b"", encrypt("hkdf-empty", b"", kdf.HKDF, b"", KEY, 1024),
          [key(KEY)], "HKDF, empty plaintext.", 1024)

    data = plaintext("hkdf-default-chunk", 64 * 1024 + 100)
    valid("hkdf-default-chunk", "hkdf-sha256", data,
          encrypt("hkdf-default-chunk", data, kdf.HKDF, b"", KEY, container.DEFAULT_CHUNK_SIZE),
          [key(KEY)], "HKDF with the default 64 KiB chunk size: one full chunk and a "
          "100-byte final chunk.", container.DEFAULT_CHUNK_SIZE)

    # Invalid files: rejected while parsing the header ----------------------------
    k = key(KEY)
    header, chunks = split(hkdf_base)
    invalid("bad-empty-file", "hkdf-sha256", b"", k, "header", "Zero-length file.")
    invalid("bad-truncated-header", "hkdf-sha256", hkdf_base[:40], k, "header",
            "Cut off in the middle of the header.")
    invalid("bad-magic", "hkdf-sha256", b"FCX2" + hkdf_base[4:], k, "header",
            "Magic is not \"FCX1\".")
    invalid("bad-version", "hkdf-sha256", hkdf_base[:4] + b"\x02" + hkdf_base[5:], k, "header",
            "Version byte 2 (only 1 exists).")
    invalid("bad-settings-len", "hkdf-sha256",
            hkdf_base[:6] + struct.pack("<H", container.MAX_SETTINGS_LEN + 1) + hkdf_base[8:],
            k, "header", "settings_len 1025, above the 1024-byte cap.")
    for size, why in [(container.MIN_CHUNK_SIZE - 1, "below the 1 KiB minimum"),
                      (container.MAX_CHUNK_SIZE + 1, "above the 16 MiB maximum")]:
        invalid(f"bad-chunk-size-{size}", "hkdf-sha256",
                hkdf_base[:OFF_CHUNK_SIZE] + struct.pack("<I", size) + hkdf_base[OFF_CHUNK_SIZE + 4:],
                k, "header", f"chunk_size {size}, {why}.")

    # ... while checking the KDF id and settings (before any KDF work) ----------
    p = passphrase(PASSPHRASE)
    caps = [
        ("unknown-kdf", 4, b"", k, "Unknown KDF id 4."),
        ("hkdf-settings", kdf.HKDF, b"\x00", k, "HKDF with a non-empty settings field."),
        ("argon2id-settings-len", kdf.ARGON2ID, b"\x00" * 8, p,
         "Argon2id settings of 8 bytes instead of 9."),
        ("argon2id-memory", kdf.ARGON2ID, Argon2Params(kdf.ARGON2_MAX_MEMORY_KIB + 1, 1, 1).encode(),
         p, "Argon2id memory 4 GiB + 1 KiB, above the 4 GiB cap."),
        ("argon2id-iterations", kdf.ARGON2ID, Argon2Params(19 * 1024, 17, 1).encode(), p,
         "Argon2id iterations 17, above the cap of 16."),
        ("argon2id-lanes", kdf.ARGON2ID, Argon2Params(19 * 1024, 2, 17).encode(), p,
         "Argon2id parallelism 17, above the cap of 16."),
        ("argon2id-zero-lanes", kdf.ARGON2ID, Argon2Params(19 * 1024, 2, 0).encode(), p,
         "Argon2id parallelism 0."),
        ("argon2id-total-work", kdf.ARGON2ID, Argon2Params(2 * 1024 * 1024, 9, 1).encode(), p,
         "Argon2id 2 GiB x 9 iterations = 18 GiB of work, above the 16 GiB cap."),
        ("scrypt-settings-len", kdf.SCRYPT, b"\x00" * 10, p, "scrypt settings of 10 bytes instead of 9."),
        ("scrypt-log2n", kdf.SCRYPT, ScryptParams(23, 8, 1).encode(), p,
         "scrypt log2(N) 23, above the cap of 22."),
        ("scrypt-r", kdf.SCRYPT, ScryptParams(10, 33, 1).encode(), p, "scrypt r 33, above the cap of 32."),
        ("scrypt-p", kdf.SCRYPT, ScryptParams(10, 8, 17).encode(), p, "scrypt p 17, above the cap of 16."),
        ("scrypt-total-work", kdf.SCRYPT, ScryptParams(22, 8, 5).encode(), p,
         "scrypt 4 GiB x p=5 = 20 GiB of work, above the 16 GiB cap."),
    ]
    for name, kdf_id, settings, secret, why in caps:
        kdf_name = kdf.KDF_NAMES.get(kdf_id, f"unknown ({kdf_id})")
        invalid(f"bad-kdf-{name}", kdf_name, with_kdf(hkdf_base, kdf_id, settings), secret, "kdf",
                why + " Must be refused without running the KDF.")

    # ... while unwrapping the file key ----------------------------------------
    invalid("bad-wrong-key", "hkdf-sha256", hkdf_base, key(WRONG_KEY), "key",
            "A valid file opened with the wrong key.")
    invalid("bad-salt-bit", "hkdf-sha256", flip(hkdf_base, OFF_SALT + 3), k, "key",
            "One bit of the salt flipped.")
    invalid("bad-wrapped-key-bit", "hkdf-sha256", flip(hkdf_base, OFF_WRAPPED + 40, 7), k, "key",
            "One bit of the wrapped file key's tag flipped.")
    invalid("bad-kdf-id-swapped", "scrypt",
            with_kdf(hkdf_base, kdf.SCRYPT, SCRYPT.encode()), p, "key",
            "KDF id and settings rewritten to scrypt: the key block AAD no longer matches.")
    tweaked = (None if argon_base is None else
               with_kdf(argon_base, kdf.ARGON2ID, Argon2Params(19 * 1024, 3, 1).encode()))
    invalid("bad-argon2id-settings-changed", "argon2id", tweaked, passphrase(PASSPHRASE), "key",
            "Argon2id iterations changed from 2 to 3 (still within the caps): the derived key "
            "and the key block AAD both change, so the right passphrase is rejected.")
    invalid("bad-passphrase", "argon2id", argon_base, passphrase(PASSPHRASE + "!"), "key",
            "A valid file opened with the wrong passphrase.")

    # ... while decrypting the body --------------------------------------------
    invalid("bad-nonce-prefix-bit", "hkdf-sha256", flip(hkdf_base, OFF_PREFIX + 2), k, "body",
            "One bit of the nonce prefix flipped (it is in every chunk's AAD and nonce).")
    invalid("bad-chunk-size-changed", "hkdf-sha256",
            hkdf_base[:OFF_CHUNK_SIZE] + struct.pack("<I", 2048) + hkdf_base[OFF_CHUNK_SIZE + 4:],
            k, "body", "chunk_size changed from 1024 to 2048 (still valid): it is in the chunk AAD.")
    invalid("bad-ciphertext-bit", "hkdf-sha256", flip(hkdf_base, len(header) + 1040 + 5), k, "body",
            "One bit of chunk 1's ciphertext flipped.")
    invalid("bad-tag-bit", "hkdf-sha256", flip(hkdf_base, len(hkdf_base) - 1, 4), k, "body",
            "One bit of the final chunk's tag flipped.")
    invalid("bad-truncated-at-chunk-boundary", "hkdf-sha256", header + chunks[0] + chunks[1], k,
            "body", "Final chunk removed: chunk 1 is now last but carries the not-last flag.")
    invalid("bad-truncated-mid-chunk", "hkdf-sha256", hkdf_base[:-100], k, "body",
            "Last 100 bytes cut off.")
    invalid("bad-no-chunks", "hkdf-sha256", header, k, "body",
            "Header only: even an empty plaintext has one chunk.")
    invalid("bad-reordered-chunks", "hkdf-sha256", header + chunks[1] + chunks[0] + chunks[2], k,
            "body", "Chunks 0 and 1 swapped.")
    full_header, full_chunks = split(hkdf_full)
    invalid("bad-trailing-byte", "hkdf-sha256", hkdf_full + b"\x00", k, "body",
            "One byte appended after a full-size final chunk.")
    invalid("bad-trailing-chunk", "hkdf-sha256", hkdf_full + full_chunks[-1], k, "body",
            "The final chunk duplicated after itself.")
    invalid("bad-trailing-after-partial", "hkdf-sha256", hkdf_base + b"\x00" * 16, k, "body",
            "16 bytes appended after a partial final chunk.")
    invalid("bad-dropped-first-chunk", "hkdf-sha256", header + chunks[1] + chunks[2], k, "body",
            "Chunk 0 removed: the counters no longer line up.")

    manifest = {
        "format": "fcx version 1",
        "generator": "tests/vectors/generate.py",
        "spec": "docs/FORMAT.md",
        "reject_at": {
            "header": "parsing the fixed header fails (bad magic, version, lengths or chunk size)",
            "kdf": "the KDF id or settings are unknown, malformed or over a cap; no KDF work is done",
            "key": "the file key fails to unwrap (wrong secret, or the key block was modified)",
            "body": "a chunk fails authentication, or data is missing, reordered or left over",
        },
        "vectors": vectors,
    }
    files[MANIFEST] = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify instead of writing")
    args = ap.parse_args(argv)
    files = build()
    if args.check:
        bad = [n for n, b in files.items() if not (HERE / n).is_file() or (HERE / n).read_bytes() != b]
        extra = sorted(p.name for p in HERE.iterdir()
                       if p.suffix in (".fcx", ".plain") and p.name not in files)
        for n in bad:
            print(f"differs or missing: {n}")
        for n in extra:
            print(f"not produced by the generator: {n}")
        return 1 if bad or extra else 0
    for n, b in files.items():
        (HERE / n).write_bytes(b)
    print(f"wrote {len(files)} files to {HERE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
