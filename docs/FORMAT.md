# The .fcx file format, version 1

This is the byte-level specification of `.fcx` version 1, the only version
that exists today. It is written from the code in
[`src/filecrypt/container.py`](../src/filecrypt/container.py) and
[`src/filecrypt/kdf.py`](../src/filecrypt/kdf.py), and the
[test vectors](../tests/vectors/) check it: if this page and the vectors
disagree, the vectors win and this page has a bug.

The [compatibility promise](compatibility.md) applies: every file that follows
this page stays decryptable by every future release.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## Overview

An `.fcx` file is a fixed header followed by a chunked AES-256-GCM body.

* Each file gets a fresh random 32-byte **file key**. The body is encrypted
  with it.
* The file key is **wrapped** (encrypted) once with AES-256-GCM under a
  32-byte **key-encryption key** (KEK). The KEK is derived from the user's
  passphrase or key with the KDF the header names, and a random 16-byte salt.
* The body is split into chunks. Each chunk is encrypted separately with the
  STREAM construction, so truncation, reordering and appended data are
  detected, and a large file can be decrypted with bounded memory.

The header is split into a **key block** (everything up to and including the
wrapped key) and a **body header** (nonce prefix and chunk size). `rekey`
replaces only the key block, and the body never changes.

## Conventions

* Integers are unsigned. They are **little-endian** except the chunk counter
  inside the nonce, which is **big-endian**.
* `||` is concatenation. `[n]` is a field of exactly `n` bytes.
* `L` is the length of the KDF settings field (`settings_len`).
* AES-256-GCM always uses a 12-byte nonce and a 16-byte tag, and the tag is
  appended to the ciphertext.

## Header

| Offset   | Size | Field              | Value                                                  |
|----------|------|--------------------|--------------------------------------------------------|
| 0        | 4    | `magic`            | ASCII `FCX1` (`46 43 58 31`)                            |
| 4        | 1    | `version`          | `1`                                                    |
| 5        | 1    | `kdf_id`           | `1` Argon2id, `2` scrypt, `3` HKDF-SHA256 (see [KDFs](#kdfs)) |
| 6        | 2    | `settings_len`     | `L`, u16 little-endian, at most 1024                   |
| 8        | L    | `settings`         | KDF settings, format depends on `kdf_id`               |
| 8+L      | 16   | `salt`             | random, fresh for every wrap                           |
| 24+L     | 48   | `wrapped_key`      | 32-byte encrypted file key, then its 16-byte GCM tag   |
| 72+L     | 7    | `nonce_prefix`     | random, chosen once when the file is encrypted         |
| 79+L     | 4    | `chunk_size`       | u32 little-endian, 1024 to 16 777 216 (1 KiB to 16 MiB) |
| 83+L     |      | chunks             | see [Body](#body)                                      |

The header is `83 + L` bytes. Bytes `0 .. 72+L` are the key block and bytes
`72+L .. 83+L` are the body header.

filecrypt writes `chunk_size` = 65 536 (64 KiB). A decryptor MUST accept any
value in the range.

### Parsing rules

A decryptor MUST reject the file before doing any key derivation when:

* it is shorter than 8 bytes, or the header is cut short;
* `magic` is not `FCX1`;
* `version` is not `1` (a later version is a different format; see
  [Versioning](#versioning));
* `settings_len` is greater than 1024;
* `chunk_size` is below 1024 or above 16 777 216.

None of the header is authenticated at this point. The key block is
authenticated when the file key is unwrapped, and the body header is
authenticated by every chunk.

## KDFs

The KDF turns the user's secret and the 16-byte `salt` into the 32-byte KEK.
The settings are read from an unauthenticated header, so a decryptor MUST
check them against the [caps](#caps-for-decryption) below **before** running
the KDF. Otherwise a crafted file could demand unbounded memory or time.

An unknown `kdf_id` MUST be rejected.

### kdf_id 1: Argon2id (passphrases, the default)

Settings are 9 bytes:

| Offset | Size | Field        | Meaning                     |
|--------|------|--------------|-----------------------------|
| 0      | 4    | `memory_kib` | memory cost in KiB, u32 LE  |
| 4      | 4    | `iterations` | time cost, u32 LE           |
| 8      | 1    | `lanes`      | parallelism, u8             |

KEK = Argon2id (version 0x13) with password = the secret bytes, salt = `salt`,
`m` = `memory_kib`, `t` = `iterations`, `p` = `lanes`, tag length 32, and no
secret key or associated data.

filecrypt writes 65 536 KiB (64 MiB), 3 iterations, 4 lanes by default.

### kdf_id 2: scrypt (passphrase fallback)

Settings are 9 bytes:

| Offset | Size | Field   | Meaning               |
|--------|------|---------|-----------------------|
| 0      | 1    | `log2n` | log2 of N, u8         |
| 1      | 4    | `r`     | block size, u32 LE    |
| 5      | 4    | `p`     | parallelism, u32 LE   |

KEK = scrypt(password = the secret bytes, salt = `salt`, N = 2^`log2n`,
r, p, dkLen = 32). Its memory is 128 × r × N bytes.

filecrypt uses scrypt only when no Argon2id implementation is installed, or
when asked. It writes N = 2^17, r = 8, p = 1 (128 MiB) by default.

### kdf_id 3: HKDF-SHA256 (keys)

Settings MUST be empty (`L` = 0). The secret MUST be at least 32 bytes.

KEK = HKDF-SHA256 (RFC 5869) with IKM = the secret bytes, salt = `salt`,
info = the 31 ASCII bytes `filecrypt v1 key-encryption key`, L = 32.

This is for random key material (keyfiles, key stores), which needs no
stretching.

### Caps for decryption

A decryptor MUST reject settings outside these limits without running the KDF.
These are the limits filecrypt enforces. They are inclusive.

| KDF      | Rule                                                              |
|----------|-------------------------------------------------------------------|
| Argon2id | settings exactly 9 bytes                                          |
| Argon2id | 1 ≤ `lanes` ≤ 16, 1 ≤ `iterations` ≤ 16                            |
| Argon2id | 8 × `lanes` ≤ `memory_kib` ≤ 4 194 304 (4 GiB)                     |
| Argon2id | `memory_kib` × 1024 × `iterations` ≤ 16 GiB (total work)           |
| scrypt   | settings exactly 9 bytes                                          |
| scrypt   | 1 ≤ `log2n` ≤ 22, 1 ≤ `r` ≤ 32, 1 ≤ `p` ≤ 16                        |
| scrypt   | 128 × r × N ≤ 4 GiB, and 128 × r × N × p ≤ 16 GiB (total work)      |
| HKDF     | settings empty, secret at least 32 bytes                          |

Decryption deliberately accepts settings weaker than the encryption floors
below, so that any file a released version wrote keeps opening.

filecrypt additionally asks the user before running settings that need more
memory than a limit (by default 1 GiB or half of physical RAM, whichever is
lower), or more than 8 times that limit in total work. That is local policy,
not part of the format.

### Floors for encryption

filecrypt refuses to encrypt with settings below these floors. Another
encryptor SHOULD use at least the same:

* Argon2id: `memory_kib` ≥ 19 456 (19 MiB), `iterations` ≥ 2, `lanes` ≥ 1.
* scrypt: r ≥ 8 and N × p ≥ 2^16.
* HKDF: keys of at least 32 bytes. Shorter secrets are passphrases and get a
  memory-hard KDF.

## Secrets: how passphrases and keys become bytes

The format works on bytes. How filecrypt turns user input into those bytes is
part of compatibility, so it is specified here.

* **Passphrases** are encoded as UTF-8 in Unicode Normalization Form C (NFC).
  The same accented passphrase gives the same bytes whether the keyboard or
  operating system produced composed characters (`é`, U+00E9) or decomposed
  ones (`e` followed by U+0301). Normalization is NFC, not NFKC, so
  compatibility characters such as ligatures stay as they are.
* A passphrase that isn't valid UTF-8 (possible with environment variables on
  POSIX) is used as its exact bytes.
* **Before normalization was added**, passphrases were used as their exact
  UTF-8 bytes. When decrypting or rekeying, a decryptor MUST first try the NFC
  bytes and, if the file key doesn't unwrap and the exact bytes differ, try
  the exact bytes. Encryption always uses the NFC bytes. A file made from a
  decomposed passphrase before the change therefore opens when the passphrase
  is entered decomposed again, but not when it is entered composed. Rekeying
  such a file moves it to NFC.
* **Keys** are never normalized. A keyfile holding standard base64 that
  decodes to at least 32 bytes (what `keygen --format base64` writes) is
  decoded. Any other keyfile is used exactly as stored. Key-store entries that
  start with `fcxkey:v1:` are base64 keys; any other key-store entry is a
  passphrase. A keyfile used with `--keyfile-is-passphrase` goes through the
  passphrase KDF but keeps its exact bytes.
* Passphrases use kdf_id 1 or 2. Keys use kdf_id 3.

## Key block

The file key is wrapped as:

```
wrapped_key = AES-256-GCM-Encrypt(key   = KEK,
                                  nonce = 12 zero bytes,
                                  plaintext = file_key[32],
                                  aad   = header bytes 0 .. 24+L)
```

The AAD is `magic || version || kdf_id || settings_len || settings || salt`,
exactly as those bytes appear in the file. The result is 48 bytes:
32 bytes of ciphertext and the 16-byte tag.

The all-zero nonce is safe because every wrap, on encrypt and on every rekey,
uses a fresh random salt. So every KEK is used for exactly one encryption. An
encryptor MUST NOT reuse a salt.

Unwrapping fails with the wrong secret, and also when the KDF id, settings or
salt were modified, since they change the KEK or the AAD. A decryptor can't
tell these apart and SHOULD report "wrong key or passphrase".

## Body

The plaintext is split into chunks of `chunk_size` bytes. Every chunk except
the last is exactly `chunk_size` bytes. The last chunk holds the remaining 0
to `chunk_size` bytes. If the plaintext is an exact multiple of `chunk_size`,
the last chunk is a full one. An empty plaintext is a single empty last chunk.

Chunk `i` (counting from 0) is encrypted as:

```
nonce_i     = nonce_prefix[7] || i as u32 big-endian || last_flag
chunk_aad   = magic || version || nonce_prefix || chunk_size (u32 LE)    (16 bytes)
ciphertext_i = AES-256-GCM-Encrypt(file_key, nonce_i, plaintext_i, chunk_aad)
```

`last_flag` is `0x01` for the last chunk and `0x00` for every other chunk.
Each stored chunk is `len(plaintext_i) + 16` bytes, so a full chunk is
`chunk_size + 16` bytes. Chunks follow the header back to back with no
framing. The chunk AAD is the same for every chunk, and it authenticates the
body header, so changing `nonce_prefix` or `chunk_size` makes every chunk
fail.

The counter is 32 bits, so a file has at most 2^32 chunks (2^32 × `chunk_size`
bytes of plaintext, 256 TiB at 64 KiB chunks). An encryptor MUST fail rather
than wrap the counter.

### Decrypting the body

A decryptor reads the body in pieces of `chunk_size + 16` bytes. A piece is
the last chunk if and only if no bytes follow it, and only then is it
decrypted with `last_flag` = `0x01`. A piece shorter than 16 bytes means the
file is truncated.

This rejects every way of cutting or rearranging the body:

* **Truncation at a chunk boundary**: the new last chunk was encrypted with
  `last_flag` = 0, so it fails.
* **Truncation inside a chunk**, or a body with no chunks: the tag fails, or
  there are fewer than 16 bytes.
* **Reordered, dropped or duplicated chunks**: the counter in the nonce no
  longer matches.
* **Trailing data** after the real last chunk: that chunk is no longer last,
  so it fails with `last_flag` = 0. filecrypt then checks whether it would
  pass with `last_flag` = 1 and if so reports trailing data specifically.
  Either way the file is rejected.

A decryptor MUST NOT release a chunk's plaintext before its tag has verified.
filecrypt also writes output to a temporary file and only moves it into place
when the whole body has verified, so a failure never leaves partial output.

An encryptor MUST NOT write an empty last chunk after a full chunk (that is, a
file whose plaintext is a non-zero multiple of `chunk_size` ends with a full
chunk flagged last). filecrypt's decryptor happens to accept such an extra
empty chunk, since it authenticates. Other decryptors MAY accept it too.

## Rekeying

Rekeying unwraps the file key with the old secret and wraps it with the new
one, with a fresh salt and possibly a different KDF. It replaces bytes
`0 .. 72+L` (the key block, whose length can change with the new KDF
settings) and copies `nonce_prefix`, `chunk_size` and every chunk unchanged.
The file key stays the same, so rekeying doesn't help after a secret has
leaked: decrypt and encrypt again instead.

## Versioning

The version byte is the only extension point. Version 1 has no flags, options
or optional fields, and it has no MAC over the whole header: each part is
authenticated where it is used (the key block by the wrap, the body header by
every chunk). Any change to the layout gets a new version byte, and readers of
version 1 reject other versions instead of guessing.

## Worked example

The vector [`tests/vectors/hkdf-key.fcx`](../tests/vectors/hkdf-key.fcx) is
2500 bytes of plaintext encrypted with the 32-byte key `00 01 02 … 1f`
(kdf_id 3, so `L` = 0). Its 83-byte header:

```
46435831                                   magic "FCX1"
01                                         version 1
03                                         kdf_id 3 (HKDF-SHA256)
0000                                       settings_len 0
4351860295a35effe8bd95a9d07aa5ae           salt
6c78f5075cebfa9d73a705fd44f39f7a           wrapped_key (32-byte ciphertext ...
d3db87347fe9e4bd6730b669d052953e
b6f8e903445a6c8f4bcae531b128ce40           ... then 16-byte tag)
dc5b099810bf9f                             nonce_prefix
00040000                                   chunk_size 1024
```

* KEK = HKDF-SHA256(IKM = key, salt, info) =
  `19b20a0b35291dde22e326bcdf02398b56463538cd6ef553159390d09f75c1e4`
* Unwrapping with the AAD `46435831 01 03 0000 4351…a5ae` (the first 24
  bytes) gives the file key
  `e50d6d745cda0ab68116ad8e2921dae5adad52f16483acc12909a9224d6c936a`
* The body is chunk 0 (1040 bytes, nonce `dc5b099810bf9f 00000000 00`),
  chunk 1 (1040 bytes, nonce `… 00000001 00`) and chunk 2 (468 bytes,
  nonce `… 00000002 01`), each with the chunk AAD
  `46435831 01 dc5b099810bf9f 00040000`. The file is 83 + 2548 = 2631 bytes.

## Test vectors

[`tests/vectors/`](../tests/vectors/) holds frozen files described by
[`vectors.json`](../tests/vectors/vectors.json):

* **Valid files** for every KDF, with the secret and the expected plaintext:
  several chunks with a partial last chunk, an exact multiple of the chunk
  size, empty plaintext, the default 64 KiB chunks, an accented passphrase
  that must open whether it's entered composed or decomposed, and a file from
  before passphrase normalization.
* **Invalid files**, each with the stage that must reject it: `header`
  (parsing), `kdf` (unknown, malformed or over-cap settings, refused without
  running the KDF), `key` (wrong secret or a modified key block) or `body`
  (flipped bits, truncation at and inside chunk boundaries, reordered,
  dropped and duplicated chunks, trailing data).

The vectors use the cheapest settings filecrypt lets you encrypt with
(Argon2id 19 MiB, 2 iterations, 1 lane; scrypt N = 2^16, r = 8, p = 1), so
each is a file a released version could have written. They were made by
[`tests/vectors/generate.py`](../tests/vectors/generate.py) with seeded
randomness, and `python tests/vectors/generate.py --check` confirms the
committed files still match. `tests/test_vectors.py` runs on every CI build.
It decrypts every valid vector, checks every invalid one fails at its stage,
and regenerates the files in memory to pin the encryption side too.

The vectors never change once committed. A change to the format gets a new
version and new vectors, alongside these.
