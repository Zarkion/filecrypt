# filecrypt

Encrypt files to the `.fcx` format from the command line. Pure Python on top of
the [`cryptography`](https://cryptography.io) library, so it runs anywhere
Python 3.9+ and cryptography wheels do (x86, ARM, Windows, macOS, Linux).

```
pip install .                 # core
pip install ".[keyring]"      # + OS keyring key source
pip install ".[argon2]"       # + argon2-cffi, only for cryptography < 44
```

## Usage

```
filecrypt encrypt report.pdf                     # asks for a passphrase twice -> report.pdf.fcx
filecrypt decrypt report.pdf.fcx                 # -> report.pdf
filecrypt keygen backup.key                      # 32 random bytes, created exclusively, mode 0600
filecrypt encrypt db.sqlite --key file:backup.key
filecrypt rekey report.pdf.fcx --key prompt --new-key file:backup.key
```

Nothing is overwritten without `--force`. Output is written to a temp file and
renamed into place, and partial output is deleted on any failure. `rekey`
replaces the file in place (use `-o` to write a copy); it only rewrites the
key block, so the encrypted body stays byte-identical.

### Key sources (`--key scheme:location`)

| Spec | Kind | Notes |
| --- | --- | --- |
| `prompt` (default) | passphrase | hidden input; asked twice when encrypting |
| `file:PATH` | key | raw bytes, or base64 as written by `keygen --format base64` |
| `env:VAR` | passphrase | |
| `stdin` | passphrase | first line of standard input |
| `keyring:SERVICE/NAME` | key or passphrase | needs the `keyring` extra |
| `azkv:VAULT/SECRET` | key or passphrase | plugin: `plugins/filecrypt-azkv` |

Passphrases go through Argon2id (or scrypt). Keys must be at least 32 bytes and
go through HKDF-SHA256; `--keyfile-is-passphrase` treats a keyfile as a
passphrase instead. Passphrases under 12 characters get a warning.

`keygen --store SPEC` saves a new key to a key source (keyring, a plugin, or
`file:`) and refuses to replace an existing entry.

### KDF options (encrypt, rekey)

`--kdf argon2id|scrypt`, `--argon-memory MIB` (default 64, min 19, max 4096),
`--argon-iterations N` (default 3, 2-16), `--argon-parallelism N` (default 4, 1-16).
scrypt defaults to N=2^17, r=8, p=1 (128 MiB) and encrypt requires N×p ≥ 2^16
with r ≥ 8. If Argon2id is unavailable (cryptography older than 44 and no
argon2-cffi), encrypt falls back to scrypt and prints a notice saying so.
Decryption refuses files whose KDF settings exceed these caps, since they are
read before anything is authenticated.

## Format

Integers are little-endian unless noted.

```
"FCX1" | version u8 (=1) | kdf_id u8 | settings_len u16 | settings
| salt[16] | wrapped_file_key[48] | nonce_prefix[7] | chunk_size u32
| chunks...
```

* **kdf_id** 1 = Argon2id (settings: memory KiB u32, iterations u32, lanes u8),
  2 = scrypt (log2 N u8, r u32, p u32), 3 = HKDF-SHA256 (no settings).
* **Envelope**: each file gets a random 32-byte file key, wrapped once with
  AES-256-GCM under the derived key (zero nonce; every wrap uses a fresh random
  salt, so each wrapping key is used once). AAD = magic..salt.
* **Body**: chunks of `chunk_size` (64 KiB) plaintext, each AES-256-GCM with
  nonce `nonce_prefix | counter u32 big-endian | last_flag u8` (STREAM).
  AAD = magic | version | nonce_prefix | chunk_size. The last chunk has flag
  1; an empty file is one empty final chunk. Truncation, reordering and
  trailing data are rejected.

Not in v1: public-key or multi-recipient encryption, secret sharing, hiding
file names or sizes.

## Writing a key-source plugin

Subclass `filecrypt.sources.KeySource`, implement `get(location, *, confirm)`
returning a `filecrypt.kdf.Secret` (and optionally `store(location, key)`),
then register it:

```toml
[project.entry-points."filecrypt.key_sources"]
myscheme = "my_package:MySource"
```

Plugins cannot replace built-in schemes. See `plugins/filecrypt-azkv` for a
complete example with tests.

## Development

```
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[test]" -e plugins/filecrypt-azkv --no-deps
.venv/Scripts/python -m pytest tests plugins/filecrypt-azkv/tests
```
