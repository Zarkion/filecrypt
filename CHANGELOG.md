# Changelog

All notable changes to filecrypt are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The `.fcx` file format has its own
version and compatibility promise: see [docs/compatibility.md](docs/compatibility.md).

## [0.1.0] - Unreleased

Nothing has been published to PyPI yet. This will be the first release, once
the `.fcx` v1 format is frozen.

### Added

- The `.fcx` v1 container: AES-256-GCM in chunks with a STREAM nonce
  (7-byte prefix, big-endian counter, last-chunk flag), and envelope
  encryption with a random per-file key wrapped by a key derived from the
  user's secret. Chunk AAD covers the fixed header.
- Key derivation: Argon2id by default (64 MiB, 3 passes, 4 lanes) through
  cryptography's built-in Argon2id or argon2-cffi, with an scrypt fallback,
  and HKDF for keyfiles and key stores.
- The commands `keygen`, `encrypt`, `decrypt` and `rekey`. Rekeying rewraps
  the file key without touching the encrypted body.
- Pluggable key sources (`--key scheme:location`): passphrase prompt,
  environment variable, standard input, keyfile and OS keyring, plus
  third-party schemes through entry points (an Azure Key Vault plugin ships
  in `plugins/`).
- `filecrypt.engine`, a UI-neutral API (encrypt, decrypt, rekey, inspect)
  with atomic output and callbacks for progress, notices and confirmations,
  so a GUI can reuse the tested code. The CLI is built on it.
- A desktop window, `filecrypt-gui` (the `gui` extra, PySide6): drop or
  choose one file to encrypt or decrypt, with a password strength meter, a
  keyfile option, a progress bar and Cancel.
- The engine tells a wrong key (`WrongKeyError`) from a damaged file
  (`CorruptedFileError`), can ask for a password again without reopening the
  file, and can be cancelled from another thread with no partial output.
  The CLI gives typed passphrases three tries on a terminal.
- The CLI never prompts without a terminal. A passphrase prompt exits with
  code 7 and names the other key sources, so input piped in on Windows now
  refuses to prompt instead of failing. A yes/no question whose answer can't
  be read counts as "no" and names the flag that answers it ahead of time.
- Passphrases are encoded as NFC UTF-8. Decrypt and rekey try the NFC bytes
  first and then the exact bytes, so files made before the change still open.
- `docs/FORMAT.md`, a byte-level specification of `.fcx` v1, and frozen test
  vectors (9 valid files and 38 invalid ones) that every build must decrypt
  or reject.
- `SECURITY.md`, a threat model and a compatibility promise that every v1
  `.fcx` file stays decryptable.
- Cross-platform CI on Linux, Windows and macOS (x86_64, arm64 and 32-bit
  Windows) for Python 3.9 to 3.14 and every Argon2 backend, plus the
  desktop window's tests.
- README notes for installing on 32-bit and ARM64 Windows, where
  cryptography has no recent wheels.
- Release tooling: a single-source version and a tag-triggered workflow that
  builds the sdist and wheel. Publishing to PyPI is off until enabled.

### Security

- `decrypt` on Windows copies the Mark of the Web (the `Zone.Identifier`
  stream) from the `.fcx` file to the decrypted file, as the desktop window
  does, and warns when the destination cannot hold it.
- Keyfiles on Windows are created with an owner-only ACL already applied, so
  no other local account can open the file before it is locked down.
- `decrypt` and `rekey` check a file's KDF cost before asking for the key, cap
  total KDF work at 16 GiB and ask before costly settings
  (`--max-kdf-memory` for scripts).
- Partial plaintext is kept off disk after crashes: delete-on-close temp files
  on Windows, an owner-only fallback, and cleanup of leftover `.part` files.
- `python -m filecrypt` drops the current folder from `sys.path`, duplicate
  plugin schemes are an error, and plugin load errors are sanitized.

[0.1.0]: https://github.com/Zarkion/filecrypt/commits/main
