# Compatibility promise

Encrypted files often outlive the software that made them. This page is the
project's written promise about what will keep working.

## The promise

**Every `.fcx` version 1 file stays decryptable by every future release of
filecrypt**, with the same key or passphrase that was used to create or last
rekey it. That holds no matter which release wrote the file, including every
0.x release.

A version 1 file is any file that starts with the magic bytes `FCX1`
followed by the version byte `1`. Concretely, future releases will keep
supporting all of these:

* the version 1 layout specified in [FORMAT.md](FORMAT.md):
  magic, version, KDF id and settings, salt, wrapped file key, nonce prefix,
  chunk size and chunks;
* KDF id 1 (Argon2id), 2 (scrypt) and 3 (HKDF-SHA256), with the settings
  encodings in FORMAT.md;
* AES-256-GCM with the STREAM nonce (7-byte prefix, 4-byte big-endian
  counter, 1-byte last-chunk flag) and the two associated-data rules;
* any chunk size from 1 KiB to 16 MiB, not just the 64 KiB filecrypt writes;
* keyfiles as raw bytes or as base64 (as written by
  `keygen --format base64`), and key-store entries tagged `fcxkey:v1:`.
  Keyfiles over 64 MiB are refused by default so the wrong file isn't read
  into memory; set `FILECRYPT_MAX_KEYFILE_MB` to a larger number of MiB to
  open files made with a bigger keyfile.

## What this means for future changes

* **New features get a new format version.** Anything that changes the
  layout, such as multiple recipients, encrypted file names or padding, will
  use a new version byte. Reading version 1 stays supported alongside it.
  New releases may write a newer version by default, but they will always
  read version 1.
* **Decryption limits never shrink below what encryption allowed.** The KDF
  caps that protect against crafted files (see the
  [threat model](threat-model.md#kdf-cost-caps)) may be tightened for new
  files, but any setting that a released version let you encrypt with stays
  decryptable. Files with expensive settings may need a confirmation or
  `--max-kdf-memory`, as they do today, but they are never refused outright.
* **Passphrase handling stays compatible.** Passphrases are encoded as
  Unicode NFC UTF-8, so the same accented passphrase works on every operating
  system. Releases before that used the exact UTF-8 bytes typed. filecrypt
  always tries those exact bytes too when the NFC form doesn't open a file,
  so files made before the change keep opening.
* **Defaults may get stronger.** New files may get higher KDF costs or a
  different default KDF. Files made with older, weaker defaults still decrypt;
  `filecrypt rekey` upgrades their key block without re-encrypting the body.
* **Algorithms aren't removed.** Even if a primitive used by version 1 were
  ever considered weak, filecrypt would keep the ability to decrypt version 1
  files (with a warning, if appropriate) so you can re-encrypt them.

## Dropping Python and library versions

filecrypt needs Python 3.9 or later and `cryptography` 48.0.1 or later
(46.0.3 on Windows ARM64, the last release with a wheel there). Argon2id comes
from `cryptography` itself, or from `argon2-cffi` when cryptography was built
against an OpenSSL older than 3.2. Files written with any version stay
readable; the floor only moved to keep known-vulnerable releases out.

* Support for an old Python or `cryptography` version is only dropped in a
  new minor release (or major, after 1.0), never in a patch release, and it
  is announced in the release notes.
* Dropping a Python version doesn't strand your files: the last release that
  supported it stays available from the repository's tags and releases, and
  newer releases still read every version 1 file.
* There will always be a supported way to decrypt Argon2id files, either
  through `cryptography`'s native support or through `argon2-cffi`.

## What is not covered

* **The command line and Python API.** Commands, options, messages and
  internal modules may change before 1.0. Changes will be noted in the release
  notes. Your files stay readable either way.
* **Key-store entries written before the `fcxkey:v1:` tag existed.** Early
  development builds stored keys in `keyring:` and plugin stores as bare
  base64. Those entries are now read as passphrases (a security fix), so files
  encrypted with them report "wrong key". To fix this, edit the entry and put
  `fcxkey:v1:` in front of the existing base64 text; the files then open
  again. This happened before any release and won't happen again for tagged
  entries.
* **Files that were damaged or tampered with.** Those are rejected by design.
* **Plugins.** Third-party key-source plugins make their own promises.

## How the promise is checked

A set of fixed version 1 test files lives in
[`tests/vectors/`](../tests/vectors/): valid files for every KDF, including
one from before passphrase normalization, and damaged or crafted files that
must be rejected. CI decrypts all of them on every change, so a release that
breaks old files can't ship unnoticed. The vectors are never changed once
committed.
