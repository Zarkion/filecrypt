# filecrypt threat model

This page says what filecrypt is meant to protect, against whom, and where it
stops. It describes `.fcx` format version 1 as implemented on `main`. If the
code and this page disagree, the code is the bug report: please open an issue
(or a private report, see [SECURITY.md](../SECURITY.md)).

## In one paragraph

filecrypt keeps the **contents** of a file secret and detects any change to
them, as long as the attacker doesn't have your key or passphrase and doesn't
control the computer you encrypt or decrypt on. It does not hide that a file
exists, what it's called, or how big it is. A passphrase is only as strong as
you make it.

## How it works (short version)

* Each file gets a fresh random 32-byte **file key**. The body is encrypted
  with AES-256-GCM in 64 KiB chunks using the STREAM construction: the nonce
  is a random 7-byte prefix, a 4-byte big-endian chunk counter and a 1-byte
  "last chunk" flag.
* The file key is **wrapped** once with AES-256-GCM under a key-encryption key
  (KEK). The KEK comes from your secret:
  * passphrases go through **Argon2id** (default 64 MiB, 3 passes, 4 lanes),
    or **scrypt** (default N=2^17, r=8, p=1) when Argon2id isn't available;
  * keys of at least 32 bytes (keyfiles, `fcxkey:v1:` key-store entries) go
    through **HKDF-SHA256**.
* Every wrap uses a fresh random 16-byte salt, so every KEK is used once.
* There is exactly one wrapped key per file. `rekey` replaces that one key
  block and leaves the encrypted body byte-identical.

The full layout is in the [format spec](FORMAT.md).

## Who we defend against

| Attacker | Example | Protected? |
| --- | --- | --- |
| Someone who gets a copy of the `.fcx` file | stolen laptop or USB stick, leaked cloud backup, email interception | **Yes**, if the key or passphrase is strong |
| Someone who can change the file in storage or in transit | tampering with a backup, a flaky disk | **Yes**, the change is detected and decryption fails |
| Someone who crafts a malicious `.fcx` file and sends it to you | trying to exhaust memory or CPU | **Partly**, see [KDF cost caps](#kdf-cost-caps) |
| Other local users on a shared computer | another account on the same Windows PC | **Partly**, see [Local attackers](#local-attackers) |
| Malware or an admin on the machine where you type the passphrase | keylogger, memory scraper, compromised OS | **No** |
| Someone who learns your key or passphrase | phishing, a reused password, a leaked keyfile | **No** |

## What filecrypt protects

* **Confidentiality of the contents.** Without the key or passphrase, the
  ciphertext reveals nothing about the plaintext beyond its length.
* **Integrity of the contents.** Every chunk is authenticated before it is
  written out. Changed bytes, swapped or reordered chunks, a file truncated at
  a chunk boundary, and extra data after the last chunk are all rejected.
* **Integrity of the key block.** The KDF id, KDF settings and salt are bound
  into the key wrap's associated data, so changing them makes unwrapping fail
  rather than silently weakening the file.
* **Atomic output.** Output is written to a temp file and renamed into place,
  and nothing is overwritten without `--force`. A failed decryption deletes
  its partial output (but see the crash caveat below).
* **Secrets in errors.** Secrets are not printed in error messages or
  tracebacks.

## What filecrypt does not protect

* **File names.** `report.pdf` becomes `report.pdf.fcx` by default, and the
  name inside the folder is not encrypted. Rename files yourself if names
  matter.
* **File size.** The ciphertext size reveals the exact plaintext size
  (it is the plaintext plus a fixed header plus 16 bytes per 64 KiB chunk).
  There is no padding.
* **Timestamps and other metadata.** Modification times, folder structure,
  owners and similar file-system metadata are untouched.
* **Which kind of secret was used.** The unencrypted header names the KDF, so
  anyone can tell whether a file was encrypted with a passphrase (Argon2id or
  scrypt, plus its cost settings) or a key (HKDF).
* **That a file is an `.fcx` file.** The header starts with the magic bytes
  `FCX1`. filecrypt is not a steganography or deniability tool.
* **Weak passphrases.** Argon2id and scrypt make each guess slow, but an
  attacker with the file can guess offline for as long as they like. A short
  or common passphrase will fall. filecrypt only warns below 12 characters; it
  does not measure strength. Use a long random passphrase, or a keyfile from
  `filecrypt keygen`.
* **Multiple recipients or public-key encryption.** Each file has exactly one
  wrapped key. Sharing a file means sharing its key or passphrase. This is
  also why AES-GCM's lack of key commitment is not a problem today: with one
  wrapped key there is only one key that could open a file. Adding
  multi-recipient support would need a new, key-committing design and a new
  format version.
* **A compromised computer.** Anything that can watch your keyboard, read
  your process memory or replace the filecrypt program can get your secret
  or the plaintext.
* **Memory hygiene.** filecrypt is written in Python, which cannot reliably
  wipe secrets from memory. Passphrases, KEKs and file keys can stay in RAM
  until the process exits and may reach the swap file, the Windows pagefile,
  hibernation files or crash dumps.
* **Plaintext after you decrypt it.** Once a file is decrypted, protecting it
  is up to you and your operating system.

### Rekey is not key rotation

`rekey` re-wraps the same file key under a new secret and copies the body
unchanged. It is fast, but it does **not** help after a secret has leaked:
anyone who had the old key or passphrase and an old copy of the file (or the
old header) can recover the file key, and that key still decrypts the new
copy. If a secret may have leaked, decrypt the file and encrypt it again,
which creates a new file key.

`rekey` also copies the body without checking it, so corruption in the body
is only found the next time you decrypt.

### Local attackers

Other user accounts on the same computer are partly in scope:

* Keyfiles from `keygen` are created owner-only: mode 0600 on Linux and macOS,
  and on Windows a protected ACL for your account and SYSTEM, applied as the
  file is created. If Windows can't create it that way, keygen restricts the
  new file before writing the key, and if that fails too it warns and the
  file keeps the folder's permissions.
* Decryption temp files (`.<name>.<random>.part`) are owner-only on Linux and
  macOS. On Windows they are opened delete-on-close but are not yet reliably
  owner-only (see Known limitations).
* `env:` passphrases can be read by other processes running as the same
  user (and by administrators). Prefer `prompt`, a keyfile or a key store.
* An administrator or root user can read anything; filecrypt cannot defend
  against them.

### Key stores and plugins

* In `keyring:` and plugin key stores, only entries written by
  `keygen --store` (tagged `fcxkey:v1:<base64>`) count as keys. Anything else
  is treated as a passphrase and goes through Argon2id or scrypt, so a
  hand-typed password never skips the slow KDF.
* The security of a key-store entry is the security of that store and of the
  account that can read it. For Azure Key Vault, filecrypt uses
  `DefaultAzureCredential`, which picks the first identity that works
  (environment variables, managed identity, Azure CLI and so on).
* Plugins are ordinary installed Python code with full access to your
  secrets. Install only plugins you trust. Only the plugin that matches the
  `--key` scheme is imported, built-in schemes can't be replaced, and a scheme
  registered by two packages is refused. `python -m filecrypt` drops the
  current folder from the import path so a folder of downloads can't plant
  code.

## KDF cost caps

The KDF settings are read from the file header **before** anything is
authenticated, so a crafted file could ask for huge amounts of memory or time.
filecrypt defends against this in two layers:

1. **Hard caps**, always enforced before any memory is allocated: Argon2id up
   to 4 GiB of memory, 16 passes and 16 lanes; scrypt up to 4 GiB of memory
   and p ≤ 16; and total work (memory × Argon2id passes, or memory × scrypt
   p) up to 16 GiB. Files above these are refused.
2. **A confirmation step** for anything expensive but within the caps. Before
   asking for the secret, `decrypt` and `rekey` check the file's KDF cost. If
   it needs more than 1 GiB of memory (or half your RAM, whichever is lower)
   or more than 8 times that in total work, filecrypt asks before continuing,
   and refuses when it isn't running interactively. `--max-kdf-memory MIB`
   sets the limit explicitly for scripts.

Even within these limits, opening a hostile file you agree to can still make
a low-memory machine swap or run for a while. This is denial of service only;
it does not expose your data.

## Crashes and leftover files

If filecrypt is killed in a way that skips cleanup (a power cut, or `kill -9`
on Linux and macOS), a `.part` temp file can be left next to the output. For
`decrypt` it may hold plaintext, possibly including the start of a file whose
later chunks would have failed authentication. These files are owner-only,
and the next run that writes the same output lists them and offers to delete
them. On Windows, delete-on-close removes them even if the process is killed
or the console window is closed.

## Known limitations

An internal security review of v1 found no critical or high-severity issues.
The medium and most low findings (M1-M3, L1-L4) are fixed on `main`. These are
still open:

* **Decryption temp files on Windows are not yet owner-only.** The usual
  delete-on-close `.part` file keeps the folder's inherited ACL, and the
  fallback `.part` file gets the owner-only ACL only just after it is
  created, so a local user who can read the folder could open it and read
  the plaintext as it is written (Windows checks access only when a file is
  opened). Keyfiles no longer have this problem: `keygen` creates them with
  the ACL already applied. Until `.part` files do the same, decrypt into a
  folder only you can read, such as your user profile.
* **"Refuse to replace" in the OS keyring is check-then-set.** OS keyrings
  have no create-only write. `keygen --store keyring:...` reads the entry back
  after writing it and reports an error if another program changed it in
  between, but a second writer that lands after that read can still replace
  the key without either run noticing. The race window is small and needs two
  `keygen --store` runs for the same entry at the same moment. In Azure Key
  Vault the same race is detected: every write is kept as a version, and
  `keygen --store` lists the versions after writing and reports an error if
  another one appeared.
* **Azure identity is chosen by azure-identity.** `DefaultAzureCredential`
  uses the first identity that works. filecrypt has no option of its own to
  restrict it, but the `AZURE_TOKEN_CREDENTIALS` environment variable does
  (for example `ManagedIdentityCredential`, or `prod`); see the
  [plugin README](../plugins/filecrypt-azkv/README.md#choosing-which-azure-identity-is-used).
* **Secrets are not wiped from memory** (see above). Python can't fully fix
  this; filecrypt does not claim to zero secrets.
* **Old files with decomposed accented passphrases.** Passphrases are now
  encoded as Unicode NFC, so an accented passphrase works the same on every
  operating system. Files made before that change used the exact bytes typed.
  filecrypt still tries those, so they keep opening, but a file whose
  passphrase was typed in decomposed form (as macOS can produce) only opens
  when it is typed that way again. Rekeying such a file once fixes this (see
  the [format spec](FORMAT.md#secrets-how-passphrases-and-keys-become-bytes)).
* **No independent audit.** The review was done as part of development, not
  by an outside party.
