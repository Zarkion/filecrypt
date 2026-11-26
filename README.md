# filecrypt

Encrypt files to the `.fcx` format from the command line. Pure Python on top of
the [`cryptography`](https://cryptography.io) library, so it runs anywhere
Python 3.9+ and cryptography wheels do (x86, ARM, Windows, macOS, Linux).

```
pip install .                 # core
pip install ".[keyring]"      # + OS keyring key source
pip install ".[argon2]"       # + argon2-cffi, only for cryptography < 44
```

**32-bit (x86) and ARM64 Windows:** the newest cryptography releases (49 and
later) publish no prebuilt wheel for these, so a plain install tries to build
cryptography from source, which needs Rust and OpenSSL and usually fails. Tell
pip to use a prebuilt cryptography instead; it then picks the newest release
that has one (48.0.1 on 32-bit, 46.0.3 on ARM64, as of November 2026):

```
pip install --only-binary=cryptography .
```

Both versions include the built-in Argon2id, so nothing else is needed. This
is the same command CI uses on its 32-bit and ARM64 Windows runners.

## Usage

```
filecrypt encrypt report.pdf                     # asks for a passphrase twice -> report.pdf.fcx
filecrypt decrypt report.pdf.fcx                 # -> report.pdf
filecrypt keygen backup.key                      # 32 random bytes, created exclusively, owner-only
filecrypt encrypt db.sqlite --key file:backup.key
filecrypt rekey report.pdf.fcx --key prompt --new-key file:backup.key
filecrypt rekey report.pdf.fcx --key prompt --new-key prompt --rotate-file-key  # after a leak
filecrypt verify report.pdf.fcx --key file:backup.key  # checks every chunk, writes nothing
filecrypt info report.pdf.fcx                    # header details, no key needed
```

Keyfiles are readable only by you: mode 0600 on Linux and macOS, and on
Windows a protected ACL granting only your account and SYSTEM, applied as the
file is created (inherited folder permissions never reach it). If Windows
refuses the ACL, keygen warns and the file keeps the folder's permissions.

Nothing is overwritten without `--force`. Output is written to a temp file
(`.<name>.<random>.part` next to the output) and renamed into place, and
partial output is deleted on any failure. On Windows the temp file is opened
delete-on-close, so it also disappears if the process is killed or the console
window is closed. A power cut, or `kill -9` on Linux and macOS, can still leave
a `.part` file behind, and for `decrypt` it may hold plaintext (owner-only:
mode 0600, or an owner-only ACL on Windows). The next run that writes the same
output lists any such leftovers and offers to delete them. `rekey`
replaces the file in place (use `-o` to write a copy); it only rewrites the
key block, so the encrypted body stays byte-identical. With
`--rotate-file-key` it re-encrypts the whole body under a new file key
instead (see below).

### Checking files and scripting

`verify` unlocks a file exactly as `decrypt` would (same key sources, KDF
cost check and retries), then authenticates every chunk and throws the
plaintext away. No output or temporary file is created, so it is safe to run
on backups. `info` needs no key: it shows what the header says (key or
passphrase, key derivation settings, chunk size) and the plaintext size the
file's length implies. None of that is authenticated, so a truncated or
edited file can show wrong values; only `verify` or `decrypt` can tell.

Every command takes `--quiet` (`-q`), which hides notices and success
messages but never errors or prompts, and `--json`, which prints one JSON
object on standard output when the command ends: `{"ok": true, "command":
..., ...}` on success, or `{"ok": false, "exit_code": N, "error": {"kind":
..., "message": ...}}` on failure. File names are JSON-escaped, so any name
round-trips. Error messages still go to standard error.

Exit codes:

| Code | Meaning | `--json` kind |
| --- | --- | --- |
| 0 | success | |
| 1 | other error, such as an existing output without `--force` | `error` |
| 2 | usage error | `usage` |
| 3 | not an .fcx file, or a malformed or unsupported header | `format` |
| 4 | wrong key or passphrase, **or** a modified header | `wrong_key_or_modified_header` |
| 5 | the key was right but the file is damaged, truncated or was tampered with | `corrupted` |
| 6 | the file's key derivation costs more than allowed (see `--max-kdf-memory`) | `kdf_cost_refused` |
| 7 | the key source failed (missing keyfile, unset variable, keyring error) | `key_source` |
| 8 | a file couldn't be read or written | `io` |
| 130 | interrupted (Ctrl+C) | `interrupted` |

Code 4 can't say which of the two it was: a wrong key and a tampered header
fail the same check, by design.

### Key sources (`--key scheme:location`)

| Spec | Kind | Notes |
| --- | --- | --- |
| `prompt` (default) | passphrase | hidden input; asked twice when encrypting |
| `file:PATH` | key | raw bytes, or base64 as written by `keygen --format base64` |
| `env:VAR` | passphrase | |
| `stdin` | passphrase | first line of standard input |
| `keyring:SERVICE/NAME` | key or passphrase | needs the `keyring` extra |
| `azkv:VAULT/SECRET` | key or passphrase | plugin: `plugins/filecrypt-azkv` |

In key stores (keyring, plugins), only entries written by `keygen --store`,
which are tagged `fcxkey:v1:<base64>`, count as keys. Anything else you put
there yourself is treated as a passphrase and goes through Argon2id.

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
Total work (memory × Argon2id iterations, or memory × scrypt p) is capped at
16 GiB. Decryption refuses files whose KDF settings exceed these caps, since
they are read before anything is authenticated.

Before deriving, `decrypt` and `rekey` check the file's KDF cost. If it needs
more than 1 GiB of memory (or half your RAM, whichever is lower), or more than
8 times that in total work, filecrypt asks before continuing, and refuses when
it isn't running interactively. `--max-kdf-memory MIB` sets the limit
explicitly for scripts; files above it are refused without asking.

## Format

The full byte-level specification, with a worked example and test vectors,
is in [docs/FORMAT.md](docs/FORMAT.md). In short (integers are little-endian
unless noted):

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

## Security and compatibility

* [Threat model](docs/threat-model.md): what filecrypt protects (contents and
  their integrity), what it doesn't (file names, sizes, weak passphrases, a
  compromised computer), and the known open limitations.
* [Security policy](SECURITY.md): how to report a vulnerability privately,
  and which versions get fixes.
* [Compatibility promise](docs/compatibility.md): every `.fcx` version 1 file
  stays decryptable by every future release.

Plain `rekey` changes which secret opens a file but keeps the same file key,
so it doesn't help after a secret has leaked. In that case use
`rekey --rotate-file-key`: it generates a new file key, checks every chunk of
the old body and re-encrypts it, and only replaces the file once all of it has
been written. Old copies of the file are still readable with the old secret,
so delete them too.

## Using filecrypt from Python

`filecrypt.engine` is the layer the CLI is built on, meant for other
front-ends such as a GUI. It never prints or prompts: the secret can be a
callable that is only invoked once the input, output and KDF cost checks have
passed, and progress, notices and confirmations go through callbacks.

```python
from filecrypt import engine
from filecrypt.kdf import Secret

def ask_password():                      # called only when it's actually needed
    return Secret(my_dialog().encode("utf-8"), "passphrase")

engine.encrypt_file("report.pdf", "report.pdf.fcx", ask_password,
                    progress=lambda done, total: bar.update(done, total),
                    notify=show_warning)

info = engine.inspect_file("report.pdf.fcx")   # needs a "key" or a "passphrase"?
engine.decrypt_file("report.pdf.fcx", "report.pdf", ask_password,
                    confirm_expensive=lambda reason: yes_no_dialog(reason))
```

For a background worker thread, pass `cancel=engine.CancelToken()` and call
`token.cancel()` from the UI: the operation stops before the next KDF run or
chunk, raises `engine.Cancelled` and leaves no partial output. Pass
`max_attempts=3` (with a callable secret) to re-ask after a wrong password
without reopening the file; `on_wrong_key(attempt)` fires before each retry.

`engine.verify_file(path, secret, ...)` takes the same keyword arguments as
`decrypt_file` (except the output ones), writes nothing, and returns the
authenticated chunk count and plaintext size. `engine.inspect_file` also
reports `chunk_count` and `plaintext_size`, read from the file's length and
therefore unauthenticated (`None` when the length is impossible).

A wrong password or key raises `container.WrongKeyError`. A file that unlocks
but then fails authentication (damaged, truncated or tampered with) raises
`container.CorruptedFileError`. Both are `container.AuthenticationError`
subclasses. Other errors a user should see derive from `engine.EngineError`
(`OutputExistsError`, `SameFileError`, `ExpensiveKDFError`, `Cancelled`,
`InputError`), alongside `container.FormatError` and `kdf.KDFError`.

## Writing a key-source plugin

Subclass `filecrypt.sources.KeySource`, implement `get(location, *, confirm)`
returning a `filecrypt.kdf.Secret` (and optionally `store(location, key)`),
then register it:

```toml
[project.entry-points."filecrypt.key_sources"]
myscheme = "my_package:MySource"
```

Plugins cannot replace built-in schemes, and if two installed packages
register the same scheme, filecrypt refuses to use either and names both.
Only the plugin matching the `--key` scheme is imported. See
`plugins/filecrypt-azkv` for a complete example with tests.

Plugins are ordinary installed code, so install only ones you trust. Run the
tool with the `filecrypt` command. `python -m filecrypt` also works and drops
the current folder from the import path first, so a folder of downloads can't
shadow a dependency or register a plugin.

## Desktop window

`filecrypt-gui` is a small window for people who'd rather not use a terminal.
It runs on Windows, macOS and Linux (64-bit; PySide6 has no 32-bit Windows
build).

```
pip install ".[gui]"
filecrypt-gui                 # or: filecrypt-gui report.pdf
```

Drop a file on the window or choose one. Files that are already `.fcx` are
decrypted, anything else is encrypted next to the original (which is kept).
Encrypting asks for the password twice, shows how strong it is, and asks you
to confirm you understand that a lost password means a lost file. A wrong
password is asked for again; a damaged file gets its own message, so nobody
retypes a correct password at a broken file. Work runs in the background with
a progress bar and a Cancel button, and cancelling leaves no partial file.
Under **Advanced** you can use a keyfile instead of a password and change the
Argon2id settings.

GUI tests use pytest-qt and run offscreen:
`pip install -e ".[test-gui]"` then `pytest tests/gui`.

### Windows: installer and Explorer integration

The easiest way onto Windows is the setup program,
`filecrypt-<version>-windows-x64-unsigned-<commit>-setup.exe`. It installs
for your account only, so it needs no administrator rights: the app goes to
`%LOCALAPPDATA%\Programs\filecrypt`, gets a Start menu entry, and is added to
Explorer. It's uninstalled from Settings > Apps like anything else, which
also takes it out of Explorer. It needs 64-bit Windows 10 or later.

**The installer is not code-signed yet**, so Windows SmartScreen says it's from
an unknown publisher; choose "More info", then "Run anyway". Before you do,
check the download against the `.sha256` file next to it:
`(Get-FileHash .\filecrypt-...-setup.exe).Hash` in PowerShell should match.
For now the installer and the portable zip are built by CI on every change
(the "Windows build" workflow's artifacts) and aren't published as releases.

Once installed (or with `filecrypt-gui --register` from a pip install or the
portable zip), Explorer gets:

- **Encrypt with filecrypt** on the right-click menu of any file. Selecting
  several files opens one window that asks for the password once.
- Double-clicking a `.fcx` file decrypts it, and its right-click menu has
  **Test with filecrypt**, which checks the password and that the file is
  intact without writing anything. If another app already opens `.fcx`
  files, Windows leaves it in charge; pick filecrypt once under "Open with".

Everything goes under `HKEY_CURRENT_USER\Software\Classes`, nothing
machine-wide. `filecrypt-gui --unregister` removes exactly what was added.
Both take `--quiet` to skip the confirmation box, which is what the installer
uses; the exit code still says whether it worked. Re-run `--register` if you
move the portable folder, because the entries point at the program's path.

## Development

```
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[test]" -e plugins/filecrypt-azkv --no-deps
.venv/Scripts/python -m pytest tests plugins/filecrypt-azkv/tests
```
