"""OS keyring key source: ``keyring:SERVICE/NAME`` (or ``keyring:NAME``).

Uses the ``keyring`` package (Windows Credential Manager, macOS Keychain,
Secret Service on Linux). Install with ``pip install filecrypt[keyring]``.
Keys are stored as ``fcxkey:v1:<base64>``. Any entry without that tag is
treated as a passphrase (and goes through Argon2id), so a hand-entered
password works safely.
"""

from __future__ import annotations

from typing import Tuple

from .kdf import Secret

DEFAULT_SERVICE = "filecrypt"


def _keyring():
    from .sources import KeySourceError
    try:
        import keyring
    except ImportError:
        raise KeySourceError("the keyring key source needs the keyring package: "
                             "pip install filecrypt[keyring]") from None
    return keyring


def _split(location: str) -> Tuple[str, str]:
    from .sources import KeySourceError
    service, sep, name = location.partition("/")
    if not sep:
        service, name = DEFAULT_SERVICE, location
    if not service or not name:
        raise KeySourceError("keyring location must be SERVICE/NAME or NAME, e.g. keyring:filecrypt/main")
    return service, name


class KeyringSource:
    name = "keyring"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        from .sources import KeySourceError, secret_from_stored_text
        service, name = _split(location)
        value = _keyring().get_password(service, name)
        if not value:
            raise KeySourceError(f"no keyring entry for {service}/{name}")
        return secret_from_stored_text(value)

    def store(self, location: str, key: bytes) -> None:
        from .sources import KeySourceError, encode_stored_key
        service, name = _split(location)
        kr = _keyring()
        if kr.get_password(service, name):
            raise KeySourceError(f"keyring entry {service}/{name} already exists")
        kr.set_password(service, name, encode_stored_key(key))
