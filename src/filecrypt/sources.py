"""Key sources, selected with ``--key scheme:location``.

Built in: prompt (default), file, env, stdin, keyring (needs the keyring extra).
Third-party sources register an entry point in the ``filecrypt.key_sources``
group, e.g. in the plugin's pyproject.toml:

    [project.entry-points."filecrypt.key_sources"]
    azkv = "filecrypt_azkv:AzureKeyVaultSource"

The entry point may name a KeySource subclass, an instance, or a zero-argument
factory returning one. Plugins cannot replace built-in schemes.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import os
import re
import sys
from typing import Dict, List, Tuple

from .kdf import MIN_KEY_BYTES, Secret
from .keygen import load_key_material, write_keyfile

ENTRY_POINT_GROUP = "filecrypt.key_sources"
DEFAULT_SPEC = "prompt"

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9_-]+$")


class KeySourceError(Exception):
    """A key source could not supply (or store) a key."""


class KeySource:
    """Base class for key sources.

    ``get`` returns the secret. ``confirm`` is True when encrypting, so
    interactive sources should ask twice. ``store`` is optional and used by
    ``keygen --store``; it receives raw key bytes.
    """

    name = "?"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        raise NotImplementedError

    def store(self, location: str, key: bytes) -> None:
        raise KeySourceError(f"the {self.name} key source cannot store keys")


class PromptSource(KeySource):
    name = "prompt"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        first = getpass.getpass("Passphrase: ")
        if not first:
            raise KeySourceError("empty passphrase")
        if confirm and getpass.getpass("Confirm passphrase: ") != first:
            raise KeySourceError("passphrases do not match")
        return Secret(first.encode("utf-8"), "passphrase")


class FileSource(KeySource):
    name = "file"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        if not location:
            raise KeySourceError("file key source needs a path, e.g. file:my.key")
        try:
            with open(location, "rb") as f:
                data = f.read()
        except OSError as e:
            raise KeySourceError(f"cannot read keyfile {location}: {e.strerror or e}") from None
        if not data:
            raise KeySourceError(f"keyfile {location} is empty")
        return Secret(load_key_material(data), "key")

    def store(self, location: str, key: bytes) -> None:
        if not location:
            raise KeySourceError("file key source needs a path, e.g. file:my.key")
        write_keyfile(location, key)


class EnvSource(KeySource):
    name = "env"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        if not location:
            raise KeySourceError("env key source needs a variable name, e.g. env:FILECRYPT_PASSPHRASE")
        value = os.environ.get(location)
        if not value:
            raise KeySourceError(f"environment variable {location} is not set or empty")
        return Secret(os.fsencode(value) if os.name != "nt" else value.encode("utf-8"), "passphrase")


class StdinSource(KeySource):
    name = "stdin"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        stream = getattr(sys.stdin, "buffer", None)
        line = stream.readline() if stream is not None else sys.stdin.readline().encode("utf-8")
        line = line.rstrip(b"\r\n")
        if not line:
            raise KeySourceError("no passphrase on standard input")
        return Secret(line, "passphrase")


_BUILTINS: Dict[str, type] = {
    "prompt": PromptSource,
    "file": FileSource,
    "env": EnvSource,
    "stdin": StdinSource,
}


STORED_KEY_PREFIX = "fcxkey:v1:"


def encode_stored_key(key: bytes) -> str:
    """Text form of a key for key stores: ``fcxkey:v1:<base64>``."""
    return STORED_KEY_PREFIX + base64.b64encode(key).decode("ascii")


def secret_from_stored_text(text: str) -> Secret:
    """Interpret a secret stored as text in a key store.

    Only text tagged ``fcxkey:v1:`` (what ``keygen --store`` writes) is a key.
    Anything else is a passphrase, even if it happens to look like base64, so
    a hand-entered password always gets the memory-hard KDF. Plugins should
    use this together with ``encode_stored_key``.
    """
    stripped = text.strip()
    if stripped.startswith(STORED_KEY_PREFIX):
        body = stripped[len(STORED_KEY_PREFIX):]
        try:
            key = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            key = b""
        if len(key) < MIN_KEY_BYTES:
            raise KeySourceError("malformed stored key (expected fcxkey:v1: followed by "
                                 f"base64 of at least {MIN_KEY_BYTES} bytes)")
        return Secret(key, "key")
    return Secret(text.encode("utf-8").strip(b"\r\n"), "passphrase")


def _register_optional_builtins() -> None:
    from .keyring_source import KeyringSource
    _BUILTINS["keyring"] = KeyringSource


try:
    _register_optional_builtins()
except ImportError:  # keyring_source module missing in a stripped install
    pass


def _entry_points():
    from importlib.metadata import entry_points
    try:
        return list(entry_points(group=ENTRY_POINT_GROUP))
    except TypeError:  # Python 3.9
        return list(entry_points().get(ENTRY_POINT_GROUP, []))


def parse_key_spec(spec: str) -> Tuple[str, str]:
    if not spec:
        raise KeySourceError("empty --key")
    scheme, sep, location = spec.partition(":")
    scheme = scheme.lower()
    if len(scheme) == 1 and sep:
        raise KeySourceError(f"--key {spec!r} looks like a Windows path; use file:{spec}")
    if not _SCHEME_RE.match(scheme):
        raise KeySourceError(f"invalid --key {spec!r}; expected scheme:location, e.g. file:my.key")
    return scheme, location


def get_source(scheme: str) -> KeySource:
    if scheme in _BUILTINS:
        return _BUILTINS[scheme]()
    for ep in _entry_points():
        if ep.name != scheme:
            continue
        try:
            obj = ep.load()
            src = obj() if callable(obj) and not isinstance(obj, KeySource) else obj
        except Exception as e:
            raise KeySourceError(f"key source plugin {scheme!r} failed to load: {e}") from None
        if not callable(getattr(src, "get", None)):
            raise KeySourceError(f"key source plugin {scheme!r} is not a key source")
        return src
    raise KeySourceError(f"unknown key source {scheme!r}; available: "
                         f"{', '.join(available_sources())}")


def available_sources() -> List[str]:
    names = list(_BUILTINS)
    names += sorted({ep.name for ep in _entry_points()} - set(names))
    return names


def resolve_secret(spec: str, *, confirm: bool = False) -> Secret:
    scheme, location = parse_key_spec(spec)
    secret = get_source(scheme).get(location, confirm=confirm)
    if not isinstance(secret, Secret):
        raise KeySourceError(f"key source {scheme!r} returned an invalid secret")
    return secret
