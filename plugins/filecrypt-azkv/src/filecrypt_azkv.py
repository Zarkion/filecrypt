"""Azure Key Vault key source for filecrypt — an example third-party plugin.

    --key azkv:VAULT/SECRET[/VERSION]
    --key azkv:https://VAULT.vault.azure.net/secrets/SECRET[/VERSION]

Authentication uses azure-identity's DefaultAzureCredential, so ``az login``,
environment variables, managed identity and the other standard methods work.
``filecrypt keygen --store azkv:VAULT/SECRET`` creates a new random key in the
vault (it refuses to replace an existing secret, and reports an error if
another writer created the same secret at the same moment). Keys are stored as
``fcxkey:v1:<base64>``; a secret without that tag is used as a passphrase.

The plugin is registered with one entry point in its pyproject.toml:

    [project.entry-points."filecrypt.key_sources"]
    azkv = "filecrypt_azkv:AzureKeyVaultSource"
"""

from __future__ import annotations

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from filecrypt.kdf import Secret
from filecrypt.sources import (KeySource, KeySourceError, encode_stored_key,
                               secret_from_stored_text)

__version__ = "0.1.0"

# Public and sovereign-cloud Key Vault DNS suffixes.
_VAULT_SUFFIXES = (
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
    ".vault.microsoftazure.de",
)
_VAULT_NAME = re.compile(r"^[A-Za-z0-9-]{3,24}$")
_SECRET_NAME = re.compile(r"^[A-Za-z0-9-]{1,127}$")
# Key Vault object versions are 32 hexadecimal characters.
_VERSION = re.compile(r"^[0-9A-Fa-f]{32}$")


def parse_location(location: str) -> Tuple[str, str, Optional[str]]:
    """Return (vault_url, secret_name, version_or_None)."""
    if location.startswith(("https://", "http://")):
        u = urlparse(location)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or not host.endswith(_VAULT_SUFFIXES):
            raise KeySourceError(f"not an Azure Key Vault URL: {location}")
        parts = [p for p in u.path.split("/") if p]
        if len(parts) not in (2, 3) or parts[0] != "secrets":
            raise KeySourceError("expected https://VAULT.vault.azure.net/secrets/NAME[/VERSION]")
        vault_url = f"https://{host}"
        name, version = parts[1], (parts[2] if len(parts) == 3 else None)
    else:
        parts = location.split("/")
        if len(parts) not in (2, 3) or not _VAULT_NAME.match(parts[0]):
            raise KeySourceError("azkv location must be VAULT/SECRET[/VERSION], e.g. azkv:myvault/filecrypt-key")
        vault_url = f"https://{parts[0].lower()}.vault.azure.net"
        name, version = parts[1], (parts[2] if len(parts) == 3 else None)
    if not _SECRET_NAME.match(name):
        raise KeySourceError(f"invalid Key Vault secret name in {location!r}")
    if version is not None and not _VERSION.match(version):
        raise KeySourceError(f"invalid Key Vault secret version in {location!r}: "
                             "expected 32 hexadecimal characters")
    return vault_url, name, version


def _make_client(vault_url: str):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        raise KeySourceError("azkv needs azure-identity and azure-keyvault-secrets: "
                             "pip install filecrypt-azkv") from None
    return SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())


def _is_not_found(exc: Exception) -> bool:
    try:
        from azure.core.exceptions import ResourceNotFoundError
    except ImportError:
        return False
    return isinstance(exc, ResourceNotFoundError)


class AzureKeyVaultSource(KeySource):
    name = "azkv"

    def get(self, location: str, *, confirm: bool = False) -> Secret:
        vault_url, name, version = parse_location(location)
        try:
            secret = _make_client(vault_url).get_secret(name, version)
        except KeySourceError:
            raise
        except Exception as e:
            if _is_not_found(e):
                raise KeySourceError(f"secret {name} not found in {vault_url}") from None
            raise KeySourceError(f"Azure Key Vault error: {e}") from None
        if not secret.value:
            raise KeySourceError(f"secret {name} in {vault_url} is empty")
        return secret_from_stored_text(secret.value)

    def store(self, location: str, key: bytes) -> None:
        vault_url, name, version = parse_location(location)
        if version:
            raise KeySourceError("cannot store to a specific secret version")
        client = _make_client(vault_url)
        try:
            client.get_secret(name)
        except Exception as e:
            if not _is_not_found(e):
                raise KeySourceError(f"Azure Key Vault error: {e}") from None
        else:
            raise KeySourceError(f"secret {name} already exists in {vault_url}")
        try:
            ours = client.set_secret(name, encode_stored_key(key)).properties.version
            versions = {p.version for p in client.list_properties_of_secret_versions(name)}
        except Exception as e:
            raise KeySourceError(f"Azure Key Vault error: {e}") from None
        # The existence check above and set_secret are two separate requests, so
        # another writer can slip in between. Key Vault keeps every value as a
        # version, so any version other than ours means that happened.
        others = sorted(versions - {ours})
        if others or ours not in versions:
            raise KeySourceError(
                f"secret {name} in {vault_url} was written by someone else at the same "
                f"time (versions: {', '.join(others) or 'unknown'}; ours: {ours}). "
                "Check which version is current before encrypting with it.")
