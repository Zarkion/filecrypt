"""Shared pytest configuration.

``@pytest.mark.requires_argon2`` marks a test that assumes an Argon2id backend
is installed (for example, that Argon2id is the default KDF). Such tests are
skipped when neither cryptography >= 44 nor argon2-cffi provides one, so the
suite stays green on the scrypt fallback without a hand-kept deselect list.
"""

import pytest

from filecrypt import kdf

# Keep the reason free of platform words: CI's skip check treats a skip whose
# message names the runner's own platform as a hidden platform-only test.
ARGON2_SKIP_REASON = "no Argon2id backend installed (scrypt fallback)"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_argon2: needs an Argon2id backend; skipped on the scrypt fallback",
    )


def pytest_collection_modifyitems(config, items):
    if kdf.argon2_available():
        return
    skip = pytest.mark.skip(reason=ARGON2_SKIP_REASON)
    for item in items:
        if item.get_closest_marker("requires_argon2"):
            item.add_marker(skip)
