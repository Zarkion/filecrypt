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


# pytest copies each running test's id into the PYTEST_CURRENT_TEST environment
# variable. Windows caps one variable at 32,767 characters, and an id built from
# a large parametrized input (say 1 MiB of bytes) froze a Windows CI job instead
# of failing. Fail collection on every platform instead, with a pointer to the
# fix: pass short labels through ``ids=`` in ``pytest.mark.parametrize``.
MAX_TEST_ID_LENGTH = 1000


def _check_test_id_lengths(items):
    long_ids = [item.nodeid for item in items if len(item.nodeid) > MAX_TEST_ID_LENGTH]
    if long_ids:
        shown = "\n".join(f"  {nid[:120]}... ({len(nid)} chars)" for nid in long_ids[:5])
        raise pytest.UsageError(
            f"{len(long_ids)} test id(s) exceed {MAX_TEST_ID_LENGTH} characters. "
            "Give the parametrize call short ids= labels, or the run can hang "
            f"on Windows:\n{shown}"
        )


def pytest_collection_modifyitems(config, items):
    _check_test_id_lengths(items)
    if kdf.argon2_available():
        return
    skip = pytest.mark.skip(reason=ARGON2_SKIP_REASON)
    for item in items:
        if item.get_closest_marker("requires_argon2"):
            item.add_marker(skip)
