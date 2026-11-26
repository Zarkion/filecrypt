"""CI guard rails, run after the test suite.

    check_ci_env.py backend <native|native+cffi|cffi|scrypt>
        Fail unless the installed packages give exactly that Argon2 backend.

    check_ci_env.py skips <junit.xml>
        Fail if a platform-specific test was skipped on the platform it targets
        (Windows ACL / delete-on-close tests on Windows, POSIX permission tests
        elsewhere), so a broken skip condition can't hide them.
"""

import platform
import struct
import sys
import xml.etree.ElementTree as ET


def check_backend(expected: str) -> None:
    from filecrypt import kdf

    native = kdf._native_argon2_available()
    cffi = kdf._cffi_argon2_available()
    actual = {(True, False): "native", (True, True): "native+cffi",
              (False, True): "cffi", (False, False): "scrypt"}[(native, cffi)]
    import cryptography
    print(f"python {platform.python_version()} {platform.machine()} "
          f"{struct.calcsize('P') * 8}-bit, cryptography {cryptography.__version__}, "
          f"argon2 backend: {actual}")
    if actual != expected:
        sys.exit(f"expected Argon2 backend {expected!r}, got {actual!r}")


def check_skips(junit_path: str) -> None:
    own = "Windows" if sys.platform == "win32" else "POSIX"
    bad = []
    for case in ET.parse(junit_path).iter("testcase"):
        skip = case.find("skipped")
        if skip is not None and own in (skip.get("message") or ""):
            bad.append(f"{case.get('classname')}::{case.get('name')}: {skip.get('message')}")
    if sys.platform == "win32":
        ran = [c for c in ET.parse(junit_path).iter("testcase")
               if "test_winacl" in (c.get("classname") or "")
               and c.find("skipped") is None]
        if not ran:
            bad.append("no test_winacl tests ran")
    if bad:
        sys.exit(f"{own}-only tests were skipped on {sys.platform}:\n  " + "\n  ".join(bad))
    print(f"no {own}-only tests skipped on {sys.platform}")


if __name__ == "__main__":
    {"backend": check_backend, "skips": check_skips}[sys.argv[1]](sys.argv[2])
