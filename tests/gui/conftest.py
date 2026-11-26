import os

# Run Qt without a display (CI, SSH sessions). Must be set before Qt starts.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# The window tests skip themselves when PySide6 or pytest-qt is missing. The CI
# job meant to run them sets this, so a broken install fails instead of skipping.
if os.environ.get("FILECRYPT_REQUIRE_GUI_TESTS"):
    import PySide6.QtWidgets  # noqa: F401
    import pytestqt  # noqa: F401




import faulthandler  # noqa: E402

import pytest  # noqa: E402

# A test that hangs would otherwise sit silently until the CI job is cancelled,
# and a cancelled job keeps no log. Instead, write each test's name and, on a
# hang, every thread's stack straight to the real stderr (bypassing pytest's
# capture) and end the process so the job fails with a log.
HANG_LIMIT_S = int(os.environ.get("FCX_HANG_S", "120"))


def _stderr_fd(config):
    try:
        from _pytest.faulthandler import fault_handler_stderr_fd_key
        return config.stash[fault_handler_stderr_fd_key]
    except Exception:
        return 2


@pytest.fixture(autouse=True)
def _fail_loudly_on_hang(request):
    fd = _stderr_fd(request.config)
    os.write(fd, f"[test] {request.node.nodeid}\n".encode("utf-8", "replace"))
    faulthandler.dump_traceback_later(HANG_LIMIT_S, exit=True, file=fd)
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()


def pytest_sessionfinish(session):
    # Also catch a hang while the process shuts down (threads, child processes).
    fd = _stderr_fd(session.config)
    os.write(fd, b"[session finished]\n")
    faulthandler.dump_traceback_later(HANG_LIMIT_S, exit=True, file=fd)
