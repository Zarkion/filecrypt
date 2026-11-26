import os
import sys

# Run Qt without a display (CI, SSH sessions). Must be set before Qt starts.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# The window tests skip themselves when PySide6 or pytest-qt is missing. The CI
# job meant to run them sets this, so a broken install fails instead of skipping.
if os.environ.get("FILECRYPT_REQUIRE_GUI_TESTS"):
    import PySide6.QtWidgets  # noqa: F401
    import pytestqt  # noqa: F401



import faulthandler  # noqa: E402
import threading  # noqa: E402

import pytest  # noqa: E402

# A GUI or pipe test that hangs would otherwise sit silently until the CI job
# times out. Print every thread's stack (outside pytest's output capture) and
# stop the run instead.
HANG_LIMIT_S = int(os.environ.get("FCX_HANG_S", "180"))


@pytest.fixture(autouse=True)
def _fail_loudly_on_hang(request):
    def on_hang():
        capman = request.config.pluginmanager.getplugin("capturemanager")
        if capman is not None:
            capman.suspend_global_capture(in_=True)
        sys.stderr.write(f"\n*** {request.node.nodeid} hung for {HANG_LIMIT_S}s ***\n")
        sys.stderr.flush()
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
        sys.stderr.flush()
        os._exit(3)

    timer = threading.Timer(HANG_LIMIT_S, on_hang)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
