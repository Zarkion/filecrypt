import os

# Run Qt without a display (CI, SSH sessions). Must be set before Qt starts.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# The window tests skip themselves when PySide6 or pytest-qt is missing. The CI
# job meant to run them sets this, so a broken install fails instead of skipping.
if os.environ.get("FILECRYPT_REQUIRE_GUI_TESTS"):
    import PySide6.QtWidgets  # noqa: F401
    import pytestqt  # noqa: F401
