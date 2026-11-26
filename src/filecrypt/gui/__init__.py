"""A desktop window for filecrypt (needs the ``gui`` extra: ``pip install filecrypt[gui]``).

Start it with ``filecrypt-gui [FILE]`` or ``python -m filecrypt.gui [FILE]``.
"""

from __future__ import annotations

import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("filecrypt-gui needs PySide6: pip install \"filecrypt[gui]\"", file=sys.stderr)
        return 2

    from .. import __version__
    from .window import MainWindow

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName("filecrypt")
    app.setApplicationVersion(__version__)
    window = MainWindow()
    paths = [a for a in argv if not a.startswith("-")]
    if paths:
        from pathlib import Path
        window.set_file(Path(paths[0]))
    window.show()
    return app.exec()
