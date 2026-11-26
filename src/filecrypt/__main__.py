import os
import sys

# `python -m filecrypt` puts the current folder first on sys.path. A folder of
# untrusted downloads could then shadow a dependency (cryptography/, keyring.py)
# or plant a *.dist-info that registers a key-source plugin. Drop it before
# importing anything else. The `filecrypt` console script doesn't have this
# problem and is the recommended way to run the tool.
_cwd = os.path.normcase(os.path.abspath(os.getcwd()))
sys.path[:] = [p for p in sys.path
               if p and os.path.normcase(os.path.abspath(p)) != _cwd]

from filecrypt.cli import main  # noqa: E402

sys.exit(main())
