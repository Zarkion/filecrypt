"""Gather the files of one Explorer right-click into one window.

When several files are selected and "Encrypt with filecrypt" is clicked,
Explorer starts one filecrypt process per file. The first one to take a
per-user lock becomes the server: it opens the window and listens on a local
pipe. Every other process sends its paths to the server and exits, so the
person sees one window listing every file and types one password.

Safety:

* The pipe's name contains the user's SID and the Windows session id, and
  Qt's ``UserAccessOption`` restricts it to the current user.
* The lock (a named mutex in the session's ``Local\\`` namespace) is taken
  before listening, so two processes starting together can't both become
  the server.
* Before sending anything, a client checks that the process on the other end
  runs the same program as itself under the same user, so a pipe squatted
  by someone else never receives the paths.
* Only an action name and a list of absolute paths cross the pipe. No
  passwords, and the server asks the person to confirm the list.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from typing import Any, List, Optional, Sequence, Tuple

PROTOCOL_VERSION = 1
MODES = ("encrypt", "decrypt", "test", "open")   # "open": no verb, pick by file type
MAX_REQUEST = 1024 * 1024                        # bytes on the wire
MAX_PATHS = 10_000
ACK = b"ok\n"


class ProtocolError(ValueError):
    """A request on the pipe isn't well formed."""


class ImpostorError(RuntimeError):
    """The pipe is served by a process that isn't this program run by this user."""


# --- the message -----------------------------------------------------------------------

def encode_request(mode: str, paths: Sequence[str]) -> bytes:
    if mode not in MODES:
        raise ProtocolError(f"unknown mode {mode!r}")
    paths = [os.fspath(p) for p in paths]
    for p in paths:
        if not os.path.isabs(p):
            raise ProtocolError(f"path is not absolute: {p!r}")
    data = json.dumps({"v": PROTOCOL_VERSION, "mode": mode, "paths": paths},
                      ensure_ascii=True).encode("ascii") + b"\n"
    if len(data) > MAX_REQUEST:
        raise ProtocolError("too many paths for one request")
    return data


def decode_request(data: bytes) -> Tuple[str, List[str]]:
    """Parse and validate one request line. Raises :class:`ProtocolError`."""
    if len(data) > MAX_REQUEST:
        raise ProtocolError("request too large")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ProtocolError("request must be exactly one line")
    try:
        msg = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("request is not JSON") from None
    if not isinstance(msg, dict) or set(msg) != {"v", "mode", "paths"}:
        raise ProtocolError("unexpected request fields")
    if msg["v"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version {msg['v']!r}")
    mode, paths = msg["mode"], msg["paths"]
    if mode not in MODES:
        raise ProtocolError(f"unknown mode {mode!r}")
    if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS:
        raise ProtocolError("paths must be a non-empty list")
    for p in paths:
        if not isinstance(p, str) or not p or "\x00" in p or not os.path.isabs(p):
            raise ProtocolError("every path must be an absolute path")
    return mode, paths


# --- who am I ----------------------------------------------------------------------------

def instance_name() -> str:
    """The pipe (Windows) or socket (elsewhere) name for this user and session."""
    if sys.platform == "win32":
        return f"filecrypt-gui-{_win_user_sid()}-{_win_session_id()}"
    base = os.environ.get("XDG_RUNTIME_DIR")      # private to the user when set
    if not base or not os.path.isdir(base):
        base = tempfile.gettempdir()
    return os.path.join(base, f"filecrypt-gui-{os.getuid()}.sock")


def _lock_name() -> str:
    if sys.platform == "win32":
        return f"Local\\filecrypt-gui-{_win_user_sid()}"
    return instance_name()[:-len(".sock")] + ".lock"


# --- the lock ------------------------------------------------------------------------------

class InstanceLock:
    """A per-user, non-blocking lock that is released when the process exits."""

    def __init__(self, name: Optional[str] = None):
        self.name = name or _lock_name()
        self._handle: Any = None

    def acquire(self) -> bool:
        if self._handle is not None:
            return True
        if sys.platform == "win32":
            self._handle = _win_mutex_acquire(self.name)
        else:
            self._handle = _posix_lock_acquire(self.name)
        return self._handle is not None

    def release(self) -> None:
        if self._handle is None:
            return
        if sys.platform == "win32":
            _win_mutex_release(self._handle)
        else:
            import fcntl
            fcntl.flock(self._handle, fcntl.LOCK_UN)
            os.close(self._handle)
        self._handle = None

    @property
    def held(self) -> bool:
        return self._handle is not None


def _posix_lock_acquire(path: str) -> Optional[int]:
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


# --- server ---------------------------------------------------------------------------------

def _qt():
    from PySide6 import QtCore, QtNetwork
    return QtCore, QtNetwork


def make_server(name: Optional[str] = None, parent: Any = None):
    """Start listening. Returns a ``Server`` whose ``received(mode, paths)`` signal fires
    for each valid request, or None if listening failed."""
    QtCore, QtNetwork = _qt()

    class Server(QtCore.QObject):
        received = QtCore.Signal(str, list)

        def __init__(self, server_name: str, parent=None):
            super().__init__(parent)
            self.name = server_name
            self.server = QtNetwork.QLocalServer(self)
            self.server.setSocketOptions(QtNetwork.QLocalServer.UserAccessOption)
            self.server.newConnection.connect(self._accept)
            self._buffers = {}
            self._answered = set()

        def listen(self) -> bool:
            if self.server.listen(self.name):
                return True
            # A crashed earlier server can leave its socket file behind (not on
            # Windows). We hold the lock, so no live server can own it.
            QtNetwork.QLocalServer.removeServer(self.name)
            return self.server.listen(self.name)

        def close(self) -> None:
            self.server.close()

        def _accept(self) -> None:
            while self.server.hasPendingConnections():
                sock = self.server.nextPendingConnection()
                self._buffers[sock] = b""
                sock.readyRead.connect(lambda s=sock: self._read(s))
                sock.disconnected.connect(lambda s=sock: self._drop(s))
                QtCore.QTimer.singleShot(10_000, lambda s=sock: self._drop(s, abort=True))
                if sock.bytesAvailable():
                    self._read(sock)

        def _drop(self, sock, abort: bool = False) -> None:
            self._answered.discard(sock)
            if self._buffers.pop(sock, None) is None:
                return          # already handled
            if abort:
                sock.abort()
            sock.deleteLater()

        def _read(self, sock) -> None:
            if sock not in self._buffers or sock in self._answered:
                return
            buf = self._buffers[sock] + bytes(sock.readAll())
            if len(buf) > MAX_REQUEST:
                self._drop(sock, abort=True)
                return
            self._buffers[sock] = buf
            if b"\n" not in buf:
                return
            try:
                mode, paths = decode_request(buf)
            except ProtocolError:
                self._drop(sock, abort=True)
                return
            # Leave closing to the client: on Windows, disconnecting a pipe throws
            # away bytes the client hasn't read yet, so it would miss the ack.
            self._answered.add(sock)
            sock.write(ACK)
            sock.flush()
            self.received.emit(mode, paths)

    server = Server(name or instance_name(), parent)
    return server if server.listen() else None


# --- client --------------------------------------------------------------------------------

def send(mode: str, paths: Sequence[str], name: Optional[str] = None,
         timeout_ms: int = 2000) -> bool:
    """Hand ``paths`` to a running server. False if no server answered.

    Raises :class:`ImpostorError` if the pipe belongs to some other program.
    """
    QtCore, QtNetwork = _qt()
    if QtCore.QCoreApplication.instance() is None:
        send._app = QtCore.QCoreApplication([sys.argv[0] if sys.argv else "filecrypt"])
    data = encode_request(mode, paths)
    sock = QtNetwork.QLocalSocket()
    sock.connectToServer(name or instance_name())
    if not sock.waitForConnected(timeout_ms):
        return False
    try:
        if sys.platform == "win32":
            pid = _win_server_pid_if_us(int(sock.socketDescriptor()))
            if not pid:
                raise ImpostorError("the filecrypt pipe is served by another program")
            _win_allow_foreground(pid)    # let the window come to the front
        sock.write(data)
        if not sock.waitForBytesWritten(timeout_ms):
            return False
        reply = b""
        deadline = time.monotonic() + timeout_ms / 1000
        while ACK not in reply and len(reply) < 16 and time.monotonic() < deadline:
            if not sock.waitForReadyRead(max(1, int((deadline - time.monotonic()) * 1000))):
                if not sock.bytesAvailable():
                    break
            reply += bytes(sock.readAll())
        return reply.startswith(ACK)
    finally:
        sock.abort()


def hand_off(mode: str, paths: Sequence[str], *, lock: Optional[InstanceLock] = None,
             name: Optional[str] = None, wait_s: float = 10.0) -> Tuple[str, Optional[InstanceLock]]:
    """Decide whether this process serves or hands its files to another one.

    Returns ``("serve", lock)`` when this process took the lock and should open the
    window and call :func:`make_server`; ``("sent", None)`` when another process
    took the files; ``("alone", None)`` when neither worked in ``wait_s`` (open a
    window without a server).
    """
    lock = lock or InstanceLock()
    deadline = time.monotonic() + wait_s
    while True:
        if lock.acquire():
            return "serve", lock
        try:
            if send(mode, paths, name=name, timeout_ms=500):
                return "sent", None
        except ImpostorError:
            return "alone", None
        if time.monotonic() >= deadline:
            return "alone", None
        time.sleep(0.1)   # the server may still be starting up


# --- Windows details -------------------------------------------------------------------------

def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    H, B, D = wintypes.HANDLE, wintypes.BOOL, wintypes.DWORD
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, B, wintypes.LPCWSTR]
    k32.CreateMutexW.restype = H
    k32.WaitForSingleObject.argtypes = [H, D]
    k32.WaitForSingleObject.restype = D
    k32.ReleaseMutex.argtypes = [H]
    k32.ReleaseMutex.restype = B
    k32.CloseHandle.argtypes = [H]
    k32.CloseHandle.restype = B
    k32.GetCurrentProcess.restype = H
    k32.GetCurrentProcessId.restype = D
    k32.ProcessIdToSessionId.argtypes = [D, ctypes.POINTER(D)]
    k32.ProcessIdToSessionId.restype = B
    k32.OpenProcess.argtypes = [D, B, D]
    k32.OpenProcess.restype = H
    k32.QueryFullProcessImageNameW.argtypes = [H, D, wintypes.LPWSTR, ctypes.POINTER(D)]
    k32.QueryFullProcessImageNameW.restype = B
    k32.GetNamedPipeServerProcessId.argtypes = [H, ctypes.POINTER(wintypes.ULONG)]
    k32.GetNamedPipeServerProcessId.restype = B
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p
    return k32


def _win_mutex_acquire(name: str) -> Optional[int]:
    k32 = _k32()
    h = k32.CreateMutexW(None, False, name)
    if not h:
        return None          # e.g. someone else created it and denied us access
    WAIT_OBJECT_0, WAIT_ABANDONED = 0x0, 0x80
    if k32.WaitForSingleObject(h, 0) in (WAIT_OBJECT_0, WAIT_ABANDONED):
        return h
    k32.CloseHandle(h)
    return None


def _win_mutex_release(handle: int) -> None:
    k32 = _k32()
    k32.ReleaseMutex(handle)
    k32.CloseHandle(handle)


def _win_session_id() -> int:
    import ctypes
    from ctypes import wintypes
    k32 = _k32()
    sid = wintypes.DWORD()
    if not k32.ProcessIdToSessionId(k32.GetCurrentProcessId(), ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.value


def _win_token_user_sid(process_handle: int) -> str:
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    k32 = _k32()
    TOKEN_QUERY, TokenUser = 0x0008, 1
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        adv.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, TokenUser, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not adv.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            k32.LocalFree(text)
    finally:
        k32.CloseHandle(token)


def _win_user_sid() -> str:
    return _win_token_user_sid(_k32().GetCurrentProcess())


def _win_process_identity(pid: int) -> Optional[Tuple[str, str]]:
    """(normalised image path, user SID) of a process, or None if it can't be read."""
    import ctypes
    from ctypes import wintypes
    k32 = _k32()
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if not k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return None
        try:
            sid = _win_token_user_sid(h)
        except OSError:
            return None
        return os.path.normcase(os.path.realpath(buf.value)), sid
    finally:
        k32.CloseHandle(h)


def _win_allow_foreground(pid: int) -> None:
    try:
        import ctypes
        ctypes.windll.user32.AllowSetForegroundWindow(pid)
    except Exception:
        pass


def _win_server_pid_if_us(pipe_handle: int) -> int:
    """The pipe server's process id if it runs our own program as our own user, else 0."""
    import ctypes
    from ctypes import wintypes
    k32 = _k32()
    pid = wintypes.ULONG()
    if not k32.GetNamedPipeServerProcessId(pipe_handle, ctypes.byref(pid)):
        return 0
    them = _win_process_identity(pid.value)
    # Compare with our own process image, not sys.executable: a venv's
    # python.exe hands over to the base interpreter, so both differ the same way.
    me = _win_process_identity(os.getpid())
    return pid.value if them is not None and me is not None and them == me else 0
