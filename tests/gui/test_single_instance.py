"""The single-instance handoff: message format, lock, and the pipe end to end."""

import json
import os
import subprocess
import sys
import uuid

import pytest

from filecrypt.gui import single_instance as si

ABS = os.path.abspath(os.sep)


def p(name):
    return os.path.join(ABS, "docs", name)


# --- the message --------------------------------------------------------------------------

def test_round_trip():
    paths = [p("a.txt"), p("ünïcode ✓.pdf"), p("-starts-with-dash")]
    data = si.encode_request("encrypt", paths)
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    assert si.decode_request(data) == ("encrypt", paths)


@pytest.mark.parametrize("mode", si.MODES)
def test_every_mode_round_trips(mode):
    assert si.decode_request(si.encode_request(mode, [p("x")]))[0] == mode


def test_encode_refuses_relative_paths_and_unknown_modes():
    with pytest.raises(si.ProtocolError):
        si.encode_request("encrypt", ["relative.txt"])
    with pytest.raises(si.ProtocolError):
        si.encode_request("delete", [p("x")])


def _raw(obj):
    return json.dumps(obj).encode() + b"\n"


@pytest.mark.parametrize("data", [
    b"",
    b"not json\n",
    b'{"v": 1, "mode": "encrypt", "paths": ["/x"]}',                 # no newline
    _raw({"v": 1, "mode": "encrypt", "paths": [p("x")]}) + b"\n",     # two lines
    _raw({"v": 2, "mode": "encrypt", "paths": [p("x")]}),
    _raw({"v": 1, "mode": "format-c", "paths": [p("x")]}),
    _raw({"v": 1, "mode": "encrypt", "paths": []}),
    _raw({"v": 1, "mode": "encrypt", "paths": "/x"}),
    _raw({"v": 1, "mode": "encrypt", "paths": ["relative"]}),
    _raw({"v": 1, "mode": "encrypt", "paths": [p("a\x00b")]}),
    _raw({"v": 1, "mode": "encrypt", "paths": [5]}),
    _raw({"v": 1, "mode": "encrypt", "paths": [p("x")], "password": "hunter2"}),
    _raw(["encrypt", p("x")]),
    b"\xff\xfe\n",
    b"x" * (si.MAX_REQUEST + 1),
])
def test_decode_rejects_bad_requests(data):
    with pytest.raises(si.ProtocolError):
        si.decode_request(data)


def test_too_many_paths_are_refused():
    with pytest.raises(si.ProtocolError):
        si.encode_request("encrypt", [p("x" * 200 + str(i)) for i in range(10_000)])


def test_instance_name_is_per_user():
    name = si.instance_name()
    if sys.platform == "win32":
        assert name.startswith("filecrypt-gui-S-1-") and name.rsplit("-", 1)[1].isdigit()
    else:
        assert name.endswith(f"filecrypt-gui-{os.getuid()}.sock")


# --- the lock ------------------------------------------------------------------------------

def _lock_name(tmp_path):
    if sys.platform == "win32":
        return f"Local\\filecrypt-test-{uuid.uuid4().hex}"
    return str(tmp_path / "test.lock")


HOLD = ("import sys, time; from filecrypt.gui.single_instance import InstanceLock; "
        "l = InstanceLock(sys.argv[1]); print(l.acquire(), flush=True); "
        "sys.stdin.readline()")


def _holder(name):
    proc = subprocess.Popen([sys.executable, "-c", HOLD, name], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "True"
    return proc


def test_lock_is_exclusive_between_processes(tmp_path):
    name = _lock_name(tmp_path)
    proc = _holder(name)
    try:
        assert not si.InstanceLock(name).acquire()
    finally:
        proc.communicate("\n", timeout=30)
    lock = si.InstanceLock(name)
    assert lock.acquire() and lock.held
    lock.release()
    assert not lock.held


def test_lock_is_freed_when_the_holder_dies(tmp_path):
    name = _lock_name(tmp_path)
    proc = _holder(name)
    proc.kill()
    proc.wait(timeout=30)
    lock = si.InstanceLock(name)
    assert lock.acquire()
    lock.release()


@pytest.mark.skipif(sys.platform == "win32", reason="checks the lock file mode")
def test_posix_lock_file_is_private(tmp_path):
    name = _lock_name(tmp_path)
    lock = si.InstanceLock(name)
    assert lock.acquire()
    assert os.stat(name).st_mode & 0o077 == 0
    lock.release()


# --- hand_off decisions -----------------------------------------------------------------------

class FakeLock:
    def __init__(self, free):
        self.free = free

    def acquire(self):
        return self.free


def test_hand_off_serves_when_the_lock_is_free():
    lock = FakeLock(True)
    assert si.hand_off("encrypt", [p("a")], lock=lock) == ("serve", lock)


def test_hand_off_sends_when_a_server_answers(monkeypatch):
    sent = []
    monkeypatch.setattr(si, "send", lambda mode, paths, name=None, timeout_ms=0:
                        sent.append((mode, paths)) or True)
    assert si.hand_off("decrypt", [p("a")], lock=FakeLock(False)) == ("sent", None)
    assert sent == [("decrypt", [p("a")])]


def test_hand_off_gives_up_and_runs_alone(monkeypatch):
    monkeypatch.setattr(si, "send", lambda *a, **k: False)
    assert si.hand_off("encrypt", [p("a")], lock=FakeLock(False), wait_s=0.3) == ("alone", None)


def test_hand_off_never_sends_to_an_impostor(monkeypatch):
    def impostor(*a, **k):
        raise si.ImpostorError("not us")
    monkeypatch.setattr(si, "send", impostor)
    assert si.hand_off("encrypt", [p("a")], lock=FakeLock(False), wait_s=5) == ("alone", None)


# --- over a real pipe (needs Qt) ----------------------------------------------------------------

CLIENT = ("import json, sys; from filecrypt.gui import single_instance as si; "
          "print(si.send(sys.argv[1], json.loads(sys.argv[2]), name=sys.argv[3], "
          "timeout_ms=10000))")


@pytest.fixture
def server(qtbot):
    pytest.importorskip("PySide6.QtNetwork", reason="needs PySide6")
    name = f"fct-{uuid.uuid4().hex[:12]}"
    srv = si.make_server(name)
    assert srv is not None, "listen failed"
    got = []
    srv.received.connect(lambda mode, paths: got.append((mode, paths)))
    yield srv, name, got
    srv.close()


def _client(mode, paths, name):
    return subprocess.Popen([sys.executable, "-c", CLIENT, mode, json.dumps(paths), name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_paths_reach_the_server(server, qtbot):
    srv, name, got = server
    paths = [p("a.txt"), p("b ✓.txt")]
    proc = _client("encrypt", paths, name)
    qtbot.waitUntil(lambda: bool(got), timeout=30_000)
    out, err = proc.communicate(timeout=30)
    assert got == [("encrypt", paths)]
    assert out.strip() == "True", err


def test_several_clients_at_once(server, qtbot):
    srv, name, got = server
    procs = [_client("decrypt", [p(f"f{i}.fcx")], name) for i in range(4)]
    qtbot.waitUntil(lambda: len(got) == 4, timeout=60_000)
    for proc in procs:
        out, err = proc.communicate(timeout=30)
        assert out.strip() == "True", err
    assert sorted(paths[0] for _, paths in got) == sorted(p(f"f{i}.fcx") for i in range(4))


def test_server_drops_garbage(server, qtbot):
    from PySide6.QtNetwork import QLocalSocket
    srv, name, got = server
    code = ("import sys; from PySide6.QtCore import QCoreApplication; "
            "from PySide6.QtNetwork import QLocalSocket; app = QCoreApplication([]); "
            "s = QLocalSocket(); s.connectToServer(sys.argv[1]); "
            "assert s.waitForConnected(10000); s.write(b'{\"v\": 1}\\n'); "
            "s.waitForBytesWritten(10000); s.waitForReadyRead(3000); "
            "print(repr(bytes(s.readAll())))")
    out = subprocess.run([sys.executable, "-c", code, name], capture_output=True, text=True,
                         timeout=60)
    assert "ok" not in out.stdout, out
    assert got == []
    assert QLocalSocket  # imported only to require QtNetwork


def test_send_without_a_server_returns_false(qtbot):
    pytest.importorskip("PySide6.QtNetwork", reason="needs PySide6")
    assert si.send("encrypt", [p("a")], name=f"fct-none-{uuid.uuid4().hex[:8]}",
                   timeout_ms=300) is False
