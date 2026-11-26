"""Copying the Mark of the Web (Zone.Identifier) from an input to its output."""

import io
import sys

import pytest

from filecrypt import _motw

MARK = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/x.exe\r\n"


class FakeStreams:
    """Alternate data streams in a dict: path + ':Zone.Identifier' -> bytes."""

    def __init__(self, streams=None, read_only=()):
        self.streams = dict(streams or {})
        self.read_only = set(read_only)

    def __call__(self, name, mode):
        if "r" in mode:
            if name not in self.streams:
                raise FileNotFoundError(name)
            return io.BytesIO(self.streams[name])
        if name.split(":Zone")[0] in self.read_only:
            raise OSError("no alternate data streams on this drive")
        store = self.streams

        class W(io.BytesIO):
            def close(self):
                store[name] = self.getvalue()
                super().close()
        return W()


def test_mark_is_copied():
    fs = FakeStreams({"in.fcx" + _motw.STREAM: MARK})
    assert _motw.copy_zone_identifier("in.fcx", "out.exe", opener=fs) is True
    assert fs.streams["out.exe" + _motw.STREAM] == MARK


def test_no_mark_means_nothing_to_do():
    fs = FakeStreams()
    assert _motw.copy_zone_identifier("in.fcx", "out.exe", opener=fs) is None
    assert fs.streams == {}


def test_write_failure_is_reported():
    fs = FakeStreams({"in.fcx" + _motw.STREAM: MARK}, read_only={"out.exe"})
    assert _motw.copy_zone_identifier("in.fcx", "out.exe", opener=fs) is False


def test_oversized_or_empty_marks_are_ignored():
    fs = FakeStreams({"big" + _motw.STREAM: b"x" * (_motw.MAX_SIZE + 1),
                      "empty" + _motw.STREAM: b""})
    assert _motw.read_zone_identifier("big", opener=fs) is None
    assert _motw.read_zone_identifier("empty", opener=fs) is None


@pytest.mark.skipif(sys.platform == "win32", reason="checks that it does nothing off NTFS")
def test_does_nothing_off_windows(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"x")
    assert _motw.copy_zone_identifier(src, tmp_path / "b") is None
    assert not (tmp_path / ("b" + _motw.STREAM)).exists()


@pytest.mark.skipif(sys.platform != "win32", reason="needs NTFS alternate data streams")
def test_real_alternate_data_stream_on_windows(tmp_path):
    src, dest = tmp_path / "in.fcx", tmp_path / "out.txt"
    src.write_bytes(b"cipher")
    dest.write_bytes(b"plain")
    with open(str(src) + _motw.STREAM, "wb") as f:
        f.write(MARK)
    assert _motw.copy_zone_identifier(src, dest) is True
    with open(str(dest) + _motw.STREAM, "rb") as f:
        assert f.read() == MARK
    assert dest.read_bytes() == b"plain"          # the file itself is untouched
