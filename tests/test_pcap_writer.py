"""Tests for classic libpcap writer (pure bytes; no root)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sniffer.pcap_writer import PcapWriter

# Fixed little-endian layouts from AGENTS.md.
_GLOBAL = struct.Struct("<IHHiIII")
_RECORD = struct.Struct("<IIII")

MAGIC = 0xA1B2C3D4
VERSION_MAJOR = 2
VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1


def _expected_file(
    snaplen: int,
    packets: list[tuple[int, bytes, int]],
    linktype: int = LINKTYPE_ETHERNET,
) -> bytes:
    out = bytearray()
    out += _GLOBAL.pack(MAGIC, VERSION_MAJOR, VERSION_MINOR, 0, 0, snaplen, linktype)
    for ts_ns, data, orig_len in packets:
        incl_len = min(len(data), snaplen)
        ts_sec = ts_ns // 1_000_000_000
        ts_usec = (ts_ns % 1_000_000_000) // 1000
        out += _RECORD.pack(ts_sec, ts_usec, incl_len, orig_len)
        out += data[:incl_len]
    return bytes(out)


def test_writes_global_header_and_two_records(tmp_path: Path) -> None:
    path = tmp_path / "out.pcap"
    pkt1 = b"\x00" * 60
    pkt2 = b"\xff" * 100
    ts1 = 1_700_000_000_123_456_789  # -> sec=1700000000, usec=123456
    ts2 = 1_700_000_001_999_999_999  # -> sec=1700000001, usec=999999
    snaplen = 65535

    with PcapWriter(path, snaplen=snaplen) as writer:
        writer.write(ts1, pkt1)
        writer.write(ts2, pkt2)

    raw = path.read_bytes()
    expected = _expected_file(
        snaplen,
        [
            (ts1, pkt1, len(pkt1)),
            (ts2, pkt2, len(pkt2)),
        ],
    )
    assert raw == expected
    assert len(raw) == 24 + 16 + 60 + 16 + 100


def test_truncates_to_snaplen_keeps_orig_len(tmp_path: Path) -> None:
    path = tmp_path / "trunc.pcap"
    data = bytes(range(256))
    ts_ns = 42_000_000_000  # exact seconds, usec=0
    snaplen = 64

    with PcapWriter(path, snaplen=snaplen) as writer:
        writer.write(ts_ns, data)

    raw = path.read_bytes()
    assert raw == _expected_file(snaplen, [(ts_ns, data, len(data))])
    # Record header: incl_len=64, orig_len=256
    ts_sec, ts_usec, incl_len, orig_len = _RECORD.unpack_from(raw, 24)
    assert (ts_sec, ts_usec, incl_len, orig_len) == (42, 0, 64, 256)
    assert raw[40:] == data[:64]


def test_explicit_orig_len(tmp_path: Path) -> None:
    path = tmp_path / "orig.pcap"
    data = b"abcd"
    with PcapWriter(path, snaplen=65535) as writer:
        writer.write(0, data, orig_len=999)
    _, _, incl_len, orig_len = _RECORD.unpack_from(path.read_bytes(), 24)
    assert incl_len == 4
    assert orig_len == 999


def test_write_before_open_raises(tmp_path: Path) -> None:
    writer = PcapWriter(tmp_path / "x.pcap", snaplen=100)
    with pytest.raises(RuntimeError, match="not open"):
        writer.write(0, b"x")


def test_custom_linktype(tmp_path: Path) -> None:
    path = tmp_path / "sll.pcap"
    with PcapWriter(path, snaplen=100, linktype=113) as writer:
        writer.write(0, b"\x00" * 10)
    magic, major, minor, _tz, _sf, snaplen, linktype = _GLOBAL.unpack_from(
        path.read_bytes(), 0
    )
    assert (magic, major, minor, snaplen, linktype) == (
        MAGIC,
        VERSION_MAJOR,
        VERSION_MINOR,
        100,
        113,
    )


def test_roundtrip_scapy_or_dpkt(tmp_path: Path) -> None:
    """If scapy or dpkt is installed, re-read the file and compare payloads."""
    path = tmp_path / "rt.pcap"
    payloads = [b"\xaa" * 32, b"\xbb" * 48]
    timestamps = [1_650_000_000_000_000_000, 1_650_000_001_500_000_000]

    with PcapWriter(path, snaplen=65535) as writer:
        for ts, data in zip(timestamps, payloads, strict=True):
            writer.write(ts, data)

    try:
        import dpkt  # type: ignore[import-untyped]
    except ImportError:
        dpkt = None

    try:
        from scapy.all import rdpcap  # type: ignore[import-untyped]
    except ImportError:
        rdpcap = None

    if dpkt is None and rdpcap is None:
        pytest.skip("neither dpkt nor scapy installed")

    if dpkt is not None:
        with path.open("rb") as fh:
            pcap = dpkt.pcap.Reader(fh)
            got = [bytes(buf) for _ts, buf in pcap]
        assert got == payloads

    if rdpcap is not None:
        pkts = rdpcap(str(path))
        assert [bytes(p) for p in pkts] == payloads
