"""Tests for AF_PACKET RawCapture (mocked socket; no root required)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sniffer.capture import (
    ETH_P_ALL,
    PACKET_ADD_MEMBERSHIP,
    PACKET_MR_PROMISC,
    SOL_PACKET,
    RawCapture,
    RawPacket,
)


def _fake_addr(
    ifname: str = "eth0",
    proto: int = 0x0800,
    pkttype: int = 0,
    hatype: int = 1,
    hw: bytes = b"\x00" * 6,
) -> tuple:
    return (ifname, proto, pkttype, hatype, hw)


@pytest.fixture
def mock_socket_mod() -> MagicMock:
    """Patch socket module pieces used by RawCapture."""
    with (
        patch("sniffer.capture.socket.AF_PACKET", 17, create=True),
        patch("sniffer.capture.socket.socket") as sock_cls,
        patch("sniffer.capture.socket.if_nametoindex", return_value=2),
        patch("sniffer.capture.select.select") as sel,
        patch("sniffer.capture.time.time_ns", return_value=1_700_000_000_123_456_789),
    ):
        sock = MagicMock()
        sock_cls.return_value = sock
        sock.fileno.return_value = 7
        yield MagicMock(sock_cls=sock_cls, sock=sock, select=sel)


def test_open_binds_interface(mock_socket_mod: MagicMock) -> None:
    with RawCapture(iface="eth0", promisc=False, snaplen=1500) as cap:
        assert cap.sock is mock_socket_mod.sock
    mock_socket_mod.sock_cls.assert_called_once()
    args, _kwargs = mock_socket_mod.sock_cls.call_args
    assert args[2] == __import__("socket").ntohs(ETH_P_ALL)
    mock_socket_mod.sock.bind.assert_called_once_with(("eth0", 0))
    mock_socket_mod.sock.close.assert_called_once()


def test_open_without_iface_does_not_bind(mock_socket_mod: MagicMock) -> None:
    with RawCapture(iface=None, promisc=False, snaplen=65535):
        pass
    mock_socket_mod.sock.bind.assert_not_called()


def test_promisc_setsockopt(mock_socket_mod: MagicMock) -> None:
    import struct

    with RawCapture(iface="eth0", promisc=True, snaplen=65535):
        pass
    expected = struct.pack("iHH8s", 2, PACKET_MR_PROMISC, 0, b"")
    mock_socket_mod.sock.setsockopt.assert_called_once_with(
        SOL_PACKET, PACKET_ADD_MEMBERSHIP, expected
    )


def test_promisc_without_iface_raises() -> None:
    with pytest.raises(ValueError, match="promiscuous"):
        RawCapture(iface=None, promisc=True, snaplen=65535).__enter__()


def test_permission_error_propagates(mock_socket_mod: MagicMock) -> None:
    mock_socket_mod.sock_cls.side_effect = PermissionError("Operation not permitted")
    with pytest.raises(PermissionError):
        RawCapture(iface="lo", promisc=False, snaplen=65535).__enter__()


def test_missing_iface_oserror(mock_socket_mod: MagicMock) -> None:
    mock_socket_mod.sock.bind.side_effect = OSError(19, "No such device")
    with pytest.raises(OSError):
        RawCapture(iface="nope0", promisc=False, snaplen=65535).__enter__()


def test_read_returns_packet(mock_socket_mod: MagicMock) -> None:
    payload = b"\xff" * 64
    mock_socket_mod.select.return_value = ([7], [], [])
    mock_socket_mod.sock.recvfrom.return_value = (payload, _fake_addr("lo", hatype=772))

    with RawCapture(iface="lo", promisc=False, snaplen=65535) as cap:
        pkt = cap.read()

    assert isinstance(pkt, RawPacket)
    assert pkt.data == payload
    assert pkt.time_ns == 1_700_000_000_123_456_789
    assert pkt.ifname == "lo"
    assert pkt.pkttype == 0
    assert pkt.hatype == 772


def test_read_timeout_returns_none(mock_socket_mod: MagicMock) -> None:
    mock_socket_mod.select.return_value = ([], [], [])
    with RawCapture(iface="eth0", promisc=False, snaplen=65535) as cap:
        assert cap.read() is None
    mock_socket_mod.sock.recvfrom.assert_not_called()


def test_read_before_open_raises() -> None:
    cap = RawCapture(iface="eth0", promisc=False, snaplen=65535)
    with pytest.raises(RuntimeError, match="not open"):
        cap.read()
