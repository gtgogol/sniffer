"""Tests for one-line summaries and hex dumps."""

from __future__ import annotations

from sniffer.capture import RawPacket
from sniffer.output import format_line, hexdump
from sniffer.parse import parse
from tests.packets import (
    ARP_FRAME,
    TCP_IPV4_SYN,
    UDP_IPV6_DNS,
    VLAN_TCP_IPV4,
)


def _pkt(data: bytes, ifname: str = "eth0") -> RawPacket:
    return RawPacket(
        data=data,
        time_ns=1_700_000_000_789_012_000,  # -> local time depends on TZ
        ifname=ifname,
        pkttype=0,
        hatype=1,
        orig_len=len(data),
    )


def test_format_line_tcp_ipv4_syn() -> None:
    data = TCP_IPV4_SYN
    line = format_line(_pkt(data), parse(data))
    assert "eth0" in line
    assert "IPv4" in line
    assert "TCP" in line
    assert "192.168.1.5:51234 -> 93.184.216.34:443" in line
    assert "[SYN]" in line
    assert f"len={len(data)}" in line


def test_format_line_udp_ipv6() -> None:
    data = UDP_IPV6_DNS
    line = format_line(_pkt(data, ifname="lo"), parse(data))
    assert "lo" in line
    assert "IPv6" in line
    assert "UDP" in line
    assert "2001:db8::1:53000 -> 2001:db8::2:53" in line
    assert f"len={len(data)}" in line


def test_format_line_vlan_still_shows_ipv4_tcp() -> None:
    data = VLAN_TCP_IPV4
    line = format_line(_pkt(data), parse(data))
    assert "IPv4 TCP" in line
    assert "443" in line


def test_format_line_arp() -> None:
    data = ARP_FRAME
    line = format_line(_pkt(data), parse(data))
    assert "ethertype=0x0806" in line
    assert f"len={len(data)}" in line
    assert "IPv4" not in line


def test_hexdump_empty() -> None:
    assert hexdump(b"") == ""


def test_hexdump_tcpdump_style() -> None:
    data = bytes(range(20))  # 0x00..0x13
    dump = hexdump(data)
    lines = dump.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("0x0000:")
    assert lines[1].startswith("0x0010:")
    # First line: 8 hex groups covering 16 bytes.
    assert "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f" in lines[0]
    # ASCII column: non-printable -> '.'
    assert lines[0].endswith("................")
    assert "1011 1213" in lines[1]
