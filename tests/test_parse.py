"""Tests for header parsing against hand-crafted reference frames."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from sniffer.parse import parse
from tests.packets import (
    ALL_REFERENCE_PACKETS,
    ARP_FRAME,
    IPV4_FRAGMENT,
    IPV4_WITH_OPTIONS,
    IPV6_HOP_BY_HOP,
    TCP_IPV4_SYN,
    UDP_IPV6_DNS,
    VLAN_TCP_IPV4,
)


def test_tcp_ipv4_syn() -> None:
    info = parse(TCP_IPV4_SYN)
    assert not info.truncated and not info.malformed
    assert info.ethernet is not None
    assert info.ethernet.dst_mac == "02:00:00:00:00:01"
    assert info.ethernet.src_mac == "02:00:00:00:00:02"
    assert info.ethernet.ethertype == 0x0800
    assert info.ethernet.vlan_id is None
    assert info.ipv4 is not None
    assert info.ipv4.src == IPv4Address("192.168.1.5")
    assert info.ipv4.dst == IPv4Address("93.184.216.34")
    assert info.ipv4.protocol == 6
    assert info.ipv4.ihl == 5
    assert info.ipv4.ttl == 64
    assert info.tcp is not None
    assert info.tcp.src_port == 51234
    assert info.tcp.dst_port == 443
    assert info.tcp.flags == 0x02
    assert info.tcp.flag_names == ["SYN"]
    assert info.udp is None
    assert info.ipv6 is None


def test_udp_ipv6_dns() -> None:
    info = parse(UDP_IPV6_DNS)
    assert not info.truncated and not info.malformed
    assert info.ethernet is not None
    assert info.ethernet.ethertype == 0x86DD
    assert info.ipv6 is not None
    assert info.ipv6.src == IPv6Address("2001:db8::1")
    assert info.ipv6.dst == IPv6Address("2001:db8::2")
    assert info.ipv6.next_header == 17
    assert info.udp is not None
    assert info.udp.src_port == 53000
    assert info.udp.dst_port == 53
    assert info.udp.length == 8
    assert info.tcp is None
    assert info.ipv4 is None


def test_vlan_tag() -> None:
    info = parse(VLAN_TCP_IPV4)
    assert not info.truncated and not info.malformed
    assert info.ethernet is not None
    assert info.ethernet.vlan_id == 100
    assert info.ethernet.ethertype == 0x0800
    assert info.ipv4 is not None
    assert info.tcp is not None
    assert info.tcp.dst_port == 443


def test_ipv4_with_options() -> None:
    info = parse(IPV4_WITH_OPTIONS)
    assert not info.truncated and not info.malformed
    assert info.ipv4 is not None
    assert info.ipv4.ihl == 6
    assert info.udp is not None
    assert info.udp.src_port == 12345


def test_ipv6_hop_by_hop() -> None:
    info = parse(IPV6_HOP_BY_HOP)
    assert not info.truncated and not info.malformed
    assert info.ipv6 is not None
    assert info.ipv6.next_header == 17
    assert info.udp is not None
    assert info.udp.dst_port == 53


def test_unknown_ethertype_arp() -> None:
    info = parse(ARP_FRAME)
    assert not info.truncated and not info.malformed
    assert info.ethernet is not None
    assert info.ethernet.ethertype == 0x0806
    assert info.ipv4 is None
    assert info.ipv6 is None
    assert info.tcp is None
    assert info.udp is None


def test_ipv4_fragment_skips_l4() -> None:
    info = parse(IPV4_FRAGMENT)
    assert not info.truncated and not info.malformed
    assert info.ipv4 is not None
    assert info.ipv4.frag_offset == 1
    assert info.tcp is None


@pytest.mark.parametrize("name,frame", sorted(ALL_REFERENCE_PACKETS.items()))
def test_truncated_at_every_length_does_not_raise(name: str, frame: bytes) -> None:
    for length in range(len(frame) + 1):
        info = parse(frame[:length])
        assert isinstance(info.truncated, bool)
        assert isinstance(info.malformed, bool)
        if length < 14:
            assert info.truncated
            assert info.ethernet is None


def test_empty_buffer() -> None:
    info = parse(b"")
    assert info.truncated
    assert info.length == 0


def test_malformed_ipv4_ihl() -> None:
    # Ethernet + IPv4 with IHL=3 (invalid).
    eth = bytes.fromhex("0200000000010200000000020800")
    # version=4, ihl=3, rest zeros / minimal
    bad = eth + bytes([0x43]) + b"\x00" * 19
    info = parse(bad)
    assert info.malformed
    assert info.ipv4 is None
