"""Tests for the simple and-joined packet filter."""

from __future__ import annotations

import pytest

from sniffer.filter import FilterSyntaxError, parse_filter
from sniffer.parse import parse
from tests.packets import (
    ARP_FRAME,
    ICMP_ECHO,
    IPV4_WITH_OPTIONS,
    IPV6_HOP_BY_HOP,
    TCP_IPV4_SYN,
    UDP_IPV6_DNS,
)


def test_proto_tcp_udp_icmp() -> None:
    tcp = parse(TCP_IPV4_SYN)
    udp = parse(UDP_IPV6_DNS)
    icmp = parse(ICMP_ECHO)
    assert parse_filter("tcp").match(tcp)
    assert not parse_filter("tcp").match(udp)
    assert parse_filter("udp").match(udp)
    assert parse_filter("icmp").match(icmp)
    assert not parse_filter("icmp").match(tcp)


def test_ip4_ip6() -> None:
    assert parse_filter("ip4").match(parse(TCP_IPV4_SYN))
    assert not parse_filter("ip4").match(parse(UDP_IPV6_DNS))
    assert parse_filter("ip6").match(parse(UDP_IPV6_DNS))
    assert not parse_filter("ip6").match(parse(TCP_IPV4_SYN))


def test_host_and_directions() -> None:
    info = parse(TCP_IPV4_SYN)
    assert parse_filter("host 192.168.1.5").match(info)
    assert parse_filter("host 93.184.216.34").match(info)
    assert not parse_filter("host 10.0.0.1").match(info)
    assert parse_filter("src host 192.168.1.5").match(info)
    assert not parse_filter("src host 93.184.216.34").match(info)
    assert parse_filter("dst host 93.184.216.34").match(info)


def test_host_ipv6() -> None:
    info = parse(UDP_IPV6_DNS)
    assert parse_filter("host 2001:db8::1").match(info)
    assert parse_filter("dst host 2001:db8::2").match(info)
    assert not parse_filter("src host 2001:db8::2").match(info)


def test_port_and_directions() -> None:
    info = parse(TCP_IPV4_SYN)
    assert parse_filter("port 443").match(info)
    assert parse_filter("port 51234").match(info)
    assert not parse_filter("port 80").match(info)
    assert parse_filter("src port 51234").match(info)
    assert parse_filter("dst port 443").match(info)
    assert not parse_filter("src port 443").match(info)


def test_udp_port() -> None:
    info = parse(IPV4_WITH_OPTIONS)
    assert parse_filter("udp and port 53").match(info)
    assert parse_filter("src port 12345").match(info)


def test_combination() -> None:
    info = parse(TCP_IPV4_SYN)
    filt = parse_filter("tcp and port 443 and host 10.0.0.1")
    assert not filt.match(info)
    filt2 = parse_filter("tcp and port 443 and host 192.168.1.5")
    assert filt2.match(info)


def test_ipv6_hop_by_hop_udp_port() -> None:
    info = parse(IPV6_HOP_BY_HOP)
    assert parse_filter("udp and port 53 and ip6").match(info)


def test_arp_matches_nothing_useful() -> None:
    info = parse(ARP_FRAME)
    assert not parse_filter("tcp").match(info)
    assert not parse_filter("ip4").match(info)
    assert not parse_filter("port 80").match(info)


@pytest.mark.parametrize(
    "expr,token",
    [
        ("tcp or udp", "or"),
        ("not tcp", "not"),
        ("host", None),
        ("port", None),
        ("src", None),
        ("tcp and", None),
        ("and tcp", None),
        ("host not-an-ip", "not-an-ip"),
        ("port 99999", "99999"),
        ("", None),
    ],
)
def test_syntax_errors(expr: str, token: str | None) -> None:
    with pytest.raises(FilterSyntaxError) as exc_info:
        parse_filter(expr)
    if token is not None:
        assert token in str(exc_info.value)
