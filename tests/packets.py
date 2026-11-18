"""Hand-crafted reference frames for parser tests (no scapy at runtime)."""

from __future__ import annotations

import struct

# --- helpers -----------------------------------------------------------------

def _mac(text: str) -> bytes:
    return bytes(int(p, 16) for p in text.split(":"))


def _ipv4(text: str) -> bytes:
    return bytes(int(p) for p in text.split("."))


def _ethernet(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def _vlan_ethernet(
    dst: str, src: str, vlan_id: int, ethertype: int, payload: bytes
) -> bytes:
    # 802.1Q: EtherType 0x8100, then TCI, then inner EtherType.
    tci = vlan_id & 0x0FFF
    return (
        _mac(dst)
        + _mac(src)
        + struct.pack("!HHH", 0x8100, tci, ethertype)
        + payload
    )


def _ipv4_header(
    *,
    src: str,
    dst: str,
    protocol: int,
    total_length: int,
    ttl: int = 64,
    identification: int = 0xABCD,
    flags_frag: int = 0x4000,  # DF set, offset 0
    ihl: int = 5,
    options: bytes = b"",
) -> bytes:
    version_ihl = (4 << 4) | ihl
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,  # TOS
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,  # checksum (unchecked by our parser)
        _ipv4(src),
        _ipv4(dst),
    )
    if options:
        header += options
        # Pad options to 4-byte multiple already expected via ihl.
    return header


def _tcp_header(
    *,
    sport: int,
    dport: int,
    seq: int = 0x11111111,
    ack: int = 0,
    data_offset: int = 5,
    flags: int = 0x02,  # SYN
    window: int = 64240,
) -> bytes:
    offset_flags = (data_offset << 12) | (flags & 0x1FF)
    return struct.pack(
        "!HHIIHHHH",
        sport,
        dport,
        seq,
        ack,
        offset_flags,
        window,
        0,  # checksum
        0,  # urgent
    )


def _udp_header(*, sport: int, dport: int, length: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, length, 0)


def _icmp_header(*, type_: int, code: int) -> bytes:
    return struct.pack("!BBH", type_, code, 0) + b"\x00" * 4


def _ipv6_header(
    *,
    src: bytes,
    dst: bytes,
    next_header: int,
    payload_length: int,
    hop_limit: int = 64,
) -> bytes:
    # version=6, traffic class=0, flow label=0
    vtf = 0x60000000
    return struct.pack("!IHBB", vtf, payload_length, next_header, hop_limit) + src + dst


# --- reference packets -------------------------------------------------------

TCP_IPV4_SYN = _ethernet(
    "02:00:00:00:00:01",
    "02:00:00:00:00:02",
    0x0800,
    _ipv4_header(
        src="192.168.1.5",
        dst="93.184.216.34",
        protocol=6,
        total_length=40,
    )
    + _tcp_header(sport=51234, dport=443, flags=0x02),
)

# Minimal DNS-like UDP over IPv6 (no real DNS payload required).
_IPV6_SRC = bytes.fromhex("20010db8000000000000000000000001")
_IPV6_DST = bytes.fromhex("20010db8000000000000000000000002")
_UDP_DNS = _udp_header(sport=53000, dport=53, length=8)
UDP_IPV6_DNS = _ethernet(
    "02:00:00:00:00:03",
    "02:00:00:00:00:04",
    0x86DD,
    _ipv6_header(
        src=_IPV6_SRC,
        dst=_IPV6_DST,
        next_header=17,
        payload_length=len(_UDP_DNS),
    )
    + _UDP_DNS,
)

# VLAN-tagged IPv4 TCP SYN (same L3/L4 as TCP_IPV4_SYN).
VLAN_TCP_IPV4 = _vlan_ethernet(
    "02:00:00:00:00:01",
    "02:00:00:00:00:02",
    vlan_id=100,
    ethertype=0x0800,
    payload=_ipv4_header(
        src="192.168.1.5",
        dst="93.184.216.34",
        protocol=6,
        total_length=40,
    )
    + _tcp_header(sport=51234, dport=443, flags=0x02),
)

# IPv4 with 4 bytes of options => IHL=6.
_IP_OPTS = b"\x01\x01\x01\x00"  # NOPs + EOL-ish padding
IPV4_WITH_OPTIONS = _ethernet(
    "02:00:00:00:00:01",
    "02:00:00:00:00:02",
    0x0800,
    _ipv4_header(
        src="10.0.0.1",
        dst="10.0.0.2",
        protocol=17,
        total_length=20 + 4 + 8,
        ihl=6,
        options=_IP_OPTS,
    )
    + _udp_header(sport=12345, dport=53, length=8),
)

# IPv6 with Hop-by-Hop extension then UDP.
# Hop-by-Hop: next_header=17 (UDP), hdr_ext_len=0 => 8 bytes total.
_HBH = struct.pack("!BB", 17, 0) + b"\x00" * 6
_UDP_AFTER_HBH = _udp_header(sport=40000, dport=53, length=8)
IPV6_HOP_BY_HOP = _ethernet(
    "02:00:00:00:00:05",
    "02:00:00:00:00:06",
    0x86DD,
    _ipv6_header(
        src=_IPV6_SRC,
        dst=_IPV6_DST,
        next_header=0,  # Hop-by-Hop
        payload_length=len(_HBH) + len(_UDP_AFTER_HBH),
    )
    + _HBH
    + _UDP_AFTER_HBH,
)

# ICMP echo request over IPv4.
ICMP_ECHO = _ethernet(
    "02:00:00:00:00:07",
    "02:00:00:00:00:08",
    0x0800,
    _ipv4_header(
        src="127.0.0.1",
        dst="127.0.0.1",
        protocol=1,
        total_length=28,
        flags_frag=0,
    )
    + _icmp_header(type_=8, code=0),
)

# Unknown EtherType (ARP) — L3/L4 absent.
ARP_FRAME = _ethernet(
    "ff:ff:ff:ff:ff:ff",
    "02:00:00:00:00:09",
    0x0806,
    b"\x00" * 28,
)

# IPv4 fragment (offset != 0) — L4 must not be parsed.
IPV4_FRAGMENT = _ethernet(
    "02:00:00:00:00:01",
    "02:00:00:00:00:02",
    0x0800,
    _ipv4_header(
        src="192.168.0.1",
        dst="192.168.0.2",
        protocol=6,
        total_length=40,
        flags_frag=0x0001,  # offset=1 (8-byte units), MF=0
    )
    + _tcp_header(sport=1, dport=2, flags=0x10),
)

ALL_REFERENCE_PACKETS: dict[str, bytes] = {
    "tcp_ipv4_syn": TCP_IPV4_SYN,
    "udp_ipv6_dns": UDP_IPV6_DNS,
    "vlan_tcp_ipv4": VLAN_TCP_IPV4,
    "ipv4_with_options": IPV4_WITH_OPTIONS,
    "ipv6_hop_by_hop": IPV6_HOP_BY_HOP,
    "icmp_echo": ICMP_ECHO,
    "arp_frame": ARP_FRAME,
    "ipv4_fragment": IPV4_FRAGMENT,
}
