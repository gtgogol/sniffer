"""Ethernet / IPv4 / IPv6 / TCP / UDP header parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

# EtherTypes / protocols
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

PROTO_TCP = 6
PROTO_UDP = 17

# IPv6 extension headers we skip through.
IPV6_HOPOPTS = 0
IPV6_ROUTING = 43
IPV6_FRAGMENT = 44
IPV6_DSTOPTS = 60
_IPV6_SKIP = frozenset(
    {IPV6_HOPOPTS, IPV6_ROUTING, IPV6_FRAGMENT, IPV6_DSTOPTS}
)

_ETH = struct.Struct("!6s6sH")
_VLAN = struct.Struct("!HH")  # TCI, EtherType
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_IPV6 = struct.Struct("!IHBB16s16s")
_TCP = struct.Struct("!HHIIHHHH")
_UDP = struct.Struct("!HHHH")


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass(slots=True)
class EthernetInfo:
    dst_mac: str
    src_mac: str
    ethertype: int
    vlan_id: int | None = None


@dataclass(slots=True)
class IPv4Info:
    version: int
    ihl: int
    total_length: int
    ttl: int
    protocol: int
    src: IPv4Address
    dst: IPv4Address
    identification: int
    flags: int
    frag_offset: int


@dataclass(slots=True)
class IPv6Info:
    version: int
    payload_length: int
    next_header: int
    hop_limit: int
    src: IPv6Address
    dst: IPv6Address


@dataclass(slots=True)
class TCPInfo:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int

    @property
    def flag_names(self) -> list[str]:
        names: list[str] = []
        mapping = (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        )
        for bit, name in mapping:
            if self.flags & bit:
                names.append(name)
        return names


@dataclass(slots=True)
class UDPInfo:
    src_port: int
    dst_port: int
    length: int


@dataclass(slots=True)
class PacketInfo:
    """Parsed view of a single frame. Missing layers are ``None``."""

    length: int
    ethernet: EthernetInfo | None = None
    ipv4: IPv4Info | None = None
    ipv6: IPv6Info | None = None
    tcp: TCPInfo | None = None
    udp: UDPInfo | None = None
    truncated: bool = False
    malformed: bool = False


def parse(data: bytes | memoryview) -> PacketInfo:
    """Parse L2–L4 headers. Never raises on truncated/malformed input."""
    buf = memoryview(data)
    info = PacketInfo(length=len(buf))
    offset = _parse_ethernet(buf, info)
    if offset is None or info.ethernet is None:
        return info

    ethertype = info.ethernet.ethertype
    if ethertype == ETHERTYPE_IPV4:
        _parse_ipv4(buf, offset, info)
    elif ethertype == ETHERTYPE_IPV6:
        _parse_ipv6(buf, offset, info)
    return info


def _need(buf: memoryview, offset: int, size: int, info: PacketInfo) -> bool:
    if offset + size > len(buf):
        info.truncated = True
        return False
    return True


def _parse_ethernet(buf: memoryview, info: PacketInfo) -> int | None:
    if not _need(buf, 0, _ETH.size, info):
        return None
    dst, src, ethertype = _ETH.unpack_from(buf, 0)
    offset = _ETH.size
    vlan_id: int | None = None

    if ethertype == ETHERTYPE_VLAN:
        if not _need(buf, offset, _VLAN.size, info):
            info.ethernet = EthernetInfo(
                dst_mac=_mac_str(dst),
                src_mac=_mac_str(src),
                ethertype=ethertype,
            )
            return None
        tci, ethertype = _VLAN.unpack_from(buf, offset)
        vlan_id = tci & 0x0FFF
        offset += _VLAN.size

    info.ethernet = EthernetInfo(
        dst_mac=_mac_str(dst),
        src_mac=_mac_str(src),
        ethertype=ethertype,
        vlan_id=vlan_id,
    )
    return offset


def _parse_ipv4(buf: memoryview, offset: int, info: PacketInfo) -> None:
    if not _need(buf, offset, _IPV4.size, info):
        return
    (
        ver_ihl,
        _tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        _checksum,
        src_raw,
        dst_raw,
    ) = _IPV4.unpack_from(buf, offset)

    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    if version != 4 or ihl < 5:
        info.malformed = True
        return

    header_len = ihl * 4
    if not _need(buf, offset, header_len, info):
        return

    frag_offset = flags_frag & 0x1FFF
    flags = (flags_frag >> 13) & 0x07
    info.ipv4 = IPv4Info(
        version=version,
        ihl=ihl,
        total_length=total_length,
        ttl=ttl,
        protocol=protocol,
        src=IPv4Address(bytes(src_raw)),
        dst=IPv4Address(bytes(dst_raw)),
        identification=identification,
        flags=flags,
        frag_offset=frag_offset,
    )

    l4_offset = offset + header_len
    # Non-first fragments are not dissected at L4.
    if frag_offset != 0:
        return
    _parse_l4(buf, l4_offset, protocol, info)


def _parse_ipv6(buf: memoryview, offset: int, info: PacketInfo) -> None:
    if not _need(buf, offset, _IPV6.size, info):
        return
    vtf, payload_length, next_header, hop_limit, src_raw, dst_raw = (
        _IPV6.unpack_from(buf, offset)
    )
    version = (vtf >> 28) & 0x0F
    if version != 6:
        info.malformed = True
        return

    info.ipv6 = IPv6Info(
        version=version,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src=IPv6Address(bytes(src_raw)),
        dst=IPv6Address(bytes(dst_raw)),
    )

    cursor = offset + _IPV6.size
    proto = next_header
    # Walk known extension headers until TCP/UDP or unknown.
    while proto in _IPV6_SKIP:
        if proto == IPV6_FRAGMENT:
            # Fixed 8-byte Fragment header.
            if not _need(buf, cursor, 8, info):
                return
            frag_next = buf[cursor]
            frag_off_flags = struct.unpack_from("!H", buf, cursor + 2)[0]
            frag_offset = frag_off_flags >> 3
            proto = frag_next
            cursor += 8
            if frag_offset != 0:
                info.ipv6.next_header = proto
                return
            continue

        # Hop-by-Hop / Routing / Dest Options: hdr_ext_len in 8-octet units
        # excluding the first 8 bytes.
        if not _need(buf, cursor, 2, info):
            return
        ext_next = buf[cursor]
        hdr_ext_len = buf[cursor + 1]
        ext_total = (hdr_ext_len + 1) * 8
        if not _need(buf, cursor, ext_total, info):
            return
        proto = ext_next
        cursor += ext_total

    info.ipv6.next_header = proto
    _parse_l4(buf, cursor, proto, info)


def _parse_l4(
    buf: memoryview,
    offset: int,
    protocol: int,
    info: PacketInfo,
) -> None:
    if protocol == PROTO_TCP:
        _parse_tcp(buf, offset, info)
    elif protocol == PROTO_UDP:
        _parse_udp(buf, offset, info)


def _parse_tcp(buf: memoryview, offset: int, info: PacketInfo) -> None:
    if not _need(buf, offset, _TCP.size, info):
        return
    sport, dport, seq, ack, offset_flags, window, _chk, _urg = _TCP.unpack_from(
        buf, offset
    )
    data_offset = (offset_flags >> 12) & 0x0F
    flags = offset_flags & 0x1FF
    if data_offset < 5:
        info.malformed = True
        return
    header_len = data_offset * 4
    if not _need(buf, offset, header_len, info):
        return
    info.tcp = TCPInfo(
        src_port=sport,
        dst_port=dport,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        flags=flags,
        window=window,
    )


def _parse_udp(buf: memoryview, offset: int, info: PacketInfo) -> None:
    if not _need(buf, offset, _UDP.size, info):
        return
    sport, dport, length, _chk = _UDP.unpack_from(buf, offset)
    info.udp = UDPInfo(src_port=sport, dst_port=dport, length=length)


def format_ip(addr: IPv4Address | IPv6Address) -> str:
    """Return the canonical string form of an IP address."""
    return str(ip_address(addr))
