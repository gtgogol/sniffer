"""One-line packet summaries and hex/ASCII dumps."""

from __future__ import annotations

from datetime import datetime

from sniffer.capture import RawPacket
from sniffer.parse import PacketInfo


def format_line(pkt: RawPacket, info: PacketInfo) -> str:
    """Format a one-line summary as specified in AGENTS.md."""
    ts = datetime.fromtimestamp(pkt.time_ns / 1_000_000_000)
    stamp = ts.strftime("%H:%M:%S.") + f"{ts.microsecond:06d}"
    parts: list[str] = [stamp, pkt.ifname]

    if info.ipv4 is not None:
        parts.append("IPv4")
        src = str(info.ipv4.src)
        dst = str(info.ipv4.dst)
    elif info.ipv6 is not None:
        parts.append("IPv6")
        src = str(info.ipv6.src)
        dst = str(info.ipv6.dst)
    else:
        if info.ethernet is not None:
            parts.append(f"ethertype=0x{info.ethernet.ethertype:04x}")
        if info.truncated:
            parts.append("truncated")
        elif info.malformed:
            parts.append("malformed")
        parts.append(f"len={info.length}")
        return " ".join(parts)

    if info.tcp is not None:
        parts.append("TCP")
        parts.append(f"{src}:{info.tcp.src_port} -> {dst}:{info.tcp.dst_port}")
        flags = ",".join(info.tcp.flag_names) or "-"
        parts.append(f"[{flags}]")
    elif info.udp is not None:
        parts.append("UDP")
        parts.append(f"{src}:{info.udp.src_port} -> {dst}:{info.udp.dst_port}")
    else:
        proto = (
            info.ipv4.protocol if info.ipv4 is not None else info.ipv6.next_header  # type: ignore[union-attr]
        )
        parts.append(f"proto={proto}")
        parts.append(f"{src} -> {dst}")

    if info.truncated:
        parts.append("truncated")
    elif info.malformed:
        parts.append("malformed")
    parts.append(f"len={info.length}")
    return " ".join(parts)


def hexdump(data: bytes) -> str:
    """Return a tcpdump ``-X``-style hex/ASCII dump (16 bytes per line)."""
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        # Groups of 2 bytes, like tcpdump -X.
        hex_groups: list[str] = []
        for i in range(0, len(chunk), 2):
            pair = chunk[i : i + 2]
            hex_groups.append(pair.hex())
        hex_part = " ".join(hex_groups)
        # Pad so ASCII column lines up (8 groups * 5 chars - trailing space).
        hex_part = f"{hex_part:<39}"
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"0x{offset:04x}:  {hex_part}  {ascii_part}")
    return "\n".join(lines)
