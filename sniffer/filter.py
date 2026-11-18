"""Simple ``and``-joined packet filter expressions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

from sniffer.parse import PacketInfo

_TOKEN = re.compile(
    r"""
    \s*(?:
        (?P<and>and)
      | (?P<kw>tcp|udp|icmp|ip4|ip6|host|src|dst|port)
      | (?P<addr>[0-9a-fA-F:.]+)
      | (?P<num>\d+)
      | (?P<bad>\S+)
    )
    """,
    re.VERBOSE,
)


class FilterSyntaxError(ValueError):
    """Raised when a filter expression cannot be parsed."""

    def __init__(self, message: str, token: str | None = None) -> None:
        self.token = token
        if token is not None:
            super().__init__(f"{message}: {token!r}")
        else:
            super().__init__(message)


@dataclass(frozen=True, slots=True)
class _Proto:
    name: str  # tcp | udp | icmp | ip4 | ip6

    def match(self, info: PacketInfo) -> bool:
        if self.name == "tcp":
            return info.tcp is not None
        if self.name == "udp":
            return info.udp is not None
        if self.name == "icmp":
            return info.icmp is not None
        if self.name == "ip4":
            return info.ipv4 is not None
        if self.name == "ip6":
            return info.ipv6 is not None
        return False


@dataclass(frozen=True, slots=True)
class _Host:
    addr: IPv4Address | IPv6Address
    direction: str  # any | src | dst

    def match(self, info: PacketInfo) -> bool:
        addrs: list[IPv4Address | IPv6Address] = []
        if info.ipv4 is not None:
            if self.direction in ("any", "src"):
                addrs.append(info.ipv4.src)
            if self.direction in ("any", "dst"):
                addrs.append(info.ipv4.dst)
        if info.ipv6 is not None:
            if self.direction in ("any", "src"):
                addrs.append(info.ipv6.src)
            if self.direction in ("any", "dst"):
                addrs.append(info.ipv6.dst)
        return any(a == self.addr for a in addrs)


@dataclass(frozen=True, slots=True)
class _Port:
    port: int
    direction: str  # any | src | dst

    def match(self, info: PacketInfo) -> bool:
        ports: list[int] = []
        if info.tcp is not None:
            if self.direction in ("any", "src"):
                ports.append(info.tcp.src_port)
            if self.direction in ("any", "dst"):
                ports.append(info.tcp.dst_port)
        if info.udp is not None:
            if self.direction in ("any", "src"):
                ports.append(info.udp.src_port)
            if self.direction in ("any", "dst"):
                ports.append(info.udp.dst_port)
        return self.port in ports


_Condition = _Proto | _Host | _Port


@dataclass(slots=True)
class Filter:
    """Conjunction of simple conditions (implicit ``and``)."""

    conditions: list[_Condition]

    def match(self, info: PacketInfo) -> bool:
        """Return True if every condition matches ``info``."""
        return all(cond.match(info) for cond in self.conditions)


def parse_filter(expr: str) -> Filter:
    """Parse an ``and``-joined filter expression into a ``Filter``.

    Supported atoms: ``tcp``, ``udp``, ``icmp``, ``ip4``, ``ip6``,
    ``host ADDR``, ``src host ADDR``, ``dst host ADDR``,
    ``port N``, ``src port N``, ``dst port N``.
    """
    text = expr.strip()
    if not text:
        raise FilterSyntaxError("empty filter expression")

    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None:
            raise FilterSyntaxError("unexpected input", text[pos:])
        if m.group("bad") is not None:
            raise FilterSyntaxError("unexpected token", m.group("bad"))
        for name in ("and", "kw", "addr", "num"):
            val = m.group(name)
            if val is not None:
                tokens.append(val)
                break
        pos = m.end()

    conditions: list[_Condition] = []
    expect_and = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if expect_and:
            if tok != "and":
                raise FilterSyntaxError("expected 'and' before", tok)
            i += 1
            if i >= len(tokens):
                raise FilterSyntaxError("trailing 'and'")
            tok = tokens[i]
            expect_and = False

        if tok in ("tcp", "udp", "icmp", "ip4", "ip6"):
            conditions.append(_Proto(tok))
            i += 1
        elif tok in ("src", "dst"):
            direction = tok
            i += 1
            if i >= len(tokens):
                raise FilterSyntaxError(f"expected 'host' or 'port' after '{direction}'")
            kind = tokens[i]
            if kind == "host":
                i += 1
                if i >= len(tokens):
                    raise FilterSyntaxError("expected address after 'host'")
                conditions.append(_Host(_parse_addr(tokens[i]), direction))
                i += 1
            elif kind == "port":
                i += 1
                if i >= len(tokens):
                    raise FilterSyntaxError("expected port number after 'port'")
                conditions.append(_Port(_parse_port(tokens[i]), direction))
                i += 1
            else:
                raise FilterSyntaxError(
                    f"expected 'host' or 'port' after '{direction}'", kind
                )
        elif tok == "host":
            i += 1
            if i >= len(tokens):
                raise FilterSyntaxError("expected address after 'host'")
            conditions.append(_Host(_parse_addr(tokens[i]), "any"))
            i += 1
        elif tok == "port":
            i += 1
            if i >= len(tokens):
                raise FilterSyntaxError("expected port number after 'port'")
            conditions.append(_Port(_parse_port(tokens[i]), "any"))
            i += 1
        elif tok == "and":
            raise FilterSyntaxError("unexpected 'and'")
        else:
            raise FilterSyntaxError("unexpected token", tok)

        expect_and = True

    if not conditions:
        raise FilterSyntaxError("empty filter expression")
    return Filter(conditions)


def _parse_addr(token: str) -> IPv4Address | IPv6Address:
    try:
        return ip_address(token)
    except ValueError as exc:
        raise FilterSyntaxError("invalid IP address", token) from exc


def _parse_port(token: str) -> int:
    if not token.isdigit():
        raise FilterSyntaxError("invalid port", token)
    port = int(token)
    if not 0 <= port <= 65535:
        raise FilterSyntaxError("port out of range", token)
    return port
