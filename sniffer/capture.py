"""AF_PACKET raw socket capture for Linux."""

from __future__ import annotations

import select
import socket
import struct
import time
from dataclasses import dataclass
from types import TracebackType
from typing import Self

# Linux packet socket constants (not always exposed by the socket module).
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772

_READ_TIMEOUT_S = 0.1


@dataclass(slots=True)
class RawPacket:
    """One frame received from an AF_PACKET socket."""

    data: bytes
    time_ns: int
    ifname: str
    pkttype: int
    hatype: int


class RawCapture:
    """Context manager around ``socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)``."""

    def __init__(self, iface: str | None, promisc: bool, snaplen: int) -> None:
        if promisc and iface is None:
            raise ValueError(
                "promiscuous mode requires an interface (-i / --interface)"
            )
        self.iface = iface
        self.promisc = promisc
        self.snaplen = snaplen
        self.sock: socket.socket | None = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def open(self) -> None:
        """Create, optionally bind, and optionally enable promiscuous mode."""
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET is only available on Linux")

        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(ETH_P_ALL),
        )

        try:
            if self.iface is not None:
                try:
                    sock.bind((self.iface, 0))
                except OSError as exc:
                    sock.close()
                    raise OSError(
                        f"cannot bind to interface {self.iface!r}: {exc}"
                    ) from exc

            if self.promisc:
                assert self.iface is not None
                try:
                    ifindex = socket.if_nametoindex(self.iface)
                except OSError as exc:
                    sock.close()
                    raise OSError(
                        f"unknown interface {self.iface!r}: {exc}"
                    ) from exc
                mreq = struct.pack(
                    "iHH8s", ifindex, PACKET_MR_PROMISC, 0, b""
                )
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

            # Non-blocking reads via select; keep a soft timeout as a fallback.
            sock.settimeout(_READ_TIMEOUT_S)
        except BaseException:
            sock.close()
            raise

        self.sock = sock

    def close(self) -> None:
        """Close the packet socket if open."""
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def read(self) -> RawPacket | None:
        """Read one packet, or return None on timeout so the caller can stop."""
        if self.sock is None:
            raise RuntimeError("RawCapture is not open")

        ready, _, _ = select.select([self.sock], [], [], _READ_TIMEOUT_S)
        if not ready:
            return None

        data, addr = self.sock.recvfrom(self.snaplen)
        time_ns = time.time_ns()
        # addr: (ifname, proto, pkttype, hatype, hardware_addr)
        ifname = addr[0]
        pkttype = int(addr[2])
        hatype = int(addr[3])
        return RawPacket(
            data=data,
            time_ns=time_ns,
            ifname=ifname,
            pkttype=pkttype,
            hatype=hatype,
        )
