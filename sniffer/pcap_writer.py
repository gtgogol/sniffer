"""Classic libpcap (microsecond) file writer."""

from __future__ import annotations

import struct
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

# Precompiled little-endian layouts (AGENTS.md).
_GLOBAL_HDR = struct.Struct("<IHHiIII")
_RECORD_HDR = struct.Struct("<IIII")

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1


class PcapWriter:
    """Write a classic pcap file; flushes after every packet record."""

    def __init__(
        self,
        path: str | Path,
        snaplen: int,
        linktype: int = LINKTYPE_ETHERNET,
    ) -> None:
        self.path = Path(path)
        self.snaplen = snaplen
        self.linktype = linktype
        self._file: BinaryIO | None = None
        self.written = 0

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
        """Open the file in binary mode and write the 24-byte global header."""
        fh = self.path.open("wb")
        try:
            fh.write(
                _GLOBAL_HDR.pack(
                    PCAP_MAGIC_USEC,
                    PCAP_VERSION_MAJOR,
                    PCAP_VERSION_MINOR,
                    0,  # thiszone
                    0,  # sigfigs
                    self.snaplen,
                    self.linktype,
                )
            )
            fh.flush()
        except BaseException:
            fh.close()
            raise
        self._file = fh
        self.written = 0

    def close(self) -> None:
        """Close the underlying file if open."""
        if self._file is not None:
            try:
                self._file.close()
            finally:
                self._file = None

    def write(
        self,
        ts_ns: int,
        data: bytes,
        orig_len: int | None = None,
    ) -> None:
        """Append one packet record and flush.

        ``incl_len`` is ``min(len(data), snaplen)``. ``orig_len`` defaults to
        the full (pre-truncation) length of ``data``.
        """
        if self._file is None:
            raise RuntimeError("PcapWriter is not open")

        if orig_len is None:
            orig_len = len(data)
        incl_len = min(len(data), self.snaplen)
        ts_sec = ts_ns // 1_000_000_000
        ts_usec = (ts_ns % 1_000_000_000) // 1000

        self._file.write(_RECORD_HDR.pack(ts_sec, ts_usec, incl_len, orig_len))
        self._file.write(data[:incl_len])
        self._file.flush()
        self.written += 1
