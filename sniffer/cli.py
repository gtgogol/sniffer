"""Command-line interface for the sniffer utility."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Args:
    """Parsed command-line arguments."""

    interface: str | None
    write: str | None
    count: int | None
    snaplen: int
    promisc: bool
    hex: bool
    quiet: bool
    filter: str | None


def _positive_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc
    if count <= 0:
        raise argparse.ArgumentTypeError(f"count must be > 0, got {count}")
    return count


def _snaplen(value: str) -> int:
    try:
        snaplen = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc
    if not 1 <= snaplen <= 262144:
        raise argparse.ArgumentTypeError(
            f"snaplen must be in 1..262144, got {snaplen}"
        )
    return snaplen


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all sniffer flags."""
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Capture network traffic to the screen and/or a pcap file.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        metavar="IFACE",
        help="interface to capture on (default: all interfaces)",
    )
    parser.add_argument(
        "-w",
        "--write",
        default=None,
        metavar="FILE",
        help="write packets to a pcap file",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=_positive_count,
        default=None,
        metavar="N",
        help="stop after N packets that passed the filter",
    )
    parser.add_argument(
        "-s",
        "--snaplen",
        type=_snaplen,
        default=65535,
        metavar="LEN",
        help="maximum stored length of each packet (default: 65535)",
    )
    parser.add_argument(
        "-p",
        "--promisc",
        action="store_true",
        help="enable promiscuous mode",
    )
    parser.add_argument(
        "-x",
        "--hex",
        action="store_true",
        help="print a hex/ASCII dump of each packet",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="do not print packets (only write to file and statistics)",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default=None,
        metavar="EXPR",
        help='packet filter, e.g. "tcp and port 443"',
    )
    return parser


def parse_args(argv: list[str] | None = None) -> Args:
    """Parse argv (or sys.argv[1:]) into an Args dataclass.

    Invalid arguments cause the process to exit with code 2 (argparse default).
    """
    parser = build_parser()
    ns = parser.parse_args(argv)
    return Args(
        interface=ns.interface,
        write=ns.write,
        count=ns.count,
        snaplen=ns.snaplen,
        promisc=ns.promisc,
        hex=ns.hex,
        quiet=ns.quiet,
        filter=ns.filter,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point used by ``python -m sniffer``."""
    parse_args(argv)
    # Capture loop is implemented in later stages.
    print("sniffer: capture not implemented yet", file=sys.stderr)
    return 0
