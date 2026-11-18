"""Command-line interface for the sniffer utility."""

from __future__ import annotations

import argparse
import signal
import sys
from dataclasses import dataclass

from sniffer.capture import (
    ARPHRD_ETHER,
    ARPHRD_LOOPBACK,
    RawCapture,
)
from sniffer.filter import Filter, FilterSyntaxError, parse_filter
from sniffer.output import format_line, hexdump
from sniffer.parse import parse
from sniffer.pcap_writer import PcapWriter

# Set by SIGINT/SIGTERM handlers; the capture loop checks this flag.
_stop_requested = False
_ETHER_HTYPES = frozenset({ARPHRD_ETHER, ARPHRD_LOOPBACK})


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


def _request_stop(signum: int, frame: object | None) -> None:
    """Signal handler: request a clean exit from the capture loop."""
    global _stop_requested
    _stop_requested = True


def _install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)


def run_capture(args: Args, packet_filter: Filter | None = None) -> int:
    """Open the capture socket and run the main loop until stop or count."""
    global _stop_requested
    _stop_requested = False
    _install_signal_handlers()

    # Line-buffered stdout so real-time output is not delayed.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    captured = 0
    passed = 0
    written = 0
    skipped_non_eth = 0
    warned_ifaces: set[str] = set()
    writer: PcapWriter | None = None
    # Parse only when needed: screen output and/or a filter.
    need_parse = (not args.quiet) or (packet_filter is not None)
    try:
        if args.write is not None:
            writer = PcapWriter(args.write, snaplen=args.snaplen)
            writer.open()

        with RawCapture(
            iface=args.interface,
            promisc=args.promisc,
            snaplen=args.snaplen,
        ) as cap:
            while not _stop_requested:
                pkt = cap.read()
                if pkt is None:
                    continue

                captured += 1

                is_ethernet = pkt.hatype in _ETHER_HTYPES
                if not is_ethernet:
                    skipped_non_eth += 1
                    if pkt.ifname not in warned_ifaces:
                        print(
                            f"sniffer: skipping non-Ethernet link type "
                            f"hatype={pkt.hatype} on {pkt.ifname}",
                            file=sys.stderr,
                        )
                        warned_ifaces.add(pkt.ifname)
                    continue

                info = parse(pkt.data) if need_parse else None
                if packet_filter is not None:
                    assert info is not None
                    if not packet_filter.match(info):
                        continue

                passed += 1
                if writer is not None:
                    writer.write(pkt.time_ns, pkt.data)
                    written = writer.written

                if not args.quiet:
                    assert info is not None
                    print(format_line(pkt, info), flush=True)
                    if args.hex:
                        print(hexdump(pkt.data), flush=True)

                if args.count is not None and passed >= args.count:
                    break
    except PermissionError:
        print(
            "sniffer: permission denied opening AF_PACKET socket.\n"
            "Hint: run with root privileges, e.g. "
            "`sudo python3 -m sniffer ...`",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError) as exc:
        print(f"sniffer: {exc}", file=sys.stderr)
        return 1
    finally:
        if writer is not None:
            writer.close()

    print(
        f"sniffer: captured={captured} passed={passed} "
        f"written={written} skipped={skipped_non_eth}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point used by ``python -m sniffer``."""
    args = parse_args(argv)
    packet_filter: Filter | None = None
    if args.filter is not None:
        try:
            packet_filter = parse_filter(args.filter)
        except FilterSyntaxError as exc:
            print(f"sniffer: invalid filter: {exc}", file=sys.stderr)
            return 2
    return run_capture(args, packet_filter=packet_filter)
