"""Tests for CLI argument parsing."""

from __future__ import annotations

import pytest

from sniffer.cli import parse_args


def test_defaults() -> None:
    args = parse_args([])
    assert args.interface is None
    assert args.write is None
    assert args.count is None
    assert args.snaplen == 65535
    assert args.promisc is False
    assert args.hex is False
    assert args.quiet is False
    assert args.filter is None


def test_all_flags() -> None:
    args = parse_args(
        [
            "-i",
            "eth0",
            "-w",
            "out.pcap",
            "-c",
            "10",
            "-s",
            "1500",
            "-p",
            "-x",
            "-q",
            "-f",
            "tcp and port 443",
        ]
    )
    assert args.interface == "eth0"
    assert args.write == "out.pcap"
    assert args.count == 10
    assert args.snaplen == 1500
    assert args.promisc is True
    assert args.hex is True
    assert args.quiet is True
    assert args.filter == "tcp and port 443"


def test_long_flag_names() -> None:
    args = parse_args(
        [
            "--interface",
            "lo",
            "--write",
            "a.pcap",
            "--count",
            "1",
            "--snaplen",
            "1",
            "--promisc",
            "--hex",
            "--quiet",
            "--filter",
            "udp",
        ]
    )
    assert args.interface == "lo"
    assert args.write == "a.pcap"
    assert args.count == 1
    assert args.snaplen == 1
    assert args.promisc is True
    assert args.hex is True
    assert args.quiet is True
    assert args.filter == "udp"


@pytest.mark.parametrize("count", ["0", "-1", "-10"])
def test_count_must_be_positive(count: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args(["-c", count])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("snaplen", ["0", "-1", "262145", "999999"])
def test_snaplen_out_of_range(snaplen: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args(["-s", snaplen])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("snaplen", ["1", "65535", "262144"])
def test_snaplen_boundaries(snaplen: str) -> None:
    args = parse_args(["-s", snaplen])
    assert args.snaplen == int(snaplen)


def test_unknown_flag_exits_2() -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args(["--unknown"])
    assert exc_info.value.code == 2
