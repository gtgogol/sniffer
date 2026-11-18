"""Tests for the CLI capture loop (mocked RawCapture)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sniffer import cli
from sniffer.capture import RawPacket
from sniffer.cli import Args, run_capture


def _args(**kwargs: object) -> Args:
    defaults: dict[str, object] = {
        "interface": "lo",
        "write": None,
        "count": 2,
        "snaplen": 65535,
        "promisc": False,
        "hex": False,
        "quiet": False,
        "filter": None,
    }
    defaults.update(kwargs)
    return Args(**defaults)  # type: ignore[arg-type]


def _pkt(n: int) -> RawPacket:
    return RawPacket(
        data=bytes([n]) * 10,
        time_ns=1_700_000_000_000_000_000 + n,
        ifname="lo",
        pkttype=0,
        hatype=772,
    )


def test_run_capture_stops_at_count(capsys: pytest.CaptureFixture[str]) -> None:
    packets = [_pkt(1), _pkt(2), _pkt(3)]
    cap = MagicMock()
    cap.__enter__.return_value = cap
    cap.__exit__.return_value = None
    cap.read.side_effect = packets

    with (
        patch("sniffer.cli.RawCapture", return_value=cap),
        patch("sniffer.cli._install_signal_handlers"),
    ):
        rc = run_capture(_args(count=2, quiet=False))

    assert rc == 0
    assert cap.read.call_count == 2
    out = capsys.readouterr()
    assert "len=10" in out.out
    assert "captured=2" in out.err
    assert "passed=2" in out.err
    assert "skipped=0" in out.err


def test_run_capture_permission_error_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cap = MagicMock()
    cap.__enter__.side_effect = PermissionError("denied")

    with (
        patch("sniffer.cli.RawCapture", return_value=cap),
        patch("sniffer.cli._install_signal_handlers"),
    ):
        rc = run_capture(_args())

    assert rc == 1
    err = capsys.readouterr().err
    assert "permission denied" in err.lower()
    assert "sudo python3 -m sniffer" in err


def test_run_capture_quiet_no_packet_lines(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cap = MagicMock()
    cap.__enter__.return_value = cap
    cap.__exit__.return_value = None
    cap.read.side_effect = [_pkt(1)]

    with (
        patch("sniffer.cli.RawCapture", return_value=cap),
        patch("sniffer.cli._install_signal_handlers"),
    ):
        rc = run_capture(_args(count=1, quiet=True))

    assert rc == 0
    out = capsys.readouterr()
    assert out.out == ""
    assert "captured=1" in out.err


def test_run_capture_writes_pcap(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "out.pcap"
    cap = MagicMock()
    cap.__enter__.return_value = cap
    cap.__exit__.return_value = None
    cap.read.side_effect = [_pkt(1), _pkt(2)]

    with (
        patch("sniffer.cli.RawCapture", return_value=cap),
        patch("sniffer.cli._install_signal_handlers"),
    ):
        rc = run_capture(_args(count=2, quiet=True, write=str(out)))

    assert rc == 0
    assert out.is_file()
    assert out.stat().st_size == 24 + 16 + 10 + 16 + 10
    assert "written=2" in capsys.readouterr().err


def test_stop_flag_exits_loop(capsys: pytest.CaptureFixture[str]) -> None:
    cap = MagicMock()
    cap.__enter__.return_value = cap
    cap.__exit__.return_value = None

    def _read() -> RawPacket | None:
        cli._stop_requested = True
        return None

    cap.read.side_effect = _read

    with (
        patch("sniffer.cli.RawCapture", return_value=cap),
        patch("sniffer.cli._install_signal_handlers"),
    ):
        rc = run_capture(_args(count=None))

    assert rc == 0
    assert "captured=0" in capsys.readouterr().err
