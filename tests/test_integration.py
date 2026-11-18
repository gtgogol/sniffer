"""Integration tests that need Linux + root (skipped otherwise)."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.root


def _has_af_packet() -> bool:
    return hasattr(socket, "AF_PACKET")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _skip_unless_linux_root() -> None:
    if not _has_af_packet():
        pytest.skip("AF_PACKET requires Linux")
    if not _is_root():
        pytest.skip("integration capture requires root or CAP_NET_RAW")


def _tcpdump_count(path: Path) -> int:
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        pytest.skip("tcpdump not installed")
    proc = subprocess.run(
        [tcpdump, "-nr", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    # tcpdump prints one line per packet to stdout when reading a file.
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return len(lines)


def _generate_udp(port: int, count: int = 5) -> None:
    payload = b"sniffer-test"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(count):
            sock.sendto(payload, ("127.0.0.1", port))
            time.sleep(0.01)


def _generate_tcp(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(2.0)

    def _client() -> None:
        time.sleep(0.05)
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as c:
            c.sendall(b"hi")

    import threading

    t = threading.Thread(target=_client, daemon=True)
    t.start()
    try:
        conn, _addr = srv.accept()
        with conn:
            conn.recv(16)
    finally:
        srv.close()
        t.join(timeout=2.0)


@pytest.fixture
def out_pcap(tmp_path: Path) -> Path:
    return tmp_path / "capture.pcap"


def test_capture_lo_writes_readable_pcap(out_pcap: Path) -> None:
    _skip_unless_linux_root()
    cmd = [
        sys.executable,
        "-m",
        "sniffer",
        "-i",
        "lo",
        "-w",
        str(out_pcap),
        "-c",
        "10",
        "-q",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.3)
    _generate_udp(19999, count=8)
    _generate_tcp(19998)
    try:
        _stdout, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _stdout, stderr = proc.communicate()
        pytest.fail(f"sniffer timed out; stderr={stderr!r}")

    assert proc.returncode == 0, stderr
    assert out_pcap.is_file()
    assert out_pcap.stat().st_size > 24
    count = _tcpdump_count(out_pcap)
    assert count == 10, f"tcpdump saw {count} packets; stderr={stderr!r}"

    tshark = shutil.which("tshark")
    if tshark is not None:
        ts = subprocess.run(
            [tshark, "-r", str(out_pcap), "-q", "-z", "io,stat,0"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert "10" in ts.stdout or "Frames" in ts.stdout


def test_filter_udp_port(out_pcap: Path) -> None:
    _skip_unless_linux_root()
    port = 9999
    cmd = [
        sys.executable,
        "-m",
        "sniffer",
        "-i",
        "lo",
        "-w",
        str(out_pcap),
        "-c",
        "3",
        "-q",
        "-f",
        f"udp and port {port}",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.3)
    # Noise on another port, then matching UDP.
    _generate_udp(port + 1, count=5)
    _generate_udp(port, count=5)
    try:
        _stdout, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _stdout, stderr = proc.communicate()
        pytest.fail(f"sniffer timed out; stderr={stderr!r}")

    assert proc.returncode == 0, stderr
    count = _tcpdump_count(out_pcap)
    assert count == 3, f"expected 3 filtered packets, got {count}; stderr={stderr}"
