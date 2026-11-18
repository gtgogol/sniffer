"""Parse throughput micro-benchmark (live AF_PACKET pps needs Linux+root)."""

from __future__ import annotations

import time

import pytest

from sniffer.parse import parse
from tests.packets import TCP_IPV4_SYN, UDP_IPV6_DNS


@pytest.mark.benchmark
def test_parse_throughput(capsys: pytest.CaptureFixture[str]) -> None:
    frames = (TCP_IPV4_SYN, UDP_IPV6_DNS)
    # Warm-up.
    for _ in range(1000):
        parse(frames[0])

    n = 50_000
    t0 = time.perf_counter()
    for i in range(n):
        parse(frames[i % len(frames)])
    elapsed = time.perf_counter() - t0
    pps = n / elapsed if elapsed > 0 else float("inf")
    # Always print so the stage report can quote real numbers.
    print(f"parse_benchmark: {n} packets in {elapsed:.4f}s -> {pps:.0f} pps")
    assert pps > 1000  # sanity floor; real machine is far higher
