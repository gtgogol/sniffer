"""Fuzz parse() with random buffers; must never raise."""

from __future__ import annotations

import random

from sniffer.parse import parse


def test_parse_random_buffers_no_exceptions() -> None:
    rng = random.Random(0x5E1FF)  # fixed seed for reproducibility
    for _ in range(100_000):
        length = rng.randint(0, 512)
        buf = rng.randbytes(length)
        info = parse(buf)
        assert info.length == length
        assert isinstance(info.truncated, bool)
        assert isinstance(info.malformed, bool)
