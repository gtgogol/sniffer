"""Shared pytest fixtures and markers."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "root: tests that require root or CAP_NET_RAW",
    )
    config.addinivalue_line(
        "markers",
        "benchmark: micro-benchmarks (parse throughput)",
    )
