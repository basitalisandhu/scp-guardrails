"""Scaling checks: ten times the input must take roughly ten times as long, not a hundred.

Each case is timed at 1x and 10x (best of three) and the ratio is held under 30. Before 0.4.0, linting a
policy with one finding per statement scanned the whole file once per finding to find its line: 300
statements took 0.034s and 3,000 took 2.44s.
"""

from __future__ import annotations

import io
import json
import time
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from scp_guardrails import _miniyaml
from scp_guardrails.cli import main

LIMIT = 30


def _policy(n: int, effect: str = "Allow") -> dict[str, object]:
    statements = [
        {
            "Sid": f"S{i}",
            "Effect": effect,
            "Action": [f"svc{i % 50}:Act{j}" for j in range(5)],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}},
        }
        for i in range(n)
    ]
    return {"Version": "2012-10-17", "Statement": statements}


def _run(argv: list[str]) -> None:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        main(argv)


def _best(fn: Callable[[], object]) -> float:
    times = []
    for _ in range(3):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return max(min(times), 1e-4)


def _case(name: str, k: int, tmp: Path) -> Callable[[], object]:
    n = 200 * k
    if name == "yaml":
        text = "protected_roles:\n" + "".join(f"  - Role{i}\n" for i in range(n * 5))
        return lambda: _miniyaml.load(text)
    a, b = tmp / f"a{k}.json", tmp / f"b{k}.json"
    a.write_text(json.dumps(_policy(n), indent=2))
    other = _policy(n, "Deny")
    other["Statement"] = other["Statement"][::-1]  # type: ignore[index]
    b.write_text(json.dumps(other, indent=2))
    argv = {
        "lint-table": ["lint", str(a)],
        "lint-sarif": ["lint", str(a), "--format", "sarif"],
        "diff": ["diff", str(a), str(b)],
        "explain": ["explain", str(b)],
    }[name]
    return lambda: _run(argv)


@pytest.mark.parametrize("name", ["lint-table", "lint-sarif", "diff", "explain", "yaml"])
def test_ten_times_the_input_stays_near_linear(name: str, tmp_path: Path) -> None:
    small, large = _best(_case(name, 1, tmp_path)), _best(_case(name, 10, tmp_path))
    assert large / small < LIMIT, f"{name}: 1x {small:.4f}s, 10x {large:.4f}s"
