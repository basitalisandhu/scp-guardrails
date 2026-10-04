"""Shared helpers. Nothing here calls AWS: every input is a fixture under tests/fixtures/ or built in tmp_path.

Fixtures use example account ids (111122223333, 999988887777, 123456789012) and example role names.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "src"))

from scp_guardrails.cli import main  # noqa: E402


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def run_json(argv: list[str]):
    rc, out, _ = run(argv)
    return rc, json.loads(out)


def fixture(name: str) -> Path:
    return FIXTURES / name


@pytest.fixture
def write(tmp_path: Path):
    def _write(name: str, body: str | dict | list) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
        return path

    return _write
