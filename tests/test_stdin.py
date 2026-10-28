"""`-` reads a policy from standard input for lint, diff and explain."""

from __future__ import annotations

import io
import json
import sys

import pytest
from conftest import FIXTURES, run


class _Stdin:
    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


@pytest.fixture
def stdin(monkeypatch: pytest.MonkeyPatch):
    def feed(data: bytes) -> None:
        monkeypatch.setattr(sys, "stdin", _Stdin(data))

    return feed


def test_lint_reads_describe_policy_output_from_stdin(stdin) -> None:
    stdin((FIXTURES / "fixture-describe-policy-output.json").read_bytes())
    rc, out, _ = run(["lint", "-", "--format", "json"])
    doc = json.loads(out)
    assert rc == 0 and doc[0]["file"] == "<stdin>"


def test_lint_stdin_findings_have_lines(stdin) -> None:
    stdin((FIXTURES / "action" / "fixture-bad-policy.json").read_bytes())
    rc, out, _ = run(["lint", "-", "--format", "json"])
    findings = json.loads(out)[0]["findings"]
    assert rc == 1 and findings and any(f["line"] > 1 for f in findings)


def test_diff_and_explain_read_stdin(stdin) -> None:
    stdin((FIXTURES / "fixture-diff-b.json").read_bytes())
    rc, out, _ = run(["diff", str(FIXTURES / "fixture-diff-a.json"), "-"])
    assert rc == 1 and "+++ <stdin>" in out
    stdin((FIXTURES / "fixture-good.json").read_bytes())
    rc, out, _ = run(["explain", "-"])
    assert rc == 0 and out.startswith("<stdin>: ")


def test_stdin_errors(stdin) -> None:
    rc, _, err = run(["diff", "-", "-"])
    assert rc == 2 and "only one of the two" in err
    stdin(b"\xff")
    rc, _, err = run(["explain", "-"])
    assert rc == 2 and "<stdin>: not UTF-8" in err
