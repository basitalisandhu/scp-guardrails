"""Seeded fuzz tests for every input reader: policies for lint, diff and explain, and YAML or JSON specs.

Bad input (non-UTF-8 bytes, wrong JSON types, deep nesting, huge integers, damaged YAML) must end with
exit code 0, 1 or 2 and a message, never a traceback or a hang. Every case runs under a wall-clock alarm.
"""

from __future__ import annotations

import io
import json
import random
import signal
import subprocess
import sys
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout, suppress
from pathlib import Path

import pytest
from conftest import ROOT

from scp_guardrails import _miniyaml
from scp_guardrails.cli import main

SEED = 20261028
SECONDS = 20
KEYS = [
    "Version", "Statement", "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition",
    "StringNotEquals", "ArnNotLike", "aws:PrincipalArn", "aws:RequestedRegion", "Policy", "Content",
]  # fmt: skip
SPEC_KEYS = [
    "allowed_regions", "protected_roles", "deny_root_user", "deny_iam_users_outside", "attach_levels",
    "max_policy_chars", "max_documents", "require_imdsv2", "deny_leave_organization", "deny_services",
    "deny_disable_security_services", "deny_public_s3_acls", "allowed_instance_types", "max_volume_iops",
]  # fmt: skip


@pytest.fixture(autouse=True)
def _alarm() -> Iterator[None]:
    if not hasattr(signal, "SIGALRM"):  # pragma: no cover - Windows
        yield
        return

    def fail(signum, frame):
        raise TimeoutError(f"case ran longer than {SECONDS}s")

    old = signal.signal(signal.SIGALRM, fail)
    signal.alarm(SECONDS)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _value(rng: random.Random, depth: int, keys: list[str]):
    pick = rng.randrange(9 if depth else 6)
    if pick == 0:
        return None
    if pick == 1:
        return rng.randrange(-3, 10**14)
    if pick == 2:
        return rng.choice([True, False])
    if pick == 3:
        return rng.choice(["*", "s3:*", "Deny", "Allow", "arn:aws:iam::*:role/X", "", "111122223333", "ec2:Run*"])
    if pick == 4:
        return 1.5
    if pick == 5:
        return "x" * rng.choice([1, 20000])
    if pick in (6, 7):
        return [_value(rng, depth - 1, keys) for _ in range(rng.randrange(3))]
    return {rng.choice(keys): _value(rng, depth - 1, keys) for _ in range(rng.randrange(5))}


def _policy(rng: random.Random) -> object:
    statements = []
    for _ in range(rng.randrange(4)):
        st = {"Effect": rng.choice(["Deny", "Allow", 5, None, ["Deny"]]), "Action": _value(rng, 2, KEYS)}
        for key in ("Resource", "Condition", "Sid", "NotAction"):
            if rng.random() < 0.5:
                st[key] = _value(rng, 3, KEYS)
        statements.append(st)
    doc: object = {"Version": "2012-10-17", "Statement": rng.choice([statements, _value(rng, 2, KEYS)])}
    if rng.random() < 0.2:
        doc = {"Policy": {"Content": json.dumps(doc) if rng.random() < 0.5 else _value(rng, 2, KEYS)}}
    return _value(rng, 3, KEYS) if rng.random() < 0.1 else doc


def _policy_bytes(rng: random.Random) -> bytes:
    kind = rng.randrange(8)
    if kind == 0:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    if kind == 1:
        depth = rng.choice([50, 5000, 100_000])
        return ("[" * depth + "]" * depth).encode()
    if kind == 2:
        return b'{"Statement": ' + b"7" * 5000 + b"}"
    return json.dumps(_policy(rng)).encode()


def _call(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, err.getvalue()


@pytest.mark.parametrize("command", ["lint", "diff", "explain"])
def test_random_policies_never_crash(command: str, tmp_path: Path) -> None:
    rng = random.Random(f"{SEED}-{command}")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    for _ in range(150):
        a.write_bytes(_policy_bytes(rng))
        b.write_bytes(_policy_bytes(rng))
        argv = {
            "lint": ["lint", str(a), "--format", rng.choice(["table", "json", "sarif"])],
            "diff": ["diff", str(a), str(b), "--format", rng.choice(["text", "json"])],
            "explain": ["explain", str(a), "--format", rng.choice(["text", "markdown", "json"])],
        }[command]
        rc, err = _call(argv)
        assert rc in (0, 1, 2), argv
        assert "Traceback" not in err


def _yamlish(rng: random.Random) -> str:
    parts = ["- ", "a: ", "[", "{", "}", "]", ":", "\n", "  ", "&x ", "*x", "|", "'", '"', "b", "#", "---\n", "? "]
    return "".join(rng.choice(parts) for _ in range(rng.randrange(1, 40)))


def test_random_specs_never_crash(tmp_path: Path) -> None:
    rng = random.Random(f"{SEED}-spec")
    for i in range(300):
        if i % 2:
            spec = tmp_path / "spec.yaml"
            spec.write_text(_yamlish(rng), encoding="utf-8")
        else:
            spec = tmp_path / "spec.json"
            body = {k: _value(rng, 2, SPEC_KEYS) for k in rng.sample(SPEC_KEYS, 4)}
            spec.write_text(json.dumps(body if rng.random() < 0.8 else _value(rng, 3, SPEC_KEYS)), encoding="utf-8")
        rc, err = _call(["build", "--spec", str(spec), "--format", "json"])
        assert rc in (0, 1, 2), spec.read_text(encoding="utf-8")[:200]
        assert "Traceback" not in err


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff\xfeA\x00", "not UTF-8 text"),
        (("[" * 100_000 + "]" * 100_000).encode(), "nested too deeply"),
        (b'{"Statement": ' + b"7" * 5000 + b"}", "invalid JSON"),
    ],
)
def test_bad_policy_files_exit_2_naming_the_file(data: bytes, message: str, tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(data)
    for argv in (["explain", str(path)], ["diff", str(path), str(path)]):
        rc, err = _call(argv)
        assert rc == 2 and str(path) in err and message in err
    rc, _ = _call(["lint", str(path)])
    assert rc == 2


def test_lint_statement_with_a_list_effect_is_a_finding(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    statement = {"Sid": ["A"], "Effect": ["Deny"], "Action": "*", "Resource": "*"}
    path.write_text(json.dumps({"Version": "2012-10-17", "Statement": [statement, statement]}))
    rc, _ = _call(["lint", str(path), "--format", "json"])
    assert rc == 1


@pytest.mark.parametrize("text", ["- - -:\n", "a:\n  - - -:\n", "[{x: 1}: 2]\n", "--- &x\n"])
def test_damaged_yaml_never_hangs(text: str) -> None:
    with suppress(_miniyaml.YAMLError):
        _miniyaml.load(text)


def test_spec_that_used_to_hang_exits_2(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yaml"
    spec.write_text("allowed_regions:\n  - - -:\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "scp_guardrails", "build", "--spec", str(spec)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 2 and "cannot parse" in proc.stderr


@pytest.mark.parametrize(
    "data", [b"\xff", ("a: " + "[" * 100_000).encode(), b'{"max_policy_chars": ' + b"9" * 5000 + b"}"]
)
def test_bad_spec_files_exit_2(data: bytes, tmp_path: Path) -> None:
    for name in ("spec.yaml", "spec.json"):
        spec = tmp_path / name
        spec.write_bytes(data)
        rc, err = _call(["build", "--spec", str(spec)])
        assert rc == 2 and str(spec) in err
