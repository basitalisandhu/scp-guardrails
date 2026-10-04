"""CLI behaviour: help, exit codes, path expansion, output files."""

import json
import subprocess
import sys

import pytest
from conftest import FIXTURES, ROOT, fixture, run

from scp_guardrails import __version__


def test_version():
    with pytest.raises(SystemExit) as exc:
        run(["--version"])
    assert exc.value.code == 0


def test_no_command_prints_help():
    rc, out, _ = run([])
    assert rc == 0 and "usage: scp-guardrails" in out


@pytest.mark.parametrize("command", ["build", "lint", "diff", "explain", "catalog"])
def test_every_command_has_help(command):
    with pytest.raises(SystemExit) as exc:
        run([command, "--help"])
    assert exc.value.code == 0


@pytest.mark.parametrize("command", ["build", "lint", "diff", "explain", "catalog"])
def test_help_through_python_m(command):
    proc = subprocess.run(
        [sys.executable, "-m", "scp_guardrails", command, "--help"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
        check=False,
    )
    assert proc.returncode == 0 and "usage: scp-guardrails" in proc.stdout


def test_version_string_in_python_m():
    proc = subprocess.run(
        [sys.executable, "-m", "scp_guardrails", "--version"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
        check=False,
    )
    assert proc.stdout.strip() == f"scp-guardrails {__version__}"


def test_lint_directory_skips_non_policies(tmp_path):
    rc, _, _ = run(["build", "--spec", str(fixture("fixture-full-spec.yaml")), "--out", str(tmp_path)])
    assert rc == 0
    rc, out, err = run(["lint", str(tmp_path), "--fail-on", "low"])
    assert rc == 0 and "skipped" in err and "manifest.json" in err
    assert "scp-01.json" in out


def test_lint_glob_pattern():
    rc, out, _ = run(["lint", str(FIXTURES / "action" / "fixture-*.json"), "--fail-on", "none"])
    assert rc == 0 and "fixture-bad-policy.json" in out and "fixture-good-policy.json" in out


def test_lint_missing_path_and_empty_glob_exit_2(tmp_path):
    assert run(["lint", str(tmp_path / "missing.json")])[0] == 2
    assert run(["lint", str(tmp_path / "*.json")])[0] == 2


def test_lint_empty_directory_exit_2(tmp_path):
    rc, _, err = run(["lint", str(tmp_path)])
    assert rc == 2 and "no policy files" in err


def test_lint_explicit_non_policy_is_linted_strictly(write):
    rc, _, _ = run(["lint", str(write("m.json", {"documents": []}))])
    assert rc == 1


def test_lint_output_file_and_sarif_file(tmp_path):
    out_file, sarif_file = tmp_path / "r.json", tmp_path / "r.sarif"
    rc, stdout, _ = run(
        [
            "lint",
            str(fixture("fixture-mgmt-lockout.json")),
            "--format",
            "json",
            "--output",
            str(out_file),
            "--sarif",
            str(sarif_file),
        ]
    )
    assert rc == 1 and stdout == ""
    assert json.loads(out_file.read_text())[0]["findings"]
    assert json.loads(sarif_file.read_text())["version"] == "2.1.0"


def test_lint_github_output_and_summary(tmp_path):
    gh, summary = tmp_path / "out", tmp_path / "summary.md"
    rc, _, _ = run(
        [
            "lint",
            str(fixture("fixture-region-gaps.json")),
            "--github-output",
            str(gh),
            "--summary",
            str(summary),
            "--fail-on",
            "medium",
        ]
    )
    assert rc == 1
    values = dict(line.split("=", 1) for line in gh.read_text().splitlines())
    assert values == {"finding-count": "3", "highest-severity": "medium", "gate": "fail", "file-count": "1"}
    text = summary.read_text()
    assert "## scp-guardrails lint" in text and "SCP-REGION-GLOBAL-GAPS" in text


def test_lint_gate_pass_output(tmp_path):
    gh = tmp_path / "out"
    rc, _, _ = run(["lint", str(fixture("fixture-good.json")), "--github-output", str(gh)])
    assert rc == 0 and "gate=pass" in gh.read_text() and "highest-severity=none" in gh.read_text()


def test_lint_multiple_files_table_counts():
    rc, out, _ = run(["lint", str(fixture("fixture-good.json")), str(fixture("fixture-mgmt-lockout.json"))])
    assert rc == 1
    assert out.strip().splitlines()[-1].startswith("2 file(s), 2 finding(s): 2 high")


def test_same_file_twice_is_linted_once():
    rc, out, _ = run(["lint", str(fixture("fixture-good.json")), str(fixture("fixture-good.json"))])
    assert rc == 0 and "1 file(s)" in out


def test_explain_bad_input(write):
    assert run(["explain", str(write("x.json", "{"))])[0] == 2
    assert run(["explain", str(write("y.json", "{}"))])[0] == 2


def test_diff_bad_input(write):
    good = str(fixture("fixture-good.json"))
    assert run(["diff", good, str(write("x.json", "nope"))])[0] == 2
    assert run(["diff", str(write("y.json", "[]")), good])[0] == 2
